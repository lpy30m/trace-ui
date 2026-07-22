use std::collections::{BTreeMap, HashMap, HashSet};

use crate::error::{Result, TraceError};
use crate::query::elf_identity::{inspect_elf_binary, ElfBinaryIdentity};
use crate::query::evidence_score::{score_evidence, EvidenceScoreSignal};
use crate::query::ollvm::{
    BranchConditionOutcomeProfile, BranchConditionStateProfile, BranchConditionValueCount,
    BranchFlagBitProfile, BranchStateObservation, DispatcherCandidate, DispatcherStateSnapshot,
    DispatcherStateTransition, DynamicBasicBlock, DynamicBlockInstruction, DynamicBranchProfile,
    DynamicCfgEdge, OllvmAnalysisOptions, OllvmBlockFingerprint, OllvmBranchCaseEvidence,
    OllvmBranchStability, OllvmCaseSummary, OllvmDispatcherCaseEvidence, OllvmDispatcherStability,
    OllvmMultiTraceReport, OllvmMultiTraceRequest, OllvmReport, OllvmScope,
    OllvmStateRegisterFingerprint, OllvmStateRegisterMatch, OllvmTraceCase,
    OllvmVersionBlockCandidate, OllvmVersionDispatcherMapping, OllvmVersionMapReport,
    OllvmVersionMapRequest, OllvmVersionSummary, OllvmVersionTargetMapping, OllvmVersionTraceCase,
    OpaqueBranchCandidate,
};
use crate::utils::parse_hex_addr;

use super::trace_diff::{operation_shape, shape_signature};
use super::TraceEngine;

const CHUNK_SIZE: u32 = 4096;
const MAX_EXECUTED_INSTRUCTIONS: usize = 1_000_000;
const MAX_BLOCK_INSTRUCTIONS: usize = 256;
const MAX_DISPATCHER_STATE_SNAPSHOTS: usize = 64;
const MAX_BRANCH_STATE_OBSERVATIONS: usize = 8;
const MAX_TOTAL_DISPATCHER_STATE_SNAPSHOTS: usize = 512;
const MAX_TOTAL_BRANCH_STATE_OBSERVATIONS: usize = 512;

#[derive(Clone, Debug)]
struct ExecutedInsn {
    seq: u32,
    ordinal: u64,
    offset: u64,
    address: u64,
    disasm: String,
    operation: String,
}

#[derive(Clone, Debug)]
struct UniqueInsn {
    address: u64,
    disasm: String,
    operation: String,
    execution_count: u64,
    sample_seq: u32,
}

#[derive(Clone, Debug)]
struct InsnTransition {
    source_offset: u64,
    target_offset: u64,
    kind: String,
    sample_seq: u32,
}

#[derive(Default)]
struct BranchStats {
    disasm: String,
    execution_count: u64,
    taken: u64,
    fallthrough: u64,
    other: u64,
    successors: HashSet<u64>,
    condition_sources: HashSet<u64>,
    observations: Vec<BranchObservationWork>,
}

#[derive(Clone, Debug)]
struct BranchObservationWork {
    seq: u32,
    outcome: String,
    successor: u64,
}

struct BlockWork {
    block: DynamicBasicBlock,
    offsets: Vec<u64>,
    indirect_branch_count: u64,
    state_registers: Vec<String>,
}

impl TraceEngine {
    pub fn analyze_ollvm(
        &self,
        session_id: &str,
        options: OllvmAnalysisOptions,
    ) -> Result<OllvmReport> {
        let info = self.get_session_info(session_id)?;
        if !info.index_ready {
            return Err(TraceError::IndexNotReady);
        }

        let (node_id, function_name, node_func_addr, node_range, excluded_ranges) = {
            let handle = self.get_handle(session_id)?;
            let state = handle
                .state
                .read()
                .map_err(|error| TraceError::Internal(error.to_string()))?;
            match options.node_id {
                None => (None, None, None, None, Vec::new()),
                Some(requested_node_id) => {
                    let tree = state.call_tree.as_ref().ok_or(TraceError::IndexNotReady)?;
                    let node = tree
                        .nodes
                        .iter()
                        .find(|node| node.id == requested_node_id)
                        .ok_or_else(|| {
                            TraceError::InvalidArgument(format!(
                                "Function node {requested_node_id} not found"
                            ))
                        })?;
                    let excluded = if options.include_child_calls {
                        Vec::new()
                    } else {
                        node.children_ids
                            .iter()
                            .filter_map(|child_id| {
                                tree.nodes.iter().find(|child| child.id == *child_id)
                            })
                            .map(|child| (child.entry_seq.saturating_add(1), child.exit_seq))
                            .collect()
                    };
                    (
                        Some(node.id),
                        node.func_name.clone(),
                        Some(node.func_addr),
                        Some((node.entry_seq, node.exit_seq)),
                        excluded,
                    )
                }
            }
        };

        let mut start_seq = options
            .start_seq
            .unwrap_or_else(|| node_range.map(|range| range.0).unwrap_or(0));
        let mut end_seq = options.end_seq.unwrap_or_else(|| {
            node_range
                .map(|range| range.1)
                .unwrap_or_else(|| info.total_lines.saturating_sub(1))
        });
        if let Some((node_start, node_end)) = node_range {
            start_seq = start_seq.max(node_start);
            end_seq = end_seq.min(node_end);
        }
        end_seq = end_seq.min(info.total_lines.saturating_sub(1));
        if start_seq > end_seq {
            return Err(TraceError::InvalidArgument(
                "OLLVM analysis start_seq must not exceed end_seq".to_string(),
            ));
        }

        let module_name = match options
            .module_name
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
        {
            Some(module) => module.to_string(),
            None => self.infer_ollvm_module(
                session_id,
                start_seq,
                end_seq,
                node_func_addr,
                &excluded_ranges,
            )?,
        };

        let mut executed = Vec::new();
        let mut module_bases: HashMap<u64, u64> = HashMap::new();
        let mut ordinal = 0u64;
        let mut instructions_truncated = false;
        let mut cursor = start_seq;
        'scan: while cursor <= end_seq {
            let chunk_end = cursor
                .saturating_add(CHUNK_SIZE.saturating_sub(1))
                .min(end_seq);
            let seqs: Vec<u32> = (cursor..=chunk_end).collect();
            for line in self.get_lines(session_id, &seqs)? {
                if line.disasm.is_empty() {
                    continue;
                }
                ordinal = ordinal.saturating_add(1);
                if in_excluded_range(line.seq, &excluded_ranges) {
                    continue;
                }
                if !line
                    .so_name
                    .as_deref()
                    .is_some_and(|value| value.eq_ignore_ascii_case(&module_name))
                {
                    continue;
                }
                let Ok(offset) = parse_hex_addr(&line.so_offset) else {
                    continue;
                };
                let Ok(address) = parse_hex_addr(&line.address) else {
                    continue;
                };
                let base = address.saturating_sub(offset);
                *module_bases.entry(base).or_default() += 1;
                executed.push(ExecutedInsn {
                    seq: line.seq,
                    ordinal,
                    offset,
                    address,
                    operation: operation_name(&line.disasm),
                    disasm: line.disasm,
                });
                if executed.len() >= MAX_EXECUTED_INSTRUCTIONS {
                    instructions_truncated = true;
                    break 'scan;
                }
            }
            if chunk_end == u32::MAX {
                break;
            }
            cursor = chunk_end.saturating_add(1);
        }
        if executed.is_empty() {
            return Err(TraceError::InvalidArgument(format!(
                "No executed instructions found for module {module_name} in the selected range"
            )));
        }
        let module_base = module_bases
            .into_iter()
            .max_by_key(|(_, count)| *count)
            .map(|(base, _)| base)
            .unwrap_or(0);

        let mut unique: BTreeMap<u64, UniqueInsn> = BTreeMap::new();
        for instruction in &executed {
            unique
                .entry(instruction.offset)
                .and_modify(|item| {
                    item.execution_count = item.execution_count.saturating_add(1);
                    item.sample_seq = item.sample_seq.min(instruction.seq);
                })
                .or_insert_with(|| UniqueInsn {
                    address: instruction.address,
                    disasm: instruction.disasm.clone(),
                    operation: instruction.operation.clone(),
                    execution_count: 1,
                    sample_seq: instruction.seq,
                });
        }

        let (transitions, branch_stats) = build_transitions(&executed, module_base);
        let leaders = collect_block_leaders(&unique, &transitions, module_base);
        let mut blocks = build_blocks(&module_name, module_base, &unique, &executed, &leaders);
        let mut offset_to_block: HashMap<u64, usize> = HashMap::new();
        for (index, block) in blocks.iter().enumerate() {
            for offset in &block.offsets {
                offset_to_block.insert(*offset, index);
            }
        }

        let mut edge_counts: HashMap<(usize, usize, String), (u64, u32, u64, u64)> = HashMap::new();
        let mut predecessors: Vec<HashSet<usize>> = vec![HashSet::new(); blocks.len()];
        let mut successors: Vec<HashSet<usize>> = vec![HashSet::new(); blocks.len()];
        for transition in transitions {
            let (Some(&source), Some(&target)) = (
                offset_to_block.get(&transition.source_offset),
                offset_to_block.get(&transition.target_offset),
            ) else {
                continue;
            };
            if source == target && transition.kind == "sequential" {
                continue;
            }
            predecessors[target].insert(source);
            successors[source].insert(target);
            edge_counts
                .entry((source, target, transition.kind))
                .and_modify(|value| {
                    value.0 = value.0.saturating_add(1);
                    value.1 = value.1.min(transition.sample_seq);
                })
                .or_insert((
                    1,
                    transition.sample_seq,
                    transition.source_offset,
                    transition.target_offset,
                ));
        }
        for index in 0..blocks.len() {
            blocks[index].block.predecessor_count = predecessors[index].len() as u32;
            blocks[index].block.successor_count = successors[index].len() as u32;
        }

        let mut all_edges: Vec<DynamicCfgEdge> = edge_counts
            .into_iter()
            .map(
                |(
                    (source, target, kind),
                    (execution_count, sample_seq, source_offset, target_offset),
                )| {
                    DynamicCfgEdge {
                        source_block_id: blocks[source].block.block_id.clone(),
                        target_block_id: blocks[target].block.block_id.clone(),
                        source_offset: format!("0x{source_offset:x}"),
                        target_offset: format!("0x{target_offset:x}"),
                        kind,
                        execution_count,
                        sample_seq,
                        backward: blocks[target].offsets[0] <= blocks[source].offsets[0],
                    }
                },
            )
            .collect();
        all_edges.sort_by(|left, right| {
            parse_hex_addr(&left.source_offset)
                .unwrap_or(0)
                .cmp(&parse_hex_addr(&right.source_offset).unwrap_or(0))
                .then_with(|| {
                    parse_hex_addr(&left.target_offset)
                        .unwrap_or(0)
                        .cmp(&parse_hex_addr(&right.target_offset).unwrap_or(0))
                })
                .then_with(|| left.kind.cmp(&right.kind))
        });

        let mut dispatcher_candidates = build_dispatcher_candidates(&blocks, &all_edges);
        dispatcher_candidates.sort_by(|left, right| {
            right
                .assessment
                .score
                .cmp(&left.assessment.score)
                .then_with(|| right.visit_count.cmp(&left.visit_count))
        });
        attach_dispatcher_state_evidence(self, session_id, &executed, &mut dispatcher_candidates);
        let mut branch_profiles = build_branch_profiles(branch_stats);
        branch_profiles.sort_by(|left, right| {
            right
                .execution_count
                .cmp(&left.execution_count)
                .then_with(|| {
                    parse_hex_addr(&left.branch_offset)
                        .unwrap_or(0)
                        .cmp(&parse_hex_addr(&right.branch_offset).unwrap_or(0))
                })
        });
        attach_branch_state_evidence(self, session_id, &mut branch_profiles);
        branch_profiles.sort_by_key(|profile| parse_hex_addr(&profile.branch_offset).unwrap_or(0));
        let mut opaque_branch_candidates = build_opaque_candidates(&branch_profiles);
        opaque_branch_candidates.sort_by(|left, right| {
            right
                .assessment
                .score
                .cmp(&left.assessment.score)
                .then_with(|| right.execution_count.cmp(&left.execution_count))
        });

        let total_block_count = blocks.len();
        let total_edge_count = all_edges.len();
        let max_blocks = options.max_blocks.clamp(1, 10_000) as usize;
        let max_edges = options.max_edges.clamp(1, 50_000) as usize;
        let candidate_ids: HashSet<String> = dispatcher_candidates
            .iter()
            .map(|candidate| candidate.block_id.clone())
            .collect();
        blocks.sort_by(|left, right| {
            candidate_ids
                .contains(&right.block.block_id)
                .cmp(&candidate_ids.contains(&left.block.block_id))
                .then_with(|| left.offsets[0].cmp(&right.offsets[0]))
        });
        let blocks_truncated = blocks.len() > max_blocks;
        blocks.truncate(max_blocks);
        blocks.sort_by_key(|block| block.offsets[0]);
        let retained_ids: HashSet<String> = blocks
            .iter()
            .map(|block| block.block.block_id.clone())
            .collect();
        all_edges.retain(|edge| {
            retained_ids.contains(&edge.source_block_id)
                && retained_ids.contains(&edge.target_block_id)
        });
        let edges_truncated = all_edges.len() > max_edges || total_edge_count > all_edges.len();
        all_edges.truncate(max_edges);

        Ok(OllvmReport {
            schema_version: "trace-ui/ollvm-v1".to_string(),
            scope: OllvmScope {
                session_id: session_id.to_string(),
                node_id,
                function_name,
                module_name,
                module_base: format!("0x{module_base:x}"),
                start_seq,
                end_seq,
                child_calls_excluded: excluded_ranges.len() as u32,
            },
            executed_instruction_count: executed.len() as u64,
            unique_instruction_count: unique.len().min(u32::MAX as usize) as u32,
            block_count: total_block_count.min(u32::MAX as usize) as u32,
            edge_count: total_edge_count.min(u32::MAX as usize) as u32,
            blocks: blocks.into_iter().map(|block| block.block).collect(),
            edges: all_edges,
            branch_profiles,
            dispatcher_candidates,
            opaque_branch_candidates,
            instructions_truncated,
            blocks_truncated,
            edges_truncated,
            limitations: vec![
                "This is a dynamic CFG: only instructions and edges executed in the selected trace range are present."
                    .to_string(),
                "A stable branch outcome in one trace is an opaque-predicate candidate, not proof that the alternate path is impossible."
                    .to_string(),
                "Dispatcher scoring uses repeated visits, fan-in/fan-out, indirect branches, state-like register operations, and backward edges."
                    .to_string(),
                "Dispatcher state snapshots and branch register observations are reconstructed from trace register checkpoints; missing or unknown register values are omitted."
                    .to_string(),
                "Child call ranges are excluded by default when a call-tree node is selected; enable includeChildCalls to retain them."
                    .to_string(),
            ],
            next_steps: vec![
                "Compare controlled traces with different inputs and confirm whether dispatcher and branch candidates keep the same structure."
                    .to_string(),
                "Generate the IDAPython bridge, review comments/colors, and enable user xrefs only after validating image-base alignment."
                    .to_string(),
                "Use Frida 16 Stalker calls or blocks to widen runtime coverage, then import the resulting trace and rerun this analysis."
                    .to_string(),
                "Use the trace-seeded probes in the generated angr script to compare observed concrete branch state with the unconstrained blank-state probe."
                    .to_string(),
            ],
        })
    }

    pub fn compare_ollvm_traces(
        &self,
        request: OllvmMultiTraceRequest,
    ) -> Result<OllvmMultiTraceReport> {
        if !(2..=16).contains(&request.cases.len()) {
            return Err(TraceError::InvalidArgument(
                "OLLVM comparison requires two to sixteen trace cases".to_string(),
            ));
        }
        let require_matching_binary = request.require_matching_binary;
        let mut labels = HashSet::new();
        let mut prepared_cases = Vec::with_capacity(request.cases.len());
        let mut binary_identity_cache: HashMap<String, ElfBinaryIdentity> = HashMap::new();
        for mut case in request.cases {
            let label = case.label.trim();
            if label.is_empty() {
                return Err(TraceError::InvalidArgument(
                    "OLLVM comparison case labels must not be empty".to_string(),
                ));
            }
            if !labels.insert(label.to_string()) {
                return Err(TraceError::InvalidArgument(format!(
                    "Duplicate OLLVM comparison case label: {label}"
                )));
            }
            case.static_binary_path = case
                .static_binary_path
                .as_deref()
                .map(str::trim)
                .filter(|path| !path.is_empty())
                .map(str::to_string);
            let binary_identity = if let Some(path) = case.static_binary_path.as_deref() {
                let identity = if let Some(identity) = binary_identity_cache.get(path) {
                    identity.clone()
                } else {
                    let identity = inspect_elf_binary(path).map_err(|error| {
                        TraceError::InvalidArgument(format!(
                            "OLLVM comparison case '{}' ELF identity failed: {error}",
                            case.label
                        ))
                    })?;
                    binary_identity_cache.insert(path.to_string(), identity.clone());
                    identity
                };
                if identity.elf_machine != 183 {
                    return Err(TraceError::InvalidArgument(format!(
                        "OLLVM comparison case '{}' selected ELF is {}, not AArch64",
                        case.label, identity.architecture
                    )));
                }
                Some(identity)
            } else {
                None
            };
            prepared_cases.push((case, binary_identity));
        }
        let provided_identity_count = prepared_cases
            .iter()
            .filter(|(_, identity)| identity.is_some())
            .count();
        if require_matching_binary && provided_identity_count != prepared_cases.len() {
            return Err(TraceError::InvalidArgument(format!(
                "requireMatchingBinary is enabled, but only {provided_identity_count}/{} cases provide staticBinaryPath",
                prepared_cases.len()
            )));
        }
        let supplied_hashes = prepared_cases
            .iter()
            .filter_map(|(_, identity)| identity.as_ref().map(|identity| &identity.binary_sha256))
            .collect::<HashSet<_>>();
        if supplied_hashes.len() > 1 {
            return Err(TraceError::InvalidArgument(format!(
                "OLLVM comparison refused: supplied ELF files have {} distinct SHA-256 values",
                supplied_hashes.len()
            )));
        }

        let mut cases = Vec::with_capacity(prepared_cases.len());
        for (case, binary_identity) in prepared_cases {
            let report = self.analyze_ollvm(
                &case.session_id,
                OllvmAnalysisOptions {
                    node_id: case.node_id,
                    module_name: case.module_name.clone(),
                    start_seq: case.start_seq,
                    end_seq: case.end_seq,
                    include_child_calls: case.include_child_calls,
                    max_blocks: request.max_blocks,
                    max_edges: request.max_edges,
                },
            )?;
            cases.push((case, report, binary_identity));
        }
        compare_ollvm_reports(cases, require_matching_binary).map_err(TraceError::InvalidArgument)
    }

    pub fn map_ollvm_versions(
        &self,
        request: OllvmVersionMapRequest,
    ) -> Result<OllvmVersionMapReport> {
        if !(2..=8).contains(&request.versions.len()) {
            return Err(TraceError::InvalidArgument(
                "OLLVM version mapping requires two to eight versions".to_string(),
            ));
        }
        if !(1..=10).contains(&request.max_matches_per_block) {
            return Err(TraceError::InvalidArgument(
                "maxMatchesPerBlock must be between 1 and 10".to_string(),
            ));
        }
        if !(1..=100).contains(&request.min_score) {
            return Err(TraceError::InvalidArgument(
                "minScore must be between 1 and 100".to_string(),
            ));
        }

        let baseline_version_id = request
            .baseline_version_id
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(str::to_string);
        let max_blocks = request.max_blocks;
        let max_edges = request.max_edges;
        let max_matches_per_block = request.max_matches_per_block as usize;
        let min_score = request.min_score;
        let mut version_ids = HashSet::new();
        let mut identity_cache: HashMap<String, ElfBinaryIdentity> = HashMap::new();
        let mut prepared = Vec::with_capacity(request.versions.len());

        for mut version in request.versions {
            version.version_id = version.version_id.trim().to_string();
            if version.version_id.is_empty() {
                return Err(TraceError::InvalidArgument(
                    "OLLVM version IDs must not be empty".to_string(),
                ));
            }
            if !version_ids.insert(version.version_id.to_ascii_lowercase()) {
                return Err(TraceError::InvalidArgument(format!(
                    "Duplicate OLLVM version ID: {}",
                    version.version_id
                )));
            }
            version.static_binary_path = version.static_binary_path.trim().to_string();
            if version.static_binary_path.is_empty() {
                return Err(TraceError::InvalidArgument(format!(
                    "OLLVM version '{}' requires staticBinaryPath",
                    version.version_id
                )));
            }
            let identity = if let Some(identity) = identity_cache.get(&version.static_binary_path) {
                identity.clone()
            } else {
                let identity =
                    inspect_elf_binary(&version.static_binary_path).map_err(|error| {
                        TraceError::InvalidArgument(format!(
                            "OLLVM version '{}' ELF identity failed: {error}",
                            version.version_id
                        ))
                    })?;
                identity_cache.insert(version.static_binary_path.clone(), identity.clone());
                identity
            };
            if identity.elf_machine != 183 {
                return Err(TraceError::InvalidArgument(format!(
                    "OLLVM version '{}' selected ELF is {}, not AArch64",
                    version.version_id, identity.architecture
                )));
            }
            prepared.push((version, identity));
        }

        if let Some(baseline) = baseline_version_id.as_deref() {
            if !version_ids.contains(&baseline.to_ascii_lowercase()) {
                return Err(TraceError::InvalidArgument(format!(
                    "baselineVersionId does not match a supplied version: {baseline}"
                )));
            }
        }
        let distinct_hashes = prepared
            .iter()
            .map(|(_, identity)| identity.binary_sha256.to_ascii_lowercase())
            .collect::<HashSet<_>>();
        if distinct_hashes.len() != prepared.len() {
            return Err(TraceError::InvalidArgument(
                "OLLVM version mapping requires a different SHA-256 for every version; use compare_ollvm_traces for repeated runs of the same ELF"
                    .to_string(),
            ));
        }

        let mut versions = Vec::with_capacity(prepared.len());
        for (version, identity) in prepared {
            let report = self.analyze_ollvm(
                &version.session_id,
                OllvmAnalysisOptions {
                    node_id: version.node_id,
                    module_name: version.module_name.clone(),
                    start_seq: version.start_seq,
                    end_seq: version.end_seq,
                    include_child_calls: version.include_child_calls,
                    max_blocks,
                    max_edges,
                },
            )?;
            versions.push((version, report, identity));
        }

        map_ollvm_version_reports(
            versions,
            baseline_version_id.as_deref(),
            max_matches_per_block,
            min_score,
        )
        .map_err(TraceError::InvalidArgument)
    }

    fn infer_ollvm_module(
        &self,
        session_id: &str,
        start_seq: u32,
        end_seq: u32,
        node_func_addr: Option<u64>,
        excluded_ranges: &[(u32, u32)],
    ) -> Result<String> {
        let probe_end = start_seq.saturating_add(511).min(end_seq);
        let seqs: Vec<u32> = (start_seq..=probe_end).collect();
        let lines = self.get_lines(session_id, &seqs)?;
        if let Some(address) = node_func_addr {
            if let Some(module) = lines.iter().find_map(|line| {
                let parsed = parse_hex_addr(&line.address).ok()?;
                (parsed == address).then(|| line.so_name.clone()).flatten()
            }) {
                return Ok(module);
            }
        }
        let mut counts: HashMap<String, u32> = HashMap::new();
        for line in lines {
            if line.disasm.is_empty() || in_excluded_range(line.seq, excluded_ranges) {
                continue;
            }
            if let Some(module) = line.so_name {
                *counts.entry(module).or_default() += 1;
            }
        }
        counts
            .into_iter()
            .max_by_key(|(_, count)| *count)
            .map(|(module, _)| module)
            .ok_or_else(|| {
                TraceError::InvalidArgument(
                    "Unable to infer a module from the selected trace range; provide module_name"
                        .to_string(),
                )
            })
    }
}

fn in_excluded_range(seq: u32, ranges: &[(u32, u32)]) -> bool {
    ranges
        .iter()
        .any(|(start, end)| seq >= *start && seq <= *end)
}

fn operation_name(disasm: &str) -> String {
    disasm
        .split_whitespace()
        .next()
        .unwrap_or("")
        .trim()
        .to_ascii_lowercase()
}

fn is_conditional_branch(operation: &str) -> bool {
    operation.starts_with("b.") || matches!(operation, "cbz" | "cbnz" | "tbz" | "tbnz")
}

fn is_call(operation: &str) -> bool {
    matches!(operation, "bl" | "blr")
}

fn is_return(operation: &str) -> bool {
    operation == "ret"
}

fn is_terminator(operation: &str) -> bool {
    is_conditional_branch(operation)
        || matches!(operation, "b" | "br")
        || is_call(operation)
        || is_return(operation)
}

fn parse_last_hex(disasm: &str) -> Option<u64> {
    let bytes = disasm.as_bytes();
    let mut positions = Vec::new();
    let mut index = 0usize;
    while index + 2 <= bytes.len() {
        if bytes[index] == b'0'
            && index + 1 < bytes.len()
            && matches!(bytes[index + 1], b'x' | b'X')
        {
            positions.push(index);
            index += 2;
        } else {
            index += 1;
        }
    }
    let start = positions.pop()?;
    let mut end = start + 2;
    while end < bytes.len() && bytes[end].is_ascii_hexdigit() {
        end += 1;
    }
    parse_hex_addr(&disasm[start..end]).ok()
}

fn direct_target_offset(instruction: &ExecutedInsn, module_base: u64) -> Option<u64> {
    if !is_conditional_branch(&instruction.operation) && instruction.operation != "b" {
        return None;
    }
    let target = parse_last_hex(&instruction.disasm)?;
    Some(if target >= module_base {
        target.saturating_sub(module_base)
    } else {
        target
    })
}

fn condition_source(operation: &str) -> bool {
    operation.starts_with("cmp")
        || operation.starts_with("cmn")
        || operation.starts_with("tst")
        || operation.starts_with("subs")
        || operation.starts_with("ands")
        || matches!(operation, "ccmp" | "ccmn")
}

fn build_transitions(
    executed: &[ExecutedInsn],
    module_base: u64,
) -> (Vec<InsnTransition>, HashMap<u64, BranchStats>) {
    let mut transitions = Vec::new();
    let mut branch_stats: HashMap<u64, BranchStats> = HashMap::new();
    for (index, instruction) in executed.iter().enumerate() {
        if is_conditional_branch(&instruction.operation) {
            let stats = branch_stats.entry(instruction.offset).or_default();
            stats.execution_count = stats.execution_count.saturating_add(1);
            if stats.disasm.is_empty() {
                stats.disasm = instruction.disasm.clone();
            }
            for previous in executed[..index].iter().rev().take(3) {
                if instruction.ordinal.saturating_sub(previous.ordinal) > 3 {
                    break;
                }
                if condition_source(&previous.operation) {
                    stats.condition_sources.insert(previous.offset);
                }
            }
        }
        let Some(next) = executed.get(index + 1) else {
            continue;
        };
        let ordinal_gap = next.ordinal.saturating_sub(instruction.ordinal);
        let direct_target = direct_target_offset(instruction, module_base);
        let kind = if is_conditional_branch(&instruction.operation) {
            let stats = branch_stats.entry(instruction.offset).or_default();
            stats.successors.insert(next.offset);
            let (kind, outcome) = if next.offset == instruction.offset.saturating_add(4) {
                stats.fallthrough = stats.fallthrough.saturating_add(1);
                ("conditional_fallthrough", "fallthrough")
            } else if direct_target == Some(next.offset) {
                stats.taken = stats.taken.saturating_add(1);
                ("conditional_taken", "taken")
            } else {
                stats.other = stats.other.saturating_add(1);
                ("conditional_other", "other")
            };
            if stats.observations.len() < MAX_BRANCH_STATE_OBSERVATIONS {
                stats.observations.push(BranchObservationWork {
                    seq: instruction.seq,
                    outcome: outcome.to_string(),
                    successor: next.offset,
                });
            }
            kind
        } else if instruction.operation == "b" {
            if direct_target.is_some_and(|target| target == next.offset) {
                "branch"
            } else if ordinal_gap == 1 {
                "branch_observed"
            } else {
                continue;
            }
        } else if instruction.operation == "br" {
            "indirect"
        } else if is_call(&instruction.operation) {
            if ordinal_gap > 1 && next.offset == instruction.offset.saturating_add(4) {
                "call_return"
            } else {
                "call"
            }
        } else if is_return(&instruction.operation) {
            continue;
        } else if ordinal_gap == 1 && next.offset == instruction.offset.saturating_add(4) {
            "sequential"
        } else {
            continue;
        };
        transitions.push(InsnTransition {
            source_offset: instruction.offset,
            target_offset: next.offset,
            kind: kind.to_string(),
            sample_seq: instruction.seq,
        });
    }
    (transitions, branch_stats)
}

fn collect_block_leaders(
    unique: &BTreeMap<u64, UniqueInsn>,
    transitions: &[InsnTransition],
    module_base: u64,
) -> HashSet<u64> {
    let mut leaders = HashSet::new();
    if let Some(offset) = unique.keys().next().copied() {
        leaders.insert(offset);
    }
    let mut previous: Option<(&u64, &UniqueInsn)> = None;
    for (offset, instruction) in unique {
        if let Some((previous_offset, previous_instruction)) = previous {
            if *offset != previous_offset.saturating_add(4)
                || is_terminator(&previous_instruction.operation)
            {
                leaders.insert(*offset);
            }
        }
        if is_terminator(&instruction.operation) {
            let fallthrough = offset.saturating_add(4);
            if unique.contains_key(&fallthrough) {
                leaders.insert(fallthrough);
            }
        }
        if let Some(target) = direct_target_offset(
            &ExecutedInsn {
                seq: instruction.sample_seq,
                ordinal: 0,
                offset: *offset,
                address: instruction.address,
                disasm: instruction.disasm.clone(),
                operation: instruction.operation.clone(),
            },
            module_base,
        ) {
            if unique.contains_key(&target) {
                leaders.insert(target);
            }
        }
        previous = Some((offset, instruction));
    }
    for transition in transitions {
        leaders.insert(transition.target_offset);
    }
    leaders
}

fn extract_state_registers(instructions: &[DynamicBlockInstruction]) -> Vec<String> {
    let mut registers = HashSet::new();
    for instruction in instructions {
        let operation = operation_name(&instruction.disasm);
        if !(condition_source(&operation)
            || operation.starts_with("csel")
            || operation.starts_with("csinc")
            || operation.starts_with("eor")
            || operation.starts_with("and")
            || operation.starts_with("ldr"))
        {
            continue;
        }
        for token in instruction
            .disasm
            .split(|character: char| !character.is_ascii_alphanumeric())
        {
            let lower = token.to_ascii_lowercase();
            let is_register = lower
                .strip_prefix('x')
                .or_else(|| lower.strip_prefix('w'))
                .and_then(|value| value.parse::<u8>().ok())
                .is_some_and(|index| index <= 30);
            if is_register {
                registers.insert(lower);
            }
        }
    }
    let mut registers: Vec<_> = registers.into_iter().collect();
    registers.sort();
    registers.truncate(8);
    registers
}

fn build_blocks(
    module_name: &str,
    module_base: u64,
    unique: &BTreeMap<u64, UniqueInsn>,
    executed: &[ExecutedInsn],
    leaders: &HashSet<u64>,
) -> Vec<BlockWork> {
    let mut groups: Vec<Vec<u64>> = Vec::new();
    let mut current = Vec::new();
    let mut previous_offset = None;
    let mut previous_terminator = false;
    for (offset, instruction) in unique {
        let start_new = !current.is_empty()
            && (leaders.contains(offset)
                || previous_offset
                    .is_some_and(|previous: u64| *offset != previous.saturating_add(4))
                || previous_terminator);
        if start_new {
            groups.push(std::mem::take(&mut current));
        }
        current.push(*offset);
        previous_offset = Some(*offset);
        previous_terminator = is_terminator(&instruction.operation);
        if previous_terminator {
            groups.push(std::mem::take(&mut current));
            previous_offset = None;
            previous_terminator = false;
        }
    }
    if !current.is_empty() {
        groups.push(current);
    }

    groups
        .into_iter()
        .filter(|offsets| !offsets.is_empty())
        .map(|offsets| {
            let start = offsets[0];
            let end = *offsets.last().unwrap();
            let mut sample_seqs: Vec<u32> = executed
                .iter()
                .filter(|instruction| instruction.offset == start)
                .map(|instruction| instruction.seq)
                .take(8)
                .collect();
            sample_seqs.sort_unstable();
            sample_seqs.dedup();
            let visit_count = executed
                .iter()
                .filter(|instruction| instruction.offset == start)
                .count() as u64;
            let instructions: Vec<_> = offsets
                .iter()
                .filter_map(|offset| {
                    let instruction = unique.get(offset)?;
                    Some(DynamicBlockInstruction {
                        offset: format!("0x{offset:x}"),
                        address: format!("0x{:x}", instruction.address),
                        disasm: instruction.disasm.clone(),
                        execution_count: instruction.execution_count,
                        sample_seq: instruction.sample_seq,
                    })
                })
                .take(MAX_BLOCK_INSTRUCTIONS)
                .collect();
            let terminal_operation = unique
                .get(&end)
                .map(|instruction| instruction.operation.clone())
                .unwrap_or_default();
            let indirect_branch_count = offsets
                .iter()
                .filter_map(|offset| unique.get(offset))
                .filter(|instruction| instruction.operation == "br")
                .map(|instruction| instruction.execution_count)
                .sum();
            let state_registers = extract_state_registers(&instructions);
            BlockWork {
                block: DynamicBasicBlock {
                    block_id: format!("{module_name}+0x{start:x}"),
                    module_name: module_name.to_string(),
                    start_offset: format!("0x{start:x}"),
                    end_offset: format!("0x{end:x}"),
                    start_address: format!("0x{:x}", module_base.saturating_add(start)),
                    end_address: format!("0x{:x}", module_base.saturating_add(end)),
                    visit_count,
                    predecessor_count: 0,
                    successor_count: 0,
                    terminal_operation,
                    sample_seqs,
                    instructions,
                },
                offsets,
                indirect_branch_count,
                state_registers,
            }
        })
        .collect()
}

fn build_dispatcher_candidates(
    blocks: &[BlockWork],
    edges: &[DynamicCfgEdge],
) -> Vec<DispatcherCandidate> {
    let mut results = Vec::new();
    for block in blocks {
        let backward_edge_count = edges
            .iter()
            .filter(|edge| edge.target_block_id == block.block.block_id && edge.backward)
            .count() as u32;
        let has_state_operations = !block.state_registers.is_empty();
        let assessment = score_evidence(
            format!("ollvm_dispatcher: {}", block.block.start_offset),
            false,
            vec![
                EvidenceScoreSignal::new(
                    "repeated_visits",
                    "Repeated runtime visits",
                    20,
                    block.block.visit_count >= 4,
                    Some(format!("{} visits", block.block.visit_count)),
                ),
                EvidenceScoreSignal::new(
                    "fan_in",
                    "Multiple dynamic predecessors",
                    20,
                    block.block.predecessor_count >= 3,
                    Some(format!("{} predecessors", block.block.predecessor_count)),
                ),
                EvidenceScoreSignal::new(
                    "fan_out",
                    "Multiple dynamic successors",
                    15,
                    block.block.successor_count >= 2,
                    Some(format!("{} successors", block.block.successor_count)),
                ),
                EvidenceScoreSignal::new(
                    "indirect_dispatch",
                    "Observed indirect branch",
                    20,
                    block.indirect_branch_count > 0,
                    Some(format!(
                        "{} indirect executions",
                        block.indirect_branch_count
                    )),
                ),
                EvidenceScoreSignal::new(
                    "backward_edges",
                    "Backward edges return to block",
                    10,
                    backward_edge_count > 0,
                    Some(format!("{} backward edges", backward_edge_count)),
                ),
                EvidenceScoreSignal::new(
                    "state_registers",
                    "State-like compare/select registers",
                    15,
                    has_state_operations,
                    Some(block.state_registers.join(", ")),
                ),
            ],
            vec![
                "Dynamic centrality can also describe a normal loop or switch dispatcher."
                    .to_string(),
                "Static dominator and unexecuted-case evidence are not available from one trace."
                    .to_string(),
            ],
        );
        if assessment.score < 40 {
            continue;
        }
        let rationale = format!(
            "visited {} times with {} predecessors, {} successors, {} indirect branch executions, and {} backward incoming edges",
            block.block.visit_count,
            block.block.predecessor_count,
            block.block.successor_count,
            block.indirect_branch_count,
            backward_edge_count
        );
        results.push(DispatcherCandidate {
            block_id: block.block.block_id.clone(),
            start_offset: block.block.start_offset.clone(),
            end_offset: block.block.end_offset.clone(),
            visit_count: block.block.visit_count,
            predecessor_count: block.block.predecessor_count,
            successor_count: block.block.successor_count,
            indirect_branch_count: block.indirect_branch_count,
            backward_edge_count,
            state_registers: block.state_registers.clone(),
            state_snapshots: Vec::new(),
            state_transitions: Vec::new(),
            state_snapshots_truncated: false,
            rationale,
            assessment,
        });
    }
    results
}

fn canonical_register_name(value: &str) -> Option<String> {
    let lower = value.trim().to_ascii_lowercase();
    if lower == "nzcv" || lower == "sp" {
        return Some(lower.to_ascii_uppercase());
    }
    let index = lower
        .strip_prefix('x')
        .or_else(|| lower.strip_prefix('w'))?
        .parse::<u8>()
        .ok()?;
    (index <= 30).then(|| format!("X{index}"))
}

fn branch_relevant_registers(disasm: &str) -> Vec<String> {
    let operation = operation_name(disasm);
    if operation.starts_with("b.") {
        return vec!["NZCV".to_string()];
    }
    for token in disasm.split(|character: char| !character.is_ascii_alphanumeric()) {
        if let Some(register) = canonical_register_name(token) {
            return vec![register];
        }
    }
    Vec::new()
}

fn attach_dispatcher_state_evidence(
    engine: &TraceEngine,
    session_id: &str,
    executed: &[ExecutedInsn],
    candidates: &mut [DispatcherCandidate],
) {
    let mut remaining_snapshots = MAX_TOTAL_DISPATCHER_STATE_SNAPSHOTS;
    for candidate in candidates {
        let Ok(start_offset) = parse_hex_addr(&candidate.start_offset) else {
            continue;
        };
        let mut registers: Vec<String> = candidate
            .state_registers
            .iter()
            .filter_map(|register| canonical_register_name(register))
            .collect::<HashSet<_>>()
            .into_iter()
            .collect();
        registers.sort();
        if registers.is_empty() {
            continue;
        }
        let visit_seqs: Vec<u32> = executed
            .iter()
            .filter(|instruction| instruction.offset == start_offset)
            .map(|instruction| instruction.seq)
            .collect();
        let snapshot_limit = MAX_DISPATCHER_STATE_SNAPSHOTS.min(remaining_snapshots);
        candidate.state_snapshots_truncated = visit_seqs.len() > snapshot_limit;
        let mut snapshots = Vec::new();
        for seq in visit_seqs.into_iter().take(snapshot_limit) {
            remaining_snapshots = remaining_snapshots.saturating_sub(1);
            let Ok(state) = engine.get_registers_at(session_id, seq) else {
                continue;
            };
            let values = registers
                .iter()
                .filter_map(|register| {
                    let value = state.get(register)?;
                    (value != "?").then(|| (register.clone(), value.clone()))
                })
                .collect::<BTreeMap<_, _>>();
            if !values.is_empty() {
                snapshots.push(DispatcherStateSnapshot { seq, values });
            }
        }
        let mut transition_counts: BTreeMap<(String, String, String), (u64, u32)> = BTreeMap::new();
        for pair in snapshots.windows(2) {
            let (left, right) = (&pair[0], &pair[1]);
            for register in &registers {
                let (Some(from_value), Some(to_value)) =
                    (left.values.get(register), right.values.get(register))
                else {
                    continue;
                };
                if from_value == to_value {
                    continue;
                }
                transition_counts
                    .entry((register.clone(), from_value.clone(), to_value.clone()))
                    .and_modify(|entry| entry.0 = entry.0.saturating_add(1))
                    .or_insert((1, left.seq));
            }
        }
        candidate.state_transitions = transition_counts
            .into_iter()
            .map(
                |((register, from_value, to_value), (execution_count, sample_seq))| {
                    DispatcherStateTransition {
                        register,
                        from_value,
                        to_value,
                        execution_count,
                        sample_seq,
                    }
                },
            )
            .collect();
        candidate.state_transitions.sort_by(|left, right| {
            right
                .execution_count
                .cmp(&left.execution_count)
                .then_with(|| left.register.cmp(&right.register))
        });
        candidate.state_snapshots = snapshots;
    }
}

fn build_branch_profiles(stats: HashMap<u64, BranchStats>) -> Vec<DynamicBranchProfile> {
    stats
        .into_iter()
        .map(|(offset, stats)| {
            let mut observed_successors: Vec<_> = stats
                .successors
                .into_iter()
                .map(|target| format!("0x{target:x}"))
                .collect();
            observed_successors.sort();
            let mut condition_source_offsets: Vec<_> = stats
                .condition_sources
                .into_iter()
                .map(|source| format!("0x{source:x}"))
                .collect();
            condition_source_offsets.sort();
            DynamicBranchProfile {
                branch_offset: format!("0x{offset:x}"),
                disasm: stats.disasm,
                execution_count: stats.execution_count,
                observed_taken_count: stats.taken,
                observed_fallthrough_count: stats.fallthrough,
                observed_other_count: stats.other,
                observed_successors,
                condition_source_offsets,
                observations_truncated: stats.execution_count as usize > stats.observations.len(),
                observations: stats
                    .observations
                    .into_iter()
                    .map(|observation| BranchStateObservation {
                        seq: observation.seq,
                        outcome: observation.outcome,
                        successor: format!("0x{:x}", observation.successor),
                        registers: BTreeMap::new(),
                    })
                    .collect(),
                condition_state_profile: Default::default(),
            }
        })
        .collect()
}

fn attach_branch_state_evidence(
    engine: &TraceEngine,
    session_id: &str,
    profiles: &mut [DynamicBranchProfile],
) {
    let mut remaining_observations = MAX_TOTAL_BRANCH_STATE_OBSERVATIONS;
    for profile in profiles {
        let registers = branch_relevant_registers(&profile.disasm);
        if registers.is_empty() {
            continue;
        }
        let enrich_count = profile.observations.len().min(remaining_observations);
        if enrich_count < profile.observations.len() {
            profile.observations_truncated = true;
        }
        for observation in profile.observations.iter_mut().take(enrich_count) {
            remaining_observations = remaining_observations.saturating_sub(1);
            let Ok(state) = engine.get_registers_at(session_id, observation.seq) else {
                continue;
            };
            observation.registers = registers
                .iter()
                .filter_map(|register| {
                    let value = state.get(register)?;
                    (value != "?").then(|| (register.clone(), value.clone()))
                })
                .collect();
        }
        profile.condition_state_profile = build_condition_state_profile(
            &profile.observations,
            profile.execution_count,
            profile.observations_truncated,
            registers.first().cloned(),
        );
    }
}

fn build_condition_state_profile(
    observations: &[BranchStateObservation],
    execution_count: u64,
    observations_truncated: bool,
    source_register: Option<String>,
) -> BranchConditionStateProfile {
    let Some(source_register) = source_register else {
        return BranchConditionStateProfile {
            incomplete: execution_count > 0 || observations_truncated,
            missing_observation_count: execution_count,
            ..Default::default()
        };
    };
    let mut values = BTreeMap::<String, u64>::new();
    let mut outcome_values = BTreeMap::<String, BTreeMap<String, u64>>::new();
    let mut outcome_counts = BTreeMap::<String, u64>::new();
    let mut overall_flags = [0u64; 8];
    let mut outcome_flags = BTreeMap::<String, [u64; 8]>::new();
    let mut captured = 0u64;
    let is_nzcv = source_register.eq_ignore_ascii_case("NZCV");
    for observation in observations {
        let Some(value) = observation.registers.get(&source_register) else {
            continue;
        };
        let value = value.trim();
        if value.is_empty() || value == "?" {
            continue;
        }
        captured = captured.saturating_add(1);
        *values.entry(value.to_string()).or_default() += 1;
        *outcome_counts
            .entry(observation.outcome.clone())
            .or_default() += 1;
        *outcome_values
            .entry(observation.outcome.clone())
            .or_default()
            .entry(value.to_string())
            .or_default() += 1;
        if is_nzcv {
            let Ok(parsed) = parse_hex_addr(value) else {
                continue;
            };
            let flags = outcome_flags
                .entry(observation.outcome.clone())
                .or_default();
            for (index, bit) in [31u8, 30, 29, 28].into_iter().enumerate() {
                let set = ((parsed >> bit) & 1) != 0;
                let slot = index * 2 + usize::from(set);
                overall_flags[slot] = overall_flags[slot].saturating_add(1);
                flags[slot] = flags[slot].saturating_add(1);
            }
        }
    }
    let mut value_items: Vec<_> = values
        .into_iter()
        .map(|(value, count)| BranchConditionValueCount { value, count })
        .collect();
    value_items.sort_by(|left, right| {
        right
            .count
            .cmp(&left.count)
            .then_with(|| left.value.cmp(&right.value))
    });
    let flag_names = ["N", "Z", "C", "V"];
    let flag_bits = if is_nzcv {
        flag_names
            .iter()
            .enumerate()
            .map(|(index, flag)| BranchFlagBitProfile {
                flag: (*flag).to_string(),
                set_count: overall_flags[index * 2 + 1],
                clear_count: overall_flags[index * 2],
            })
            .collect()
    } else {
        Vec::new()
    };
    let mut outcomes = outcome_counts
        .into_iter()
        .map(|(outcome, observation_count)| {
            let mut outcome_value_items: Vec<_> = outcome_values
                .remove(&outcome)
                .unwrap_or_default()
                .into_iter()
                .map(|(value, count)| BranchConditionValueCount { value, count })
                .collect();
            outcome_value_items.sort_by(|left, right| {
                right
                    .count
                    .cmp(&left.count)
                    .then_with(|| left.value.cmp(&right.value))
            });
            let flags = outcome_flags.remove(&outcome).unwrap_or_default();
            let outcome_flag_bits = if is_nzcv {
                flag_names
                    .iter()
                    .enumerate()
                    .map(|(index, flag)| BranchFlagBitProfile {
                        flag: (*flag).to_string(),
                        set_count: flags[index * 2 + 1],
                        clear_count: flags[index * 2],
                    })
                    .collect()
            } else {
                Vec::new()
            };
            BranchConditionOutcomeProfile {
                outcome,
                observation_count,
                values: outcome_value_items,
                flag_bits: outcome_flag_bits,
            }
        })
        .collect::<Vec<_>>();
    outcomes.sort_by(|left, right| left.outcome.cmp(&right.outcome));
    let missing = execution_count.saturating_sub(captured);
    BranchConditionStateProfile {
        source_register: Some(source_register),
        captured_observation_count: captured,
        missing_observation_count: missing,
        distinct_value_count: value_items.len() as u32,
        values: value_items,
        flag_bits,
        outcomes,
        incomplete: missing > 0 || observations_truncated,
    }
}

fn build_opaque_candidates(profiles: &[DynamicBranchProfile]) -> Vec<OpaqueBranchCandidate> {
    let mut results = Vec::new();
    for profile in profiles {
        let offset = parse_hex_addr(&profile.branch_offset).unwrap_or(0);
        let observed_total = profile
            .observed_taken_count
            .saturating_add(profile.observed_fallthrough_count)
            .saturating_add(profile.observed_other_count);
        let one_outcome = profile.observed_other_count == 0
            && ((profile.observed_taken_count > 0 && profile.observed_fallthrough_count == 0)
                || (profile.observed_fallthrough_count > 0 && profile.observed_taken_count == 0));
        if profile.execution_count < 2 || !one_outcome {
            continue;
        }
        let backward_successor = profile
            .observed_successors
            .iter()
            .filter_map(|target| parse_hex_addr(target).ok())
            .any(|target| target <= offset);
        let complete_observations = observed_total >= profile.execution_count.saturating_sub(1);
        let assessment = score_evidence(
            format!("opaque_branch: 0x{offset:x}"),
            false,
            vec![
                EvidenceScoreSignal::new(
                    "repeated_branch",
                    "Branch executed repeatedly",
                    25,
                    profile.execution_count >= 3,
                    Some(format!("{} executions", profile.execution_count)),
                ),
                EvidenceScoreSignal::new(
                    "single_outcome",
                    "Only one branch outcome observed",
                    30,
                    one_outcome,
                    Some(format!(
                        "taken={}, fallthrough={}, other={}",
                        profile.observed_taken_count,
                        profile.observed_fallthrough_count,
                        profile.observed_other_count
                    )),
                ),
                EvidenceScoreSignal::new(
                    "condition_source",
                    "Nearby flag-producing instruction observed",
                    20,
                    !profile.condition_source_offsets.is_empty(),
                    Some(profile.condition_source_offsets.join(", ")),
                ),
                EvidenceScoreSignal::new(
                    "complete_observations",
                    "Most executions have a classified successor",
                    15,
                    complete_observations,
                    Some(format!(
                        "{observed_total}/{} classified",
                        profile.execution_count
                    )),
                ),
                EvidenceScoreSignal::new(
                    "loop_context",
                    "Observed successor is backward or self-directed",
                    10,
                    backward_successor,
                    None,
                ),
            ],
            vec![
                "One trace cannot prove the untaken edge is unreachable for all inputs or states."
                    .to_string(),
                "Repeat with controlled input/state changes before patching or deleting the branch."
                    .to_string(),
            ],
        );
        let rationale = format!(
            "{} executions produced one observed outcome (taken={}, fallthrough={}); alternate static path remains unverified",
            profile.execution_count,
            profile.observed_taken_count,
            profile.observed_fallthrough_count
        );
        results.push(OpaqueBranchCandidate {
            branch_offset: profile.branch_offset.clone(),
            disasm: profile.disasm.clone(),
            execution_count: profile.execution_count,
            observed_taken_count: profile.observed_taken_count,
            observed_fallthrough_count: profile.observed_fallthrough_count,
            observed_other_count: profile.observed_other_count,
            observed_successors: profile.observed_successors.clone(),
            condition_source_offsets: profile.condition_source_offsets.clone(),
            observations: profile.observations.clone(),
            observations_truncated: profile.observations_truncated,
            condition_state_profile: profile.condition_state_profile.clone(),
            rationale,
            assessment,
        });
    }
    results
}

fn compare_ollvm_reports(
    cases: Vec<(OllvmTraceCase, OllvmReport, Option<ElfBinaryIdentity>)>,
    require_matching_binary: bool,
) -> std::result::Result<OllvmMultiTraceReport, String> {
    let Some(first_module) = cases
        .first()
        .map(|(_, report, _)| report.scope.module_name.clone())
    else {
        return Err("OLLVM comparison requires at least one case".to_string());
    };
    if cases
        .iter()
        .any(|(_, report, _)| !report.scope.module_name.eq_ignore_ascii_case(&first_module))
    {
        return Err("OLLVM comparison cases must analyze the same module basename".to_string());
    }

    let provided_identity_count = cases
        .iter()
        .filter(|(_, _, identity)| identity.is_some())
        .count();
    if require_matching_binary && provided_identity_count != cases.len() {
        return Err(format!(
            "requireMatchingBinary is enabled, but only {provided_identity_count}/{} cases provide staticBinaryPath",
            cases.len()
        ));
    }
    let known_binary_hashes = cases
        .iter()
        .filter_map(|(_, _, identity)| {
            identity
                .as_ref()
                .map(|identity| identity.binary_sha256.to_ascii_lowercase())
        })
        .collect::<HashSet<_>>();
    if known_binary_hashes.len() > 1 {
        return Err(format!(
            "OLLVM comparison refused: supplied ELF files have {} distinct SHA-256 values",
            known_binary_hashes.len()
        ));
    }
    let same_binary_confirmed = provided_identity_count == cases.len();
    let binary_identity_status = if same_binary_confirmed {
        "confirmed-same-supplied-elf"
    } else if provided_identity_count > 0 {
        "incomplete-supplied-elf-identity"
    } else {
        "unconfirmed-no-static-elf"
    }
    .to_string();
    let binary_sha256 = same_binary_confirmed
        .then(|| known_binary_hashes.iter().next().cloned())
        .flatten();
    let build_id = same_binary_confirmed
        .then(|| {
            cases
                .first()
                .and_then(|(_, _, identity)| identity.as_ref())
                .and_then(|identity| identity.build_id.clone())
        })
        .flatten();

    let summaries = cases
        .iter()
        .map(|(case, report, binary_identity)| OllvmCaseSummary {
            session_id: case.session_id.clone(),
            label: case.label.clone(),
            module_name: report.scope.module_name.clone(),
            block_count: report.block_count,
            edge_count: report.edge_count,
            dispatcher_candidate_count: report.dispatcher_candidates.len() as u32,
            branch_profile_count: report.branch_profiles.len() as u32,
            opaque_branch_candidate_count: report.opaque_branch_candidates.len() as u32,
            binary_identity: binary_identity.clone(),
        })
        .collect();

    let mut dispatcher_offsets = HashSet::new();
    for (_, report, _) in &cases {
        dispatcher_offsets.extend(
            report
                .dispatcher_candidates
                .iter()
                .map(|candidate| candidate.start_offset.to_ascii_lowercase()),
        );
    }
    let mut dispatcher_stability = Vec::new();
    for offset in dispatcher_offsets {
        let mut evidence = Vec::new();
        let mut candidate_register_sets = Vec::new();
        for (case, report, _) in &cases {
            let block = report
                .blocks
                .iter()
                .find(|block| block.start_offset.eq_ignore_ascii_case(&offset));
            let candidate = report
                .dispatcher_candidates
                .iter()
                .find(|candidate| candidate.start_offset.eq_ignore_ascii_case(&offset));
            let block_id = candidate
                .map(|candidate| candidate.block_id.as_str())
                .or_else(|| block.map(|block| block.block_id.as_str()));
            let mut successors = block_id
                .map(|block_id| {
                    report
                        .edges
                        .iter()
                        .filter(|edge| edge.source_block_id == block_id)
                        .map(|edge| edge.target_offset.to_ascii_lowercase())
                        .collect::<HashSet<_>>()
                        .into_iter()
                        .collect::<Vec<_>>()
                })
                .unwrap_or_default();
            successors.sort_by_key(|value| parse_hex_addr(value).unwrap_or(0));
            let state_registers = candidate
                .map(|candidate| candidate.state_registers.clone())
                .unwrap_or_default();
            if candidate.is_some() {
                candidate_register_sets.push(
                    state_registers
                        .iter()
                        .filter_map(|register| canonical_register_name(register))
                        .collect::<HashSet<_>>(),
                );
            }
            evidence.push(OllvmDispatcherCaseEvidence {
                label: case.label.clone(),
                present: block.is_some(),
                candidate: candidate.is_some(),
                visit_count: candidate
                    .map(|candidate| candidate.visit_count)
                    .or_else(|| block.map(|block| block.visit_count))
                    .unwrap_or_default(),
                score: candidate
                    .map(|candidate| candidate.assessment.score)
                    .unwrap_or_default(),
                successors,
                state_registers,
                state_transition_count: candidate
                    .map(|candidate| candidate.state_transitions.len() as u32)
                    .unwrap_or_default(),
            });
        }
        let present_in_runs = evidence.iter().filter(|item| item.present).count() as u32;
        let candidate_in_runs = evidence.iter().filter(|item| item.candidate).count() as u32;
        let mut observed_state_registers = candidate_register_sets
            .iter()
            .flat_map(|registers| registers.iter().cloned())
            .collect::<HashSet<_>>()
            .into_iter()
            .collect::<Vec<_>>();
        observed_state_registers.sort();
        let mut common_state_registers =
            candidate_register_sets.first().cloned().unwrap_or_default();
        for registers in candidate_register_sets.iter().skip(1) {
            common_state_registers.retain(|register| registers.contains(register));
        }
        let mut common_state_registers: Vec<_> = common_state_registers.into_iter().collect();
        common_state_registers.sort();
        let successor_signatures = evidence
            .iter()
            .filter(|item| item.present)
            .map(|item| item.successors.join(","))
            .collect::<HashSet<_>>();
        let stable_successors = present_in_runs >= 2 && successor_signatures.len() == 1;
        let transition_runs = evidence
            .iter()
            .filter(|item| item.state_transition_count > 0)
            .count() as u32;
        let assessment = score_evidence(
            format!("ollvm_dispatcher_multirun:{offset}"),
            false,
            vec![
                EvidenceScoreSignal::new(
                    "present_all_runs",
                    "Block observed in every controlled run",
                    20,
                    present_in_runs as usize == cases.len(),
                    Some(format!("{present_in_runs}/{} runs", cases.len())),
                ),
                EvidenceScoreSignal::new(
                    "candidate_all_runs",
                    "Dispatcher candidate in every run",
                    30,
                    candidate_in_runs as usize == cases.len(),
                    Some(format!("{candidate_in_runs}/{} runs", cases.len())),
                ),
                EvidenceScoreSignal::new(
                    "stable_successors",
                    "Observed successor set is stable across runs",
                    15,
                    stable_successors,
                    None,
                ),
                EvidenceScoreSignal::new(
                    "common_state_registers",
                    "State-like registers recur across runs",
                    15,
                    !common_state_registers.is_empty(),
                    Some(common_state_registers.join(", ")),
                ),
                EvidenceScoreSignal::new(
                    "state_transitions",
                    "Changing state-register values observed in multiple runs",
                    20,
                    transition_runs >= 2,
                    Some(format!("{transition_runs} runs")),
                ),
            ],
            vec![
                "A stable central block can still be a normal switch or loop dispatcher."
                    .to_string(),
                "Cross-run structural stability does not prove OLLVM control-flow flattening."
                    .to_string(),
            ],
        );
        dispatcher_stability.push(OllvmDispatcherStability {
            start_offset: offset.clone(),
            present_in_runs,
            candidate_in_runs,
            common_state_registers,
            observed_state_registers,
            rationale: format!(
                "candidate in {candidate_in_runs}/{} runs; block present in {present_in_runs}/{} runs",
                cases.len(),
                cases.len()
            ),
            cases: evidence,
            assessment,
        });
    }
    dispatcher_stability.sort_by(|left, right| {
        right
            .assessment
            .score
            .cmp(&left.assessment.score)
            .then_with(|| {
                parse_hex_addr(&left.start_offset)
                    .unwrap_or(0)
                    .cmp(&parse_hex_addr(&right.start_offset).unwrap_or(0))
            })
    });

    let mut branch_offsets = HashSet::new();
    for (_, report, _) in &cases {
        branch_offsets.extend(
            report
                .branch_profiles
                .iter()
                .map(|profile| profile.branch_offset.to_ascii_lowercase()),
        );
    }
    let mut branch_stability = Vec::new();
    for offset in branch_offsets {
        let mut evidence = Vec::new();
        let mut outcomes = HashSet::new();
        let mut all_single_outcome = true;
        let mut repeated_in_all_present = true;
        let mut condition_source_runs = 0u32;
        for (case, report, _) in &cases {
            let profile = report
                .branch_profiles
                .iter()
                .find(|profile| profile.branch_offset.eq_ignore_ascii_case(&offset));
            if let Some(profile) = profile {
                let outcome = if profile.observed_other_count == 0
                    && profile.observed_taken_count > 0
                    && profile.observed_fallthrough_count == 0
                {
                    Some("taken")
                } else if profile.observed_other_count == 0
                    && profile.observed_fallthrough_count > 0
                    && profile.observed_taken_count == 0
                {
                    Some("fallthrough")
                } else {
                    None
                };
                if let Some(outcome) = outcome {
                    outcomes.insert(outcome);
                } else {
                    all_single_outcome = false;
                }
                repeated_in_all_present &= profile.execution_count >= 2;
                if !profile.condition_source_offsets.is_empty() {
                    condition_source_runs = condition_source_runs.saturating_add(1);
                }
                evidence.push(OllvmBranchCaseEvidence {
                    label: case.label.clone(),
                    present: true,
                    execution_count: profile.execution_count,
                    observed_taken_count: profile.observed_taken_count,
                    observed_fallthrough_count: profile.observed_fallthrough_count,
                    observed_other_count: profile.observed_other_count,
                    observed_successors: profile.observed_successors.clone(),
                });
            } else {
                evidence.push(OllvmBranchCaseEvidence {
                    label: case.label.clone(),
                    present: false,
                    execution_count: 0,
                    observed_taken_count: 0,
                    observed_fallthrough_count: 0,
                    observed_other_count: 0,
                    observed_successors: Vec::new(),
                });
            }
        }
        let present_in_runs = evidence.iter().filter(|item| item.present).count() as u32;
        let alternate_outcomes_observed = outcomes.len() > 1 || !all_single_outcome;
        let stable_single_outcome = present_in_runs >= 2
            && all_single_outcome
            && outcomes.len() == 1
            && !alternate_outcomes_observed;
        let classification = if alternate_outcomes_observed {
            "alternate-outcomes-observed"
        } else if stable_single_outcome && present_in_runs as usize == cases.len() {
            "stable-single-outcome-across-runs"
        } else if stable_single_outcome {
            "partial-coverage-single-outcome"
        } else {
            "insufficient-cross-run-evidence"
        }
        .to_string();
        let successor_signatures = evidence
            .iter()
            .filter(|item| item.present)
            .map(|item| item.observed_successors.join(","))
            .collect::<HashSet<_>>();
        let assessment = score_evidence(
            format!("opaque_branch_multirun:{offset}"),
            false,
            vec![
                EvidenceScoreSignal::new(
                    "present_multiple_runs",
                    "Branch observed in multiple runs",
                    20,
                    present_in_runs >= 2,
                    Some(format!("{present_in_runs}/{} runs", cases.len())),
                ),
                EvidenceScoreSignal::new(
                    "stable_single_outcome",
                    "Same single outcome observed across runs",
                    35,
                    stable_single_outcome,
                    Some(classification.clone()),
                ),
                EvidenceScoreSignal::new(
                    "stable_successor",
                    "Observed successor set is identical",
                    20,
                    stable_single_outcome && successor_signatures.len() == 1,
                    None,
                ),
                EvidenceScoreSignal::new(
                    "repeated_each_run",
                    "Branch repeated in each run where present",
                    15,
                    present_in_runs >= 2 && repeated_in_all_present,
                    None,
                ),
                EvidenceScoreSignal::new(
                    "condition_sources",
                    "Condition-source instructions recur across runs",
                    10,
                    condition_source_runs >= 2,
                    Some(format!("{condition_source_runs} runs")),
                ),
            ],
            vec![
                "Even a stable single outcome across controlled runs does not prove the alternate path is infeasible."
                    .to_string(),
                "Observed alternate outcomes are evidence against treating the branch as globally opaque."
                    .to_string(),
            ],
        );
        let rationale = if alternate_outcomes_observed {
            format!(
                "Different outcomes or unclassified successors were observed across {present_in_runs} runs; do not patch this branch as opaque."
            )
        } else {
            format!(
                "The same single outcome was observed in {present_in_runs}/{} runs; untested states remain unknown.",
                cases.len()
            )
        };
        branch_stability.push(OllvmBranchStability {
            branch_offset: offset,
            present_in_runs,
            stable_single_outcome,
            alternate_outcomes_observed,
            classification,
            cases: evidence,
            rationale,
            assessment,
        });
    }
    branch_stability.sort_by(|left, right| {
        right
            .assessment
            .score
            .cmp(&left.assessment.score)
            .then_with(|| {
                parse_hex_addr(&left.branch_offset)
                    .unwrap_or(0)
                    .cmp(&parse_hex_addr(&right.branch_offset).unwrap_or(0))
            })
    });

    Ok(OllvmMultiTraceReport {
        schema_version: "trace-ui/ollvm-multitrace-v2".to_string(),
        cases: summaries,
        binary_identity_status: binary_identity_status.clone(),
        same_binary_confirmed,
        binary_sha256,
        build_id,
        dispatcher_stability,
        branch_stability,
        verification_gate_met: false,
        limitations: vec![
            if same_binary_confirmed {
                "Every selected static ELF has the same exact SHA-256. This confirms the user-supplied files are identical, but the trace format does not cryptographically attest that the selected ELF was the image mapped at runtime."
                    .to_string()
            } else {
                format!(
                    "Static ELF identity is {binary_identity_status}; module-relative alignment remains unconfirmed until every case supplies the matching ELF."
                )
            },
            "Only executed blocks, edges, and branch outcomes are compared. Missing coverage is not evidence of infeasibility."
                .to_string(),
            "Cross-run dispatcher and opaque-branch classifications remain Candidate/Related evidence."
                .to_string(),
        ],
        next_steps: vec![
            if same_binary_confirmed {
                "Keep the confirmed ELF SHA-256 with exported IDA/angr evidence and reject results produced against another binary hash."
                    .to_string()
            } else {
                "Select the matching ELF for every run and enable requireMatchingBinary before treating module-relative offsets as cross-run evidence."
                    .to_string()
            },
            "Repeat with controlled input groups that exercise different state values and inspect branches classified as alternate-outcomes-observed."
                .to_string(),
            "Run the generated angr bridge manually with trace-seeded branch snapshots and compare the exact binary SHA-256."
                .to_string(),
            "Import the dynamic offsets into IDA and reconcile dispatcher/state transitions with static def-use and dominator structure."
                .to_string(),
        ],
    })
}

fn map_ollvm_version_reports(
    versions: Vec<(OllvmVersionTraceCase, OllvmReport, ElfBinaryIdentity)>,
    baseline_version_id: Option<&str>,
    max_matches_per_block: usize,
    min_score: u8,
) -> std::result::Result<OllvmVersionMapReport, String> {
    if versions.len() < 2 {
        return Err("OLLVM version mapping requires at least two versions".to_string());
    }
    let distinct_hashes = versions
        .iter()
        .map(|(_, _, identity)| identity.binary_sha256.to_ascii_lowercase())
        .collect::<HashSet<_>>();
    if distinct_hashes.len() != versions.len() {
        return Err("OLLVM version mapping requires distinct ELF SHA-256 values; use compare_ollvm_traces for the same ELF".to_string());
    }
    let baseline_index = match baseline_version_id {
        Some(requested) => versions
            .iter()
            .position(|(version, _, _)| version.version_id.eq_ignore_ascii_case(requested))
            .ok_or_else(|| {
                format!("baselineVersionId does not match a supplied version: {requested}")
            })?,
        None => 0,
    };
    let baseline_id = versions[baseline_index].0.version_id.clone();
    let summaries = versions
        .iter()
        .map(|(version, report, identity)| OllvmVersionSummary {
            version_id: version.version_id.clone(),
            session_id: version.session_id.clone(),
            module_name: report.scope.module_name.clone(),
            block_count: report.block_count,
            edge_count: report.edge_count,
            dispatcher_candidate_count: report.dispatcher_candidates.len() as u32,
            binary_identity: identity.clone(),
        })
        .collect();

    let (_, baseline_report, _) = &versions[baseline_index];
    let mut dispatcher_mappings = Vec::new();
    for dispatcher in &baseline_report.dispatcher_candidates {
        let Some(source_block) = baseline_report
            .blocks
            .iter()
            .find(|block| block.block_id == dispatcher.block_id)
        else {
            continue;
        };
        let source_fingerprint = block_fingerprint(
            &baseline_id,
            baseline_report,
            source_block,
            Some(dispatcher),
        );
        let mut targets = Vec::new();
        for (target_index, (target_version, target_report, _)) in versions.iter().enumerate() {
            if target_index == baseline_index {
                continue;
            }
            let mut candidates = target_report
                .blocks
                .iter()
                .filter_map(|target_block| {
                    let target_dispatcher = target_report
                        .dispatcher_candidates
                        .iter()
                        .find(|candidate| candidate.block_id == target_block.block_id);
                    let target_fingerprint = block_fingerprint(
                        &target_version.version_id,
                        target_report,
                        target_block,
                        target_dispatcher,
                    );
                    let candidate =
                        compare_block_fingerprints(&source_fingerprint, target_fingerprint);
                    (candidate.score >= min_score).then_some(candidate)
                })
                .collect::<Vec<_>>();
            candidates.sort_by(|left, right| {
                right.score.cmp(&left.score).then_with(|| {
                    parse_hex_addr(&left.target_block.start_offset)
                        .unwrap_or(0)
                        .cmp(&parse_hex_addr(&right.target_block.start_offset).unwrap_or(0))
                })
            });
            let ambiguous = candidates
                .get(0)
                .zip(candidates.get(1))
                .is_some_and(|(first, second)| first.score.saturating_sub(second.score) <= 5);
            candidates.truncate(max_matches_per_block);
            targets.push(OllvmVersionTargetMapping {
                target_version_id: target_version.version_id.clone(),
                ambiguous,
                candidates,
            });
        }
        dispatcher_mappings.push(OllvmVersionDispatcherMapping {
            source_block: source_fingerprint,
            targets,
        });
    }

    Ok(OllvmVersionMapReport {
        schema_version: "trace-ui/ollvm-version-map-v1".to_string(),
        baseline_version_id: baseline_id,
        versions: summaries,
        dispatcher_mappings,
        verification_gate_met: false,
        limitations: vec![
            "Every version uses a user-selected exact ELF with a distinct SHA-256, but the trace format does not cryptographically attest which image was mapped at runtime."
                .to_string(),
            "Mappings compare normalized dynamic block and state-role shapes only. They are structural candidates, never Verified proof of equivalent functions or recovered control flow."
                .to_string(),
            "Dynamic coverage is incomplete; unexecuted blocks, edges, state values, and alternate paths are absent. Small or template-like dispatcher blocks can collide and are marked ambiguous when top scores are close."
                .to_string(),
            "Source offsets, concrete dispatcher values, heap/stack addresses, Frida captures, and angr seeds must not be copied to another version."
                .to_string(),
        ],
        next_steps: vec![
            "Review strong non-ambiguous candidates in each exact IDA database and compare surrounding static def-use, dominators, and successor structure."
                .to_string(),
            "Generate a new exact-offset Frida 16.x Hook for each target version and let the user execute it manually; do not reuse a baseline capture at a relocated candidate."
                .to_string(),
            "Generate and run a separate angr bridge manually for each exact ELF, then compare bounded seeded-flow outcomes as Candidate/Related evidence."
                .to_string(),
            "Collect controlled traces with wider coverage when a mapping is missing or ambiguous."
                .to_string(),
        ],
    })
}

fn block_fingerprint(
    version_id: &str,
    report: &OllvmReport,
    block: &DynamicBasicBlock,
    dispatcher: Option<&DispatcherCandidate>,
) -> OllvmBlockFingerprint {
    let normalized_operations = block
        .instructions
        .iter()
        .take(64)
        .map(|instruction| operation_shape(&operation_name(&instruction.disasm)))
        .collect::<Vec<_>>();
    let operation_signature = shape_signature(&normalized_operations.join(","));
    let mut outgoing_edge_kinds = report
        .edges
        .iter()
        .filter(|edge| edge.source_block_id == block.block_id)
        .map(|edge| edge.kind.to_ascii_lowercase())
        .collect::<HashSet<_>>()
        .into_iter()
        .collect::<Vec<_>>();
    outgoing_edge_kinds.sort();
    let backward_edge_count = report
        .edges
        .iter()
        .filter(|edge| edge.source_block_id == block.block_id && edge.backward)
        .count() as u32;
    OllvmBlockFingerprint {
        version_id: version_id.to_string(),
        block_id: block.block_id.clone(),
        module_name: block.module_name.clone(),
        start_offset: block.start_offset.clone(),
        end_offset: block.end_offset.clone(),
        sample_seq: block.sample_seqs.first().copied(),
        operation_signature,
        instruction_count: block.instructions.len() as u32,
        terminal_shape: operation_shape(&block.terminal_operation.to_ascii_lowercase()),
        normalized_operations,
        predecessor_count: block.predecessor_count,
        successor_count: block.successor_count,
        outgoing_edge_kinds,
        dispatcher_candidate: dispatcher.is_some(),
        indirect_branch_count: dispatcher
            .map(|candidate| candidate.indirect_branch_count)
            .unwrap_or_default(),
        backward_edge_count: dispatcher
            .map(|candidate| candidate.backward_edge_count)
            .unwrap_or(backward_edge_count),
        state_registers: dispatcher
            .map(state_register_fingerprints)
            .unwrap_or_default(),
    }
}

fn state_register_fingerprints(
    candidate: &DispatcherCandidate,
) -> Vec<OllvmStateRegisterFingerprint> {
    let mut registers = candidate
        .state_registers
        .iter()
        .filter_map(|register| canonical_register_name(register))
        .collect::<HashSet<_>>();
    for snapshot in &candidate.state_snapshots {
        registers.extend(
            snapshot
                .values
                .keys()
                .filter_map(|register| canonical_register_name(register)),
        );
    }
    registers.extend(
        candidate
            .state_transitions
            .iter()
            .filter_map(|transition| canonical_register_name(&transition.register)),
    );
    let mut fingerprints = registers
        .into_iter()
        .map(|register| {
            let values = candidate
                .state_snapshots
                .iter()
                .filter_map(|snapshot| {
                    snapshot.values.iter().find_map(|(name, value)| {
                        (canonical_register_name(name).as_deref() == Some(register.as_str()))
                            .then(|| value.to_ascii_lowercase())
                    })
                })
                .collect::<Vec<_>>();
            let transitions = candidate
                .state_transitions
                .iter()
                .filter(|transition| {
                    canonical_register_name(&transition.register).as_deref()
                        == Some(register.as_str())
                })
                .collect::<Vec<_>>();
            let transition_count = transitions.iter().fold(0u32, |total, transition| {
                total.saturating_add(transition.execution_count.min(u32::MAX as u64) as u32)
            });
            let self_transition_count = transitions
                .iter()
                .filter(|transition| {
                    transition
                        .from_value
                        .eq_ignore_ascii_case(&transition.to_value)
                })
                .fold(0u32, |total, transition| {
                    total.saturating_add(transition.execution_count.min(u32::MAX as u64) as u32)
                });
            let distinct_transitions = transitions
                .iter()
                .map(|transition| {
                    format!(
                        "{}->{}",
                        transition.from_value.to_ascii_lowercase(),
                        transition.to_value.to_ascii_lowercase()
                    )
                })
                .collect::<HashSet<_>>();
            let value_width_bits = values
                .iter()
                .chain(
                    transitions
                        .iter()
                        .flat_map(|transition| [&transition.from_value, &transition.to_value]),
                )
                .filter_map(|value| hex_value_width(value))
                .max();
            OllvmStateRegisterFingerprint {
                register,
                snapshot_count: values.len() as u32,
                distinct_value_count: values.iter().collect::<HashSet<_>>().len() as u32,
                transition_count,
                distinct_transition_count: distinct_transitions.len() as u32,
                self_transition_count,
                value_width_bits,
            }
        })
        .collect::<Vec<_>>();
    fingerprints.sort_by(|left, right| left.register.cmp(&right.register));
    fingerprints
}

fn hex_value_width(value: &str) -> Option<u32> {
    let digits = value
        .trim()
        .trim_start_matches("0x")
        .trim_start_matches("0X");
    (!digits.is_empty()
        && digits
            .chars()
            .all(|character| character.is_ascii_hexdigit()))
    .then(|| (digits.len() as u32).saturating_mul(4))
}

fn compare_block_fingerprints(
    source: &OllvmBlockFingerprint,
    target: OllvmBlockFingerprint,
) -> OllvmVersionBlockCandidate {
    let operation_similarity =
        sequence_similarity(&source.normalized_operations, &target.normalized_operations);
    let operation_points = ((operation_similarity as u16 * 50 + 50) / 100) as u8;
    let terminal_points = if source.terminal_shape == target.terminal_shape {
        10
    } else {
        0
    };
    let predecessor_points =
        scaled_count_similarity(source.predecessor_count, target.predecessor_count, 5);
    let successor_points =
        scaled_count_similarity(source.successor_count, target.successor_count, 10);
    let edge_kind_points =
        set_similarity_points(&source.outgoing_edge_kinds, &target.outgoing_edge_kinds, 5);
    let dispatcher_points = if target.dispatcher_candidate { 10 } else { 0 };
    let state_register_matches =
        match_state_registers(&source.state_registers, &target.state_registers);
    let state_points = state_register_matches
        .first()
        .map(|matched| ((matched.score as u16 * 10 + 50) / 100) as u8)
        .unwrap_or_default();
    let score = operation_points
        .saturating_add(terminal_points)
        .saturating_add(predecessor_points)
        .saturating_add(successor_points)
        .saturating_add(edge_kind_points)
        .saturating_add(dispatcher_points)
        .saturating_add(state_points)
        .min(100);
    let classification = if score >= 80 {
        "strong-structural-candidate"
    } else if score >= 65 {
        "related-structural-candidate"
    } else {
        "weak-structural-candidate"
    }
    .to_string();
    let assessment = score_evidence(
        format!(
            "ollvm_version_block:{}:{}",
            source.start_offset, target.start_offset
        ),
        false,
        vec![
            EvidenceScoreSignal::new(
                "operation_sequence",
                "Normalized instruction-operation sequence similarity",
                operation_points as i16,
                operation_points > 0,
                Some(format!("{operation_similarity}% LCS similarity")),
            ),
            EvidenceScoreSignal::new(
                "terminal_shape",
                "Terminal operation family matches",
                terminal_points as i16,
                terminal_points > 0,
                Some(format!("{} vs {}", source.terminal_shape, target.terminal_shape)),
            ),
            EvidenceScoreSignal::new(
                "predecessor_shape",
                "Dynamic predecessor-count shape",
                predecessor_points as i16,
                predecessor_points > 0,
                Some(format!("{} vs {}", source.predecessor_count, target.predecessor_count)),
            ),
            EvidenceScoreSignal::new(
                "successor_shape",
                "Dynamic successor-count shape",
                successor_points as i16,
                successor_points > 0,
                Some(format!("{} vs {}", source.successor_count, target.successor_count)),
            ),
            EvidenceScoreSignal::new(
                "edge_kinds",
                "Outgoing dynamic edge-kind similarity",
                edge_kind_points as i16,
                edge_kind_points > 0,
                Some(format!("{:?} vs {:?}", source.outgoing_edge_kinds, target.outgoing_edge_kinds)),
            ),
            EvidenceScoreSignal::new(
                "dispatcher_role",
                "Target is independently ranked as a dispatcher candidate",
                dispatcher_points as i16,
                dispatcher_points > 0,
                None,
            ),
            EvidenceScoreSignal::new(
                "state_register_role",
                "Best state-register behavioral role similarity",
                state_points as i16,
                state_points > 0,
                state_register_matches.first().map(|matched| matched.rationale.clone()),
            ),
        ],
        vec![
            "Different offsets and concrete state values are intentionally not treated as equivalence evidence."
                .to_string(),
            "Dynamic structural similarity can collide and does not prove semantic equivalence or OLLVM provenance."
                .to_string(),
        ],
    );
    OllvmVersionBlockCandidate {
        target_block: target,
        score,
        classification,
        operation_similarity,
        state_register_matches,
        rationale: format!(
            "score {score}/100: operations {operation_similarity}%, terminal +{terminal_points}, predecessors +{predecessor_points}, successors +{successor_points}, edge kinds +{edge_kind_points}, dispatcher role +{dispatcher_points}, state role +{state_points}"
        ),
        assessment,
    }
}

fn sequence_similarity(left: &[String], right: &[String]) -> u8 {
    if left.is_empty() && right.is_empty() {
        return 100;
    }
    if left.is_empty() || right.is_empty() {
        return 0;
    }
    let mut previous = vec![0u16; right.len() + 1];
    let mut current = vec![0u16; right.len() + 1];
    for left_item in left {
        for (index, right_item) in right.iter().enumerate() {
            current[index + 1] = if left_item == right_item {
                previous[index].saturating_add(1)
            } else {
                current[index].max(previous[index + 1])
            };
        }
        std::mem::swap(&mut previous, &mut current);
        current.fill(0);
    }
    let denominator = left.len().max(right.len()) as u32;
    ((previous[right.len()] as u32 * 100 + denominator / 2) / denominator) as u8
}

fn scaled_count_similarity(left: u32, right: u32, maximum: u8) -> u8 {
    if left == 0 && right == 0 {
        return maximum;
    }
    let high = left.max(right);
    let low = left.min(right);
    ((low as u64 * maximum as u64 + high as u64 / 2) / high as u64) as u8
}

fn set_similarity_points(left: &[String], right: &[String], maximum: u8) -> u8 {
    let left = left.iter().collect::<HashSet<_>>();
    let right = right.iter().collect::<HashSet<_>>();
    let union = left.union(&right).count();
    if union == 0 {
        return maximum;
    }
    let intersection = left.intersection(&right).count();
    ((intersection * maximum as usize + union / 2) / union) as u8
}

fn match_state_registers(
    source: &[OllvmStateRegisterFingerprint],
    target: &[OllvmStateRegisterFingerprint],
) -> Vec<OllvmStateRegisterMatch> {
    let mut pairs = source
        .iter()
        .flat_map(|source_register| {
            target.iter().map(move |target_register| {
                let score = state_register_similarity(source_register, target_register);
                (source_register, target_register, score)
            })
        })
        .collect::<Vec<_>>();
    pairs.sort_by(|left, right| right.2.cmp(&left.2));
    let mut used_source = HashSet::new();
    let mut used_target = HashSet::new();
    let mut matches = Vec::new();
    for (source_register, target_register, score) in pairs {
        if used_source.contains(&source_register.register)
            || used_target.contains(&target_register.register)
        {
            continue;
        }
        used_source.insert(source_register.register.clone());
        used_target.insert(target_register.register.clone());
        matches.push(OllvmStateRegisterMatch {
            source_register: source_register.register.clone(),
            target_register: target_register.register.clone(),
            score,
            rationale: format!(
                "{} -> {} role score {score}/100 (snapshots {}:{}, distinct values {}:{}, transitions {}:{}, distinct transitions {}:{}, self transitions {}:{})",
                source_register.register,
                target_register.register,
                source_register.snapshot_count,
                target_register.snapshot_count,
                source_register.distinct_value_count,
                target_register.distinct_value_count,
                source_register.transition_count,
                target_register.transition_count,
                source_register.distinct_transition_count,
                target_register.distinct_transition_count,
                source_register.self_transition_count,
                target_register.self_transition_count,
            ),
        });
    }
    matches.sort_by(|left, right| right.score.cmp(&left.score));
    matches
}

fn state_register_similarity(
    source: &OllvmStateRegisterFingerprint,
    target: &OllvmStateRegisterFingerprint,
) -> u8 {
    scaled_count_similarity(source.snapshot_count, target.snapshot_count, 25)
        .saturating_add(scaled_count_similarity(
            source.distinct_value_count,
            target.distinct_value_count,
            20,
        ))
        .saturating_add(scaled_count_similarity(
            source.transition_count,
            target.transition_count,
            25,
        ))
        .saturating_add(scaled_count_similarity(
            source.distinct_transition_count,
            target.distinct_transition_count,
            15,
        ))
        .saturating_add(scaled_count_similarity(
            source.self_transition_count,
            target.self_transition_count,
            10,
        ))
        .saturating_add(
            (source.value_width_bits == target.value_width_bits
                && source.value_width_bits.is_some())
            .then_some(2)
            .unwrap_or_default(),
        )
        .saturating_add(
            source
                .register
                .eq_ignore_ascii_case(&target.register)
                .then_some(3)
                .unwrap_or_default(),
        )
        .min(100)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn insn(seq: u32, offset: u64, disasm: &str) -> ExecutedInsn {
        ExecutedInsn {
            seq,
            ordinal: seq as u64 + 1,
            offset,
            address: 0x100000 + offset,
            disasm: disasm.to_string(),
            operation: operation_name(disasm),
        }
    }

    #[test]
    fn classifies_repeated_single_outcome_branch_as_candidate_not_proof() {
        let executed = vec![
            insn(0, 0x100, "cmp w8, #1"),
            insn(1, 0x104, "b.eq 0x100200"),
            insn(2, 0x108, "add w0, w0, #1"),
            insn(3, 0x100, "cmp w8, #1"),
            insn(4, 0x104, "b.eq 0x100200"),
            insn(5, 0x108, "add w0, w0, #1"),
            insn(6, 0x100, "cmp w8, #1"),
            insn(7, 0x104, "b.eq 0x100200"),
            insn(8, 0x108, "ret"),
        ];
        let (_, stats) = build_transitions(&executed, 0x100000);
        let profiles = build_branch_profiles(stats);
        let candidates = build_opaque_candidates(&profiles);
        assert_eq!(candidates.len(), 1);
        assert_eq!(candidates[0].observed_fallthrough_count, 3);
        assert!(!candidates[0].assessment.verification_gate_met);
        assert_ne!(candidates[0].assessment.grade, "verified");
    }

    #[test]
    fn extracts_last_branch_target_as_module_offset() {
        let instruction = insn(0, 0x100, "tbz w8, #3, 0x101234");
        assert_eq!(direct_target_offset(&instruction, 0x100000), Some(0x1234));
    }

    #[test]
    fn branch_profiles_keep_bounded_outcome_observations() {
        let executed = vec![
            insn(0, 0x100, "cbz w8, 0x100200"),
            insn(1, 0x200, "add w0, w0, #1"),
            insn(2, 0x100, "cbz w8, 0x100200"),
            insn(3, 0x104, "ret"),
        ];
        let (_, stats) = build_transitions(&executed, 0x100000);
        let profiles = build_branch_profiles(stats);
        let profile = profiles
            .iter()
            .find(|profile| profile.branch_offset == "0x100")
            .unwrap();
        assert_eq!(profile.observed_taken_count, 1);
        assert_eq!(profile.observed_fallthrough_count, 1);
        assert_eq!(profile.observations.len(), 2);
        assert_eq!(branch_relevant_registers(&profile.disasm), vec!["X8"]);
    }

    #[test]
    fn aggregates_nzcv_bits_and_outcomes_without_claiming_completeness() {
        let observations = vec![
            BranchStateObservation {
                seq: 1,
                outcome: "taken".to_string(),
                successor: "0x200".to_string(),
                registers: [("NZCV".to_string(), "0x40000000".to_string())]
                    .into_iter()
                    .collect(),
            },
            BranchStateObservation {
                seq: 2,
                outcome: "fallthrough".to_string(),
                successor: "0x108".to_string(),
                registers: [("NZCV".to_string(), "0x20000000".to_string())]
                    .into_iter()
                    .collect(),
            },
        ];
        let profile =
            build_condition_state_profile(&observations, 3, true, Some("NZCV".to_string()));
        assert_eq!(profile.captured_observation_count, 2);
        assert_eq!(profile.missing_observation_count, 1);
        assert_eq!(profile.distinct_value_count, 2);
        assert!(profile.incomplete);
        assert_eq!(profile.outcomes.len(), 2);
        let z = profile
            .flag_bits
            .iter()
            .find(|flag| flag.flag == "Z")
            .unwrap();
        assert_eq!(z.set_count, 1);
        assert_eq!(z.clear_count, 1);
        let c = profile
            .flag_bits
            .iter()
            .find(|flag| flag.flag == "C")
            .unwrap();
        assert_eq!(c.set_count, 1);
        assert_eq!(c.clear_count, 1);
    }

    fn report_with_branch(session_id: &str, taken: u64, fallthrough: u64) -> OllvmReport {
        OllvmReport {
            schema_version: "trace-ui/ollvm-v1".to_string(),
            scope: OllvmScope {
                session_id: session_id.to_string(),
                node_id: None,
                function_name: Some("target".to_string()),
                module_name: "libtarget.so".to_string(),
                module_base: "0x100000".to_string(),
                start_seq: 0,
                end_seq: 10,
                child_calls_excluded: 0,
            },
            executed_instruction_count: taken + fallthrough,
            unique_instruction_count: 2,
            block_count: 0,
            edge_count: 0,
            blocks: Vec::new(),
            edges: Vec::new(),
            branch_profiles: vec![DynamicBranchProfile {
                branch_offset: "0x104".to_string(),
                disasm: "b.eq 0x200".to_string(),
                execution_count: taken + fallthrough,
                observed_taken_count: taken,
                observed_fallthrough_count: fallthrough,
                observed_other_count: 0,
                observed_successors: if taken > 0 && fallthrough > 0 {
                    vec!["0x108".to_string(), "0x200".to_string()]
                } else if taken > 0 {
                    vec!["0x200".to_string()]
                } else {
                    vec!["0x108".to_string()]
                },
                condition_source_offsets: vec!["0x100".to_string()],
                observations: Vec::new(),
                observations_truncated: false,
                condition_state_profile: Default::default(),
            }],
            dispatcher_candidates: Vec::new(),
            opaque_branch_candidates: Vec::new(),
            instructions_truncated: false,
            blocks_truncated: false,
            edges_truncated: false,
            limitations: Vec::new(),
            next_steps: Vec::new(),
        }
    }

    fn trace_case(session_id: &str, label: &str) -> OllvmTraceCase {
        OllvmTraceCase {
            session_id: session_id.to_string(),
            label: label.to_string(),
            node_id: None,
            module_name: Some("libtarget.so".to_string()),
            start_seq: None,
            end_seq: None,
            include_child_calls: false,
            static_binary_path: None,
        }
    }

    fn binary_identity(hash: char, build_id: Option<&str>) -> ElfBinaryIdentity {
        ElfBinaryIdentity {
            binary_path: "libtarget.so".to_string(),
            binary_sha256: std::iter::repeat_n(hash, 64).collect(),
            file_size: 4096,
            format: "ELF64 little-endian".to_string(),
            architecture: "AArch64".to_string(),
            elf_machine: 183,
            build_id: build_id.map(str::to_string),
        }
    }

    fn version_case(
        session_id: &str,
        version_id: &str,
        binary_path: &str,
    ) -> OllvmVersionTraceCase {
        OllvmVersionTraceCase {
            version_id: version_id.to_string(),
            session_id: session_id.to_string(),
            node_id: None,
            module_name: None,
            start_seq: None,
            end_seq: None,
            include_child_calls: false,
            static_binary_path: binary_path.to_string(),
        }
    }

    fn dispatcher_report(session_id: &str, module_name: &str, offsets: &[u64]) -> OllvmReport {
        let blocks = offsets
            .iter()
            .map(|offset| DynamicBasicBlock {
                block_id: format!("{module_name}+0x{offset:x}"),
                module_name: module_name.to_string(),
                start_offset: format!("0x{offset:x}"),
                end_offset: format!("0x{:x}", offset + 8),
                start_address: format!("0x{:x}", 0x100000 + offset),
                end_address: format!("0x{:x}", 0x100008 + offset),
                visit_count: 12,
                predecessor_count: 3,
                successor_count: 2,
                terminal_operation: "br".to_string(),
                sample_seqs: vec![10],
                instructions: vec![
                    DynamicBlockInstruction {
                        offset: format!("0x{offset:x}"),
                        address: format!("0x{:x}", 0x100000 + offset),
                        disasm: "ldr w8, [x20]".to_string(),
                        execution_count: 12,
                        sample_seq: 10,
                    },
                    DynamicBlockInstruction {
                        offset: format!("0x{:x}", offset + 4),
                        address: format!("0x{:x}", 0x100004 + offset),
                        disasm: "eor w9, w8, w10".to_string(),
                        execution_count: 12,
                        sample_seq: 11,
                    },
                    DynamicBlockInstruction {
                        offset: format!("0x{:x}", offset + 8),
                        address: format!("0x{:x}", 0x100008 + offset),
                        disasm: "br x11".to_string(),
                        execution_count: 12,
                        sample_seq: 12,
                    },
                ],
            })
            .collect::<Vec<_>>();
        let dispatcher_candidates = blocks
            .iter()
            .map(|block| DispatcherCandidate {
                block_id: block.block_id.clone(),
                start_offset: block.start_offset.clone(),
                end_offset: block.end_offset.clone(),
                visit_count: 12,
                predecessor_count: 3,
                successor_count: 2,
                indirect_branch_count: 12,
                backward_edge_count: 1,
                state_registers: vec!["X8".to_string()],
                state_snapshots: vec![
                    DispatcherStateSnapshot {
                        seq: 10,
                        values: BTreeMap::from([("X8".to_string(), "0x1".to_string())]),
                    },
                    DispatcherStateSnapshot {
                        seq: 20,
                        values: BTreeMap::from([("X8".to_string(), "0x2".to_string())]),
                    },
                ],
                state_transitions: vec![DispatcherStateTransition {
                    register: "X8".to_string(),
                    from_value: "0x1".to_string(),
                    to_value: "0x2".to_string(),
                    execution_count: 1,
                    sample_seq: 20,
                }],
                state_snapshots_truncated: false,
                rationale: "synthetic dispatcher".to_string(),
                assessment: score_evidence("synthetic", false, Vec::new(), Vec::new()),
            })
            .collect();
        OllvmReport {
            schema_version: "trace-ui/ollvm-v1".to_string(),
            scope: OllvmScope {
                session_id: session_id.to_string(),
                node_id: None,
                function_name: Some("target".to_string()),
                module_name: module_name.to_string(),
                module_base: "0x100000".to_string(),
                start_seq: 0,
                end_seq: 30,
                child_calls_excluded: 0,
            },
            executed_instruction_count: blocks.len() as u64 * 36,
            unique_instruction_count: blocks.len() as u32 * 3,
            block_count: blocks.len() as u32,
            edge_count: 0,
            blocks,
            edges: Vec::new(),
            branch_profiles: Vec::new(),
            dispatcher_candidates,
            opaque_branch_candidates: Vec::new(),
            instructions_truncated: false,
            blocks_truncated: false,
            edges_truncated: false,
            limitations: Vec::new(),
            next_steps: Vec::new(),
        }
    }

    #[test]
    fn cross_version_mapping_matches_relocated_dispatcher_without_verifying_it() {
        let mapped = map_ollvm_version_reports(
            vec![
                (
                    version_case("a", "v1", "v1.so"),
                    dispatcher_report("a", "libold.so", &[0x100]),
                    binary_identity('a', Some("build-a")),
                ),
                (
                    version_case("b", "v2", "v2.so"),
                    dispatcher_report("b", "librenamed.so", &[0x900]),
                    binary_identity('b', Some("build-b")),
                ),
            ],
            Some("v1"),
            3,
            55,
        )
        .unwrap();
        let candidate = &mapped.dispatcher_mappings[0].targets[0].candidates[0];
        assert_eq!(candidate.target_block.start_offset, "0x900");
        assert!(candidate.score >= 80);
        assert_eq!(candidate.classification, "strong-structural-candidate");
        assert!(!candidate.assessment.verification_gate_met);
        assert_ne!(candidate.assessment.grade, "verified");
        assert!(!mapped.verification_gate_met);
    }

    #[test]
    fn cross_version_mapping_rejects_same_elf_hash() {
        let error = map_ollvm_version_reports(
            vec![
                (
                    version_case("a", "v1", "v1.so"),
                    dispatcher_report("a", "lib.so", &[0x100]),
                    binary_identity('a', None),
                ),
                (
                    version_case("b", "v2", "v2.so"),
                    dispatcher_report("b", "lib.so", &[0x900]),
                    binary_identity('a', None),
                ),
            ],
            None,
            3,
            55,
        )
        .unwrap_err();
        assert!(error.contains("compare_ollvm_traces"));
    }

    #[test]
    fn cross_version_mapping_marks_template_collision_ambiguous() {
        let mapped = map_ollvm_version_reports(
            vec![
                (
                    version_case("a", "v1", "v1.so"),
                    dispatcher_report("a", "lib.so", &[0x100]),
                    binary_identity('a', None),
                ),
                (
                    version_case("b", "v2", "v2.so"),
                    dispatcher_report("b", "lib2.so", &[0x900, 0xa00]),
                    binary_identity('b', None),
                ),
            ],
            None,
            3,
            55,
        )
        .unwrap();
        let target = &mapped.dispatcher_mappings[0].targets[0];
        assert!(target.ambiguous);
        assert_eq!(target.candidates.len(), 2);
    }

    #[test]
    fn multirun_comparison_rejects_global_opaque_claim_after_alternate_outcomes() {
        let compared = compare_ollvm_reports(
            vec![
                (
                    trace_case("a", "taken"),
                    report_with_branch("a", 3, 0),
                    None,
                ),
                (
                    trace_case("b", "fallthrough"),
                    report_with_branch("b", 0, 3),
                    None,
                ),
            ],
            false,
        )
        .unwrap();
        let branch = &compared.branch_stability[0];
        assert!(branch.alternate_outcomes_observed);
        assert!(!branch.stable_single_outcome);
        assert_eq!(branch.classification, "alternate-outcomes-observed");
        assert!(!branch.assessment.verification_gate_met);
        assert!(!compared.verification_gate_met);
    }

    #[test]
    fn multirun_stable_single_outcome_remains_candidate_only() {
        let compared = compare_ollvm_reports(
            vec![
                (
                    trace_case("a", "run-a"),
                    report_with_branch("a", 3, 0),
                    None,
                ),
                (
                    trace_case("b", "run-b"),
                    report_with_branch("b", 4, 0),
                    None,
                ),
            ],
            false,
        )
        .unwrap();
        let branch = &compared.branch_stability[0];
        assert!(branch.stable_single_outcome);
        assert!(!branch.alternate_outcomes_observed);
        assert_eq!(branch.classification, "stable-single-outcome-across-runs");
        assert_ne!(branch.assessment.grade, "verified");
    }

    #[test]
    fn multirun_confirms_identical_supplied_elf_hashes_without_verifying_ollvm() {
        let compared = compare_ollvm_reports(
            vec![
                (
                    trace_case("a", "run-a"),
                    report_with_branch("a", 3, 0),
                    Some(binary_identity('a', Some("build-a"))),
                ),
                (
                    trace_case("b", "run-b"),
                    report_with_branch("b", 4, 0),
                    Some(binary_identity('a', Some("build-a"))),
                ),
            ],
            true,
        )
        .unwrap();
        assert!(compared.same_binary_confirmed);
        assert_eq!(
            compared.binary_identity_status,
            "confirmed-same-supplied-elf"
        );
        let expected_sha256 = "a".repeat(64);
        assert_eq!(
            compared.binary_sha256.as_deref(),
            Some(expected_sha256.as_str())
        );
        assert_eq!(compared.build_id.as_deref(), Some("build-a"));
        assert!(!compared.verification_gate_met);
    }

    #[test]
    fn multirun_rejects_different_supplied_elf_hashes() {
        let error = compare_ollvm_reports(
            vec![
                (
                    trace_case("a", "run-a"),
                    report_with_branch("a", 3, 0),
                    Some(binary_identity('a', None)),
                ),
                (
                    trace_case("b", "run-b"),
                    report_with_branch("b", 4, 0),
                    Some(binary_identity('b', None)),
                ),
            ],
            false,
        )
        .unwrap_err();
        assert!(error.contains("distinct SHA-256"));
    }

    #[test]
    fn multirun_requires_every_elf_when_policy_is_enabled() {
        let error = compare_ollvm_reports(
            vec![
                (
                    trace_case("a", "run-a"),
                    report_with_branch("a", 3, 0),
                    Some(binary_identity('a', None)),
                ),
                (
                    trace_case("b", "run-b"),
                    report_with_branch("b", 4, 0),
                    None,
                ),
            ],
            true,
        )
        .unwrap_err();
        assert!(error.contains("requireMatchingBinary"));
    }
}
