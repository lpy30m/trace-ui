use std::collections::{BTreeMap, HashMap, HashSet};

use crate::error::{Result, TraceError};
use crate::query::evidence_score::{score_evidence, EvidenceScoreSignal};
use crate::query::ollvm::{
    DispatcherCandidate, DynamicBasicBlock, DynamicBlockInstruction, DynamicCfgEdge,
    OllvmAnalysisOptions, OllvmReport, OllvmScope, OpaqueBranchCandidate,
};
use crate::utils::parse_hex_addr;

use super::TraceEngine;

const CHUNK_SIZE: u32 = 4096;
const MAX_EXECUTED_INSTRUCTIONS: usize = 1_000_000;
const MAX_BLOCK_INSTRUCTIONS: usize = 256;

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
        let mut opaque_branch_candidates = build_opaque_candidates(branch_stats);
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
            ],
        })
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
            if next.offset == instruction.offset.saturating_add(4) {
                stats.fallthrough = stats.fallthrough.saturating_add(1);
                "conditional_fallthrough"
            } else if direct_target == Some(next.offset) {
                stats.taken = stats.taken.saturating_add(1);
                "conditional_taken"
            } else {
                stats.other = stats.other.saturating_add(1);
                "conditional_other"
            }
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
            rationale,
            assessment,
        });
    }
    results
}

fn build_opaque_candidates(stats: HashMap<u64, BranchStats>) -> Vec<OpaqueBranchCandidate> {
    let mut results = Vec::new();
    for (offset, stats) in stats {
        let observed_total = stats
            .taken
            .saturating_add(stats.fallthrough)
            .saturating_add(stats.other);
        let one_outcome = stats.other == 0
            && ((stats.taken > 0 && stats.fallthrough == 0)
                || (stats.fallthrough > 0 && stats.taken == 0));
        if stats.execution_count < 2 || !one_outcome {
            continue;
        }
        let backward_successor = stats.successors.iter().any(|target| *target <= offset);
        let complete_observations = observed_total >= stats.execution_count.saturating_sub(1);
        let assessment = score_evidence(
            format!("opaque_branch: 0x{offset:x}"),
            false,
            vec![
                EvidenceScoreSignal::new(
                    "repeated_branch",
                    "Branch executed repeatedly",
                    25,
                    stats.execution_count >= 3,
                    Some(format!("{} executions", stats.execution_count)),
                ),
                EvidenceScoreSignal::new(
                    "single_outcome",
                    "Only one branch outcome observed",
                    30,
                    one_outcome,
                    Some(format!(
                        "taken={}, fallthrough={}, other={}",
                        stats.taken, stats.fallthrough, stats.other
                    )),
                ),
                EvidenceScoreSignal::new(
                    "condition_source",
                    "Nearby flag-producing instruction observed",
                    20,
                    !stats.condition_sources.is_empty(),
                    Some(
                        stats
                            .condition_sources
                            .iter()
                            .map(|source| format!("0x{source:x}"))
                            .collect::<Vec<_>>()
                            .join(", "),
                    ),
                ),
                EvidenceScoreSignal::new(
                    "complete_observations",
                    "Most executions have a classified successor",
                    15,
                    complete_observations,
                    Some(format!(
                        "{observed_total}/{} classified",
                        stats.execution_count
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
        let rationale = format!(
            "{} executions produced one observed outcome (taken={}, fallthrough={}); alternate static path remains unverified",
            stats.execution_count, stats.taken, stats.fallthrough
        );
        results.push(OpaqueBranchCandidate {
            branch_offset: format!("0x{offset:x}"),
            disasm: stats.disasm,
            execution_count: stats.execution_count,
            observed_taken_count: stats.taken,
            observed_fallthrough_count: stats.fallthrough,
            observed_other_count: stats.other,
            observed_successors,
            condition_source_offsets,
            rationale,
            assessment,
        });
    }
    results
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
        let candidates = build_opaque_candidates(stats);
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
}
