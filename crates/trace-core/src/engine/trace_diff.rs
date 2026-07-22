use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet};

use crate::analysis::{
    TraceCountDelta, TraceDiffOptions, TraceDiffResult, TraceDiffSection,
    TraceFunctionClusterMatch, TraceFunctionClusterSection, TraceProfileSummary,
};
use crate::error::{Result, TraceError};

use super::TraceEngine;

const PROFILE_CHUNK_SIZE: u32 = 4096;
const DEFAULT_MAX_ITEMS: u32 = 100;
const MAX_DIFF_ITEMS: u32 = 1000;

#[derive(Clone, Debug)]
struct ProfileItem {
    label: String,
    count: u64,
    sample_seq: u32,
}

#[derive(Clone, Debug)]
struct FunctionShapeItem {
    module: String,
    offset: String,
    signature: String,
    normalized_shape: String,
    call_count: u64,
    sample_seq: u32,
    instruction_count: u64,
}

#[derive(Default)]
struct FunctionShapeAccumulator {
    module: Option<String>,
    offset: Option<String>,
    operations: Vec<String>,
    instruction_count: u64,
    sample_seq: Option<u32>,
}

#[derive(Default)]
struct TraceProfile {
    summary: Option<TraceProfileSummary>,
    functions: HashMap<String, ProfileItem>,
    branches: HashMap<String, ProfileItem>,
    instructions: HashMap<String, ProfileItem>,
    memory_access_sites: HashMap<String, ProfileItem>,
    function_shapes: Vec<FunctionShapeItem>,
}

impl TraceEngine {
    pub fn compare_trace_sessions(
        &self,
        left_session_id: &str,
        right_session_id: &str,
        options: TraceDiffOptions,
    ) -> Result<TraceDiffResult> {
        self.compare_trace_sessions_cancellable(
            left_session_id,
            right_session_id,
            options,
            |_, _| true,
        )
    }

    pub fn compare_trace_sessions_cancellable<F>(
        &self,
        left_session_id: &str,
        right_session_id: &str,
        options: TraceDiffOptions,
        mut checkpoint: F,
    ) -> Result<TraceDiffResult>
    where
        F: FnMut(u32, u32) -> bool,
    {
        let left_info = self.get_session_info(left_session_id)?;
        let right_info = self.get_session_info(right_session_id)?;
        if !left_info.index_ready || !right_info.index_ready {
            return Err(TraceError::IndexNotReady);
        }
        let left_total = selected_line_count(left_info.total_lines, &options);
        let right_total = selected_line_count(right_info.total_lines, &options);
        let total = left_total.saturating_add(right_total);
        let mut processed = 0u32;

        let left = build_profile(self, left_session_id, &options, |count| {
            processed = processed.saturating_add(count);
            checkpoint(processed, total)
        })?;
        let right = build_profile(self, right_session_id, &options, |count| {
            processed = processed.saturating_add(count);
            checkpoint(processed, total)
        })?;
        let max_items = if options.max_items == 0 {
            DEFAULT_MAX_ITEMS
        } else {
            options.max_items
        }
        .clamp(1, MAX_DIFF_ITEMS) as usize;

        Ok(TraceDiffResult {
            left: left.summary.expect("profile summary"),
            right: right.summary.expect("profile summary"),
            functions: diff_maps(&left.functions, &right.functions, max_items),
            function_clusters: cluster_function_shapes(
                &left.function_shapes,
                &right.function_shapes,
                max_items,
            ),
            branches: diff_maps(&left.branches, &right.branches, max_items),
            instructions: diff_maps(&left.instructions, &right.instructions, max_items),
            memory_access_sites: diff_maps(
                &left.memory_access_sites,
                &right.memory_access_sites,
                max_items,
            ),
            limitations: vec![
                "The diff compares executed instruction locations and counts; unexecuted paths are not represented."
                    .to_string(),
                "Memory differences are grouped by access site and direction, not by absolute runtime value."
                    .to_string(),
                "Module-relative offsets reduce ASLR noise, but code changes that move instructions can still appear as additions and removals."
                    .to_string(),
                "Instruction bytes at the same module-relative location are not compared; this is an execution-profile diff, not a binary diff."
                    .to_string(),
                "Cross-version function clusters use normalized executed mnemonic shapes. Identical small wrappers or unexecuted paths can remain ambiguous."
                    .to_string(),
            ],
        })
    }
}

fn selected_line_count(total_lines: u32, options: &TraceDiffOptions) -> u32 {
    let start = options.start_seq.unwrap_or(0).min(total_lines);
    let end = options
        .end_seq
        .map(|value| value.saturating_add(1))
        .unwrap_or(total_lines)
        .min(total_lines);
    end.saturating_sub(start)
}

fn build_profile<F>(
    engine: &TraceEngine,
    session_id: &str,
    options: &TraceDiffOptions,
    mut checkpoint: F,
) -> Result<TraceProfile>
where
    F: FnMut(u32) -> bool,
{
    let info = engine.get_session_info(session_id)?;
    let call_tree = {
        let handle = engine.get_handle(session_id)?;
        let state = handle
            .state
            .read()
            .map_err(|error| TraceError::Internal(error.to_string()))?;
        state.call_tree.clone().ok_or(TraceError::IndexNotReady)?
    };
    let mut shape_nodes = call_tree
        .nodes
        .iter()
        .filter(|node| node.id != 0)
        .map(|node| (node.entry_seq, node.exit_seq, node.id, node.func_addr))
        .collect::<Vec<_>>();
    shape_nodes.sort_by(|left, right| {
        left.0
            .cmp(&right.0)
            .then_with(|| right.1.cmp(&left.1))
            .then_with(|| left.2.cmp(&right.2))
    });
    let mut node_cursor = 0_usize;
    let mut active_nodes: Vec<(u32, u32, u32, u64)> = Vec::new();
    let mut function_shape_accumulators: HashMap<u32, FunctionShapeAccumulator> = HashMap::new();
    let start = options.start_seq.unwrap_or(0).min(info.total_lines);
    let end = options
        .end_seq
        .map(|value| value.saturating_add(1))
        .unwrap_or(info.total_lines)
        .min(info.total_lines);
    let mut profile = TraceProfile::default();
    let mut modules = HashSet::new();
    let mut instruction_count = 0u64;
    let mut call_count = 0u64;
    let mut branch_count = 0u64;
    let mut memory_access_count = 0u64;

    let mut cursor = start;
    while cursor < end {
        let chunk_end = cursor.saturating_add(PROFILE_CHUNK_SIZE).min(end);
        let seqs: Vec<u32> = (cursor..chunk_end).collect();
        let lines = engine.get_lines(session_id, &seqs)?;
        for line in lines {
            while active_nodes
                .last()
                .is_some_and(|(_, exit_seq, _, _)| *exit_seq < line.seq)
            {
                active_nodes.pop();
            }
            while node_cursor < shape_nodes.len() && shape_nodes[node_cursor].0 <= line.seq {
                let node = shape_nodes[node_cursor];
                if node.1 >= line.seq {
                    active_nodes.push(node);
                }
                node_cursor += 1;
            }
            if line.disasm.is_empty() {
                continue;
            }
            instruction_count = instruction_count.saturating_add(1);
            if let Some(module) = line.so_name.as_deref() {
                modules.insert(module.to_string());
            }
            let location = location_key(line.so_name.as_deref(), &line.so_offset, &line.address);
            let operation = operation_name(&line.disasm);

            if let Some((entry_seq, _, function_id, function_addr)) = active_nodes.last().copied() {
                if line.seq > entry_seq {
                    let accumulator = function_shape_accumulators.entry(function_id).or_default();
                    accumulator.instruction_count = accumulator.instruction_count.saturating_add(1);
                    accumulator.sample_seq.get_or_insert(line.seq);
                    if accumulator.module.is_none() {
                        if let (Some(module), Some(address), Some(offset)) = (
                            line.so_name.as_deref(),
                            parse_hex_number(&line.address),
                            parse_hex_number(&line.so_offset),
                        ) {
                            let module_base = address.saturating_sub(offset);
                            let function_offset = function_addr.saturating_sub(module_base);
                            accumulator.module = Some(module.to_ascii_lowercase());
                            accumulator.offset = Some(format!("0x{function_offset:x}"));
                        }
                    }
                    let shape = operation_shape(&operation);
                    if accumulator.operations.len() < 64
                        && accumulator.operations.last().map(String::as_str) != Some(shape.as_str())
                    {
                        accumulator.operations.push(shape);
                    }
                }
            }
            bump(
                &mut profile.instructions,
                location.clone(),
                format!("{location} {}", line.disasm),
                line.seq,
            );

            if is_branch(&operation) {
                branch_count = branch_count.saturating_add(1);
                bump(
                    &mut profile.branches,
                    location.clone(),
                    format!("{location} {}", line.disasm),
                    line.seq,
                );
            }
            if let Some(call) = line.call_info.as_ref() {
                call_count = call_count.saturating_add(1);
                let key = call.func_name.to_ascii_lowercase();
                bump(
                    &mut profile.functions,
                    key,
                    call.func_name.clone(),
                    line.seq,
                );
            }
            if let Some(rw) = line.mem_rw.as_deref() {
                memory_access_count = memory_access_count.saturating_add(1);
                bump(
                    &mut profile.memory_access_sites,
                    format!("{location}|{rw}"),
                    format!("{location} {rw}"),
                    line.seq,
                );
            }
        }
        let processed = chunk_end.saturating_sub(cursor);
        if !checkpoint(processed) {
            return Err(TraceError::Cancelled);
        }
        cursor = chunk_end;
    }

    let mut modules: Vec<_> = modules.into_iter().collect();
    modules.sort();
    profile.function_shapes = finalize_function_shapes(function_shape_accumulators);
    profile.summary = Some(TraceProfileSummary {
        session_id: session_id.to_string(),
        file_path: info.file_path,
        total_lines: info.total_lines,
        scanned_lines: end.saturating_sub(start),
        instruction_count,
        call_count,
        branch_count,
        memory_access_count,
        modules,
    });
    Ok(profile)
}

fn parse_hex_number(value: &str) -> Option<u64> {
    u64::from_str_radix(
        value
            .trim()
            .trim_start_matches("0x")
            .trim_start_matches("0X"),
        16,
    )
    .ok()
}

pub(super) fn operation_shape(operation: &str) -> String {
    let shape = if matches!(operation, "bl" | "blr") {
        "call"
    } else if operation == "ret" {
        "return"
    } else if is_branch(operation) {
        "branch"
    } else if operation.starts_with("ldr")
        || operation.starts_with("ldp")
        || operation.starts_with("ld1")
    {
        "load"
    } else if operation.starts_with("str")
        || operation.starts_with("stp")
        || operation.starts_with("st1")
    {
        "store"
    } else if matches!(
        operation,
        "eor" | "eon" | "and" | "ands" | "orr" | "orn" | "bic"
    ) {
        "logic"
    } else if matches!(operation, "lsl" | "lsr" | "asr" | "ror" | "extr") {
        "shift"
    } else if operation.starts_with("add") || operation.starts_with("sub") {
        "arithmetic"
    } else if operation.starts_with("mul")
        || operation.starts_with("madd")
        || operation.starts_with("msub")
    {
        "multiply"
    } else if operation.starts_with("cmp")
        || operation.starts_with("cmn")
        || operation.starts_with("tst")
    {
        "compare"
    } else if operation.starts_with("mov") || operation.starts_with("fmov") {
        "move"
    } else if operation.starts_with("aes")
        || operation.starts_with("sha")
        || operation.starts_with("sm3")
        || operation.starts_with("sm4")
        || operation.starts_with("crc32")
    {
        "crypto"
    } else {
        operation
    };
    shape.to_string()
}

pub(super) fn shape_signature(shape: &str) -> String {
    let digest = Sha256::digest(shape.as_bytes());
    digest[..12]
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn finalize_function_shapes(
    accumulators: HashMap<u32, FunctionShapeAccumulator>,
) -> Vec<FunctionShapeItem> {
    let mut grouped: HashMap<(String, String, String), FunctionShapeItem> = HashMap::new();
    for accumulator in accumulators.into_values() {
        if accumulator.operations.len() < 4 || accumulator.instruction_count < 4 {
            continue;
        }
        let (Some(module), Some(offset), Some(sample_seq)) = (
            accumulator.module,
            accumulator.offset,
            accumulator.sample_seq,
        ) else {
            continue;
        };
        let normalized_shape = accumulator.operations.join(">");
        let signature = shape_signature(&normalized_shape);
        grouped
            .entry((module.clone(), offset.clone(), signature.clone()))
            .and_modify(|item| {
                item.call_count = item.call_count.saturating_add(1);
                item.instruction_count = item
                    .instruction_count
                    .saturating_add(accumulator.instruction_count);
                item.sample_seq = item.sample_seq.min(sample_seq);
            })
            .or_insert(FunctionShapeItem {
                module,
                offset,
                signature,
                normalized_shape,
                call_count: 1,
                sample_seq,
                instruction_count: accumulator.instruction_count,
            });
    }
    grouped.into_values().collect()
}

fn cluster_function_shapes(
    left: &[FunctionShapeItem],
    right: &[FunctionShapeItem],
    max_items: usize,
) -> TraceFunctionClusterSection {
    let mut used_right = HashSet::new();
    let mut matches = Vec::new();
    for left_item in left {
        let candidate = right
            .iter()
            .enumerate()
            .filter(|(index, right_item)| {
                !used_right.contains(index)
                    && left_item.module == right_item.module
                    && left_item.signature == right_item.signature
            })
            .min_by_key(|(_, right_item)| {
                left_item
                    .instruction_count
                    .abs_diff(right_item.instruction_count)
            });
        let Some((right_index, right_item)) = candidate else {
            continue;
        };
        used_right.insert(right_index);
        matches.push(TraceFunctionClusterMatch {
            signature: left_item.signature.clone(),
            module: left_item.module.clone(),
            normalized_shape: left_item.normalized_shape.clone(),
            left_offset: left_item.offset.clone(),
            right_offset: right_item.offset.clone(),
            left_call_count: left_item.call_count,
            right_call_count: right_item.call_count,
            left_sample_seq: left_item.sample_seq,
            right_sample_seq: right_item.sample_seq,
            relocated: left_item.offset != right_item.offset,
        });
    }
    matches.sort_by(|left, right| {
        right
            .relocated
            .cmp(&left.relocated)
            .then_with(|| left.module.cmp(&right.module))
            .then_with(|| left.left_offset.cmp(&right.left_offset))
    });
    let total_matches = matches.len().min(u32::MAX as usize) as u32;
    let relocated_matches = matches.iter().filter(|item| item.relocated).count() as u32;
    let truncated = matches.len() > max_items;
    matches.truncate(max_items);
    TraceFunctionClusterSection {
        matches,
        total_matches,
        relocated_matches,
        truncated,
    }
}

fn bump(map: &mut HashMap<String, ProfileItem>, key: String, label: String, sample_seq: u32) {
    map.entry(key)
        .and_modify(|item| item.count = item.count.saturating_add(1))
        .or_insert(ProfileItem {
            label,
            count: 1,
            sample_seq,
        });
}

fn diff_maps(
    left: &HashMap<String, ProfileItem>,
    right: &HashMap<String, ProfileItem>,
    max_items: usize,
) -> TraceDiffSection {
    let mut added = Vec::new();
    let mut removed = Vec::new();
    let mut changed = Vec::new();
    let mut keys: HashSet<&str> = left.keys().map(String::as_str).collect();
    keys.extend(right.keys().map(String::as_str));
    for key in keys {
        let left_item = left.get(key);
        let right_item = right.get(key);
        let left_count = left_item.map_or(0, |item| item.count);
        let right_count = right_item.map_or(0, |item| item.count);
        if left_count == right_count {
            continue;
        }
        let delta = right_count as i128 - left_count as i128;
        let item = TraceCountDelta {
            key: key.to_string(),
            label: right_item
                .or(left_item)
                .map(|item| item.label.clone())
                .unwrap_or_else(|| key.to_string()),
            left_count,
            right_count,
            delta: delta.clamp(i64::MIN as i128, i64::MAX as i128) as i64,
            left_sample_seq: left_item.map(|item| item.sample_seq),
            right_sample_seq: right_item.map(|item| item.sample_seq),
        };
        if left_item.is_none() {
            added.push(item);
        } else if right_item.is_none() {
            removed.push(item);
        } else {
            changed.push(item);
        }
    }
    sort_deltas(&mut added);
    sort_deltas(&mut removed);
    sort_deltas(&mut changed);
    let total_added = added.len().min(u32::MAX as usize) as u32;
    let total_removed = removed.len().min(u32::MAX as usize) as u32;
    let total_changed = changed.len().min(u32::MAX as usize) as u32;
    let truncated =
        added.len() > max_items || removed.len() > max_items || changed.len() > max_items;
    added.truncate(max_items);
    removed.truncate(max_items);
    changed.truncate(max_items);
    TraceDiffSection {
        added,
        removed,
        changed,
        total_added,
        total_removed,
        total_changed,
        truncated,
    }
}

fn sort_deltas(items: &mut [TraceCountDelta]) {
    items.sort_by(|left, right| {
        right
            .delta
            .unsigned_abs()
            .cmp(&left.delta.unsigned_abs())
            .then_with(|| left.label.cmp(&right.label))
    });
}

fn location_key(module: Option<&str>, so_offset: &str, address: &str) -> String {
    let module = module.unwrap_or("unknown");
    if !so_offset.is_empty() {
        format!("{module}!{so_offset}")
    } else {
        format!("{module}!{address}")
    }
}

fn operation_name(disasm: &str) -> String {
    disasm
        .split_whitespace()
        .next()
        .unwrap_or_default()
        .trim_matches(|character: char| !character.is_ascii_alphanumeric() && character != '.')
        .to_ascii_lowercase()
}

fn is_branch(operation: &str) -> bool {
    operation == "b"
        || operation.starts_with("b.")
        || matches!(
            operation,
            "bl" | "blr" | "br" | "ret" | "cbz" | "cbnz" | "tbz" | "tbnz"
        )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{BuildOptions, TraceEngine};

    fn session(engine: &TraceEngine, lines: &[&str]) -> (String, std::path::PathBuf) {
        let path = std::env::temp_dir().join(format!(
            "trace-ui-diff-{}.gumtrace.txt",
            uuid::Uuid::new_v4()
        ));
        std::fs::write(&path, lines.join("\n")).unwrap();
        let info = engine.create_session(path.to_str().unwrap()).unwrap();
        engine
            .build_index(
                &info.session_id,
                BuildOptions {
                    force_rebuild: true,
                    skip_strings: true,
                },
                None,
            )
            .unwrap();
        (info.session_id, path)
    }

    #[test]
    fn compares_calls_branches_and_memory_sites() {
        let engine = TraceEngine::new();
        let (left, left_path) = session(
            &engine,
            &[
                "[lib.so] 0x1000!0x10 mov x0, #1; x0=0x1",
                "[lib.so] 0x1004!0x14 bl #0x2000",
                "call func: read(3, 0x5000, 4)",
                "ret: 4",
            ],
        );
        let (right, right_path) = session(
            &engine,
            &[
                "[lib.so] 0x1000!0x10 mov x0, #1; x0=0x1",
                "[lib.so] 0x1004!0x14 bl #0x2000",
                "call func: read(3, 0x5000, 4)",
                "ret: 4",
                "[lib.so] 0x1008!0x18 bl #0x3000",
                "call func: write(3, 0x5000, 4)",
                "ret: 4",
            ],
        );

        let diff = engine
            .compare_trace_sessions(
                &left,
                &right,
                TraceDiffOptions {
                    max_items: 20,
                    ..TraceDiffOptions::default()
                },
            )
            .unwrap();
        assert!(diff
            .functions
            .added
            .iter()
            .any(|item| item.label == "write"));
        assert!(diff.branches.total_added > 0);
        assert!(diff.right.instruction_count > diff.left.instruction_count);

        engine.delete_file_cache(left_path.to_str().unwrap());
        engine.delete_file_cache(right_path.to_str().unwrap());
        engine.close_session(&left).unwrap();
        engine.close_session(&right).unwrap();
        let _ = std::fs::remove_file(left_path);
        let _ = std::fs::remove_file(right_path);
    }

    #[test]
    fn clusters_relocated_functions_by_normalized_executed_shape() {
        let engine = TraceEngine::new();
        let (left, left_path) = session(
            &engine,
            &[
                "[lib.so] 0x1000!0x0 bl #0x1100",
                "[lib.so] 0x1100!0x100 mov x1, x0; x1=0x5000",
                "[lib.so] 0x1104!0x104 ldr x2, [x1]; x2=0x12",
                "[lib.so] 0x1108!0x108 eor x2, x2, x3; x2=0x34",
                "[lib.so] 0x110c!0x10c str x2, [x1]; mem_w=0x5000/8=0x34",
                "[lib.so] 0x1110!0x110 ret",
            ],
        );
        let (right, right_path) = session(
            &engine,
            &[
                "[lib.so] 0x1000!0x0 bl #0x1300",
                "[lib.so] 0x1300!0x300 mov x9, x8; x9=0x6000",
                "[lib.so] 0x1304!0x304 ldr x10, [x9]; x10=0x56",
                "[lib.so] 0x1308!0x308 eor x10, x10, x11; x10=0x78",
                "[lib.so] 0x130c!0x30c str x10, [x9]; mem_w=0x6000/8=0x78",
                "[lib.so] 0x1310!0x310 ret",
            ],
        );

        let diff = engine
            .compare_trace_sessions(
                &left,
                &right,
                TraceDiffOptions {
                    max_items: 20,
                    ..TraceDiffOptions::default()
                },
            )
            .unwrap();
        let relocated = diff
            .function_clusters
            .matches
            .iter()
            .find(|item| item.relocated)
            .unwrap();
        assert_eq!(relocated.module, "lib.so");
        assert_eq!(relocated.left_offset, "0x100");
        assert_eq!(relocated.right_offset, "0x300");
        assert_eq!(relocated.normalized_shape, "move>load>logic>store>return");
        assert_eq!(diff.function_clusters.relocated_matches, 1);

        engine.delete_file_cache(left_path.to_str().unwrap());
        engine.delete_file_cache(right_path.to_str().unwrap());
        engine.close_session(&left).unwrap();
        engine.close_session(&right).unwrap();
        let _ = std::fs::remove_file(left_path);
        let _ = std::fs::remove_file(right_path);
    }
}
