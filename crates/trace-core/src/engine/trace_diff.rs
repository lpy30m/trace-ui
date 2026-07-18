use std::collections::{HashMap, HashSet};

use crate::analysis::{
    TraceCountDelta, TraceDiffOptions, TraceDiffResult, TraceDiffSection, TraceProfileSummary,
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

#[derive(Default)]
struct TraceProfile {
    summary: Option<TraceProfileSummary>,
    functions: HashMap<String, ProfileItem>,
    branches: HashMap<String, ProfileItem>,
    instructions: HashMap<String, ProfileItem>,
    memory_access_sites: HashMap<String, ProfileItem>,
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
            if line.disasm.is_empty() {
                continue;
            }
            instruction_count = instruction_count.saturating_add(1);
            if let Some(module) = line.so_name.as_deref() {
                modules.insert(module.to_string());
            }
            let location = location_key(line.so_name.as_deref(), &line.so_offset, &line.address);
            let operation = operation_name(&line.disasm);
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
}
