use std::collections::{BTreeMap, HashMap};

use crate::error::{Result, TraceError};
use crate::query::call_tree::{CallTree, CallTreeNode};
use crate::query::memory_object::{
    explain_memory_pointer_from_report, reconstruct_memory_objects, MemoryAccessKind,
    MemoryAccessObservation, MemoryAccessSample, MemoryObjectGraphReport, MemoryObjectOptions,
    MemoryPointerExplanation, MemoryStackFrameObservation,
};
use crate::session::SessionState;
use trace_parser::types::RegId;

use super::TraceEngine;

const STACK_ABOVE_ENTRY_ALLOWANCE: u64 = 0x10_000;

const POINTER_REGISTER_NAMES: &[(&str, usize)] = &[
    ("X0", 0),
    ("X1", 1),
    ("X2", 2),
    ("X3", 3),
    ("X4", 4),
    ("X5", 5),
    ("X6", 6),
    ("X7", 7),
    ("X8", 8),
    ("X9", 9),
    ("X10", 10),
    ("X11", 11),
    ("X12", 12),
    ("X13", 13),
    ("X14", 14),
    ("X15", 15),
    ("X16", 16),
    ("X17", 17),
    ("X18", 18),
    ("X19", 19),
    ("X20", 20),
    ("X21", 21),
    ("X22", 22),
    ("X23", 23),
    ("X24", 24),
    ("X25", 25),
    ("X26", 26),
    ("X27", 27),
    ("X28", 28),
    ("X29", 29),
    ("X30", 30),
    ("SP", 31),
];

fn register_values_at_state(state: &SessionState, seq: u32) -> Result<[u64; RegId::COUNT]> {
    let reg_view = state
        .reg_checkpoints_view()
        .ok_or(TraceError::IndexNotReady)?;
    let line_index = state.line_index_view().ok_or(TraceError::IndexNotReady)?;
    let (checkpoint_seq, snapshot) = reg_view
        .nearest_before(seq)
        .ok_or_else(|| TraceError::Internal("no register checkpoint available".to_string()))?;
    let mut values = *snapshot;
    for replay_seq in checkpoint_seq..=seq {
        if let Some(raw) = line_index.get_line(&state.mmap, replay_seq) {
            if let Ok(line) = std::str::from_utf8(raw) {
                crate::phase2::update_reg_values(&mut values, line);
            }
        }
    }
    Ok(values)
}

fn register_values_for_sequences(
    state: &SessionState,
    sequences: &[u32],
) -> Result<HashMap<u32, [u64; RegId::COUNT]>> {
    let reg_view = state
        .reg_checkpoints_view()
        .ok_or(TraceError::IndexNotReady)?;
    let line_index = state.line_index_view().ok_or(TraceError::IndexNotReady)?;
    let mut grouped = BTreeMap::<u32, Vec<u32>>::new();
    for seq in sequences.iter().copied() {
        let (checkpoint_seq, _) = reg_view
            .nearest_before(seq)
            .ok_or_else(|| TraceError::Internal("no register checkpoint available".to_string()))?;
        grouped.entry(checkpoint_seq).or_default().push(seq);
    }

    let mut result = HashMap::with_capacity(sequences.len());
    for (checkpoint_seq, mut targets) in grouped {
        targets.sort_unstable();
        targets.dedup();
        let (_, snapshot) = reg_view
            .nearest_before(checkpoint_seq)
            .ok_or_else(|| TraceError::Internal("no register checkpoint available".to_string()))?;
        let mut values = *snapshot;
        let mut replay_seq = checkpoint_seq;
        for target in targets {
            while replay_seq <= target {
                if let Some(raw) = line_index.get_line(&state.mmap, replay_seq) {
                    if let Ok(line) = std::str::from_utf8(raw) {
                        crate::phase2::update_reg_values(&mut values, line);
                    }
                }
                let Some(next) = replay_seq.checked_add(1) else {
                    break;
                };
                replay_seq = next;
            }
            result.insert(target, values);
        }
    }
    Ok(result)
}

fn collect_stack_frames(
    state: &SessionState,
    options: &MemoryObjectOptions,
) -> (Vec<MemoryStackFrameObservation>, u32) {
    if !options.include_stack_frames {
        return (Vec::new(), 0);
    }
    let Some(tree) = state.call_tree.as_ref() else {
        return (Vec::new(), 0);
    };
    let scope_start = options.start_seq.unwrap_or(0);
    let scope_end = options
        .end_seq
        .unwrap_or_else(|| state.total_lines.saturating_sub(1));
    let scoped_nodes = tree
        .nodes
        .iter()
        .filter(|node| node.entry_seq <= scope_end && node.exit_seq >= scope_start)
        .collect::<Vec<_>>();
    let target_sequences = scoped_nodes
        .iter()
        .flat_map(|node| [node.entry_seq, node.exit_seq])
        .collect::<Vec<_>>();
    let values_by_seq = match register_values_for_sequences(state, &target_sequences) {
        Ok(values) => values,
        Err(_) => return (Vec::new(), scoped_nodes.len().min(u32::MAX as usize) as u32),
    };
    let mut frames = Vec::new();
    let mut skipped = 0u32;
    for node in scoped_nodes {
        let Some(entry_values) = values_by_seq.get(&node.entry_seq) else {
            skipped += 1;
            continue;
        };
        let entry_sp = entry_values[31];
        if entry_sp == u64::MAX || entry_sp == 0 {
            skipped += 1;
            continue;
        }
        let exit_sp = values_by_seq
            .get(&node.exit_seq)
            .map(|values| values[31])
            .filter(|value| *value != u64::MAX && *value != 0);
        frames.push(MemoryStackFrameObservation {
            call_node_id: node.id,
            parent_call_node_id: node.parent_id,
            function_name: node.func_name.clone(),
            entry_seq: node.entry_seq,
            exit_seq: node.exit_seq,
            entry_sp,
            exit_sp,
        });
    }
    (frames, skipped)
}

fn node_by_id(tree: &CallTree, node_id: u32) -> Option<&CallTreeNode> {
    tree.nodes
        .get(node_id as usize)
        .filter(|node| node.id == node_id)
        .or_else(|| tree.nodes.iter().find(|node| node.id == node_id))
}

fn deepest_call_node_id(tree: &CallTree, seq: u32) -> Option<u32> {
    let mut current = node_by_id(tree, 0)?;
    loop {
        let next = current
            .children_ids
            .iter()
            .rev()
            .filter_map(|child_id| node_by_id(tree, *child_id))
            .find(|child| child.entry_seq <= seq && seq <= child.exit_seq);
        match next {
            Some(child) => current = child,
            None => return Some(current.id),
        }
    }
}

fn stack_node_for_access(
    tree: Option<&CallTree>,
    frame_sp: &HashMap<u32, u64>,
    seq: u32,
    address: u64,
    max_stack_distance: u64,
) -> Option<u32> {
    let tree = tree?;
    let mut node_id = deepest_call_node_id(tree, seq)?;
    loop {
        if let Some(entry_sp) = frame_sp.get(&node_id).copied() {
            let lower = entry_sp.saturating_sub(max_stack_distance);
            let upper = entry_sp.saturating_add(STACK_ABOVE_ENTRY_ALLOWANCE);
            if address >= lower && address <= upper {
                return Some(node_id);
            }
        }
        let node = node_by_id(tree, node_id)?;
        node_id = node.parent_id?;
    }
}

fn nearby_accesses(
    state: &SessionState,
    address: u64,
    seq: u32,
) -> Result<Vec<MemoryAccessSample>> {
    let view = state.mem_accesses_view().ok_or(TraceError::IndexNotReady)?;
    let mut samples = view
        .iter_all()
        .filter(|(base, record)| {
            address >= *base && address < base.saturating_add(u64::from(record.size.max(1)))
        })
        .map(|(base, record)| MemoryAccessSample {
            seq: record.seq,
            address: format!("0x{base:x}"),
            size: record.size,
            kind: if record.is_read() {
                "read".to_string()
            } else {
                "write".to_string()
            },
            instruction_address: format!("0x{:x}", record.insn_addr),
        })
        .collect::<Vec<_>>();
    samples.sort_by_key(|sample| (sample.seq.abs_diff(seq), sample.seq));
    samples.truncate(32);
    samples.sort_by_key(|sample| sample.seq);
    Ok(samples)
}

impl TraceEngine {
    pub fn reconstruct_memory_objects(
        &self,
        session_id: &str,
        options: MemoryObjectOptions,
    ) -> Result<MemoryObjectGraphReport> {
        let handle = self.get_handle(session_id)?;
        let state = handle
            .state
            .read()
            .map_err(|error| TraceError::Internal(error.to_string()))?;
        let mem_view = state.mem_accesses_view().ok_or(TraceError::IndexNotReady)?;
        let (stack_frames, skipped_stack_frames) = collect_stack_frames(&state, &options);
        let frame_sp = stack_frames
            .iter()
            .map(|frame| (frame.call_node_id, frame.entry_sp))
            .collect::<HashMap<_, _>>();
        let call_tree = state.call_tree.as_ref();
        let max_stack_distance = options.max_stack_distance.max(0x1000);
        let accesses = mem_view.iter_all().map(|(address, record)| {
            let call_node_id = stack_node_for_access(
                call_tree,
                &frame_sp,
                record.seq,
                address,
                max_stack_distance,
            );
            MemoryAccessObservation {
                seq: record.seq,
                address,
                size: record.size,
                kind: if record.is_read() {
                    MemoryAccessKind::Read
                } else {
                    MemoryAccessKind::Write
                },
                instruction_address: record.insn_addr,
                call_node_id,
            }
        });
        let mut report = reconstruct_memory_objects(
            &state.call_annotations,
            accesses,
            &stack_frames,
            state.total_lines,
            &options,
        );
        if skipped_stack_frames > 0 {
            report.limitations.push(format!(
                "{skipped_stack_frames} call-tree frame(s) had no usable entry SP checkpoint and were omitted from stack-object reconstruction."
            ));
        }
        Ok(report)
    }

    pub fn explain_memory_pointer(
        &self,
        session_id: &str,
        address: u64,
        seq: u32,
        include_stack_frames: bool,
    ) -> Result<MemoryPointerExplanation> {
        let info = self.get_session_info(session_id)?;
        if !info.index_ready {
            return Err(TraceError::IndexNotReady);
        }
        let query_seq = seq.min(info.total_lines.saturating_sub(1));
        let options = MemoryObjectOptions {
            start_seq: Some(0),
            end_seq: Some(query_seq),
            include_stack_frames,
            include_runtime_clusters: false,
            max_objects: 100_000,
            max_aliases_per_object: 128,
            max_field_windows_per_object: 128,
            max_access_samples_per_object: 32,
            max_anomalies: 512,
            max_runtime_clusters: 1,
            max_accesses: 5_000_000,
            max_stack_distance: default_stack_distance(),
        };
        let report = self.reconstruct_memory_objects(session_id, options)?;

        let handle = self.get_handle(session_id)?;
        let state = handle
            .state
            .read()
            .map_err(|error| TraceError::Internal(error.to_string()))?;
        let values = register_values_at_state(&state, query_seq)?;
        let registers = POINTER_REGISTER_NAMES
            .iter()
            .filter_map(|(name, index)| {
                let value = values[*index];
                (value != u64::MAX).then(|| ((*name).to_string(), value))
            })
            .collect::<Vec<_>>();
        let nearby = nearby_accesses(&state, address, query_seq)?;
        Ok(explain_memory_pointer_from_report(
            &report, address, query_seq, &registers, nearby,
        ))
    }
}

fn default_stack_distance() -> u64 {
    1024 * 1024
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deepest_call_node_prefers_nested_child() {
        let tree = CallTree {
            nodes: vec![
                CallTreeNode {
                    id: 0,
                    func_addr: 0,
                    func_name: None,
                    entry_seq: 0,
                    exit_seq: 100,
                    parent_id: None,
                    children_ids: vec![1],
                },
                CallTreeNode {
                    id: 1,
                    func_addr: 0x1000,
                    func_name: Some("outer".to_string()),
                    entry_seq: 10,
                    exit_seq: 90,
                    parent_id: Some(0),
                    children_ids: vec![2],
                },
                CallTreeNode {
                    id: 2,
                    func_addr: 0x2000,
                    func_name: Some("inner".to_string()),
                    entry_seq: 20,
                    exit_seq: 30,
                    parent_id: Some(1),
                    children_ids: Vec::new(),
                },
            ],
        };
        assert_eq!(deepest_call_node_id(&tree, 25), Some(2));
        assert_eq!(deepest_call_node_id(&tree, 50), Some(1));
        assert_eq!(deepest_call_node_id(&tree, 5), Some(0));
    }

    #[test]
    fn stack_access_can_fall_back_to_parent_frame() {
        let tree = CallTree {
            nodes: vec![
                CallTreeNode {
                    id: 0,
                    func_addr: 0,
                    func_name: None,
                    entry_seq: 0,
                    exit_seq: 100,
                    parent_id: None,
                    children_ids: vec![1],
                },
                CallTreeNode {
                    id: 1,
                    func_addr: 0x1000,
                    func_name: None,
                    entry_seq: 10,
                    exit_seq: 90,
                    parent_id: Some(0),
                    children_ids: vec![2],
                },
                CallTreeNode {
                    id: 2,
                    func_addr: 0x2000,
                    func_name: None,
                    entry_seq: 20,
                    exit_seq: 30,
                    parent_id: Some(1),
                    children_ids: Vec::new(),
                },
            ],
        };
        let frame_sp = HashMap::from([(1, 0x8000)]);
        assert_eq!(
            stack_node_for_access(Some(&tree), &frame_sp, 25, 0x7ff0, 0x1000),
            Some(1)
        );
    }
}
