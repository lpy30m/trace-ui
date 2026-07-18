use std::collections::VecDeque;

use bitvec::prelude::*;

use crate::flat::scan_view::ScanView;
use crate::scanner::{CONTROL_DEP_BIT, LINE_MASK};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ForwardTraversal {
    pub affected: BitVec,
    pub terminal_seqs: Vec<u32>,
    pub traversed_edges: u64,
    pub truncated: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ForwardDependencyIndex {
    offsets: Vec<usize>,
    consumers: Vec<u32>,
    line_count: u32,
}

impl ForwardDependencyIndex {
    pub fn edge_count(&self) -> u64 {
        self.consumers.len() as u64
    }

    pub fn line_count(&self) -> u32 {
        self.line_count
    }
}

/// Follow the dependency graph in the forward direction.
///
/// The stored graph points from each instruction to its dependencies. This
/// routine builds a compact reverse adjacency index, then walks consumers from
/// the resolved source definitions. Pair-instruction tags are intentionally
/// collapsed to instruction precision, which is conservative and avoids
/// missing consumers when shared pair dependencies are involved.
pub fn bfs_forward_with_options<F>(
    view: &ScanView<'_>,
    start_indices: &[u32],
    data_only: bool,
    max_nodes: usize,
    mut checkpoint: F,
) -> Option<ForwardTraversal>
where
    F: FnMut(u32, u32) -> bool,
{
    let index = build_forward_index(view, &mut checkpoint)?;
    traverse_forward_index(&index, start_indices, data_only, max_nodes, &mut checkpoint)
}

pub fn build_forward_index<F>(
    view: &ScanView<'_>,
    mut checkpoint: F,
) -> Option<ForwardDependencyIndex>
where
    F: FnMut(u32, u32) -> bool,
{
    let line_count = view.line_count as usize;
    if line_count == 0 {
        return Some(ForwardDependencyIndex {
            offsets: vec![0],
            consumers: Vec::new(),
            line_count: 0,
        });
    }

    let mut counts = vec![0u32; line_count];
    let mut edge_count = 0usize;
    for consumer in 0..line_count {
        for_each_dependency(view, consumer as u32, |dependency| {
            let source = (dependency & LINE_MASK) as usize;
            if source < line_count {
                counts[source] = counts[source].saturating_add(1);
                edge_count = edge_count.saturating_add(1);
            }
        });
        if consumer % 4096 == 0 && !checkpoint(consumer as u32, view.line_count.saturating_mul(2)) {
            return None;
        }
    }

    let mut offsets = vec![0usize; line_count + 1];
    for index in 0..line_count {
        offsets[index + 1] = offsets[index].saturating_add(counts[index] as usize);
    }
    let mut cursors = offsets[..line_count].to_vec();
    let mut consumers = vec![0u32; edge_count];
    for consumer in 0..line_count {
        for_each_dependency(view, consumer as u32, |dependency| {
            let source = (dependency & LINE_MASK) as usize;
            if source < line_count {
                let cursor = cursors[source];
                consumers[cursor] = consumer as u32 | (dependency & CONTROL_DEP_BIT);
                cursors[source] += 1;
            }
        });
        if consumer % 4096 == 0
            && !checkpoint(
                view.line_count.saturating_add(consumer as u32),
                view.line_count.saturating_mul(2),
            )
        {
            return None;
        }
    }

    Some(ForwardDependencyIndex {
        offsets,
        consumers,
        line_count: view.line_count,
    })
}

pub fn traverse_forward_index<F>(
    index: &ForwardDependencyIndex,
    start_indices: &[u32],
    data_only: bool,
    max_nodes: usize,
    mut checkpoint: F,
) -> Option<ForwardTraversal>
where
    F: FnMut(u32, u32) -> bool,
{
    let line_count = index.line_count as usize;
    if line_count == 0 {
        return Some(ForwardTraversal {
            affected: BitVec::new(),
            terminal_seqs: Vec::new(),
            traversed_edges: 0,
            truncated: false,
        });
    }

    let node_limit = max_nodes.max(1).min(line_count);
    let mut affected = bitvec![0; line_count];
    let mut queue = VecDeque::new();
    for &raw in start_indices {
        let line = (raw & LINE_MASK) as usize;
        if line < line_count && !affected[line] {
            affected.set(line, true);
            queue.push_back(line as u32);
        }
    }

    let mut affected_count = affected.count_ones();
    let mut traversed_edges = 0u64;
    let mut next_checkpoint = 4096u64;
    let mut truncated = false;
    while let Some(source) = queue.pop_front() {
        let start = index.offsets[source as usize];
        let end = index.offsets[source as usize + 1];
        for &raw_consumer in &index.consumers[start..end] {
            if data_only && raw_consumer & CONTROL_DEP_BIT != 0 {
                continue;
            }
            let consumer = raw_consumer & LINE_MASK;
            traversed_edges = traversed_edges.saturating_add(1);
            if affected[consumer as usize] {
                continue;
            }
            if affected_count >= node_limit {
                truncated = true;
                continue;
            }
            affected.set(consumer as usize, true);
            affected_count += 1;
            queue.push_back(consumer);
        }
        if traversed_edges >= next_checkpoint {
            if !checkpoint(
                index.line_count.saturating_mul(2),
                index.line_count.saturating_mul(2),
            ) {
                return None;
            }
            next_checkpoint = traversed_edges.saturating_add(4096);
        }
    }

    let mut terminal_seqs = Vec::new();
    for source in affected.iter_ones() {
        let start = index.offsets[source];
        let end = index.offsets[source + 1];
        if index.consumers[start..end]
            .iter()
            .filter(|consumer| !data_only || **consumer & CONTROL_DEP_BIT == 0)
            .next()
            .is_none()
        {
            terminal_seqs.push(source as u32);
        }
    }

    Some(ForwardTraversal {
        affected,
        terminal_seqs,
        traversed_edges,
        truncated,
    })
}

fn for_each_dependency<F>(view: &ScanView<'_>, line: u32, mut visit: F)
where
    F: FnMut(u32),
{
    if let Some(split) = view.pair_split.get(&line) {
        for &dependency in split
            .shared
            .iter()
            .chain(split.half1_deps.iter())
            .chain(split.half2_deps.iter())
        {
            visit(dependency);
        }
        return;
    }

    for &dependency in view
        .deps
        .row(line as usize)
        .iter()
        .chain(view.deps.patch_row(line as usize).iter())
    {
        visit(dependency);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::flat::convert;
    use crate::scanner;
    use trace_parser::types::RegId;

    #[test]
    fn follows_register_and_memory_consumers_forward() {
        let trace = [
            r#"[00:00:00 001][lib.so 0x100] [d2800548] 0x40000100: "mov x8, #42" => x8=0x2a"#,
            r#"[00:00:00 001][lib.so 0x104] [aa0803e0] 0x40000104: "mov x0, x8" x8=0x2a => x0=0x2a"#,
            r#"[00:00:00 001][lib.so 0x108] [f9000be0] 0x40000108: "str x0, [sp, #0x10]" ; mem[WRITE] abs=0xbffff010 x0=0x2a sp=0xbffff000 => x0=0x2a"#,
            r#"[00:00:00 001][lib.so 0x10c] [f9400be1] 0x4000010c: "ldr x1, [sp, #0x10]" ; mem[READ] abs=0xbffff010 sp=0xbffff000 => x1=0x2a"#,
            r#"[00:00:00 001][lib.so 0x110] [91000422] 0x40000110: "add x2, x1, #1" x1=0x2a => x2=0x2b"#,
            r#"[00:00:00 001][lib.so 0x114] [d2800c63] 0x40000114: "mov x3, #99" => x3=0x63"#,
        ]
        .join("\n");
        let state = scanner::scan_from_string(&trace, false).unwrap();
        let deps = convert::deps_to_flat(&state.deps);
        let pair_split = convert::pair_split_to_flat(&state.pair_split);
        let view = ScanView {
            deps: deps.view(),
            pair_split: pair_split.view(),
            line_count: state.line_count,
        };
        let source = *state.reg_last_def.get(&RegId::X8).unwrap();
        let result = bfs_forward_with_options(&view, &[source], true, 100, |_, _| true).unwrap();

        for seq in 0..=4 {
            assert!(result.affected[seq], "line {seq} should be affected");
        }
        assert!(
            !result.affected[5],
            "unrelated definition should be excluded"
        );
        assert_eq!(result.terminal_seqs, vec![4]);
        assert!(!result.truncated);
    }

    #[test]
    fn follows_aapcs_argument_into_branch_link_call() {
        let trace = [
            r#"[00:00:00 001][lib.so 0x100] [d2800060] 0x40000100: "mov x0, #3" => x0=0x3"#,
            r#"[00:00:00 001][lib.so 0x104] [94000000] 0x40000104: "bl #0x40000200" => x30=0x40000108"#,
            r#"[00:00:00 001][lib.so 0x108] [d2800c68] 0x40000108: "mov x8, #99" => x8=0x63"#,
        ]
        .join("\n");
        let state = scanner::scan_from_string(&trace, false).unwrap();
        let deps = convert::deps_to_flat(&state.deps);
        let pair_split = convert::pair_split_to_flat(&state.pair_split);
        let view = ScanView {
            deps: deps.view(),
            pair_split: pair_split.view(),
            line_count: state.line_count,
        };
        let source = *state.reg_last_def.get(&RegId::X0).unwrap();
        let result = bfs_forward_with_options(&view, &[source], true, 100, |_, _| true).unwrap();

        assert!(result.affected[0]);
        assert!(result.affected[1], "branch-link call must consume x0");
        assert!(!result.affected[2], "unrelated register definition must be excluded");
        assert_eq!(result.terminal_seqs, vec![1]);
    }

    #[test]
    fn respects_node_limit_and_cancellation() {
        let trace = [
            r#"[00:00:00 001][lib.so 0x100] [d2800020] 0x40000100: "mov x0, #1" => x0=0x1"#,
            r#"[00:00:00 001][lib.so 0x104] [91000400] 0x40000104: "add x0, x0, #1" x0=0x1 => x0=0x2"#,
            r#"[00:00:00 001][lib.so 0x108] [91000400] 0x40000108: "add x0, x0, #1" x0=0x2 => x0=0x3"#,
        ]
        .join("\n");
        let state = scanner::scan_from_string(&trace, false).unwrap();
        let deps = convert::deps_to_flat(&state.deps);
        let pair_split = convert::pair_split_to_flat(&state.pair_split);
        let view = ScanView {
            deps: deps.view(),
            pair_split: pair_split.view(),
            line_count: state.line_count,
        };

        let limited = bfs_forward_with_options(&view, &[0], true, 2, |_, _| true).unwrap();
        assert_eq!(limited.affected.count_ones(), 2);
        assert!(limited.truncated);
        assert!(limited.terminal_seqs.is_empty());
        assert!(bfs_forward_with_options(&view, &[0], true, 10, |_, _| false).is_none());
    }

    #[test]
    fn cached_index_supports_data_only_and_control_modes() {
        let index = ForwardDependencyIndex {
            offsets: vec![0, 2, 2, 2],
            consumers: vec![1, 2 | CONTROL_DEP_BIT],
            line_count: 3,
        };

        let data_only = traverse_forward_index(&index, &[0], true, 10, |_, _| true).unwrap();
        assert!(data_only.affected[0]);
        assert!(data_only.affected[1]);
        assert!(!data_only.affected[2]);

        let with_control = traverse_forward_index(&index, &[0], false, 10, |_, _| true).unwrap();
        assert!(with_control.affected[2]);
    }
}
