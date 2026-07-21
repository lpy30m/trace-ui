use std::collections::BTreeMap;

use crate::api_types::CallTreeNodeDto;
use crate::error::{Result, TraceError};
use crate::query::function_inspect::{
    FunctionCallAnnotation, FunctionInspection, FunctionRef, MemTouch, RegValue,
};

/// 为界定函数内存 I/O 扫描的行数上限，避免超大函数拖慢检查。
const MEM_IO_LINE_CAP: u32 = 4096;
/// 每个方向（读/写）返回的不同地址上限。
const MAX_MEM_TOUCH: usize = 200;

fn func_ref(dto: &CallTreeNodeDto) -> FunctionRef {
    FunctionRef {
        func_id: dto.id,
        func_addr: dto.func_addr.clone(),
        func_name: dto.func_name.clone(),
        entry_seq: dto.entry_seq,
        exit_seq: dto.exit_seq,
        line_count: dto.line_count,
    }
}

fn to_touches(map: BTreeMap<String, (u32, u8)>) -> Vec<MemTouch> {
    let mut v: Vec<MemTouch> = map
        .into_iter()
        .map(|(addr, (count, size))| MemTouch { addr, count, size })
        .collect();
    v.sort_by(|a, b| b.count.cmp(&a.count).then(a.addr.cmp(&b.addr)));
    v.truncate(MAX_MEM_TOUCH);
    v
}

impl super::TraceEngine {
    /// 检查指定 call-tree 节点：入口 X0-X7、返回 X0、调用注解、父/子函数、内存 I/O。
    pub fn inspect_function(&self, session_id: &str, node_id: u32) -> Result<FunctionInspection> {
        let nodes = self.get_call_tree_children(session_id, node_id, true)?;
        let node = nodes.first().cloned().ok_or_else(|| {
            TraceError::InvalidArgument(format!("Function node {node_id} not found"))
        })?;
        let children: Vec<FunctionRef> = nodes.iter().skip(1).map(func_ref).collect();

        let parent = match node.parent_id {
            Some(pid) => self
                .get_call_tree_children(session_id, pid, true)
                .ok()
                .and_then(|v| v.first().map(func_ref)),
            None => None,
        };

        let entry_regs = self
            .get_registers_at(session_id, node.entry_seq)
            .unwrap_or_default();
        let mut entry_args = Vec::new();
        for i in 0..8u8 {
            let key = format!("X{i}");
            if let Some(v) = entry_regs.get(&key) {
                if v != "?" {
                    entry_args.push(RegValue {
                        reg: key,
                        value: v.clone(),
                    });
                }
            }
        }

        let return_value = if node.exit_seq > node.entry_seq {
            self.get_registers_at(session_id, node.exit_seq)
                .ok()
                .and_then(|m| m.get("X0").filter(|v| *v != "?").cloned())
        } else {
            None
        };

        // 调用注解挂在 bl/blr 行；entry_seq 可能是 bl 行或被调方首行，两处都试。
        let call_annotation = self.get_handle(session_id).ok().and_then(|h| {
            let state = h.state.read().ok()?;
            let ann = state.call_annotations.get(&node.entry_seq).or_else(|| {
                state
                    .call_annotations
                    .get(&node.entry_seq.saturating_sub(1))
            })?;
            Some(FunctionCallAnnotation {
                func_name: ann.func_name.clone(),
                is_jni: ann.is_jni,
                args: ann
                    .args
                    .iter()
                    .map(|(idx, val)| RegValue {
                        reg: idx.clone(),
                        value: val.clone(),
                    })
                    .collect(),
                ret_value: ann.ret_value.clone(),
            })
        });

        let (memory_reads, memory_writes, scanned_lines, io_truncated) =
            self.collect_function_mem_io(session_id, node.entry_seq, node.exit_seq)?;

        Ok(FunctionInspection {
            func_id: node.id,
            func_addr: node.func_addr,
            func_name: node.func_name,
            entry_seq: node.entry_seq,
            exit_seq: node.exit_seq,
            line_count: node.line_count,
            parent,
            entry_args,
            return_value,
            call_annotation,
            child_count: children.len() as u32,
            children,
            memory_reads,
            memory_writes,
            scanned_lines,
            io_truncated,
        })
    }

    /// 检查包含 `seq` 的最内层函数。
    pub fn inspect_function_at_seq(
        &self,
        session_id: &str,
        seq: u32,
    ) -> Result<FunctionInspection> {
        let node_id = {
            let handle = self.get_handle(session_id)?;
            let state = handle
                .state
                .read()
                .map_err(|e| TraceError::Internal(e.to_string()))?;
            let ct = state.call_tree.as_ref().ok_or(TraceError::IndexNotReady)?;
            crate::query::crypto_functions::innermost_function_for_seq(ct, seq).ok_or_else(
                || TraceError::InvalidArgument(format!("No function contains seq {seq}")),
            )?
        };
        self.inspect_function(session_id, node_id)
    }

    fn collect_function_mem_io(
        &self,
        session_id: &str,
        entry_seq: u32,
        exit_seq: u32,
    ) -> Result<(Vec<MemTouch>, Vec<MemTouch>, u32, bool)> {
        let last = exit_seq.min(entry_seq.saturating_add(MEM_IO_LINE_CAP).saturating_sub(1));
        let io_truncated = exit_seq > last;
        let mut reads: BTreeMap<String, (u32, u8)> = BTreeMap::new();
        let mut writes: BTreeMap<String, (u32, u8)> = BTreeMap::new();
        let mut scanned_lines = 0u32;

        let mut seq = entry_seq;
        while seq <= last {
            let end = seq.saturating_add(2047).min(last);
            let seqs: Vec<u32> = (seq..=end).collect();
            let lines = self.get_lines(session_id, &seqs)?;
            for l in &lines {
                scanned_lines += 1;
                let (Some(addr), Some(rw)) = (l.mem_addr.as_deref(), l.mem_rw.as_deref()) else {
                    continue;
                };
                let size = l.mem_size.unwrap_or(0);
                if rw.contains('R') {
                    reads.entry(addr.to_string()).or_insert((0, size)).0 += 1;
                }
                if rw.contains('W') {
                    writes.entry(addr.to_string()).or_insert((0, size)).0 += 1;
                }
            }
            if end == last {
                break;
            }
            seq = end + 1;
        }

        Ok((
            to_touches(reads),
            to_touches(writes),
            scanned_lines,
            io_truncated,
        ))
    }
}
