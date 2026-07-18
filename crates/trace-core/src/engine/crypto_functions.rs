use crate::error::{Result, TraceError};
use crate::query::crypto_functions::{
    aggregate_signals, crypto_insn_family, finalize_candidate, line_might_contain_crypto_insn,
    score_candidate, CryptoCallAnnotation, CryptoFunctionIo, CryptoFunctionReport,
    CryptoFunctionsOptions, CryptoInsnHit, CryptoMagicHit, CryptoRegValue,
};
use trace_parser::types::TraceFormat;
use trace_parser::{gumtrace as gumtrace_parser, parser};

/// 扫描一个 chunk 里的专用密码指令（助记符级）。
fn scan_insn_chunk(
    data: &[u8],
    start_seq: u32,
    end_seq: u32,
    start_offset: usize,
    trace_format: TraceFormat,
) -> Vec<CryptoInsnHit> {
    let mut hits = Vec::new();
    let mut pos = start_offset;
    let mut seq = start_seq;
    while pos < data.len() && seq < end_seq {
        let end = memchr::memchr(b'\n', &data[pos..])
            .map(|i| pos + i)
            .unwrap_or(data.len());
        let line = &data[pos..end];
        if line_might_contain_crypto_insn(line) {
            if let Ok(line_str) = std::str::from_utf8(line) {
                let parsed = match trace_format {
                    TraceFormat::Unidbg => parser::parse_line(line_str),
                    TraceFormat::Gumtrace => gumtrace_parser::parse_line_gumtrace(line_str),
                };
                if let Some(p) = parsed {
                    if let Some(family) = crypto_insn_family(p.mnemonic.as_str()) {
                        hits.push(CryptoInsnHit { seq, family });
                    }
                }
            }
        }
        pos = end + 1;
        seq += 1;
    }
    hits
}

fn truncate_report(mut report: CryptoFunctionReport, max_candidates: u32) -> CryptoFunctionReport {
    let max = max_candidates.clamp(1, 500) as usize;
    if report.candidates.len() > max {
        report.candidates.truncate(max);
        report.candidates_truncated = true;
    }
    report
}

impl super::TraceEngine {
    pub fn analyze_crypto_functions(
        &self,
        session_id: &str,
        options: CryptoFunctionsOptions,
    ) -> Result<CryptoFunctionReport> {
        // 内存缓存命中（忽略 max_candidates —— 缓存全量，按需截断）
        {
            let handle = self.get_handle(session_id)?;
            let state = handle
                .state
                .read()
                .map_err(|e| TraceError::Internal(e.to_string()))?;
            if let Some(cached) = &state.crypto_functions_cache {
                return Ok(truncate_report(cached.clone(), options.max_candidates));
            }
        }

        // 1. 复用 scan_crypto 拿 magic 命中（自带内存+磁盘缓存）
        let crypto = self.scan_crypto(session_id)?;
        let magic_hits: Vec<CryptoMagicHit> = crypto
            .matches
            .iter()
            .map(|m| CryptoMagicHit {
                seq: m.seq,
                algorithm: m.algorithm.clone(),
                magic_hex: m.magic_hex.clone(),
            })
            .collect();

        let handle = self.get_handle(session_id)?;

        // 2. 并行 chunk 扫描专用密码指令 + 快照 call_tree（照抄 scan_crypto 的分块）
        let (mmap_ref, total_lines, trace_format, chunks, call_tree, node_count) = {
            let state = handle
                .state
                .read()
                .map_err(|e| TraceError::Internal(e.to_string()))?;
            let call_tree = state.call_tree.clone().ok_or(TraceError::IndexNotReady)?;
            let node_count = call_tree.nodes.len() as u32;
            let total_lines = state
                .lidx_store
                .as_ref()
                .map(|s| s.total_lines())
                .unwrap_or(0);
            let num_cpus = std::thread::available_parallelism()
                .map(|n| n.get())
                .unwrap_or(4);
            let chunks: Option<Vec<(u32, u32, usize)>> = if num_cpus > 1 && total_lines > 10000 {
                state.line_index_view().map(|li| {
                    let data: &[u8] = &state.mmap;
                    let num_chunks = num_cpus.min(16);
                    let lines_per_chunk = (total_lines as usize + num_chunks - 1) / num_chunks;
                    let mut chunks = Vec::with_capacity(num_chunks);
                    for i in 0..num_chunks {
                        let s = (i * lines_per_chunk) as u32;
                        if s >= total_lines {
                            break;
                        }
                        let e = ((i + 1) * lines_per_chunk).min(total_lines as usize) as u32;
                        let off = li.line_byte_offset(data, s).unwrap_or(0) as usize;
                        chunks.push((s, e, off));
                    }
                    chunks
                })
            } else {
                None
            };
            (
                state.mmap.clone(),
                total_lines,
                state.trace_format,
                chunks,
                call_tree,
                node_count,
            )
        };

        let data: &[u8] = &mmap_ref;
        let insn_hits: Vec<CryptoInsnHit> = if let Some(chunks) = chunks {
            use rayon::prelude::*;
            let per: Vec<Vec<CryptoInsnHit>> = chunks
                .par_iter()
                .map(|&(s, e, off)| scan_insn_chunk(data, s, e, off, trace_format))
                .collect();
            per.into_iter().flatten().collect()
        } else {
            scan_insn_chunk(data, 0, total_lines, 0, trace_format)
        };

        // 3+4. 聚合 + 评分
        let raws = aggregate_signals(&magic_hits, &insn_hits, &call_tree);
        let functions_with_signals = raws.len() as u32;
        let mut scored: Vec<_> = raws
            .into_iter()
            .map(|r| {
                let a = score_candidate(&r);
                (r, a)
            })
            .collect();
        // 按分数降序，次序稳定：分数 → 密码指令数 → entry_seq 升序
        scored.sort_by(|a, b| {
            b.1.score
                .cmp(&a.1.score)
                .then(b.0.crypto_insn_total.cmp(&a.0.crypto_insn_total))
                .then(a.0.entry_seq.cmp(&b.0.entry_seq))
        });

        // 5. 全量候选（不截断）先存缓存；返回时再按 max_candidates 截断
        let mut candidates = Vec::with_capacity(scored.len());
        for (raw, assessment) in scored {
            let io = self.extract_function_io(session_id, raw.entry_seq, raw.exit_seq);
            candidates.push(finalize_candidate(raw, io, assessment));
        }

        let full = CryptoFunctionReport {
            candidates,
            total_functions_scanned: node_count,
            functions_with_signals,
            magic_hit_count: magic_hits.len() as u32,
            crypto_insn_count: insn_hits.len() as u32,
            candidates_truncated: false,
            limitations: vec![
                "Only executed instructions recorded in the trace are analyzed.".to_string(),
                "Magic-constant hits are substring matches over line text and can be coincidental; confidence weighs corroborating signals.".to_string(),
                "Dedicated crypto instructions are strong evidence but absent from software (table-based) implementations.".to_string(),
                "Entry X0-X7 and return X0 are read from register checkpoints at function entry/exit and may not all be live arguments.".to_string(),
            ],
        };

        // 6. 存内存缓存
        {
            let mut state = handle
                .state
                .write()
                .map_err(|e| TraceError::Internal(e.to_string()))?;
            state.crypto_functions_cache = Some(full.clone());
        }

        Ok(truncate_report(full, options.max_candidates))
    }

    /// 提取函数入口 X0-X7、返回 X0、调用注解。
    fn extract_function_io(
        &self,
        session_id: &str,
        entry_seq: u32,
        exit_seq: u32,
    ) -> CryptoFunctionIo {
        let mut entry_args = Vec::new();
        if let Ok(regs) = self.get_registers_at(session_id, entry_seq) {
            for i in 0..8u8 {
                let key = format!("X{i}");
                if let Some(v) = regs.get(&key) {
                    if v != "?" {
                        entry_args.push(CryptoRegValue {
                            reg: key,
                            value: v.clone(),
                        });
                    }
                }
            }
        }
        let return_value = self
            .get_registers_at(session_id, exit_seq)
            .ok()
            .and_then(|m| m.get("X0").filter(|v| *v != "?").cloned());

        // 调用注解挂在 bl/blr 行；entry_seq 可能是 bl 行或被调方首行，两处都试。
        let call_annotation = self.get_handle(session_id).ok().and_then(|h| {
            let state = h.state.read().ok()?;
            let ann = state
                .call_annotations
                .get(&entry_seq)
                .or_else(|| state.call_annotations.get(&entry_seq.saturating_sub(1)))?;
            Some(CryptoCallAnnotation {
                func_name: ann.func_name.clone(),
                is_jni: ann.is_jni,
                args: ann
                    .args
                    .iter()
                    .map(|(idx, val)| CryptoRegValue {
                        reg: idx.clone(),
                        value: val.clone(),
                    })
                    .collect(),
                ret_value: ann.ret_value.clone(),
            })
        });

        CryptoFunctionIo {
            entry_args,
            return_value,
            call_annotation,
        }
    }
}
