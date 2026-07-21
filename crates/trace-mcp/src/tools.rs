use std::sync::Arc;

use rmcp::{
    handler::server::{
        router::tool::ToolRouter,
        wrapper::{Json, Parameters},
    },
    model::{ServerCapabilities, ServerInfo},
    tool, tool_handler, tool_router, ServerHandler,
};

use crate::types::*;
use trace_core::{
    api_types::TraceLine, apply_resource_validation, classify_flow_endpoints,
    generate_frida_hook as build_frida_hook, generate_ida_ollvm_script, parse_hex_addr,
    parse_ida_annotation_bundle, score_evidence, summarize_dependency_graph, AnalysisEvidence,
    BuildOptions, CryptoFunctionsOptions, CryptoMaterialKind, CryptoMaterialMultiTraceRequest,
    CryptoMaterialOptions, CryptoMaterialTraceCase, DepTreeOptions, EvidenceScoreSignal,
    ForwardSliceOptions, FridaArgumentKind, FridaArgumentSpec, FridaCaptureDirection,
    FridaHookRequest, FridaStalkerMode, HashAlgorithm, HashMatchRequest, HashTransformOptions,
    OllvmAnalysisOptions, SearchOptions, SliceOptions, StringQueryOptions, TraceDiffOptions,
    TraceEngine, ValueEndian, ValueSearchKind, ValueSearchRequest, WhiteBoxMultiTraceRequest,
    WhiteBoxOptions, WhiteBoxTraceCaseRequest,
};

fn decode_hex_bytes(value: &str) -> Result<Vec<u8>, String> {
    let clean = value
        .trim()
        .trim_start_matches("0x")
        .replace([' ', ':', '-'], "");
    if clean.len() % 2 != 0 {
        return Err("hex value must contain complete bytes".into());
    }
    (0..clean.len())
        .step_by(2)
        .map(|i| {
            u8::from_str_radix(&clean[i..i + 2], 16)
                .map_err(|_| format!("invalid hex at byte {}", i / 2))
        })
        .collect()
}

// ── 截断常量 ──
// NOTE: 修改这些值时，需同步更新对应 #[tool] 描述中的硬编码数字。

// Referenced in: get_trace_lines description ("up to 100 lines per call")
const MAX_LINES: u32 = 100;
// Referenced in: search_instructions description ("up to 200 results")
const MAX_SEARCH: u32 = 200;
const DEFAULT_SEARCH: u32 = 30;
const TASK_CANCELLED: &str = "__analysis_task_cancelled__";

fn json(val: &impl serde::Serialize) -> String {
    serde_json::to_string(val)
        .unwrap_or_else(|e| format!("{{\"error\": \"serialization failed: {}\"}}", e))
}

/// Run a blocking closure on the tokio blocking thread pool to avoid starving
/// the async runtime. Used for heavy TraceEngine operations.
async fn blocking<F, T>(f: F) -> Result<T, String>
where
    F: FnOnce() -> Result<T, String> + Send + 'static,
    T: Send + 'static,
{
    tokio::task::spawn_blocking(f)
        .await
        .map_err(|e| format!("Task panicked: {}", e))?
}

/// Compact 模式下裁剪 TraceLine 为精简 JSON
fn compact_line(line: &TraceLine) -> serde_json::Value {
    let mut obj = serde_json::json!({
        "seq": line.seq,
        "address": line.address,
    });
    if !line.so_offset.is_empty() {
        obj["so_offset"] = serde_json::json!(line.so_offset);
    }
    obj["disasm"] = serde_json::json!(line.disasm);
    if !line.changes.is_empty() {
        obj["changes"] = serde_json::json!(line.changes);
    }
    if let Some(ref rw) = line.mem_rw {
        obj["mem_rw"] = serde_json::json!(rw);
    }
    if let Some(ref addr) = line.mem_addr {
        obj["mem_addr"] = serde_json::json!(addr);
    }
    if let Some(ref name) = line.so_name {
        obj["so_name"] = serde_json::json!(name);
    }
    if let Some(ref info) = line.call_info {
        if !info.func_name.is_empty() {
            obj["func_name"] = serde_json::json!(info.func_name);
        }
        obj["is_jni"] = serde_json::json!(info.is_jni);
        if !info.args.is_empty() {
            obj["call_args"] = serde_json::json!(info.args);
        }
        if let Some(ret_value) = info.ret_value.as_ref() {
            obj["return_value"] = serde_json::json!(ret_value);
        }
    }
    obj
}

fn format_lines(lines: &[TraceLine], full: bool) -> Vec<serde_json::Value> {
    if full {
        lines
            .iter()
            .map(|l| {
                serde_json::to_value(l)
                    .unwrap_or_else(|e| serde_json::json!({"error": e.to_string()}))
            })
            .collect()
    } else {
        lines.iter().map(|l| compact_line(l)).collect()
    }
}

/// 检查 changes 字段是否仅包含栈/帧指针寄存器变化
fn is_stack_only_change(changes: &str) -> bool {
    if changes.is_empty() {
        return false;
    }
    let mut has_any = false;
    for token in changes.split_whitespace() {
        if let Some(eq_pos) = token.find('=') {
            let reg = &token[..eq_pos];
            has_any = true;
            match reg {
                "sp" | "x29" | "fp" | "wsp" | "w29" => {}
                _ => return false,
            }
        }
    }
    has_any
}

/// Parse address range string like "0x246F00-0x249800"
fn parse_addr_range(range: &str) -> Result<(u64, u64), String> {
    let parts: Vec<&str> = range.split('-').collect();
    if parts.len() != 2 {
        return Err(format!(
            "Invalid addr_range format '{}'. Expected: '0x246F00-0x249800'",
            range
        ));
    }
    let start = parse_hex_addr(parts[0].trim())?;
    let end = parse_hex_addr(parts[1].trim())?;
    if start > end {
        return Err(format!(
            "Invalid addr_range: start (0x{:x}) > end (0x{:x})",
            start, end
        ));
    }
    Ok((start, end))
}

/// Parse seq range string like "3000-6000"
fn parse_seq_range(range: &str) -> Result<(u32, u32), String> {
    let parts: Vec<&str> = range.split('-').collect();
    if parts.len() != 2 {
        return Err(format!(
            "Invalid seq_range format '{}'. Expected: '3000-6000'",
            range
        ));
    }
    let start: u32 = parts[0]
        .trim()
        .parse()
        .map_err(|_| format!("Invalid start seq: '{}'", parts[0].trim()))?;
    let end: u32 = parts[1]
        .trim()
        .parse()
        .map_err(|_| format!("Invalid end seq: '{}'", parts[1].trim()))?;
    if start > end {
        return Err(format!(
            "Invalid seq_range: start ({}) > end ({})",
            start, end
        ));
    }
    Ok((start, end))
}

/// Check if TraceLine's SO offset falls within an address range
fn line_in_addr_range(line: &TraceLine, start: u64, end: u64) -> bool {
    parse_hex_addr(&line.so_offset)
        .map(|offset| offset >= start && offset <= end)
        .unwrap_or(false)
}

fn digest_algorithm(algorithm: KnownDigestAlgorithm) -> Option<HashAlgorithm> {
    match algorithm {
        KnownDigestAlgorithm::Auto => None,
        KnownDigestAlgorithm::Crc32 => Some(HashAlgorithm::Crc32),
        KnownDigestAlgorithm::Md5 => Some(HashAlgorithm::Md5),
        KnownDigestAlgorithm::Sha1 => Some(HashAlgorithm::Sha1),
        KnownDigestAlgorithm::Sha256 => Some(HashAlgorithm::Sha256),
        KnownDigestAlgorithm::Sha384 => Some(HashAlgorithm::Sha384),
        KnownDigestAlgorithm::Sha512 => Some(HashAlgorithm::Sha512),
    }
}

fn trace_memory_origin(
    engine: &TraceEngine,
    session_id: &str,
    addr: &str,
    byte_len: u32,
    seq: u32,
    data_only: bool,
    start_seq: Option<u32>,
    max_dependency_nodes: u32,
) -> Result<serde_json::Value, String> {
    let source_spec = format!("mem:{addr}:{byte_len}@{}", seq.saturating_add(1));
    let slice = engine
        .run_slice(
            session_id,
            std::slice::from_ref(&source_spec),
            SliceOptions {
                start_seq,
                end_seq: Some(seq),
                data_only,
            },
        )
        .map_err(|error| error.to_string())?;
    let graph = engine
        .build_dep_tree_from_slice(
            session_id,
            DepTreeOptions {
                data_only,
                max_nodes: Some(max_dependency_nodes.clamp(1, 5000)),
            },
        )
        .map_err(|error| error.to_string())?;
    let strings = engine
        .get_strings(
            session_id,
            StringQueryOptions {
                min_len: 4,
                offset: 0,
                limit: 5000,
                search: None,
            },
        )
        .map(|result| result.strings)
        .unwrap_or_default();
    let summary = summarize_dependency_graph(&graph, &strings, Some(200));
    Ok(serde_json::json!({
        "source_spec": source_spec,
        "marked_count": slice.marked_count,
        "total_lines": slice.total_lines,
        "percentage": slice.percentage,
        "warnings": slice.warnings,
        "summary": summary,
    }))
}

fn push_unique(target: &mut Vec<String>, value: impl Into<String>) {
    let value = value.into();
    if !value.is_empty() && !target.contains(&value) {
        target.push(value);
    }
}

fn collect_known_digest_evidence(result: &serde_json::Value) -> AnalysisEvidence {
    let mut evidence = AnalysisEvidence::default();
    for section in ["string_matches", "memory_matches"] {
        let Some(section) = result.get(section) else {
            continue;
        };
        if let Some(queries) = section.get("queries").and_then(|value| value.as_array()) {
            for query in queries {
                if let Some(algorithm) = query.get("algorithm").and_then(|value| value.as_str()) {
                    push_unique(&mut evidence.algorithms, algorithm);
                }
                if let Some(digest) = query
                    .get("normalizedDigest")
                    .and_then(|value| value.as_str())
                {
                    push_unique(&mut evidence.digests, digest);
                }
                if let Some(warning) = query.get("error").and_then(|value| value.as_str()) {
                    push_unique(&mut evidence.warnings, warning);
                }
            }
        }
        if let Some(matches) = section.get("matches").and_then(|value| value.as_array()) {
            for matched in matches {
                if let Some(address) = matched.get("addr").and_then(|value| value.as_str()) {
                    push_unique(&mut evidence.addresses, address);
                }
                if let Some(content) = matched.get("content").and_then(|value| value.as_str()) {
                    push_unique(&mut evidence.key_strings, content);
                }
            }
        }
    }

    if let Some(traced) = result
        .get("traced_matches")
        .and_then(|value| value.as_array())
    {
        for matched in traced {
            let Some(analysis) = matched.get("analysis").filter(|value| !value.is_null()) else {
                if let Some(error) = matched
                    .get("analysis_error")
                    .and_then(|value| value.as_str())
                {
                    push_unique(&mut evidence.warnings, error);
                }
                continue;
            };
            if let Some(warnings) = analysis.get("warnings").and_then(|value| value.as_array()) {
                for warning in warnings {
                    if let Some(message) = warning.get("message").and_then(|value| value.as_str()) {
                        push_unique(&mut evidence.warnings, message);
                    }
                }
            }
            let Some(summary) = analysis.get("summary") else {
                continue;
            };
            for (field, target) in [
                ("functions", &mut evidence.functions),
                ("modules", &mut evidence.modules),
                ("memoryReads", &mut evidence.memory_reads),
                ("memoryWrites", &mut evidence.memory_writes),
            ] {
                if let Some(values) = summary.get(field).and_then(|value| value.as_array()) {
                    for value in values.iter().filter_map(|value| value.as_str()) {
                        push_unique(target, value);
                    }
                }
            }
            if let Some(strings) = summary.get("keyStrings").and_then(|value| value.as_array()) {
                for string in strings {
                    if let Some(content) = string.get("content").and_then(|value| value.as_str()) {
                        push_unique(&mut evidence.key_strings, content);
                    }
                }
            }
            if let Some(operations) = summary.get("operations").and_then(|value| value.as_array()) {
                for operation in operations {
                    if let Some(name) = operation.get("operation").and_then(|value| value.as_str())
                    {
                        push_unique(&mut evidence.operations, name);
                    }
                }
            }
        }
    }
    evidence
}

fn collect_taint_evidence(result: &serde_json::Value) -> AnalysisEvidence {
    let mut evidence = AnalysisEvidence::default();
    if let Some(lines) = result.get("lines").and_then(|value| value.as_array()) {
        for line in lines {
            if let Some(module) = line.get("so_name").and_then(|value| value.as_str()) {
                push_unique(&mut evidence.modules, module);
            }
            if let Some(function) = line.get("func_name").and_then(|value| value.as_str()) {
                push_unique(&mut evidence.functions, function);
            }
            if let Some(address) = line.get("address").and_then(|value| value.as_str()) {
                push_unique(&mut evidence.addresses, address);
            }
            if let Some(memory_address) = line.get("mem_addr").and_then(|value| value.as_str()) {
                let rw = line
                    .get("mem_rw")
                    .and_then(|value| value.as_str())
                    .unwrap_or("");
                if rw.contains('R') {
                    push_unique(&mut evidence.memory_reads, memory_address);
                }
                if rw.contains('W') {
                    push_unique(&mut evidence.memory_writes, memory_address);
                }
            }
            if let Some(disasm) = line.get("disasm").and_then(|value| value.as_str()) {
                let operation = disasm
                    .split_whitespace()
                    .next()
                    .unwrap_or("unknown")
                    .trim_matches(|character: char| !character.is_ascii_alphanumeric())
                    .to_ascii_lowercase();
                push_unique(&mut evidence.operations, operation);
            }
        }
    }
    if let Some(warnings) = result.get("warnings").and_then(|value| value.as_array()) {
        for warning in warnings {
            if let Some(message) = warning.get("message").and_then(|value| value.as_str()) {
                push_unique(&mut evidence.warnings, message);
            }
        }
    }
    evidence
}

fn save_backward_taint_result(
    engine: &TraceEngine,
    session_id: &str,
    request: serde_json::Value,
    mut result: serde_json::Value,
    tainted_seqs: &[u32],
) -> Result<serde_json::Value, String> {
    let evidence = collect_taint_evidence(&result);
    let mut stored_result = result.clone();
    stored_result["tainted_seqs"] = serde_json::json!(tainted_seqs);
    let record = engine
        .save_analysis(
            session_id,
            "backward_taint",
            "Backward taint analysis",
            request,
            stored_result,
            evidence,
        )
        .map_err(|error| error.to_string())?;
    result["analysis_id"] = serde_json::json!(record.analysis_id);
    result["saved"] = serde_json::json!(true);
    result["compare_with"] = serde_json::json!("compare_analyses");
    Ok(result)
}

fn run_known_digest_analysis(
    engine: &TraceEngine,
    session_id: &str,
    req: AnalyzeKnownDigestRequest,
) -> Result<(serde_json::Value, AnalysisEvidence, serde_json::Value), String> {
    if !req.search_strings && !req.search_memory {
        return Err("Enable search_strings, search_memory, or both.".to_string());
    }
    if req.digests.is_empty() {
        return Err("Provide at least one known digest.".to_string());
    }

    let request_record = serde_json::json!({
        "digests": req.digests.clone(),
        "algorithm": format!("{:?}", req.algorithm).to_ascii_lowercase(),
        "search_strings": req.search_strings,
        "search_memory": req.search_memory,
        "utf8_nul": req.utf8_nul,
        "utf16le": req.utf16le,
        "utf16le_nul": req.utf16le_nul,
        "trace_matches": req.trace_matches,
        "max_trace_matches": req.max_trace_matches,
        "data_only": req.data_only,
    });
    let request = HashMatchRequest {
        digests: req.digests,
        algorithm: digest_algorithm(req.algorithm),
        transforms: HashTransformOptions {
            utf8_nul: req.utf8_nul,
            utf16le: req.utf16le,
            utf16le_nul: req.utf16le_nul,
        },
        max_results: Some(req.max_results.clamp(1, 500)),
    };

    let string_matches = if req.search_strings {
        match engine.match_known_digests(session_id, &request) {
            Ok(result) => Some(result),
            Err(_) if req.auto_scan_strings => {
                engine
                    .scan_strings(session_id)
                    .map_err(|error| error.to_string())?;
                Some(
                    engine
                        .match_known_digests(session_id, &request)
                        .map_err(|error| error.to_string())?,
                )
            }
            Err(error) => return Err(error.to_string()),
        }
    } else {
        None
    };
    let memory_matches = if req.search_memory {
        Some(
            engine
                .find_digest_memory(session_id, &request)
                .map_err(|error| error.to_string())?,
        )
    } else {
        None
    };

    let mut traced_matches = Vec::new();
    let trace_limit = req.max_trace_matches.clamp(1, 10) as usize;
    if req.trace_matches {
        if let Some(response) = &memory_matches {
            for matched in response.matches.iter().take(trace_limit) {
                let analysis = trace_memory_origin(
                    engine,
                    session_id,
                    &matched.addr,
                    matched.byte_len,
                    matched.last_write_seq,
                    req.data_only,
                    req.start_seq,
                    req.max_dependency_nodes,
                );
                traced_matches.push(serde_json::json!({
                    "kind": "digest_output",
                    "query_index": matched.query_index,
                    "digest": matched.normalized_digest,
                    "algorithm": matched.algorithm,
                    "addr": matched.addr,
                    "byte_len": matched.byte_len,
                    "seq": matched.last_write_seq,
                    "write_seqs": matched.write_seqs,
                    "analysis": analysis.as_ref().ok(),
                    "analysis_error": analysis.err(),
                }));
            }
        }
        let remaining = trace_limit.saturating_sub(traced_matches.len());
        if remaining > 0 {
            if let Some(response) = &string_matches {
                for matched in response.matches.iter().take(remaining) {
                    let analysis = trace_memory_origin(
                        engine,
                        session_id,
                        &matched.addr,
                        matched.byte_len,
                        matched.seq,
                        req.data_only,
                        req.start_seq,
                        req.max_dependency_nodes,
                    );
                    traced_matches.push(serde_json::json!({
                        "kind": "candidate_string",
                        "query_index": matched.query_index,
                        "digest": matched.normalized_digest,
                        "algorithm": matched.algorithm,
                        "content": matched.content,
                        "transform": matched.transform,
                        "addr": matched.addr,
                        "byte_len": matched.byte_len,
                        "seq": matched.seq,
                        "analysis": analysis.as_ref().ok(),
                        "analysis_error": analysis.err(),
                    }));
                }
            }
        }
    }

    let mut result = serde_json::json!({
        "session_id": session_id,
        "string_matches": string_matches,
        "memory_matches": memory_matches,
        "traced_matches": traced_matches,
        "limitations": [
            "Only candidates and memory buffers observed in the trace are verified.",
            "A digest match alone does not prove which function produced it unless the dependency evidence supports that conclusion.",
            "The session's active taint view still reflects the last automatically traced match."
        ],
        "hint": if req.trace_matches {
            "Review traced_matches.summary and key_steps, then use get_trace_lines or get_memory for exact evidence."
        } else {
            "Run taint_analysis with mem:ADDRESS:SIZE@(SEQ+1), or repeat with trace_matches=true."
        },
    });
    let candidate_assessments = score_known_digest_candidates(&result);
    let verified_count = candidate_assessments
        .iter()
        .filter(|item| item["assessment"]["grade"] == "verified")
        .count();
    let related_count = candidate_assessments
        .iter()
        .filter(|item| item["assessment"]["grade"] == "related")
        .count();
    let uncertain_count = candidate_assessments.len() - verified_count - related_count;
    result["candidate_assessments"] = serde_json::Value::Array(candidate_assessments);
    result["assessment_summary"] = serde_json::json!({
        "verified": verified_count,
        "related": related_count,
        "uncertain": uncertain_count,
        "scope_note": "Candidate verification and producer attribution are scored separately."
    });
    let evidence = collect_known_digest_evidence(&result);
    Ok((result, evidence, request_record))
}

fn score_known_digest_candidates(result: &serde_json::Value) -> Vec<serde_json::Value> {
    let traced = result
        .get("traced_matches")
        .and_then(serde_json::Value::as_array)
        .cloned()
        .unwrap_or_default();
    let mut assessments = Vec::new();

    if let Some(matches) = result
        .get("string_matches")
        .and_then(|value| value.get("matches"))
        .and_then(serde_json::Value::as_array)
    {
        for matched in matches {
            let query_index = matched
                .get("queryIndex")
                .and_then(serde_json::Value::as_u64)
                .unwrap_or_default();
            let addr = matched
                .get("addr")
                .and_then(serde_json::Value::as_str)
                .unwrap_or_default();
            let seq = matched
                .get("seq")
                .and_then(serde_json::Value::as_u64)
                .unwrap_or_default();
            let trace = traced.iter().find(|item| {
                item.get("kind").and_then(serde_json::Value::as_str) == Some("candidate_string")
                    && item.get("query_index").and_then(serde_json::Value::as_u64)
                        == Some(query_index)
                    && item.get("addr").and_then(serde_json::Value::as_str) == Some(addr)
                    && item.get("seq").and_then(serde_json::Value::as_u64) == Some(seq)
            });
            let origin_available = trace
                .and_then(|item| item.get("analysis"))
                .is_some_and(|value| !value.is_null());
            let origin_truncated = trace
                .and_then(|item| item.get("analysis"))
                .and_then(|analysis| analysis.get("summary"))
                .and_then(|summary| summary.get("truncated"))
                .and_then(serde_json::Value::as_bool)
                .unwrap_or(false);
            let function_context = trace
                .and_then(|item| item.get("analysis"))
                .and_then(|analysis| analysis.get("summary"))
                .and_then(|summary| summary.get("functions"))
                .and_then(serde_json::Value::as_array)
                .is_some_and(|values| !values.is_empty());
            let xrefs = matched
                .get("xrefCount")
                .and_then(serde_json::Value::as_u64)
                .unwrap_or_default();
            let assessment = score_evidence(
                "candidate_bytes",
                true,
                vec![
                    EvidenceScoreSignal::new(
                        "exact_digest_recomputation",
                        "The candidate bytes recompute to the requested digest.",
                        60,
                        true,
                        matched
                            .get("normalizedDigest")
                            .and_then(serde_json::Value::as_str)
                            .map(str::to_string),
                    ),
                    EvidenceScoreSignal::new(
                        "runtime_observation",
                        "The candidate was observed in runtime memory.",
                        10,
                        true,
                        Some(format!("{addr} at seq {seq}")),
                    ),
                    EvidenceScoreSignal::new(
                        "explicit_transform",
                        "The exact encoding transform is recorded.",
                        10,
                        matched.get("transform").is_some(),
                        matched.get("transform").map(serde_json::Value::to_string),
                    ),
                    EvidenceScoreSignal::new(
                        "runtime_xref",
                        "The runtime string has instruction cross-references.",
                        5,
                        xrefs > 0,
                        Some(format!("xref_count={xrefs}")),
                    ),
                    EvidenceScoreSignal::new(
                        "origin_trace",
                        "A backward origin trace was produced for the candidate.",
                        10,
                        origin_available,
                        origin_available.then(|| format!("candidate origin traced from {addr} at seq {seq}")),
                    ),
                    EvidenceScoreSignal::new(
                        "function_context",
                        "The origin trace contains function-level context.",
                        5,
                        function_context,
                        None,
                    ),
                    EvidenceScoreSignal::new(
                        "truncated_origin",
                        "The origin trace was truncated.",
                        -10,
                        origin_truncated,
                        None,
                    ),
                ],
                vec![
                    "Verified means these candidate bytes produce the digest; it does not by itself prove that the traced program used them for this output."
                        .to_string(),
                ],
            );
            assessments.push(serde_json::json!({
                "kind": "candidate_string",
                "query_index": query_index,
                "digest": matched.get("normalizedDigest"),
                "addr": addr,
                "seq": seq,
                "content": matched.get("content"),
                "transform": matched.get("transform"),
                "assessment": assessment,
            }));
        }
    }

    if let Some(matches) = result
        .get("memory_matches")
        .and_then(|value| value.get("matches"))
        .and_then(serde_json::Value::as_array)
    {
        for matched in matches {
            let query_index = matched
                .get("queryIndex")
                .and_then(serde_json::Value::as_u64)
                .unwrap_or_default();
            let addr = matched
                .get("addr")
                .and_then(serde_json::Value::as_str)
                .unwrap_or_default();
            let seq = matched
                .get("lastWriteSeq")
                .and_then(serde_json::Value::as_u64)
                .unwrap_or_default();
            let trace = traced.iter().find(|item| {
                item.get("kind").and_then(serde_json::Value::as_str) == Some("digest_output")
                    && item.get("query_index").and_then(serde_json::Value::as_u64)
                        == Some(query_index)
                    && item.get("addr").and_then(serde_json::Value::as_str) == Some(addr)
                    && item.get("seq").and_then(serde_json::Value::as_u64) == Some(seq)
            });
            let origin_available = trace
                .and_then(|item| item.get("analysis"))
                .is_some_and(|value| !value.is_null());
            let write_count = matched
                .get("writeSeqs")
                .and_then(serde_json::Value::as_array)
                .map_or(0, Vec::len);
            let assessment = score_evidence(
                "digest_output_buffer",
                true,
                vec![
                    EvidenceScoreSignal::new(
                        "exact_digest_bytes",
                        "The reconstructed memory bytes exactly equal the requested digest.",
                        65,
                        true,
                        matched
                            .get("normalizedDigest")
                            .and_then(serde_json::Value::as_str)
                            .map(str::to_string),
                    ),
                    EvidenceScoreSignal::new(
                        "runtime_writes",
                        "The digest buffer was reconstructed from observed memory writes.",
                        20,
                        write_count > 0,
                        Some(format!("write_count={write_count}")),
                    ),
                    EvidenceScoreSignal::new(
                        "complete_buffer_width",
                        "The full digest-width buffer was reconstructed.",
                        10,
                        matched
                            .get("byteLen")
                            .and_then(serde_json::Value::as_u64)
                            .unwrap_or_default()
                            > 0,
                        matched.get("byteLen").map(serde_json::Value::to_string),
                    ),
                    EvidenceScoreSignal::new(
                        "origin_trace",
                        "A backward trace was produced from the digest output buffer.",
                        5,
                        origin_available,
                        origin_available.then(|| format!("digest output traced from {addr} at seq {seq}")),
                    ),
                ],
                vec![
                    "Verified means the output buffer contains the digest bytes; the original input still requires dependency evidence."
                        .to_string(),
                ],
            );
            assessments.push(serde_json::json!({
                "kind": "digest_output",
                "query_index": query_index,
                "digest": matched.get("normalizedDigest"),
                "addr": addr,
                "seq": seq,
                "assessment": assessment,
            }));
        }
    }
    assessments
}

fn run_crypto_detection(
    engine: &TraceEngine,
    session_id: &str,
    context_lines: u32,
    max_matches: u32,
) -> Result<serde_json::Value, String> {
    let context_lines = context_lines.min(10);
    let scan_result = if let Ok(Some(cached)) = engine.load_crypto_cache(session_id) {
        cached
    } else {
        engine
            .scan_crypto(session_id)
            .map_err(|error| error.to_string())?
    };
    let mut matches = Vec::new();
    for matched in scan_result
        .matches
        .iter()
        .take(max_matches.clamp(1, 200) as usize)
    {
        let start = matched.seq.saturating_sub(context_lines);
        let end = matched.seq.saturating_add(context_lines);
        let seqs: Vec<u32> = (start..=end).collect();
        let context: Vec<_> = engine
            .get_lines(session_id, &seqs)
            .unwrap_or_default()
            .iter()
            .map(|line| {
                let mut value = compact_line(line);
                value["is_match"] = serde_json::json!(line.seq == matched.seq);
                value
            })
            .collect();
        matches.push(serde_json::json!({
            "algorithm": matched.algorithm,
            "magic_hex": matched.magic_hex,
            "seq": matched.seq,
            "address": matched.address,
            "disasm": matched.disasm,
            "context": context,
        }));
    }
    Ok(serde_json::json!({
        "algorithms_found": scan_result.algorithms_found,
        "match_count": scan_result.matches.len(),
        "matches": matches,
        "matches_truncated": scan_result.matches.len() > max_matches.clamp(1, 200) as usize,
        "total_lines_scanned": scan_result.total_lines_scanned,
    }))
}

fn collect_crypto_evidence(result: &serde_json::Value) -> AnalysisEvidence {
    let mut evidence = AnalysisEvidence::default();
    if let Some(algorithms) = result
        .get("algorithms_found")
        .and_then(|value| value.as_array())
    {
        for algorithm in algorithms.iter().filter_map(|value| value.as_str()) {
            push_unique(&mut evidence.algorithms, algorithm);
        }
    }
    if let Some(matches) = result.get("matches").and_then(|value| value.as_array()) {
        for matched in matches {
            if let Some(address) = matched.get("address").and_then(|value| value.as_str()) {
                push_unique(&mut evidence.addresses, address);
            }
            if let Some(context) = matched.get("context").and_then(|value| value.as_array()) {
                for line in context {
                    if let Some(function) = line.get("func_name").and_then(|value| value.as_str()) {
                        push_unique(&mut evidence.functions, function);
                    }
                    if let Some(module) = line.get("so_name").and_then(|value| value.as_str()) {
                        push_unique(&mut evidence.modules, module);
                    }
                }
            }
        }
    }
    evidence
}

fn merge_evidence(mut left: AnalysisEvidence, right: AnalysisEvidence) -> AnalysisEvidence {
    fn append(target: &mut Vec<String>, values: Vec<String>) {
        for value in values {
            push_unique(target, value);
        }
    }
    append(&mut left.algorithms, right.algorithms);
    append(&mut left.digests, right.digests);
    append(&mut left.functions, right.functions);
    append(&mut left.modules, right.modules);
    append(&mut left.key_strings, right.key_strings);
    append(&mut left.memory_reads, right.memory_reads);
    append(&mut left.memory_writes, right.memory_writes);
    append(&mut left.addresses, right.addresses);
    append(&mut left.operations, right.operations);
    append(&mut left.warnings, right.warnings);
    left
}

fn run_crypto_flow_analysis(
    engine: &TraceEngine,
    session_id: &str,
    req: InvestigateCryptoFlowRequest,
    checkpoint: &mut dyn FnMut(&str, u8) -> Result<(), String>,
) -> Result<(serde_json::Value, AnalysisEvidence, serde_json::Value), String> {
    let request_record = serde_json::json!({
        "digests": req.digests.clone(),
        "algorithm": format!("{:?}", req.algorithm).to_ascii_lowercase(),
        "context_lines": req.context_lines,
        "max_crypto_matches": req.max_crypto_matches,
        "trace_matches": req.trace_matches,
        "max_trace_matches": req.max_trace_matches,
        "data_only": req.data_only,
    });
    checkpoint("crypto_detection", 10)?;
    let crypto = run_crypto_detection(
        engine,
        session_id,
        req.context_lines,
        req.max_crypto_matches,
    )?;
    let mut evidence = collect_crypto_evidence(&crypto);
    checkpoint("digest_correlation", 45)?;
    let digest_analysis = if req.digests.is_empty() {
        None
    } else {
        let digest_request = AnalyzeKnownDigestRequest {
            session_id: None,
            digests: req.digests,
            algorithm: req.algorithm,
            search_strings: true,
            search_memory: true,
            auto_scan_strings: true,
            utf8_nul: req.utf8_nul,
            utf16le: req.utf16le,
            utf16le_nul: req.utf16le_nul,
            max_results: 100,
            trace_matches: req.trace_matches,
            max_trace_matches: req.max_trace_matches,
            data_only: req.data_only,
            start_seq: None,
            max_dependency_nodes: 1000,
        };
        let (result, digest_evidence, _) =
            run_known_digest_analysis(engine, session_id, digest_request)?;
        evidence = merge_evidence(evidence, digest_evidence);
        Some(result)
    };
    checkpoint("evidence_synthesis", 85)?;

    let conclusion = if !evidence.digests.is_empty()
        && !evidence.algorithms.is_empty()
        && (!evidence.functions.is_empty() || !evidence.memory_writes.is_empty())
    {
        "Crypto signatures and known digest evidence were both observed. Review the traced dependency summaries before treating the producing function as confirmed."
    } else if !evidence.digests.is_empty() {
        "Known digest evidence was observed, but the trace does not yet provide enough function-level crypto evidence for attribution."
    } else if !evidence.algorithms.is_empty() {
        "Crypto signatures were detected. Provide known digests or trace relevant input/output buffers to strengthen attribution."
    } else {
        "No supported crypto signature or known digest evidence was found in the current trace."
    };
    let result = serde_json::json!({
        "session_id": session_id,
        "conclusion": conclusion,
        "confidence": if !evidence.digests.is_empty() && !evidence.functions.is_empty() {
            "medium"
        } else if !evidence.algorithms.is_empty() || !evidence.digests.is_empty() {
            "low"
        } else {
            "none"
        },
        "crypto_detection": crypto,
        "digest_analysis": digest_analysis,
        "evidence": evidence.clone(),
        "limitations": [
            "Magic constants and instruction signatures indicate possible algorithms, not definitive function identity.",
            "Digest candidates are verified only against bytes observed in the trace.",
            "Salted, chunked, transformed, or incomplete inputs may require additional targeted analysis."
        ],
        "next_actions": [
            "Compare this analysis with another candidate using compare_analyses.",
            "Use get_trace_lines around matching sequences for exact instruction evidence.",
            "Use get_memory on reported input/output addresses at the relevant sequence."
        ],
    });
    checkpoint("ready_to_save", 95)?;
    Ok((result, evidence, request_record))
}

fn operation_name(line: &TraceLine) -> String {
    line.disasm
        .split_whitespace()
        .next()
        .unwrap_or("unknown")
        .trim_matches(|character: char| !character.is_ascii_alphanumeric())
        .to_ascii_lowercase()
}

fn explicit_source_summary(spec: &str) -> serde_json::Value {
    let (kind, category) = if spec.starts_with("reg:") {
        ("register_input", "register")
    } else if spec.starts_with("mem:") {
        ("memory_input", "memory")
    } else {
        ("explicit_input", "unknown")
    };
    serde_json::json!({
        "spec": spec,
        "direction": "source",
        "kind": kind,
        "category": category,
        "confidence": "high",
        "external": false,
        "reason": "The caller explicitly selected this value as the forward-analysis input."
    })
}

fn run_forward_taint_analysis(
    engine: &TraceEngine,
    session_id: &str,
    req: ForwardTaintAnalysisRequest,
    checkpoint: &mut dyn FnMut(&str, u8) -> Result<(), String>,
) -> Result<(serde_json::Value, AnalysisEvidence, serde_json::Value), String> {
    let request_record = serde_json::json!({
        "from_specs": req.from_specs.clone(),
        "data_only": req.data_only,
        "start_seq": req.start_seq,
        "end_seq": req.end_seq,
        "max_nodes": req.max_nodes.clamp(1, 100_000),
        "include_lines": req.include_lines.min(500),
        "max_sinks": req.max_sinks.clamp(1, 500),
    });
    checkpoint("resolving_sources", 5)?;
    let mut cancellation_error = None;
    let forward_result = engine.run_forward_slice_cancellable(
        session_id,
        &req.from_specs,
        ForwardSliceOptions {
            start_seq: req.start_seq,
            end_seq: req.end_seq,
            data_only: req.data_only,
            max_nodes: req.max_nodes.clamp(1, 100_000),
        },
        |processed, total| {
            let fraction = if total == 0 {
                0
            } else {
                ((processed as u64 * 60) / total as u64).min(60) as u8
            };
            match checkpoint("building_forward_graph", 10 + fraction) {
                Ok(()) => true,
                Err(error) => {
                    cancellation_error = Some(error);
                    false
                }
            }
        },
    );
    if let Some(error) = cancellation_error {
        return Err(error);
    }
    let forward = forward_result.map_err(|error| error.to_string())?;

    checkpoint("classifying_outputs", 75)?;
    let terminal: std::collections::HashSet<u32> = forward.terminal_seqs.iter().copied().collect();
    let include_limit = req.include_lines.min(500) as usize;
    let sink_limit = req.max_sinks.clamp(1, 500) as usize;
    let mut inline_lines = Vec::new();
    let mut potential_sinks = Vec::new();
    let mut potential_sources = Vec::new();
    let mut flow_endpoints = Vec::new();
    let mut endpoint_kind_counts = std::collections::BTreeMap::<String, u32>::new();
    let mut endpoint_category_counts = std::collections::BTreeMap::<String, u32>::new();
    let mut source_endpoint_count = 0u32;
    let mut sink_endpoint_count = 0u32;
    let mut external_endpoint_count = 0u32;
    let mut high_confidence_endpoint_count = 0u32;
    let mut evidence = AnalysisEvidence::default();
    let mut affected_memory_ranges = Vec::<(u64, u64)>::new();

    for chunk in forward.affected_seqs.chunks(2048) {
        let lines = engine
            .get_lines(session_id, chunk)
            .map_err(|error| error.to_string())?;
        let resource_contexts = engine
            .get_call_resource_contexts(session_id, chunk)
            .unwrap_or_default();
        for line in lines {
            let operation = operation_name(&line);
            push_unique(&mut evidence.operations, operation.clone());
            if let Some(module) = line.so_name.as_deref() {
                push_unique(&mut evidence.modules, module);
            }
            if let Some(call) = line.call_info.as_ref() {
                push_unique(&mut evidence.functions, &call.func_name);
            }
            if let Some(address) = line.mem_addr.as_deref() {
                push_unique(&mut evidence.addresses, address);
                if line.mem_rw.as_deref().is_some_and(|rw| rw.contains('R')) {
                    push_unique(&mut evidence.memory_reads, address);
                }
                if line.mem_rw.as_deref().is_some_and(|rw| rw.contains('W')) {
                    push_unique(&mut evidence.memory_writes, address);
                    if let Ok(start) = parse_hex_addr(address) {
                        let size = line.mem_size.unwrap_or(1) as u64;
                        affected_memory_ranges.push((start, start.saturating_add(size)));
                    }
                }
            }
            if inline_lines.len() < include_limit {
                inline_lines.push(compact_line(&line));
            }
            let resource_context = resource_contexts.get(&line.seq);
            let classifications = classify_flow_endpoints(&line, terminal.contains(&line.seq));
            for mut classification in classifications {
                if let Some(context) = resource_context {
                    apply_resource_validation(&mut classification, context);
                }
                *endpoint_kind_counts
                    .entry(classification.kind.clone())
                    .or_default() += 1;
                *endpoint_category_counts
                    .entry(classification.category.clone())
                    .or_default() += 1;
                if classification.direction == "source" {
                    source_endpoint_count = source_endpoint_count.saturating_add(1);
                } else {
                    sink_endpoint_count = sink_endpoint_count.saturating_add(1);
                }
                if classification.external {
                    external_endpoint_count = external_endpoint_count.saturating_add(1);
                }
                if classification.confidence == "high" {
                    high_confidence_endpoint_count =
                        high_confidence_endpoint_count.saturating_add(1);
                }

                let mut endpoint = serde_json::to_value(&classification)
                    .unwrap_or_else(|error| serde_json::json!({"error": error.to_string()}));
                endpoint["line"] = compact_line(&line);
                if let Some(context) = resource_context {
                    endpoint["call_context"] = serde_json::to_value(context)
                        .unwrap_or_else(|error| serde_json::json!({"error": error.to_string()}));
                }
                if flow_endpoints.len() < sink_limit.saturating_mul(2) {
                    flow_endpoints.push(endpoint.clone());
                }
                if classification.direction == "source" {
                    if potential_sources.len() < sink_limit {
                        potential_sources.push(endpoint);
                    }
                } else if potential_sinks.len() < sink_limit {
                    potential_sinks.push(endpoint);
                }
            }
        }
    }

    if let Ok(strings) = engine.get_strings(
        session_id,
        StringQueryOptions {
            min_len: 4,
            offset: 0,
            limit: 5000,
            search: None,
        },
    ) {
        for string in strings.strings {
            let Ok(start) = parse_hex_addr(&string.addr) else {
                continue;
            };
            let end = start.saturating_add(string.byte_len as u64);
            if affected_memory_ranges
                .iter()
                .any(|(write_start, write_end)| *write_start < end && start < *write_end)
            {
                push_unique(&mut evidence.key_strings, string.content);
            }
        }
    }
    for warning in &forward.warnings {
        push_unique(&mut evidence.warnings, &warning.message);
    }
    if forward.truncated {
        push_unique(
            &mut evidence.warnings,
            format!(
                "Forward traversal reached the max_nodes limit ({}).",
                req.max_nodes.clamp(1, 100_000)
            ),
        );
    }
    push_unique(
        &mut evidence.warnings,
        "Forward dependencies use conservative instruction-level precision for pair instructions.",
    );
    evidence.functions.truncate(100);
    evidence.modules.truncate(100);
    evidence.key_strings.truncate(100);
    evidence.memory_reads.truncate(500);
    evidence.memory_writes.truncate(500);
    evidence.addresses.truncate(500);
    evidence.operations.truncate(100);
    evidence.warnings.truncate(100);
    let input_sources = forward
        .source_specs
        .iter()
        .map(|spec| explicit_source_summary(spec))
        .collect::<Vec<_>>();

    checkpoint("evidence_synthesis", 90)?;
    let result = serde_json::json!({
        "session_id": session_id,
        "direction": "forward",
        "source_specs": forward.source_specs,
        "source_seqs": forward.source_seqs,
        "affected_count": forward.affected_count,
        "total_lines": forward.total_lines,
        "traversed_edges": forward.traversed_edges,
        "forward_index_edges": forward.forward_index_edges,
        "forward_index_reused": forward.forward_index_reused,
        "truncated": forward.truncated,
        "warnings": forward.warnings,
        "affected_seq_preview": forward.affected_seqs.iter().take(500).copied().collect::<Vec<_>>(),
        "affected_seq_preview_truncated": forward.affected_seqs.len() > 500,
        "terminal_seqs": forward.terminal_seqs.iter().take(sink_limit).copied().collect::<Vec<_>>(),
        "lines": inline_lines,
        "lines_truncated": forward.affected_count as usize > include_limit,
        "input_sources": input_sources,
        "potential_sources": potential_sources,
        "potential_sinks": potential_sinks,
        "flow_endpoints": flow_endpoints,
        "flow_endpoints_truncated": (source_endpoint_count + sink_endpoint_count) as usize > sink_limit.saturating_mul(2),
        "endpoint_summary": {
            "source_count": source_endpoint_count,
            "sink_count": sink_endpoint_count,
            "external_count": external_endpoint_count,
            "high_confidence_count": high_confidence_endpoint_count,
            "kind_counts": endpoint_kind_counts,
            "category_counts": endpoint_category_counts,
        },
        "evidence": evidence.clone(),
        "limitations": [
            "This is dynamic forward data flow over instructions observed in the trace; unexecuted paths are not represented.",
            "Pair instructions are conservatively tracked at instruction precision and may include extra consumers.",
            "Endpoint classifications are deterministic candidates; file descriptors, socket lifetimes, syscall numbers, and call arguments are not yet cross-validated."
        ],
        "next_actions": [
            "Use get_trace_lines on potential sink sequences to inspect exact register and memory evidence.",
            "Run taint_analysis backward from a potential sink, then compare both analysis_id values with compare_analyses.",
            "Use get_memory at reported write addresses and sequences to inspect affected output bytes."
        ]
    });
    checkpoint("ready_to_save", 96)?;
    Ok((result, evidence, request_record))
}

fn collect_trace_diff_evidence(diff: &serde_json::Value) -> AnalysisEvidence {
    let mut evidence = AnalysisEvidence::default();
    for side in ["left", "right"] {
        if let Some(modules) = diff
            .get(side)
            .and_then(|value| value.get("modules"))
            .and_then(serde_json::Value::as_array)
        {
            for module in modules.iter().filter_map(serde_json::Value::as_str) {
                push_unique(&mut evidence.modules, module);
            }
        }
    }
    if let Some(functions) = diff.get("functions") {
        for bucket in ["added", "removed", "changed"] {
            if let Some(items) = functions.get(bucket).and_then(serde_json::Value::as_array) {
                for item in items {
                    if let Some(label) = item.get("label").and_then(serde_json::Value::as_str) {
                        push_unique(&mut evidence.functions, label);
                    }
                }
            }
        }
    }
    if let Some(clusters) = diff
        .get("functionClusters")
        .and_then(|value| value.get("matches"))
        .and_then(serde_json::Value::as_array)
    {
        for cluster in clusters {
            let module = cluster
                .get("module")
                .and_then(serde_json::Value::as_str)
                .unwrap_or("unknown");
            let left_offset = cluster
                .get("leftOffset")
                .and_then(serde_json::Value::as_str)
                .unwrap_or("?");
            let right_offset = cluster
                .get("rightOffset")
                .and_then(serde_json::Value::as_str)
                .unwrap_or("?");
            push_unique(
                &mut evidence.functions,
                &format!("{module}!{left_offset} -> {right_offset}"),
            );
        }
    }
    if let Some(branches) = diff.get("branches") {
        for bucket in ["added", "removed", "changed"] {
            if let Some(items) = branches.get(bucket).and_then(serde_json::Value::as_array) {
                for item in items {
                    if let Some(label) = item.get("label").and_then(serde_json::Value::as_str) {
                        push_unique(&mut evidence.operations, label);
                    }
                }
            }
        }
    }
    evidence.functions.truncate(100);
    evidence.operations.truncate(100);
    evidence
}

fn run_trace_diff_analysis(
    engine: &TraceEngine,
    left_session_id: &str,
    right_session_id: &str,
    start_seq: Option<u32>,
    end_seq: Option<u32>,
    max_items: u32,
    checkpoint: &mut dyn FnMut(&str, u8) -> Result<(), String>,
) -> Result<(serde_json::Value, AnalysisEvidence, serde_json::Value), String> {
    let request = serde_json::json!({
        "left_session_id": left_session_id,
        "right_session_id": right_session_id,
        "start_seq": start_seq,
        "end_seq": end_seq,
        "max_items": max_items.clamp(1, 1000),
    });
    let mut cancellation_error = None;
    let diff = engine.compare_trace_sessions_cancellable(
        left_session_id,
        right_session_id,
        TraceDiffOptions {
            start_seq,
            end_seq,
            max_items: max_items.clamp(1, 1000),
        },
        |processed, total| {
            let progress = if total == 0 {
                90
            } else {
                5 + ((processed as u64 * 85) / total as u64).min(85) as u8
            };
            match checkpoint("profiling_traces", progress) {
                Ok(()) => true,
                Err(error) => {
                    cancellation_error = Some(error);
                    false
                }
            }
        },
    );
    if let Some(error) = cancellation_error {
        return Err(error);
    }
    let diff = diff.map_err(|error| error.to_string())?;
    checkpoint("synthesizing_trace_diff", 94)?;
    let result = serde_json::to_value(diff).map_err(|error| error.to_string())?;
    let evidence = collect_trace_diff_evidence(&result);
    Ok((result, evidence, request))
}

fn collect_search_evidence(lines: &[TraceLine]) -> AnalysisEvidence {
    let mut evidence = AnalysisEvidence::default();
    for line in lines {
        if let Some(module) = line.so_name.as_deref() {
            push_unique(&mut evidence.modules, module);
        }
        if let Some(call) = line.call_info.as_ref() {
            push_unique(&mut evidence.functions, &call.func_name);
        }
        if !line.address.is_empty() {
            push_unique(&mut evidence.addresses, &line.address);
        }
        push_unique(&mut evidence.operations, operation_name(line));
    }
    evidence
}

fn result_has_verified_digest(result: &serde_json::Value) -> bool {
    result
        .get("assessment_summary")
        .and_then(|value| value.get("verified"))
        .and_then(serde_json::Value::as_u64)
        .unwrap_or_default()
        > 0
}

fn result_has_verified_sink(result: &serde_json::Value) -> bool {
    result
        .get("flow_endpoints")
        .and_then(serde_json::Value::as_array)
        .is_some_and(|items| {
            items.iter().any(|item| {
                item.get("call_context")
                    .and_then(|value| value.get("resourceValidation"))
                    .and_then(|value| value.get("status"))
                    .and_then(serde_json::Value::as_str)
                    == Some("verified")
            })
        })
}

fn trace_diff_change_count(result: &serde_json::Value) -> u64 {
    let exact_changes = ["functions", "branches", "instructions", "memoryAccessSites"]
        .iter()
        .filter_map(|section| result.get(*section))
        .map(|section| {
            ["totalAdded", "totalRemoved", "totalChanged"]
                .iter()
                .filter_map(|field| section.get(*field).and_then(serde_json::Value::as_u64))
                .sum::<u64>()
        })
        .sum::<u64>();
    exact_changes
        + result
            .get("functionClusters")
            .and_then(|section| section.get("relocatedMatches"))
            .and_then(serde_json::Value::as_u64)
            .unwrap_or_default()
}

fn run_auto_investigation(
    engine: &TraceEngine,
    session_id: &str,
    req: AutoInvestigateRequest,
    checkpoint: &mut dyn FnMut(&str, u8) -> Result<(), String>,
) -> Result<(serde_json::Value, AnalysisEvidence, serde_json::Value), String> {
    if req.compare_analysis_ids.len() == 1 || req.compare_analysis_ids.len() > 10 {
        return Err("compare_analysis_ids must contain either zero or 2-10 IDs".to_string());
    }
    let request_record = serde_json::json!({
        "objective": req.objective,
        "digests": req.digests,
        "algorithm": format!("{:?}", req.algorithm).to_ascii_lowercase(),
        "from_specs": req.from_specs,
        "search_terms": req.search_terms,
        "compare_analysis_ids": req.compare_analysis_ids,
        "compare_session_id": req.compare_session_id,
        "include_crypto": req.include_crypto,
        "data_only": req.data_only,
        "max_search_results": req.max_search_results,
        "max_trace_matches": req.max_trace_matches,
        "max_diff_items": req.max_diff_items,
    });
    let mut evidence = AnalysisEvidence::default();
    let mut steps = Vec::new();
    let mut mode_count = 0u32;
    let mut search_match_count = 0u64;
    let mut crypto_match_count = 0u64;
    let mut verified_digest = false;
    let mut dependency_context = false;
    let mut dataflow_supported = false;
    let mut verified_sink = false;
    let mut diff_changes = 0u64;
    let mut truncated = false;

    checkpoint("session_overview", 3)?;
    let session = engine
        .get_session_info(session_id)
        .map_err(|error| error.to_string())?;
    let mut functions = engine
        .get_function_calls(session_id)
        .map_err(|error| error.to_string())?
        .functions;
    functions.sort_by(|left, right| right.occurrences.len().cmp(&left.occurrences.len()));
    let function_overview: Vec<_> = functions
        .iter()
        .take(30)
        .map(|function| {
            serde_json::json!({
                "func_name": function.func_name,
                "call_count": function.occurrences.len(),
                "is_jni": function.is_jni,
            })
        })
        .collect();
    steps.push(serde_json::json!({
        "stage": "session_overview",
        "status": "completed",
        "output": {
            "file_path": session.file_path,
            "total_lines": session.total_lines,
            "trace_format": session.trace_format,
            "function_count": functions.len(),
            "top_functions": function_overview,
        }
    }));

    let mut terms = Vec::new();
    for term in req.search_terms.iter().map(|term| term.trim()) {
        if !term.is_empty() && !terms.iter().any(|existing: &String| existing == term) {
            terms.push(term.to_string());
        }
        if terms.len() >= 10 {
            break;
        }
    }
    if !terms.is_empty() {
        mode_count = mode_count.saturating_add(1);
        checkpoint("searching_terms", 12)?;
        let mut searches = Vec::new();
        for term in terms {
            let search = engine
                .search(
                    session_id,
                    &term,
                    SearchOptions {
                        case_sensitive: false,
                        use_regex: false,
                        fuzzy: false,
                        max_results: Some(req.max_search_results.clamp(1, 100)),
                    },
                )
                .map_err(|error| error.to_string())?;
            let lines = engine
                .get_lines(session_id, &search.match_seqs)
                .map_err(|error| error.to_string())?;
            evidence = merge_evidence(evidence, collect_search_evidence(&lines));
            search_match_count = search_match_count.saturating_add(search.total_matches as u64);
            truncated |= search.truncated;
            searches.push(serde_json::json!({
                "term": term,
                "total_matches": search.total_matches,
                "truncated": search.truncated,
                "lines": lines.iter().map(compact_line).collect::<Vec<_>>(),
            }));
        }
        steps.push(serde_json::json!({
            "stage": "search",
            "status": "completed",
            "output": searches,
        }));
    }

    if req.include_crypto {
        mode_count = mode_count.saturating_add(1);
        checkpoint("crypto_detection", 28)?;
        let crypto = run_crypto_detection(engine, session_id, 3, 50)?;
        crypto_match_count = crypto
            .get("match_count")
            .and_then(serde_json::Value::as_u64)
            .unwrap_or_default();
        truncated |= crypto
            .get("matches_truncated")
            .and_then(serde_json::Value::as_bool)
            .unwrap_or(false);
        evidence = merge_evidence(evidence, collect_crypto_evidence(&crypto));
        steps.push(serde_json::json!({
            "stage": "crypto_detection",
            "status": "completed",
            "output": crypto,
        }));
    }

    if !req.digests.is_empty() {
        mode_count = mode_count.saturating_add(1);
        checkpoint("known_digest_analysis", 45)?;
        let digest_request = AnalyzeKnownDigestRequest {
            session_id: None,
            digests: req.digests,
            algorithm: req.algorithm,
            search_strings: true,
            search_memory: true,
            auto_scan_strings: true,
            utf8_nul: true,
            utf16le: true,
            utf16le_nul: true,
            max_results: 100,
            trace_matches: true,
            max_trace_matches: req.max_trace_matches.clamp(1, 10),
            data_only: req.data_only,
            start_seq: None,
            max_dependency_nodes: 2000,
        };
        let (digest, digest_evidence, _) =
            run_known_digest_analysis(engine, session_id, digest_request)?;
        verified_digest = result_has_verified_digest(&digest);
        dependency_context |= digest
            .get("traced_matches")
            .and_then(serde_json::Value::as_array)
            .is_some_and(|items| {
                items.iter().any(|item| {
                    item.get("analysis")
                        .is_some_and(|analysis| !analysis.is_null())
                })
            });
        evidence = merge_evidence(evidence, digest_evidence);
        steps.push(serde_json::json!({
            "stage": "known_digest_analysis",
            "status": "completed",
            "output": digest,
        }));
    }

    if !req.from_specs.is_empty() {
        mode_count = mode_count.saturating_add(1);
        checkpoint("forward_data_flow", 63)?;
        let forward_request = ForwardTaintAnalysisRequest {
            session_id: None,
            from_specs: req.from_specs,
            data_only: req.data_only,
            start_seq: None,
            end_seq: None,
            max_nodes: 20_000,
            include_lines: 150,
            max_sinks: 100,
        };
        let mut nested_checkpoint = |_: &str, _: u8| checkpoint("forward_data_flow", 70);
        let (forward, forward_evidence, _) = run_forward_taint_analysis(
            engine,
            session_id,
            forward_request,
            &mut nested_checkpoint,
        )?;
        dataflow_supported |= forward
            .get("affected_count")
            .and_then(serde_json::Value::as_u64)
            .unwrap_or_default()
            > 1;
        verified_sink = result_has_verified_sink(&forward);
        truncated |= forward
            .get("truncated")
            .and_then(serde_json::Value::as_bool)
            .unwrap_or(false);
        evidence = merge_evidence(evidence, forward_evidence);
        steps.push(serde_json::json!({
            "stage": "forward_data_flow",
            "status": "completed",
            "output": forward,
        }));
    }

    if req.compare_analysis_ids.len() >= 2 {
        mode_count = mode_count.saturating_add(1);
        checkpoint("comparing_analyses", 78)?;
        let comparison = engine
            .compare_analyses(session_id, &req.compare_analysis_ids)
            .map_err(|error| error.to_string())?;
        steps.push(serde_json::json!({
            "stage": "analysis_comparison",
            "status": "completed",
            "output": comparison,
        }));
    }

    if let Some(other_session_id) = req.compare_session_id.as_deref() {
        mode_count = mode_count.saturating_add(1);
        checkpoint("trace_diff", 82)?;
        let mut diff_checkpoint =
            |_: &str, progress: u8| checkpoint("trace_diff", 82 + (progress / 8).min(12));
        let (diff, diff_evidence, _) = run_trace_diff_analysis(
            engine,
            session_id,
            other_session_id,
            None,
            None,
            req.max_diff_items.clamp(1, 500),
            &mut diff_checkpoint,
        )?;
        diff_changes = trace_diff_change_count(&diff);
        evidence = merge_evidence(evidence, diff_evidence);
        steps.push(serde_json::json!({
            "stage": "trace_diff",
            "status": "completed",
            "output": diff,
        }));
    }

    checkpoint("evidence_synthesis", 96)?;
    let warnings_present = !evidence.warnings.is_empty();
    let verification_gate = verified_sink && dataflow_supported;
    let assessment = score_evidence(
        "auto_investigation",
        verification_gate,
        vec![
            EvidenceScoreSignal::new(
                "objective",
                "A concrete investigation objective was supplied.",
                5,
                !req.objective.trim().is_empty(),
                Some(req.objective.clone()),
            ),
            EvidenceScoreSignal::new(
                "search_matches",
                "Search terms produced runtime evidence.",
                15,
                search_match_count > 0,
                Some(format!("match_count={search_match_count}")),
            ),
            EvidenceScoreSignal::new(
                "crypto_signatures",
                "Cryptographic signatures were observed.",
                10,
                crypto_match_count > 0,
                Some(format!("match_count={crypto_match_count}")),
            ),
            EvidenceScoreSignal::new(
                "verified_digest_candidate",
                "At least one digest candidate was exactly verified.",
                25,
                verified_digest,
                None,
            ),
            EvidenceScoreSignal::new(
                "data_flow",
                "Dependency analysis supports a concrete data-flow path.",
                25,
                dataflow_supported,
                None,
            ),
            EvidenceScoreSignal::new(
                "dependency_context",
                "Backward dependency context was collected for a candidate or output buffer.",
                10,
                dependency_context,
                None,
            ),
            EvidenceScoreSignal::new(
                "verified_sink",
                "A Source/Sink endpoint has verified cross-call resource provenance.",
                25,
                verified_sink,
                None,
            ),
            EvidenceScoreSignal::new(
                "trace_diff",
                "A second trace produced execution-profile differences.",
                10,
                diff_changes > 0,
                Some(format!("change_count={diff_changes}")),
            ),
            EvidenceScoreSignal::new(
                "independent_modes",
                "Multiple independent analysis modes contributed evidence.",
                10,
                mode_count >= 2,
                Some(format!("mode_count={mode_count}")),
            ),
            EvidenceScoreSignal::new(
                "warnings",
                "The investigation contains warnings or known limitations.",
                -10,
                warnings_present,
                Some(format!("warning_count={}", evidence.warnings.len())),
            ),
            EvidenceScoreSignal::new(
                "truncated",
                "One or more bounded stages were truncated.",
                -10,
                truncated,
                None,
            ),
        ],
        vec![
            "The orchestration is deterministic and evidence-driven; it does not infer unexecuted program behavior."
                .to_string(),
            "A verified candidate score applies only to its declared scope and should not be generalized to producer attribution without data-flow evidence."
                .to_string(),
        ],
    );
    let conclusion = match assessment.grade.as_str() {
        "verified" => "The investigation found high-confidence evidence that satisfies the declared verification gate. Review the scored factors and exact trace lines before final attribution.",
        "related" => "The investigation found related evidence, but at least one verification gate or strong data-flow link is still missing.",
        _ => "The available trace evidence is insufficient for a reliable conclusion. Narrow the objective or provide known values and explicit data sources.",
    };
    let result = serde_json::json!({
        "session_id": session_id,
        "objective": req.objective,
        "conclusion": conclusion,
        "assessment": assessment,
        "steps": steps,
        "evidence": evidence.clone(),
        "limitations": [
            "Only executed behavior recorded in the trace is analyzed.",
            "Search, digest tracing, forward flow, and Trace Diff use bounded result sets.",
            "Natural-language objectives are recorded for the AI client; deterministic stages are selected from the structured request fields."
        ],
        "next_actions": [
            "Inspect factors with zero or negative awarded_points and collect the missing evidence.",
            "Use get_trace_lines and get_memory for exact evidence around the highest-scoring findings.",
            "Export this analysis_id as Markdown or JSON after review."
        ]
    });
    Ok((result, evidence, request_record))
}

const RECIPE_FORWARD: &str = "forward_to_sinks";
const RECIPE_DIGEST: &str = "known_digest_flow";
const RECIPE_CRYPTO: &str = "crypto_investigation";
const RECIPE_AUTO: &str = "auto_investigation";

fn built_in_recipes() -> Vec<serde_json::Value> {
    vec![
        serde_json::json!({
            "recipe_id": RECIPE_FORWARD,
            "name": "Forward input to sinks",
            "description": "Follow a register or memory input to classified source/sink endpoints.",
            "workflow": RECIPE_FORWARD,
            "built_in": true,
            "defaults": {
                "data_only": true,
                "max_nodes": 10000,
                "include_lines": 100,
                "max_sinks": 100
            }
        }),
        serde_json::json!({
            "recipe_id": RECIPE_DIGEST,
            "name": "Known digest to input",
            "description": "Match known digests against runtime strings and memory, then trace candidate origins.",
            "workflow": RECIPE_DIGEST,
            "built_in": true,
            "defaults": {
                "search_strings": true,
                "search_memory": true,
                "auto_scan_strings": true,
                "trace_matches": true,
                "data_only": true,
                "max_trace_matches": 3
            }
        }),
        serde_json::json!({
            "recipe_id": RECIPE_CRYPTO,
            "name": "Crypto investigation",
            "description": "Detect crypto signatures and optionally correlate known digests.",
            "workflow": RECIPE_CRYPTO,
            "built_in": true,
            "defaults": {
                "trace_matches": true,
                "data_only": true,
                "context_lines": 3,
                "max_crypto_matches": 50,
                "max_trace_matches": 3
            }
        }),
        serde_json::json!({
            "recipe_id": RECIPE_AUTO,
            "name": "Automatic evidence investigation",
            "description": "Combine searches, crypto detection, known digests, forward flow, saved-analysis comparison, and optional Trace Diff.",
            "workflow": RECIPE_AUTO,
            "built_in": true,
            "defaults": {
                "include_crypto": true,
                "data_only": true,
                "max_search_results": 20,
                "max_trace_matches": 3,
                "max_diff_items": 50
            }
        }),
    ]
}

fn supported_recipe_workflow(workflow: &str) -> bool {
    matches!(
        workflow,
        RECIPE_FORWARD | RECIPE_DIGEST | RECIPE_CRYPTO | RECIPE_AUTO
    )
}

fn merge_recipe_values(
    defaults: serde_json::Value,
    inputs: serde_json::Value,
) -> Result<serde_json::Value, String> {
    let mut merged = defaults.as_object().cloned().unwrap_or_default();
    let overrides = inputs
        .as_object()
        .ok_or_else(|| "Recipe inputs must be a JSON object".to_string())?;
    for (key, value) in overrides {
        merged.insert(key.clone(), value.clone());
    }
    Ok(serde_json::Value::Object(merged))
}

fn recipe_definition(
    engine: &TraceEngine,
    session_id: &str,
    recipe_id: &str,
) -> Result<(String, String, String, serde_json::Value, bool), String> {
    if let Some(recipe) = built_in_recipes()
        .into_iter()
        .find(|recipe| recipe.get("recipe_id").and_then(|value| value.as_str()) == Some(recipe_id))
    {
        return Ok((
            recipe
                .get("name")
                .and_then(|value| value.as_str())
                .unwrap_or(recipe_id)
                .to_string(),
            recipe
                .get("description")
                .and_then(|value| value.as_str())
                .unwrap_or_default()
                .to_string(),
            recipe
                .get("workflow")
                .and_then(|value| value.as_str())
                .unwrap_or_default()
                .to_string(),
            recipe
                .get("defaults")
                .cloned()
                .unwrap_or_else(|| serde_json::json!({})),
            true,
        ));
    }

    let record = engine
        .get_analysis(session_id, recipe_id)
        .map_err(|error| error.to_string())?;
    if record.kind != "analysis_recipe" {
        return Err(format!("Analysis {recipe_id} is not an analysis recipe"));
    }
    let result = record
        .result
        .as_object()
        .ok_or_else(|| "Saved recipe definition is invalid".to_string())?;
    let workflow = result
        .get("workflow")
        .and_then(|value| value.as_str())
        .ok_or_else(|| "Saved recipe is missing workflow".to_string())?;
    if !supported_recipe_workflow(workflow) {
        return Err(format!("Unsupported recipe workflow: {workflow}"));
    }
    Ok((
        result
            .get("name")
            .and_then(|value| value.as_str())
            .unwrap_or(&record.title)
            .to_string(),
        result
            .get("description")
            .and_then(|value| value.as_str())
            .unwrap_or_default()
            .to_string(),
        workflow.to_string(),
        result
            .get("defaults")
            .cloned()
            .unwrap_or_else(|| serde_json::json!({})),
        false,
    ))
}

fn run_recipe_analysis(
    engine: &TraceEngine,
    session_id: &str,
    req: RunAnalysisRecipeRequest,
) -> Result<(serde_json::Value, AnalysisEvidence, serde_json::Value), String> {
    let (name, description, workflow, defaults, built_in) =
        recipe_definition(engine, session_id, &req.recipe_id)?;
    let resolved_inputs = merge_recipe_values(defaults, req.inputs)?;
    let request_record = serde_json::json!({
        "recipe_id": req.recipe_id,
        "recipe_name": name,
        "workflow": workflow,
        "built_in": built_in,
        "inputs": resolved_inputs,
    });

    let mut resolved = request_record
        .get("inputs")
        .cloned()
        .unwrap_or_else(|| serde_json::json!({}));
    if let Some(object) = resolved.as_object_mut() {
        object.insert("session_id".to_string(), serde_json::Value::Null);
    }

    let (output, evidence) = match workflow.as_str() {
        RECIPE_FORWARD => {
            let request: ForwardTaintAnalysisRequest = serde_json::from_value(resolved)
                .map_err(|error| format!("Invalid forward_to_sinks inputs: {error}"))?;
            let mut checkpoint = |_: &str, _: u8| Ok(());
            let (result, evidence, _) =
                run_forward_taint_analysis(engine, session_id, request, &mut checkpoint)?;
            (result, evidence)
        }
        RECIPE_DIGEST => {
            let request: AnalyzeKnownDigestRequest = serde_json::from_value(resolved)
                .map_err(|error| format!("Invalid known_digest_flow inputs: {error}"))?;
            let (result, evidence, _) = run_known_digest_analysis(engine, session_id, request)?;
            (result, evidence)
        }
        RECIPE_CRYPTO => {
            let request: InvestigateCryptoFlowRequest = serde_json::from_value(resolved)
                .map_err(|error| format!("Invalid crypto_investigation inputs: {error}"))?;
            let mut checkpoint = |_: &str, _: u8| Ok(());
            let (result, evidence, _) =
                run_crypto_flow_analysis(engine, session_id, request, &mut checkpoint)?;
            (result, evidence)
        }
        RECIPE_AUTO => {
            let request: AutoInvestigateRequest = serde_json::from_value(resolved)
                .map_err(|error| format!("Invalid auto_investigation inputs: {error}"))?;
            let mut checkpoint = |_: &str, _: u8| Ok(());
            let (result, evidence, _) =
                run_auto_investigation(engine, session_id, request, &mut checkpoint)?;
            (result, evidence)
        }
        _ => return Err(format!("Unsupported recipe workflow: {workflow}")),
    };

    let result = serde_json::json!({
        "recipe_id": req.recipe_id,
        "recipe_name": name,
        "description": description,
        "workflow": workflow,
        "built_in": built_in,
        "output": output,
    });
    Ok((result, evidence, request_record))
}

#[derive(Clone)]
pub struct TraceToolHandler {
    engine: Arc<TraceEngine>,
    tool_router: ToolRouter<Self>,
}

impl std::fmt::Debug for TraceToolHandler {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TraceToolHandler").finish()
    }
}

#[tool_router]
impl TraceToolHandler {
    pub fn new(engine: Arc<TraceEngine>) -> Self {
        Self {
            engine,
            tool_router: Self::tool_router(),
        }
    }

    /// Implicit session resolution: auto-resolve when only one session is open
    fn resolve_session(&self, session_id: Option<String>) -> Result<String, String> {
        match session_id {
            Some(id) => Ok(id),
            None => {
                let sessions = self.engine.list_sessions();
                match sessions.len() {
                    0 => Err("No active session. Call open_trace first.".into()),
                    1 => Ok(sessions[0].session_id.clone()),
                    n => Err(format!(
                        "Multiple sessions active ({}). Please specify session_id. \
                         Use list_sessions to see all sessions.",
                        n
                    )),
                }
            }
        }
    }

    #[tool(
        name = "health",
        description = "Return server build identity, schema version, and high-level capabilities."
    )]
    fn health(
        &self,
        Parameters(_req): Parameters<HealthRequest>,
    ) -> Result<Json<HealthResponse>, String> {
        Ok(Json(HealthResponse {
            status: "ok".to_string(),
            version: env!("CARGO_PKG_VERSION").to_string(),
            build_revision: option_env!("TRACE_UI_BUILD_REVISION")
                .unwrap_or("development")
                .to_string(),
            schema_version: "2026-07-21".to_string(),
            capabilities: vec![
                "crypto_implementation_analysis".to_string(),
                "semantic_aes_verification".to_string(),
                "backward_taint".to_string(),
                "forward_taint".to_string(),
                "call_effects".to_string(),
                "analysis_scoped_pagination".to_string(),
                "structured_tool_output".to_string(),
                "unified_value_search".to_string(),
                "crypto_material_index".to_string(),
                "frida_hook_generation".to_string(),
                "dynamic_cfg_ollvm_analysis".to_string(),
                "idapython_bridge_generation".to_string(),
            ],
        }))
    }

    // ━━━━━━━━━━━━━━━━━━━━━━ 会话管理 ━━━━━━━━━━━━━━━━━━━━━━

    #[tool(
        name = "open_trace",
        description = "Open a trace file and build its index. This is the first step before any analysis. \
            Returns session info including session_id, module_name, entry_address, trace_format, \
            function_count, and other metadata needed for all subsequent operations. \
            Building the index may take a few seconds for large files."
    )]
    async fn open_trace(
        &self,
        Parameters(req): Parameters<OpenTraceRequest>,
    ) -> Result<String, String> {
        let engine = self.engine.clone();
        blocking(move || {
            let session = engine
                .create_session(&req.file_path)
                .map_err(|e| format!("Failed to open trace: {}", e))?;

            let session_id = session.session_id.clone();
            let options = BuildOptions {
                force_rebuild: req.force_rebuild,
                skip_strings: req.skip_strings,
            };

            match engine.build_index(&session_id, options, None) {
                Ok(build) => {
                    // Extract additional info (graceful fallback on failure)
                    let module_name = engine
                        .get_lines(&session_id, &[0])
                        .ok()
                        .and_then(|lines| lines.first().and_then(|l| l.so_name.clone()));

                    let entry_address = engine
                        .get_call_tree_children(&session_id, 0, true)
                        .ok()
                        .and_then(|nodes| nodes.first().map(|n| n.func_addr.clone()));

                    let trace_format = engine
                        .get_session_info(&session_id)
                        .ok()
                        .and_then(|info| info.trace_format.map(|f| format!("{:?}", f)));

                    let function_count = engine.get_call_tree_node_count(&session_id).ok();

                    Ok(json(&serde_json::json!({
                        "session_id": session_id,
                        "file_path": session.file_path,
                        "file_size": session.file_size,
                        "total_lines": build.total_lines,
                        "has_string_index": build.has_string_index,
                        "from_cache": build.from_cache,
                        "module_name": module_name,
                        "entry_address": entry_address,
                        "trace_format": trace_format,
                        "function_count": function_count,
                    })))
                }
                Err(e) => {
                    let _ = engine.close_session(&session_id);
                    Err(format!("Failed to build index: {}", e))
                }
            }
        })
        .await
    }

    #[tool(
        name = "close_trace",
        description = "Close a trace session and release its in-memory indexes. Associated background analysis tasks are cancelled. Saved analysis records remain on disk and are restored when the same unchanged trace is opened again."
    )]
    fn close_trace(
        &self,
        Parameters(req): Parameters<CloseTraceRequest>,
    ) -> Result<String, String> {
        let sid = self.resolve_session(req.session_id)?;
        self.engine
            .close_session(&sid)
            .map_err(|error| error.to_string())?;
        Ok(json(&serde_json::json!({
            "session_id": sid,
            "closed": true,
        })))
    }

    // ━━━━━━━━━━━━━━━━━━━━━━ 数据查看 ━━━━━━━━━━━━━━━━━━━━━━

    #[tool(
        name = "get_trace_lines",
        description = "Retrieve instruction lines from the trace. Each line contains: \
            address, disassembly, register changes, and memory access info. \
            Lines are identified by 0-based sequence numbers. \
            Returns up to 100 lines per call."
    )]
    fn get_trace_lines(
        &self,
        Parameters(req): Parameters<GetTraceLinesRequest>,
    ) -> Result<String, String> {
        let sid = self.resolve_session(req.session_id.clone())?;
        let count = req.count.min(MAX_LINES);
        let end = req.start_seq.saturating_add(count);
        let seqs: Vec<u32> = (req.start_seq..end).collect();
        let lines = self
            .engine
            .get_lines(&sid, &seqs)
            .map_err(|e| e.to_string())?;
        Ok(json(&serde_json::json!({
            "lines": format_lines(&lines, req.full),
            "count": lines.len(),
            "start_seq": req.start_seq,
            "requested": count,
        })))
    }

    #[tool(
        name = "get_memory",
        description = "Read memory contents at a specific address and instruction line. \
            Shows the byte values as they were at that point in execution. \
            Unknown bytes (never written) are marked in the 'known' array."
    )]
    fn get_memory(&self, Parameters(req): Parameters<GetMemoryRequest>) -> Result<String, String> {
        let sid = self.resolve_session(req.session_id)?;
        let addr = parse_hex_addr(&req.address)?;
        let length = req.length.min(256);
        let seq = match req.seq {
            Some(s) => s,
            None => {
                let info = self
                    .engine
                    .get_session_info(&sid)
                    .map_err(|e| e.to_string())?;
                info.total_lines.saturating_sub(1)
            }
        };
        self.engine
            .get_memory_at(&sid, addr, seq, length)
            .map(|snap| json(&snap))
            .map_err(|e| e.to_string())
    }

    // ━━━━━━━━━━━━━━━━━━━━━━ 搜索与分析 ━━━━━━━━━━━━━━━━━━━━━━

    #[tool(
        name = "search_instructions",
        description = "Search for instructions matching a text or regex pattern in the trace. \
            Returns matching line numbers and a preview of each match. \
            Use regex for complex patterns like 'bl.*0x[0-9a-f]+' to find specific branch targets. \
            Wrap pattern in /slashes/ for auto-regex detection. \
            Supports optional seq_range ('3000-6000') and addr_range ('0x246F00-0x249800') filters \
            to narrow results to a specific execution window or code region."
    )]
    async fn search_instructions(
        &self,
        Parameters(req): Parameters<SearchInstructionsRequest>,
    ) -> Result<String, String> {
        let sid = self.resolve_session(req.session_id)?;
        let engine = self.engine.clone();
        blocking(move || {
            let max = req.max_results.unwrap_or(DEFAULT_SEARCH).min(MAX_SEARCH);
            let options = SearchOptions {
                case_sensitive: req.case_sensitive,
                use_regex: req.use_regex,
                fuzzy: false,
                max_results: Some(max),
            };
            let result = engine
                .search(&sid, &req.query, options)
                .map_err(|e| e.to_string())?;

            // seq range filter
            let filtered_seqs: Vec<u32> = if let Some(ref range) = req.seq_range {
                let (start, end) = parse_seq_range(range)?;
                result
                    .match_seqs
                    .iter()
                    .copied()
                    .filter(|&seq| seq >= start && seq <= end)
                    .collect()
            } else {
                result.match_seqs.clone()
            };

            let total_after_seq_filter = filtered_seqs.len();

            // Load lines (take more than needed to handle addr_range filtering)
            let load_count = if req.addr_range.is_some() {
                (max as usize) * 3
            } else {
                max as usize
            };
            let preview_seqs: Vec<u32> = filtered_seqs.iter().copied().take(load_count).collect();
            let lines = engine
                .get_lines(&sid, &preview_seqs)
                .map_err(|e| e.to_string())?;

            // addr_range filter
            let final_lines: Vec<&TraceLine> = if let Some(ref range) = req.addr_range {
                let (start, end) = parse_addr_range(range)?;
                lines
                    .iter()
                    .filter(|l| line_in_addr_range(l, start, end))
                    .take(max as usize)
                    .collect()
            } else {
                lines.iter().take(max as usize).collect()
            };

            let matches: Vec<serde_json::Value> = if req.full {
                final_lines
                    .iter()
                    .map(|l| {
                        serde_json::to_value(l)
                            .unwrap_or_else(|e| serde_json::json!({"error": e.to_string()}))
                    })
                    .collect()
            } else {
                final_lines.iter().map(|l| compact_line(l)).collect()
            };

            let effective_total = if req.seq_range.is_some() || req.addr_range.is_some() {
                total_after_seq_filter
            } else {
                result.total_matches as usize
            };

            Ok(json(&serde_json::json!({
                "matches": matches,
                "total_matches": effective_total,
                "total_scanned": result.total_scanned,
                "truncated": result.truncated || final_lines.len() < total_after_seq_filter,
            })))
        })
        .await
    }

    #[tool(
        name = "search_value",
        description = "Search one value across reconstructed historical memory, runtime strings, and exact trace text. Auto mode exposes every byte interpretation (UTF-8, UTF-16LE, hex, integer/address endian forms, and digest bytes) instead of silently changing the input. Results include exact addr/seq anchors suitable for get_memory and backward/forward taint."
    )]
    async fn search_value(
        &self,
        Parameters(req): Parameters<SearchValueRequest>,
    ) -> Result<String, String> {
        let sid = self.resolve_session(req.session_id)?;
        let engine = self.engine.clone();
        blocking(move || {
            let request = ValueSearchRequest {
                query: req.query,
                kind: match req.kind {
                    ValueSearchKindRequest::Auto => ValueSearchKind::Auto,
                    ValueSearchKindRequest::Text => ValueSearchKind::Text,
                    ValueSearchKindRequest::Hex => ValueSearchKind::Hex,
                    ValueSearchKindRequest::Integer => ValueSearchKind::Integer,
                    ValueSearchKindRequest::Address => ValueSearchKind::Address,
                    ValueSearchKindRequest::Digest => ValueSearchKind::Digest,
                },
                endian: match req.endian {
                    ValueEndianRequest::Little => ValueEndian::Little,
                    ValueEndianRequest::Big => ValueEndian::Big,
                    ValueEndianRequest::Both => ValueEndian::Both,
                },
                integer_width: req.integer_width,
                include_utf8: req.include_utf8,
                include_utf16le: req.include_utf16le,
                include_nul: req.include_nul,
                search_strings: req.search_strings,
                search_memory: req.search_memory,
                search_trace: req.search_trace,
                max_results: Some(req.max_results.clamp(1, 500)),
            };
            engine
                .search_value(&sid, &request)
                .map(|response| json(&response))
                .map_err(|error| error.to_string())
        })
        .await
    }

    #[tool(
        name = "get_tainted_lines",
        description = "Retrieve instructions from one saved backward taint analysis by analysis_id. \
            Returns full line content with disassembly for each tainted instruction. \
            Supports pagination with offset/limit. \
            By default, filters out lines that only modify stack/frame pointer registers. \
            Supports addr_range filter and context_lines to show surrounding non-tainted lines."
    )]
    fn get_tainted_lines(
        &self,
        Parameters(req): Parameters<GetTaintedLinesRequest>,
    ) -> Result<Json<GetTaintedLinesResponse>, String> {
        let sid = self.resolve_session(req.session_id)?;
        let limit = req.limit.min(200);
        let ctx_lines = req.context_lines.min(5);

        let analysis = self
            .engine
            .get_analysis(&sid, &req.analysis_id)
            .map_err(|e| e.to_string())?;
        let all_seqs = self
            .engine
            .get_analysis_tainted_seqs(&sid, &req.analysis_id)
            .map_err(|e| e.to_string())?;

        let total_tainted = all_seqs.len() as u32;

        // 栈操作过滤
        let (after_stack_filter, stack_ops_filtered) =
            if req.ignore_stack_ops && !all_seqs.is_empty() {
                let all_lines = self
                    .engine
                    .get_lines(&sid, &all_seqs)
                    .map_err(|e| e.to_string())?;
                let kept: Vec<TraceLine> = all_lines
                    .into_iter()
                    .filter(|line| !is_stack_only_change(&line.changes))
                    .collect();
                let filtered_count = total_tainted - kept.len() as u32;
                (kept, filtered_count)
            } else {
                let all_lines = self
                    .engine
                    .get_lines(&sid, &all_seqs)
                    .map_err(|e| e.to_string())?;
                (all_lines, 0u32)
            };

        // 地址范围过滤
        let after_addr_filter: Vec<TraceLine> = if let Some(ref range) = req.addr_range {
            let (start, end) = parse_addr_range(range)?;
            after_stack_filter
                .into_iter()
                .filter(|l| line_in_addr_range(l, start, end))
                .collect()
        } else {
            after_stack_filter
        };

        let total_after_filter = after_addr_filter.len() as u32;

        // 分页
        let page_lines: Vec<TraceLine> = after_addr_filter
            .into_iter()
            .skip(req.offset as usize)
            .take(limit as usize)
            .collect();

        // 上下文摘要
        let context = Some(format!(
            "analysis_id={}, taint from {}, data_only={}",
            req.analysis_id,
            analysis
                .request
                .get("from_specs")
                .map(ToString::to_string)
                .unwrap_or_default(),
            analysis
                .request
                .get("data_only")
                .and_then(|value| value.as_bool())
                .unwrap_or(false)
        ));

        // 上下文行展开
        if ctx_lines > 0 && !page_lines.is_empty() {
            let tainted_seqs: std::collections::HashSet<u32> =
                page_lines.iter().map(|l| l.seq).collect();
            let mut expanded_seqs = std::collections::BTreeSet::new();
            for line in &page_lines {
                let start = line.seq.saturating_sub(ctx_lines);
                let end = line.seq.saturating_add(ctx_lines);
                for s in start..=end {
                    expanded_seqs.insert(s);
                }
            }
            let extra_seqs: Vec<u32> = expanded_seqs
                .iter()
                .copied()
                .filter(|s| !tainted_seqs.contains(s))
                .collect();
            let extra_lines = self.engine.get_lines(&sid, &extra_seqs).unwrap_or_default();
            let extra_map: std::collections::HashMap<u32, &TraceLine> =
                extra_lines.iter().map(|l| (l.seq, l)).collect();

            let mut output_lines: Vec<serde_json::Value> = Vec::new();
            for seq in expanded_seqs {
                if let Some(tl) = page_lines.iter().find(|l| l.seq == seq) {
                    let mut obj = if req.full {
                        serde_json::to_value(tl)
                            .unwrap_or_else(|e| serde_json::json!({"error": e.to_string()}))
                    } else {
                        compact_line(tl)
                    };
                    obj.as_object_mut()
                        .map(|o| o.insert("tainted".to_string(), serde_json::json!(true)));
                    output_lines.push(obj);
                } else if let Some(el) = extra_map.get(&seq) {
                    let mut obj = if req.full {
                        serde_json::to_value(*el)
                            .unwrap_or_else(|e| serde_json::json!({"error": e.to_string()}))
                    } else {
                        compact_line(el)
                    };
                    obj.as_object_mut()
                        .map(|o| o.insert("tainted".to_string(), serde_json::json!(false)));
                    output_lines.push(obj);
                }
            }

            return Ok(Json(GetTaintedLinesResponse {
                analysis_id: req.analysis_id,
                context,
                lines: output_lines,
                total_tainted,
                total_after_filter,
                stack_ops_filtered,
                offset: req.offset,
                count: page_lines.len(),
                context_lines: ctx_lines,
                has_more: (req.offset as usize + page_lines.len()) < total_after_filter as usize,
            }));
        }

        Ok(Json(GetTaintedLinesResponse {
            analysis_id: req.analysis_id,
            context,
            lines: format_lines(&page_lines, req.full),
            total_tainted,
            total_after_filter,
            stack_ops_filtered,
            offset: req.offset,
            count: page_lines.len(),
            context_lines: 0,
            has_more: (req.offset as usize + page_lines.len()) < total_after_filter as usize,
        }))
    }

    // ━━━━━━━━━━━━━━━━━━━━━━ 结构信息 ━━━━━━━━━━━━━━━━━━━━━━

    fn collect_tree_to_depth(
        &self,
        session_id: &str,
        node_id: u32,
        depth: u32,
        max_nodes: u32,
    ) -> Result<Vec<serde_json::Value>, String> {
        let nodes = self
            .engine
            .get_call_tree_children(session_id, node_id, true)
            .map_err(|e| e.to_string())?;
        if nodes.is_empty() {
            return Ok(vec![]);
        }
        let mut result: Vec<serde_json::Value> =
            vec![serde_json::to_value(&nodes[0]).map_err(|e| e.to_string())?];
        if depth <= 1 {
            for child in &nodes[1..] {
                if result.len() as u32 >= max_nodes {
                    break;
                }
                result.push(serde_json::to_value(child).map_err(|e| e.to_string())?);
            }
        } else {
            for child in &nodes[1..] {
                if result.len() as u32 >= max_nodes {
                    break;
                }
                let remaining = max_nodes - result.len() as u32;
                let sub = self.collect_tree_to_depth(session_id, child.id, depth - 1, remaining)?;
                result.extend(sub);
            }
        }
        Ok(result)
    }

    #[tool(
        name = "get_call_tree",
        description = "Get the function call tree rooted at a specific node. \
            Use node_id=0 to start from the root. depth controls expansion levels (1-3). \
            Returns nodes array, count, total_node_count (full tree size), and depth used. \
            Each node contains: function address, name, entry/exit line numbers, and child node IDs."
    )]
    fn get_call_tree(
        &self,
        Parameters(req): Parameters<GetCallTreeRequest>,
    ) -> Result<String, String> {
        let sid = self.resolve_session(req.session_id)?;
        let depth = req.depth.min(3).max(1);
        let max_nodes: u32 = 500;
        let nodes = self.collect_tree_to_depth(&sid, req.node_id, depth, max_nodes)?;
        let total_count = self.engine.get_call_tree_node_count(&sid).unwrap_or(0);
        Ok(json(&serde_json::json!({
            "nodes": nodes,
            "count": nodes.len(),
            "total_node_count": total_count,
            "depth": depth,
            "hint": "Use analyze_function with node_id for detailed analysis including entry arguments.",
        })))
    }

    #[tool(
        name = "get_strings",
        description = "List runtime strings found in the trace. \
            These are strings observed in memory during execution. \
            Supports filtering by minimum length and search query. \
            Each string includes its memory address, content, encoding, and access type."
    )]
    fn get_strings(
        &self,
        Parameters(req): Parameters<GetStringsRequest>,
    ) -> Result<String, String> {
        let sid = self.resolve_session(req.session_id)?;
        let limit = req.limit.min(200);
        let options = StringQueryOptions {
            min_len: req.min_len,
            offset: req.offset,
            limit,
            search: req.search,
        };
        let result = self
            .engine
            .get_strings(&sid, options)
            .map_err(|e| e.to_string())?;
        let has_results = !result.strings.is_empty();
        let mut response = serde_json::json!({
            "strings": result.strings,
            "total": result.total,
            "offset": req.offset,
            "has_more": (req.offset + result.strings.len() as u32) < result.total,
        });
        if has_results {
            response["hint"] = serde_json::json!("Use search_instructions with the string's memory address to find which instructions access it.");
        }
        Ok(json(&response))
    }

    // ━━━━━━━━━━━━━━━━━━━━━━ Batch 2: 组合工具 ━━━━━━━━━━━━━━━━━━━━━━

    #[tool(
        name = "taint_analysis",
        description = "Run backward taint analysis and return results in one call. \
            Traces where a value came from by following data/control dependencies. \
            Sources accept explicit display-line or sequence anchors, for example \
            mem:0x1000:32@line:5930 or mem:0x1000:32@seq:5929 (size 1-4096 bytes). \
            Returns analysis stats plus the first page of tainted instructions and saves an analysis_id. \
            Use get_tainted_lines to paginate if has_more is true, or compare_analyses to compare with forward flow."
    )]
    async fn taint_analysis(
        &self,
        Parameters(req): Parameters<TaintAnalysisRequest>,
    ) -> Result<String, String> {
        let sid = self.resolve_session(req.session_id.clone())?;
        let engine = self.engine.clone();
        blocking(move || {
            let request_record = serde_json::json!({
                "from_specs": req.from_specs.clone(),
                "data_only": req.data_only,
                "start_seq": req.start_seq,
                "end_seq": req.end_seq,
                "include_lines": req.include_lines.min(200),
                "addr_range": req.addr_range.clone(),
                "ignore_stack_ops": req.ignore_stack_ops,
            });
            // 1. 执行污点分析
            let options = SliceOptions {
                start_seq: req.start_seq,
                end_seq: req.end_seq,
                data_only: req.data_only,
            };
            let result = engine
                .run_slice(&sid, &req.from_specs, options)
                .map_err(|e| e.to_string())?;
            let all_seqs = engine.get_tainted_seqs(&sid).map_err(|e| e.to_string())?;

            // 2. 仅返回统计信息
            let include = req.include_lines.min(200);
            if include == 0 {
                let response = serde_json::json!({
                    "marked_count": result.marked_count,
                    "total_lines": result.total_lines,
                    "percentage": format!("{:.2}%", result.percentage),
                    "warnings": result.warnings,
                    "lines": [],
                    "total_after_filter": result.marked_count,
                    "stack_ops_filtered": 0,
                    "count": 0,
                    "has_more": result.marked_count > 0,
                    "hint": "Use get_tainted_lines to retrieve tainted instructions.",
                });
                return save_backward_taint_result(
                    &engine,
                    &sid,
                    request_record,
                    response,
                    &all_seqs,
                )
                .map(|response| json(&response));
            }

            // 3. 获取污点行
            let all_seqs = engine.get_tainted_seqs(&sid).map_err(|e| e.to_string())?;

            if all_seqs.is_empty() {
                let response = serde_json::json!({
                    "marked_count": result.marked_count,
                    "total_lines": result.total_lines,
                    "percentage": format!("{:.2}%", result.percentage),
                    "warnings": result.warnings,
                    "lines": [],
                    "total_after_filter": 0,
                    "stack_ops_filtered": 0,
                    "count": 0,
                    "has_more": false,
                });
                return save_backward_taint_result(
                    &engine,
                    &sid,
                    request_record,
                    response,
                    &all_seqs,
                )
                .map(|response| json(&response));
            }

            let all_lines = engine
                .get_lines(&sid, &all_seqs)
                .map_err(|e| e.to_string())?;

            // 4. 栈操作过滤
            let (kept, stack_filtered) = if req.ignore_stack_ops {
                let before = all_lines.len();
                let filtered: Vec<TraceLine> = all_lines
                    .into_iter()
                    .filter(|l| !is_stack_only_change(&l.changes))
                    .collect();
                let diff = before - filtered.len();
                (filtered, diff as u32)
            } else {
                (all_lines, 0u32)
            };

            // 5. 地址范围过滤
            let after_addr: Vec<TraceLine> = if let Some(ref range) = req.addr_range {
                let (start, end) = parse_addr_range(range)?;
                kept.into_iter()
                    .filter(|l| line_in_addr_range(l, start, end))
                    .collect()
            } else {
                kept
            };

            let total_after_filter = after_addr.len();

            // 6. 取前 include 行
            let page: Vec<&TraceLine> = after_addr.iter().take(include as usize).collect();
            let count = page.len();
            let lines: Vec<serde_json::Value> = page.iter().map(|l| compact_line(l)).collect();

            let response = serde_json::json!({
                "marked_count": result.marked_count,
                "total_lines": result.total_lines,
                "percentage": format!("{:.2}%", result.percentage),
                "warnings": result.warnings,
                "lines": lines,
                "total_after_filter": total_after_filter,
                "stack_ops_filtered": stack_filtered,
                "count": count,
                "has_more": count < total_after_filter,
                "hint": if count < total_after_filter {
                    "Use get_tainted_lines with offset to see more results."
                } else {
                    "All tainted lines included."
                },
            });
            save_backward_taint_result(&engine, &sid, request_record, response, &all_seqs)
                .map(|response| json(&response))
        })
        .await
    }

    #[tool(
        name = "forward_taint_analysis",
        description = "Trace where an input value flows forward and save the result under analysis_id. \
            Accepts sources such as reg:X0@line:1234 and 1-4096 byte memory sources such as \
            mem:0xbffff000:32@seq:5929. Returns affected instructions, \
            a reusable dependency-index status, and classified source/sink endpoints with category, confidence, \
            external-boundary flag, reason, structured evidence, and bounded previews. Use compare_analyses \
            with a backward taint analysis or another hypothesis."
    )]
    async fn forward_taint_analysis(
        &self,
        Parameters(req): Parameters<ForwardTaintAnalysisRequest>,
    ) -> Result<String, String> {
        let sid = self.resolve_session(req.session_id.clone())?;
        let engine = self.engine.clone();
        blocking(move || {
            let mut checkpoint = |_: &str, _: u8| Ok(());
            let (mut result, evidence, request) =
                run_forward_taint_analysis(&engine, &sid, req, &mut checkpoint)?;
            let record = engine
                .save_analysis(
                    &sid,
                    "forward_taint",
                    "Forward taint analysis",
                    request,
                    result.clone(),
                    evidence,
                )
                .map_err(|error| error.to_string())?;
            result["analysis_id"] = serde_json::json!(record.analysis_id);
            result["saved"] = serde_json::json!(true);
            Ok(json(&result))
        })
        .await
    }

    #[tool(
        name = "start_forward_taint_analysis",
        description = "Start forward taint analysis as a cancellable background task. Returns task_id immediately. \
            Poll get_analysis_task until completed, then retrieve the saved analysis_id with get_analysis."
    )]
    fn start_forward_taint_analysis(
        &self,
        Parameters(req): Parameters<ForwardTaintAnalysisRequest>,
    ) -> Result<String, String> {
        let sid = self.resolve_session(req.session_id.clone())?;
        let task = self
            .engine
            .create_analysis_task(&sid, "forward_taint")
            .map_err(|error| error.to_string())?;
        let task_id = task.task_id.clone();
        let worker_task_id = task_id.clone();
        let engine = self.engine.clone();
        tokio::task::spawn_blocking(move || {
            let outcome = (|| -> Result<(), String> {
                engine
                    .start_analysis_task(&worker_task_id, "starting")
                    .map_err(|error| error.to_string())?;
                let mut checkpoint = |stage: &str, progress: u8| -> Result<(), String> {
                    if engine.analysis_task_cancelled(&worker_task_id) {
                        let _ = engine.mark_analysis_task_cancelled(&worker_task_id);
                        return Err(TASK_CANCELLED.to_string());
                    }
                    engine
                        .update_analysis_task(&worker_task_id, stage, progress)
                        .map_err(|error| error.to_string())
                };
                let (result, evidence, request) =
                    run_forward_taint_analysis(&engine, &sid, req, &mut checkpoint)?;
                checkpoint("saving", 98)?;
                let record = engine
                    .save_analysis(
                        &sid,
                        "forward_taint",
                        "Forward taint analysis",
                        request,
                        result,
                        evidence,
                    )
                    .map_err(|error| error.to_string())?;
                if engine.analysis_task_cancelled(&worker_task_id) {
                    let _ = engine.delete_analysis(&sid, &record.analysis_id);
                    let _ = engine.mark_analysis_task_cancelled(&worker_task_id);
                    return Err(TASK_CANCELLED.to_string());
                }
                engine
                    .complete_analysis_task(&worker_task_id, &record.analysis_id)
                    .map_err(|error| error.to_string())?;
                Ok(())
            })();
            if let Err(error) = outcome {
                if error == TASK_CANCELLED {
                    let _ = engine.mark_analysis_task_cancelled(&worker_task_id);
                } else {
                    let _ = engine.fail_analysis_task(&worker_task_id, &error);
                }
            }
        });
        Ok(json(&serde_json::json!({
            "task": task,
            "task_id": task_id,
            "poll_with": "get_analysis_task",
            "cancel_with": "cancel_analysis_task",
        })))
    }

    #[tool(
        name = "analyze_known_digest",
        description = "Investigate known CRC32, MD5, SHA-1, SHA-256, SHA-384, or SHA-512 values. \
            Matches extracted runtime strings, reconstructs binary digest output buffers from memory writes, \
            and can automatically run multi-byte backward taint analysis for top matches. \
            Returns strict match evidence, invalid-input details, memory write locations, warnings, \
            dependency summaries, key operations, functions, modules, memory inputs/outputs, and key strings. \
            This verifies candidates present in the trace; it does not brute-force or reverse a digest."
    )]
    async fn analyze_known_digest(
        &self,
        Parameters(req): Parameters<AnalyzeKnownDigestRequest>,
    ) -> Result<String, String> {
        let sid = self.resolve_session(req.session_id.clone())?;
        let engine = self.engine.clone();
        blocking(move || {
            let (mut result, evidence, request) = run_known_digest_analysis(&engine, &sid, req)?;
            let digest_count = request
                .get("digests")
                .and_then(|value| value.as_array())
                .map_or(0, Vec::len);
            let record = engine
                .save_analysis(
                    &sid,
                    "known_digest",
                    &format!("Known digest investigation ({digest_count} queries)"),
                    request,
                    result.clone(),
                    evidence,
                )
                .map_err(|error| error.to_string())?;
            result["analysis_id"] = serde_json::json!(record.analysis_id);
            result["saved"] = serde_json::json!(true);
            Ok(json(&result))
        })
        .await
    }

    #[tool(
        name = "investigate_crypto_flow",
        description = "Run an AI-oriented crypto investigation workflow. Detects cryptographic signatures, \
            optionally correlates known digests with runtime strings and memory output buffers, traces top \
            digest matches, combines the evidence, and saves the complete investigation under an analysis_id. \
            Use get_analysis or compare_analyses to review and compare investigations later."
    )]
    async fn investigate_crypto_flow(
        &self,
        Parameters(req): Parameters<InvestigateCryptoFlowRequest>,
    ) -> Result<String, String> {
        let sid = self.resolve_session(req.session_id.clone())?;
        let engine = self.engine.clone();
        blocking(move || {
            let mut checkpoint = |_: &str, _: u8| Ok(());
            let (result, evidence, request_record) =
                run_crypto_flow_analysis(&engine, &sid, req, &mut checkpoint)?;
            let record = engine
                .save_analysis(
                    &sid,
                    "crypto_flow",
                    "Crypto flow investigation",
                    request_record,
                    result.clone(),
                    evidence,
                )
                .map_err(|error| error.to_string())?;
            let mut response = result;
            response["analysis_id"] = serde_json::json!(record.analysis_id);
            response["saved"] = serde_json::json!(true);
            Ok(json(&response))
        })
        .await
    }

    #[tool(
        name = "auto_investigate",
        description = "Run a deterministic AI-oriented investigation plan and save one evidence package. It can combine session overview, literal searches, crypto detection, known-digest verification, forward data flow, comparison of saved analyses, and execution-profile Trace Diff against a second open session. Returns scored factors, verification scope, limitations, steps, and an analysis_id."
    )]
    async fn auto_investigate(
        &self,
        Parameters(req): Parameters<AutoInvestigateRequest>,
    ) -> Result<String, String> {
        let sid = self.resolve_session(req.session_id.clone())?;
        let engine = self.engine.clone();
        blocking(move || {
            let mut checkpoint = |_: &str, _: u8| Ok(());
            let (result, evidence, request) =
                run_auto_investigation(&engine, &sid, req, &mut checkpoint)?;
            let record = engine
                .save_analysis(
                    &sid,
                    "auto_investigation",
                    "Automatic evidence investigation",
                    request,
                    result.clone(),
                    evidence,
                )
                .map_err(|error| error.to_string())?;
            let mut response = result;
            response["analysis_id"] = serde_json::json!(record.analysis_id);
            response["saved"] = serde_json::json!(true);
            Ok(json(&response))
        })
        .await
    }

    #[tool(
        name = "start_auto_investigation",
        description = "Start auto_investigate as a cancellable background task. Poll get_analysis_task until completed, then retrieve the analysis_id with get_analysis."
    )]
    fn start_auto_investigation(
        &self,
        Parameters(req): Parameters<AutoInvestigateRequest>,
    ) -> Result<String, String> {
        let sid = self.resolve_session(req.session_id.clone())?;
        let task = self
            .engine
            .create_analysis_task(&sid, "auto_investigation")
            .map_err(|error| error.to_string())?;
        let task_id = task.task_id.clone();
        let worker_task_id = task_id.clone();
        let engine = self.engine.clone();
        tokio::task::spawn_blocking(move || {
            let outcome = (|| -> Result<(), String> {
                engine
                    .start_analysis_task(&worker_task_id, "starting")
                    .map_err(|error| error.to_string())?;
                let mut checkpoint = |stage: &str, progress: u8| -> Result<(), String> {
                    if engine.analysis_task_cancelled(&worker_task_id) {
                        let _ = engine.mark_analysis_task_cancelled(&worker_task_id);
                        return Err(TASK_CANCELLED.to_string());
                    }
                    engine
                        .update_analysis_task(&worker_task_id, stage, progress)
                        .map_err(|error| error.to_string())
                };
                let (result, evidence, request) =
                    run_auto_investigation(&engine, &sid, req, &mut checkpoint)?;
                checkpoint("saving", 98)?;
                let record = engine
                    .save_analysis(
                        &sid,
                        "auto_investigation",
                        "Automatic evidence investigation",
                        request,
                        result,
                        evidence,
                    )
                    .map_err(|error| error.to_string())?;
                if engine.analysis_task_cancelled(&worker_task_id) {
                    let _ = engine.delete_analysis(&sid, &record.analysis_id);
                    let _ = engine.mark_analysis_task_cancelled(&worker_task_id);
                    return Err(TASK_CANCELLED.to_string());
                }
                engine
                    .complete_analysis_task(&worker_task_id, &record.analysis_id)
                    .map_err(|error| error.to_string())?;
                Ok(())
            })();
            if let Err(error) = outcome {
                if error == TASK_CANCELLED {
                    let _ = engine.mark_analysis_task_cancelled(&worker_task_id);
                } else {
                    let _ = engine.fail_analysis_task(&worker_task_id, &error);
                }
            }
        });
        Ok(json(&serde_json::json!({
            "task": task,
            "task_id": task_id,
            "poll_with": "get_analysis_task",
            "cancel_with": "cancel_analysis_task",
        })))
    }

    #[tool(
        name = "start_crypto_investigation",
        description = "Start a crypto-flow investigation as a background task and return immediately with task_id. \
            Poll get_analysis_task for stage and progress. On completion the task contains analysis_id. \
            Cancellation is cooperative and is checked between crypto scan, digest correlation, evidence synthesis, and save."
    )]
    fn start_crypto_investigation(
        &self,
        Parameters(req): Parameters<InvestigateCryptoFlowRequest>,
    ) -> Result<String, String> {
        let sid = self.resolve_session(req.session_id.clone())?;
        let task = self
            .engine
            .create_analysis_task(&sid, "crypto_flow")
            .map_err(|error| error.to_string())?;
        let task_id = task.task_id.clone();
        let worker_task_id = task_id.clone();
        let engine = self.engine.clone();
        tokio::task::spawn_blocking(move || {
            let outcome = (|| -> Result<(), String> {
                engine
                    .start_analysis_task(&worker_task_id, "starting")
                    .map_err(|error| error.to_string())?;
                let mut checkpoint = |stage: &str, progress: u8| -> Result<(), String> {
                    if engine.analysis_task_cancelled(&worker_task_id) {
                        let _ = engine.mark_analysis_task_cancelled(&worker_task_id);
                        return Err(TASK_CANCELLED.to_string());
                    }
                    engine
                        .update_analysis_task(&worker_task_id, stage, progress)
                        .map_err(|error| error.to_string())
                };
                let (result, evidence, request) =
                    run_crypto_flow_analysis(&engine, &sid, req, &mut checkpoint)?;
                checkpoint("saving", 98)?;
                let record = engine
                    .save_analysis(
                        &sid,
                        "crypto_flow",
                        "Crypto flow investigation",
                        request,
                        result,
                        evidence,
                    )
                    .map_err(|error| error.to_string())?;
                if engine.analysis_task_cancelled(&worker_task_id) {
                    let _ = engine.delete_analysis(&sid, &record.analysis_id);
                    let _ = engine.mark_analysis_task_cancelled(&worker_task_id);
                    return Err(TASK_CANCELLED.to_string());
                }
                engine
                    .complete_analysis_task(&worker_task_id, &record.analysis_id)
                    .map_err(|error| error.to_string())?;
                Ok(())
            })();
            if let Err(error) = outcome {
                if error == TASK_CANCELLED {
                    let _ = engine.mark_analysis_task_cancelled(&worker_task_id);
                } else {
                    let _ = engine.fail_analysis_task(&worker_task_id, &error);
                }
            }
        });
        Ok(json(&serde_json::json!({
            "task": task,
            "task_id": task_id,
            "poll_with": "get_analysis_task",
            "cancel_with": "cancel_analysis_task",
        })))
    }

    #[tool(
        name = "get_analysis_task",
        description = "Get background analysis task status, stage, progress, cancellation state, error, and final analysis_id."
    )]
    fn get_analysis_task(
        &self,
        Parameters(req): Parameters<GetAnalysisTaskRequest>,
    ) -> Result<String, String> {
        let sid = self.resolve_session(req.session_id)?;
        let task = self
            .engine
            .get_analysis_task(&sid, &req.task_id)
            .map_err(|error| error.to_string())?;
        Ok(json(&task))
    }

    #[tool(
        name = "list_analysis_tasks",
        description = "List recent background analysis tasks for the current trace session."
    )]
    fn list_analysis_tasks(
        &self,
        Parameters(req): Parameters<ListAnalysisTasksRequest>,
    ) -> Result<String, String> {
        let sid = self.resolve_session(req.session_id)?;
        let tasks = self
            .engine
            .list_analysis_tasks(&sid, req.limit)
            .map_err(|error| error.to_string())?;
        Ok(json(&serde_json::json!({
            "session_id": sid,
            "count": tasks.len(),
            "tasks": tasks,
        })))
    }

    #[tool(
        name = "cancel_analysis_task",
        description = "Request cooperative cancellation of a queued or running background analysis task."
    )]
    fn cancel_analysis_task(
        &self,
        Parameters(req): Parameters<CancelAnalysisTaskRequest>,
    ) -> Result<String, String> {
        let sid = self.resolve_session(req.session_id)?;
        let requested = self
            .engine
            .cancel_analysis_task(&sid, &req.task_id)
            .map_err(|error| error.to_string())?;
        let task = self.engine.get_analysis_task(&sid, &req.task_id).ok();
        Ok(json(&serde_json::json!({
            "session_id": sid,
            "task_id": req.task_id,
            "cancellation_requested": requested,
            "task": task,
        })))
    }

    #[tool(
        name = "save_analysis_recipe",
        description = "Save a reusable AI analysis recipe for the current trace. Supported workflows are forward_to_sinks, known_digest_flow, crypto_investigation, and auto_investigation. Defaults are persisted with the trace and merged with inputs supplied to run_analysis_recipe."
    )]
    fn save_analysis_recipe(
        &self,
        Parameters(req): Parameters<SaveAnalysisRecipeRequest>,
    ) -> Result<String, String> {
        let sid = self.resolve_session(req.session_id)?;
        if req.name.trim().is_empty() {
            return Err("Recipe name cannot be empty".to_string());
        }
        if !supported_recipe_workflow(&req.workflow) {
            return Err(format!("Unsupported recipe workflow: {}", req.workflow));
        }
        let defaults = if req.defaults.is_null() {
            serde_json::json!({})
        } else if req.defaults.is_object() {
            req.defaults
        } else {
            return Err("Recipe defaults must be a JSON object".to_string());
        };
        let definition = serde_json::json!({
            "name": req.name.trim(),
            "description": req.description,
            "workflow": req.workflow,
            "defaults": defaults,
            "built_in": false,
        });
        let record = self
            .engine
            .save_analysis(
                &sid,
                "analysis_recipe",
                req.name.trim(),
                definition.clone(),
                definition.clone(),
                AnalysisEvidence::default(),
            )
            .map_err(|error| error.to_string())?;
        Ok(json(&serde_json::json!({
            "recipe_id": record.analysis_id,
            "saved": true,
            "recipe": definition,
        })))
    }

    #[tool(
        name = "list_analysis_recipes",
        description = "List built-in and saved analysis recipes available for the current trace session."
    )]
    fn list_analysis_recipes(
        &self,
        Parameters(req): Parameters<ListAnalysisRecipesRequest>,
    ) -> Result<String, String> {
        let sid = self.resolve_session(req.session_id)?;
        let mut recipes = built_in_recipes();
        let saved = self
            .engine
            .list_analyses(&sid, Some("analysis_recipe"), 100)
            .map_err(|error| error.to_string())?;
        for summary in saved {
            let record = self
                .engine
                .get_analysis(&sid, &summary.analysis_id)
                .map_err(|error| error.to_string())?;
            recipes.push(serde_json::json!({
                "recipe_id": record.analysis_id,
                "name": record.result.get("name"),
                "description": record.result.get("description"),
                "workflow": record.result.get("workflow"),
                "defaults": record.result.get("defaults"),
                "built_in": false,
                "created_at_ms": record.created_at_ms,
            }));
        }
        Ok(json(&serde_json::json!({
            "session_id": sid,
            "count": recipes.len(),
            "recipes": recipes,
        })))
    }

    #[tool(
        name = "run_analysis_recipe",
        description = "Run a built-in or saved analysis recipe. Runtime inputs override saved defaults. The completed recipe run is saved under a new analysis_id and can be compared, exported, or retrieved later."
    )]
    async fn run_analysis_recipe(
        &self,
        Parameters(req): Parameters<RunAnalysisRecipeRequest>,
    ) -> Result<String, String> {
        let sid = self.resolve_session(req.session_id.clone())?;
        let engine = self.engine.clone();
        blocking(move || {
            let (mut result, evidence, request) = run_recipe_analysis(&engine, &sid, req)?;
            let recipe_name = result
                .get("recipe_name")
                .and_then(|value| value.as_str())
                .unwrap_or("Analysis recipe");
            let record = engine
                .save_analysis(
                    &sid,
                    "recipe_run",
                    &format!("Recipe: {recipe_name}"),
                    request,
                    result.clone(),
                    evidence,
                )
                .map_err(|error| error.to_string())?;
            result["analysis_id"] = serde_json::json!(record.analysis_id);
            result["saved"] = serde_json::json!(true);
            Ok(json(&result))
        })
        .await
    }

    #[tool(
        name = "delete_analysis_recipe",
        description = "Delete a saved custom analysis recipe. Built-in recipe IDs cannot be deleted."
    )]
    fn delete_analysis_recipe(
        &self,
        Parameters(req): Parameters<DeleteAnalysisRecipeRequest>,
    ) -> Result<String, String> {
        let sid = self.resolve_session(req.session_id)?;
        if built_in_recipes().iter().any(|recipe| {
            recipe.get("recipe_id").and_then(|value| value.as_str()) == Some(req.recipe_id.as_str())
        }) {
            return Err("Built-in recipes cannot be deleted".to_string());
        }
        let record = self
            .engine
            .get_analysis(&sid, &req.recipe_id)
            .map_err(|error| error.to_string())?;
        if record.kind != "analysis_recipe" {
            return Err(format!("Analysis {} is not a recipe", req.recipe_id));
        }
        let deleted = self
            .engine
            .delete_analysis(&sid, &req.recipe_id)
            .map_err(|error| error.to_string())?;
        Ok(json(&serde_json::json!({
            "recipe_id": req.recipe_id,
            "deleted": deleted,
        })))
    }

    #[tool(
        name = "list_analyses",
        description = "List saved AI analysis records for a trace session. Returns compact metadata, \
            evidence highlights, warning counts, and analysis IDs for later retrieval or comparison."
    )]
    fn list_analyses(
        &self,
        Parameters(req): Parameters<ListAnalysesRequest>,
    ) -> Result<String, String> {
        let sid = self.resolve_session(req.session_id)?;
        let records = self
            .engine
            .list_analyses(&sid, req.kind.as_deref(), req.limit)
            .map_err(|error| error.to_string())?;
        Ok(json(&serde_json::json!({
            "session_id": sid,
            "count": records.len(),
            "analyses": records,
        })))
    }

    #[tool(
        name = "get_analysis",
        description = "Retrieve one saved analysis by analysis_id, including its original request, \
            structured result, normalized evidence, limitations, and suggested next actions."
    )]
    fn get_analysis(
        &self,
        Parameters(req): Parameters<GetAnalysisRequest>,
    ) -> Result<Json<GetAnalysisResponse>, String> {
        let sid = self.resolve_session(req.session_id)?;
        let record = self
            .engine
            .get_analysis(&sid, &req.analysis_id)
            .map_err(|error| error.to_string())?;
        let include = req.include.as_deref().unwrap_or("summary");
        let mut result = record.result.clone();
        let sequence_field = if result.get("tainted_seqs").is_some() {
            Some("tainted_seqs")
        } else if result.get("affected_seqs").is_some() {
            Some("affected_seqs")
        } else {
            None
        };
        let page = if include.eq_ignore_ascii_case("lines") {
            sequence_field.and_then(|field| {
                let values = result.get(field)?.as_array()?;
                let offset = req.offset as usize;
                let limit = req.limit.clamp(1, 1000) as usize;
                let items = values
                    .iter()
                    .skip(offset)
                    .take(limit)
                    .cloned()
                    .collect::<Vec<_>>();
                Some(AnalysisPageResponse {
                    field: field.to_string(),
                    offset: req.offset,
                    count: items.len(),
                    total: values.len(),
                    has_more: offset.saturating_add(items.len()) < values.len(),
                    items,
                })
            })
        } else {
            None
        };
        if !include.eq_ignore_ascii_case("full") {
            if let Some(field) = sequence_field {
                let count = result
                    .get(field)
                    .and_then(|value| value.as_array())
                    .map_or(0, Vec::len);
                result.as_object_mut().map(|object| {
                    object.remove(field);
                    object.insert(format!("{field}_count"), serde_json::json!(count));
                });
            }
        }
        Ok(Json(GetAnalysisResponse {
            analysis_id: record.analysis_id,
            kind: record.kind,
            title: record.title,
            created_at_ms: record.created_at_ms,
            request: record.request,
            result,
            evidence: serde_json::to_value(record.evidence).map_err(|e| e.to_string())?,
            page,
        }))
    }

    #[tool(
        name = "export_analysis_report",
        description = "Export any saved analysis_id as a structured JSON or Markdown report. Provide output_path to write a file, or omit it to return report content inline for another AI step."
    )]
    fn export_analysis_report(
        &self,
        Parameters(req): Parameters<ExportAnalysisReportRequest>,
    ) -> Result<String, String> {
        let sid = self.resolve_session(req.session_id)?;
        let format = req.format.to_ascii_lowercase();
        if !matches!(format.as_str(), "json" | "markdown" | "md") {
            return Err("Report format must be markdown or json".to_string());
        }
        if let Some(output_path) = req.output_path {
            let mut exported = self
                .engine
                .export_analysis_report(&sid, &req.analysis_id, &format, &output_path)
                .map_err(|error| error.to_string())?;
            if req.include_content {
                exported.content = Some(
                    self.engine
                        .render_analysis_report(&sid, &req.analysis_id, &format)
                        .map_err(|error| error.to_string())?,
                );
            }
            return Ok(json(&exported));
        }

        let content = self
            .engine
            .render_analysis_report(&sid, &req.analysis_id, &format)
            .map_err(|error| error.to_string())?;
        Ok(json(&serde_json::json!({
            "analysis_id": req.analysis_id,
            "format": if format == "md" { "markdown" } else { format.as_str() },
            "output_path": serde_json::Value::Null,
            "bytes_written": content.len(),
            "content": content,
        })))
    }

    #[tool(
        name = "compare_analyses",
        description = "Compare two to ten saved analyses from the same trace. Returns common and unique \
            algorithms, digests, functions, modules, strings, memory addresses, operations, and warnings."
    )]
    fn compare_analyses(
        &self,
        Parameters(req): Parameters<CompareAnalysesRequest>,
    ) -> Result<String, String> {
        let sid = self.resolve_session(req.session_id)?;
        let comparison = self
            .engine
            .compare_analyses(&sid, &req.analysis_ids)
            .map_err(|error| error.to_string())?;
        Ok(json(&comparison))
    }

    #[tool(
        name = "compare_traces",
        description = "Compare two open trace sessions by module-relative executed instruction locations and counts. Also clusters relocated functions by normalized executed mnemonic shape, returning both version offsets and jumpable sample sequences. The result is saved under analysis_id for reports and later review."
    )]
    async fn compare_traces(
        &self,
        Parameters(req): Parameters<CompareTracesRequest>,
    ) -> Result<String, String> {
        let left_sid = self.resolve_session(req.session_id)?;
        let right_sid = req.other_session_id;
        let engine = self.engine.clone();
        blocking(move || {
            let mut checkpoint = |_: &str, _: u8| Ok(());
            let (result, evidence, request) = run_trace_diff_analysis(
                &engine,
                &left_sid,
                &right_sid,
                req.start_seq,
                req.end_seq,
                req.max_items,
                &mut checkpoint,
            )?;
            let record = engine
                .save_analysis(
                    &left_sid,
                    "trace_diff",
                    "Dynamic trace comparison",
                    request,
                    result.clone(),
                    evidence,
                )
                .map_err(|error| error.to_string())?;
            let mut response = result;
            response["analysis_id"] = serde_json::json!(record.analysis_id);
            response["saved"] = serde_json::json!(true);
            Ok(json(&response))
        })
        .await
    }

    #[tool(
        name = "start_trace_diff",
        description = "Start compare_traces as a cancellable background task for large traces. Poll get_analysis_task until completion; the task returns an analysis_id saved on the left/base session."
    )]
    fn start_trace_diff(
        &self,
        Parameters(req): Parameters<CompareTracesRequest>,
    ) -> Result<String, String> {
        let left_sid = self.resolve_session(req.session_id)?;
        let right_sid = req.other_session_id;
        let task = self
            .engine
            .create_analysis_task(&left_sid, "trace_diff")
            .map_err(|error| error.to_string())?;
        let task_id = task.task_id.clone();
        let worker_task_id = task_id.clone();
        let engine = self.engine.clone();
        tokio::task::spawn_blocking(move || {
            let outcome = (|| -> Result<(), String> {
                engine
                    .start_analysis_task(&worker_task_id, "starting")
                    .map_err(|error| error.to_string())?;
                let mut checkpoint = |stage: &str, progress: u8| -> Result<(), String> {
                    if engine.analysis_task_cancelled(&worker_task_id) {
                        let _ = engine.mark_analysis_task_cancelled(&worker_task_id);
                        return Err(TASK_CANCELLED.to_string());
                    }
                    engine
                        .update_analysis_task(&worker_task_id, stage, progress)
                        .map_err(|error| error.to_string())
                };
                let (result, evidence, request) = run_trace_diff_analysis(
                    &engine,
                    &left_sid,
                    &right_sid,
                    req.start_seq,
                    req.end_seq,
                    req.max_items,
                    &mut checkpoint,
                )?;
                checkpoint("saving", 98)?;
                let record = engine
                    .save_analysis(
                        &left_sid,
                        "trace_diff",
                        "Dynamic trace comparison",
                        request,
                        result,
                        evidence,
                    )
                    .map_err(|error| error.to_string())?;
                if engine.analysis_task_cancelled(&worker_task_id) {
                    let _ = engine.delete_analysis(&left_sid, &record.analysis_id);
                    let _ = engine.mark_analysis_task_cancelled(&worker_task_id);
                    return Err(TASK_CANCELLED.to_string());
                }
                engine
                    .complete_analysis_task(&worker_task_id, &record.analysis_id)
                    .map_err(|error| error.to_string())?;
                Ok(())
            })();
            if let Err(error) = outcome {
                if error == TASK_CANCELLED {
                    let _ = engine.mark_analysis_task_cancelled(&worker_task_id);
                } else {
                    let _ = engine.fail_analysis_task(&worker_task_id, &error);
                }
            }
        });
        Ok(json(&serde_json::json!({
            "task": task,
            "task_id": task_id,
            "poll_with": "get_analysis_task",
            "cancel_with": "cancel_analysis_task",
        })))
    }

    #[tool(
        name = "delete_analysis",
        description = "Delete a saved analysis record from the current trace session."
    )]
    fn delete_analysis(
        &self,
        Parameters(req): Parameters<DeleteAnalysisRequest>,
    ) -> Result<String, String> {
        let sid = self.resolve_session(req.session_id)?;
        let deleted = self
            .engine
            .delete_analysis(&sid, &req.analysis_id)
            .map_err(|error| error.to_string())?;
        Ok(json(&serde_json::json!({
            "session_id": sid,
            "analysis_id": req.analysis_id,
            "deleted": deleted,
        })))
    }

    #[tool(
        name = "analyze_function",
        description = "Analyze functions. Three modes: \
            (1) node_id: detailed analysis of one call with entry args (X0-X7) and return value (X0). \
            (2) func_name: find all calls matching a name (partial, case-insensitive). \
            (3) No arguments: list all functions with pagination (use offset/limit)."
    )]
    fn analyze_function(
        &self,
        Parameters(req): Parameters<AnalyzeFunctionRequest>,
    ) -> Result<String, String> {
        let sid = self.resolve_session(req.session_id)?;

        if let Some(node_id) = req.node_id {
            // Mode 1: 按 node_id 分析函数调用详情
            let nodes = self
                .engine
                .get_call_tree_children(&sid, node_id, true)
                .map_err(|e| e.to_string())?;
            let node = nodes
                .first()
                .ok_or_else(|| format!("Node {} not found", node_id))?;

            // 获取入口参数 X0-X7
            let entry_regs = self
                .engine
                .get_registers_at(&sid, node.entry_seq)
                .unwrap_or_default();
            let mut args = serde_json::Map::new();
            for i in 0..=7 {
                let reg_name = format!("X{}", i);
                if let Some(val) = entry_regs.get(&reg_name) {
                    args.insert(reg_name, serde_json::json!(val));
                }
            }

            // 获取返回值
            let return_value = if node.exit_seq > node.entry_seq {
                self.engine
                    .get_registers_at(&sid, node.exit_seq)
                    .ok()
                    .and_then(|regs| regs.get("X0").cloned())
            } else {
                None
            };

            // 子调用
            let children = nodes.iter().skip(1).collect::<Vec<_>>();
            let sub_calls: Vec<serde_json::Value> = children
                .iter()
                .map(|c| {
                    serde_json::json!({
                        "node_id": c.id,
                        "func_name": c.func_name,
                        "func_addr": c.func_addr,
                        "entry_seq": c.entry_seq,
                        "exit_seq": c.exit_seq,
                        "line_count": c.line_count,
                    })
                })
                .collect();

            Ok(json(&serde_json::json!({
                "node_id": node.id,
                "func_name": node.func_name,
                "func_addr": node.func_addr,
                "entry_seq": node.entry_seq,
                "exit_seq": node.exit_seq,
                "line_count": node.line_count,
                "args": args,
                "return_value": return_value,
                "sub_calls": sub_calls,
                "sub_call_count": sub_calls.len(),
            })))
        } else if let Some(ref func_name) = req.func_name {
            // Mode 2: 按名称搜索函数
            let result = self
                .engine
                .get_function_calls(&sid)
                .map_err(|e| e.to_string())?;

            let query_lower = func_name.to_lowercase();
            let matched: Vec<serde_json::Value> = result
                .functions
                .iter()
                .filter(|f| f.func_name.to_lowercase().contains(&query_lower))
                .map(|f| {
                    let occs: Vec<serde_json::Value> = f
                        .occurrences
                        .iter()
                        .take(50)
                        .map(|o| {
                            serde_json::json!({
                                "seq": o.seq,
                                "summary": o.summary,
                            })
                        })
                        .collect();
                    let total_occs = f.occurrences.len();
                    serde_json::json!({
                        "func_name": f.func_name,
                        "call_count": total_occs,
                        "is_jni": f.is_jni,
                        "occurrences": occs,
                        "occurrences_truncated": total_occs > 50,
                    })
                })
                .collect();

            Ok(json(&serde_json::json!({
                "query": func_name,
                "matched_functions": matched.len(),
                "functions": matched,
                "hint": if matched.is_empty() {
                    "No functions matched. Try a broader search term or use analyze_function with no arguments to list all functions."
                } else {
                    "Use analyze_function with node_id from get_call_tree to inspect a specific call's arguments and return value."
                },
            })))
        } else {
            // Mode 3: list all functions with pagination
            let result = self
                .engine
                .get_function_calls(&sid)
                .map_err(|e| e.to_string())?;

            let limit = req.limit.min(100) as usize;
            let total = result.functions.len();
            let page: Vec<serde_json::Value> = result
                .functions
                .iter()
                .skip(req.offset as usize)
                .take(limit)
                .map(|f| {
                    serde_json::json!({
                        "func_name": f.func_name,
                        "call_count": f.occurrences.len(),
                        "is_jni": f.is_jni,
                    })
                })
                .collect();

            Ok(json(&serde_json::json!({
                "functions": page,
                "total": total,
                "total_calls": result.total_calls,
                "offset": req.offset,
                "has_more": (req.offset as usize + page.len()) < total,
                "hint": "Use analyze_function with func_name to search, or node_id for detailed analysis with entry arguments.",
            })))
        }
    }

    #[tool(
        name = "analyze_crypto",
        description = "Detect cryptographic algorithms in the trace with surrounding code context. \
            Scans for magic constants of known algorithms (AES, SHA256, MD5, DES, etc.). \
            Returns each detection with context instructions. \
            Use taint_analysis on detection points to trace key/data sources."
    )]
    async fn analyze_crypto(
        &self,
        Parameters(req): Parameters<AnalyzeCryptoRequest>,
    ) -> Result<String, String> {
        let sid = self.resolve_session(req.session_id)?;
        let engine = self.engine.clone();
        blocking(move || {
            let ctx_count = req.context_lines.min(10);

            // 1. 尝试缓存，否则扫描
            let scan_result = if let Ok(Some(cached)) = engine.load_crypto_cache(&sid) {
                cached
            } else {
                engine.scan_crypto(&sid)
                    .map_err(|e| e.to_string())?
            };

            // 2. 为每个匹配收集上下文行
            let mut matches_output: Vec<serde_json::Value> = Vec::new();
            for m in &scan_result.matches {
                let start = m.seq.saturating_sub(ctx_count);
                let end = m.seq.saturating_add(ctx_count);
                let ctx_seqs: Vec<u32> = (start..=end).collect();
                let ctx_lines = engine.get_lines(&sid, &ctx_seqs)
                    .unwrap_or_default();

                let context: Vec<serde_json::Value> = ctx_lines.iter().map(|l| {
                    let mut obj = compact_line(l);
                    obj.as_object_mut().map(|o| {
                        o.insert("is_match".to_string(), serde_json::json!(l.seq == m.seq));
                    });
                    obj
                }).collect();

                matches_output.push(serde_json::json!({
                    "algorithm": m.algorithm,
                    "magic_hex": m.magic_hex,
                    "seq": m.seq,
                    "address": m.address,
                    "disasm": m.disasm,
                    "context": context,
                }));
            }

            Ok(json(&serde_json::json!({
                "algorithms_found": scan_result.algorithms_found,
                "match_count": scan_result.matches.len(),
                "matches": matches_output,
                "total_lines_scanned": scan_result.total_lines_scanned,
                "hint": "Use taint_analysis with 'reg:X0@<seq>' on a match's seq to trace the key/data source.",
            })))
        }).await
    }

    #[tool(
        name = "analyze_crypto_functions",
        description = "Identify likely cryptographic FUNCTIONS (not just isolated constants). \
            Aggregates magic-constant hits and dedicated ARM64 crypto instructions (AES/SHA/SM3/SM4/CRC32/PMULL) \
            by their enclosing function, scores each with explainable High/Medium/Low confidence, and reports \
            entry X0-X7, return X0, and any call annotation. Saves an analysis_id for get_analysis/compare_analyses."
    )]
    async fn analyze_crypto_functions(
        &self,
        Parameters(req): Parameters<AnalyzeCryptoFunctionsRequest>,
    ) -> Result<String, String> {
        let sid = self.resolve_session(req.session_id)?;
        let engine = self.engine.clone();
        let max_candidates = req.max_candidates;
        blocking(move || {
            let report = engine
                .analyze_crypto_functions(&sid, CryptoFunctionsOptions { max_candidates })
                .map_err(|e| e.to_string())?;

            let mut result =
                serde_json::to_value(&report).map_err(|e| format!("serialize failed: {e}"))?;

            let mut evidence = AnalysisEvidence::default();
            for c in &report.candidates {
                for a in &c.algorithms {
                    push_unique(&mut evidence.algorithms, a.clone());
                }
                if let Some(name) = &c.func_name {
                    push_unique(&mut evidence.functions, name.clone());
                }
                push_unique(&mut evidence.functions, c.func_addr.clone());
                push_unique(&mut evidence.addresses, c.func_addr.clone());
                for k in c.crypto_insn_counts.keys() {
                    push_unique(&mut evidence.operations, k.clone());
                }
            }
            evidence.algorithms.truncate(100);
            evidence.functions.truncate(100);
            evidence.addresses.truncate(200);
            evidence.operations.truncate(50);

            let request_record = serde_json::json!({ "max_candidates": max_candidates });
            match engine.save_analysis(
                &sid,
                "crypto_functions",
                "Function-level crypto identification",
                request_record,
                result.clone(),
                evidence,
            ) {
                Ok(record) => {
                    result["analysis_id"] = serde_json::json!(record.analysis_id);
                    result["saved"] = serde_json::json!(true);
                    result["compare_with"] = serde_json::json!("compare_analyses");
                }
                Err(e) => {
                    result["saved"] = serde_json::json!(false);
                    result["save_error"] = serde_json::json!(e.to_string());
                }
            }
            Ok(json(&result))
        })
        .await
    }

    #[tool(
        name = "analyze_crypto_materials",
        description = "Build a unified evidence-ranked index of runtime cryptographic material: raw/derived keys, password, salt, IV, nonce, counter, plaintext/ciphertext, digest/MAC, AAD and authentication tags. Reconstructs MD5/SHA/HMAC/PBKDF2 formulas from call ABI plus hexdumps and imports semantically verified AES material. Only deterministic recomputation opens the Verified gate; API roles remain Related. Saves an analysis_id."
    )]
    async fn analyze_crypto_materials(
        &self,
        Parameters(req): Parameters<AnalyzeCryptoMaterialsRequest>,
    ) -> Result<String, String> {
        let sid = self.resolve_session(req.session_id)?;
        let engine = self.engine.clone();
        blocking(move || {
            let report = engine
                .analyze_crypto_materials(
                    &sid,
                    CryptoMaterialOptions {
                        max_materials: req.max_materials.clamp(1, 5_000),
                        include_unknown: req.include_unknown,
                    },
                )
                .map_err(|error| error.to_string())?;
            let mut evidence = AnalysisEvidence::default();
            for material in &report.materials {
                if let Some(algorithm) = &material.algorithm {
                    push_unique(&mut evidence.algorithms, algorithm.clone());
                }
                if let Some(function) = &material.function_name {
                    push_unique(&mut evidence.functions, function.clone());
                }
                if let Some(address) = &material.address {
                    push_unique(&mut evidence.addresses, address.clone());
                }
                if let Some(bytes) = &material.bytes_hex {
                    match material.kind {
                        CryptoMaterialKind::Key
                        | CryptoMaterialKind::ExpandedKey
                        | CryptoMaterialKind::DerivedKey
                        | CryptoMaterialKind::Password
                        | CryptoMaterialKind::Salt => {
                            push_unique(&mut evidence.key_strings, bytes.clone())
                        }
                        CryptoMaterialKind::Digest
                        | CryptoMaterialKind::Mac
                        | CryptoMaterialKind::AuthTag => {
                            push_unique(&mut evidence.digests, bytes.clone())
                        }
                        _ => {}
                    }
                }
                push_unique(&mut evidence.operations, material.role.clone());
            }
            for formula in &report.formulas {
                push_unique(&mut evidence.operations, formula.expression.clone());
            }
            evidence.algorithms.truncate(100);
            evidence.functions.truncate(100);
            evidence.addresses.truncate(200);
            evidence.key_strings.truncate(100);
            evidence.digests.truncate(100);
            evidence.operations.truncate(200);

            let mut result = serde_json::to_value(&report)
                .map_err(|error| format!("serialize failed: {error}"))?;
            let record = engine
                .save_analysis(
                    &sid,
                    "crypto_materials",
                    "Cryptographic material and formula index",
                    serde_json::json!({
                        "maxMaterials": req.max_materials,
                        "includeUnknown": req.include_unknown,
                    }),
                    result.clone(),
                    evidence,
                )
                .map_err(|error| error.to_string())?;
            result["analysisId"] = serde_json::json!(record.analysis_id);
            result["saved"] = serde_json::json!(true);
            Ok(json(&result))
        })
        .await
    }

    #[tool(
        name = "compare_crypto_material_traces",
        description = "Compare two to sixteen controlled traces after indexing crypto material. Pairs sharing input_group are checked for changing ranges inside semantically verified digest inputs. Returns saltOrNonceCandidate ranges with exact offsets and bytes, but deliberately keeps the verification gate closed until API provenance or additional controlled runs identify the role."
    )]
    async fn compare_crypto_material_traces(
        &self,
        Parameters(req): Parameters<CompareCryptoMaterialTracesRequest>,
    ) -> Result<String, String> {
        if !(2..=16).contains(&req.cases.len()) {
            return Err("Two to sixteen trace cases are required".to_string());
        }
        let first_session = req.cases[0].session_id.clone();
        let request = CryptoMaterialMultiTraceRequest {
            cases: req
                .cases
                .into_iter()
                .map(|case| CryptoMaterialTraceCase {
                    session_id: case.session_id,
                    label: case.label,
                    input_group: case.input_group,
                })
                .collect(),
        };
        let engine = self.engine.clone();
        blocking(move || {
            let report = engine
                .compare_crypto_material_traces(request)
                .map_err(|error| error.to_string())?;
            let mut evidence = AnalysisEvidence::default();
            for candidate in &report.dynamic_parameter_candidates {
                push_unique(&mut evidence.algorithms, candidate.algorithm.clone());
                if let Some(function) = &candidate.function_name {
                    push_unique(&mut evidence.functions, function.clone());
                }
                push_unique(
                    &mut evidence.operations,
                    format!(
                        "{}@+{}:{}->{}",
                        candidate.role_hint,
                        candidate.byte_offset,
                        candidate.left_variable_hex,
                        candidate.right_variable_hex
                    ),
                );
            }
            let mut result = serde_json::to_value(&report)
                .map_err(|error| format!("serialize failed: {error}"))?;
            let record = engine
                .save_analysis(
                    &first_session,
                    "crypto_material_diff",
                    "Controlled multi-trace crypto material comparison",
                    serde_json::json!({ "caseCount": report.cases.len() }),
                    result.clone(),
                    evidence,
                )
                .map_err(|error| error.to_string())?;
            result["analysisId"] = serde_json::json!(record.analysis_id);
            result["saved"] = serde_json::json!(true);
            Ok(json(&result))
        })
        .await
    }

    #[tool(
        name = "generate_frida_hook",
        description = "Generate a bounded ARM64 Frida 16.x Interceptor hook for a module export or module-relative offset. Captures selected X0-X7 arguments, SP/LR/PC, return value, optional backtrace, and optional Stalker calls/blocks/instructions. The script emits structured trace-ui/frida-hook-v1 send() messages and is intended to be loaded manually by the user."
    )]
    fn generate_frida_hook(
        &self,
        Parameters(req): Parameters<GenerateFridaHookRequest>,
    ) -> Result<String, String> {
        let request = FridaHookRequest {
            module_name: req.module_name,
            symbol: req.symbol,
            offset: req.offset,
            function_name: req.function_name,
            arguments: req
                .arguments
                .into_iter()
                .map(|argument| FridaArgumentSpec {
                    index: argument.index,
                    label: argument.label,
                    kind: match argument.kind {
                        FridaArgumentKindRequest::Integer => FridaArgumentKind::Integer,
                        FridaArgumentKindRequest::Pointer => FridaArgumentKind::Pointer,
                        FridaArgumentKindRequest::Utf8String => FridaArgumentKind::Utf8String,
                        FridaArgumentKindRequest::Utf16String => FridaArgumentKind::Utf16String,
                        FridaArgumentKindRequest::ByteArray => FridaArgumentKind::ByteArray,
                    },
                    direction: match argument.direction {
                        FridaCaptureDirectionRequest::Input => FridaCaptureDirection::Input,
                        FridaCaptureDirectionRequest::Output => FridaCaptureDirection::Output,
                        FridaCaptureDirectionRequest::InOut => FridaCaptureDirection::InOut,
                    },
                    length: argument.length,
                    length_arg: argument.length_arg,
                })
                .collect(),
            capture_registers: req.capture_registers,
            capture_return: req.capture_return,
            capture_backtrace: req.capture_backtrace,
            stalker: match req.stalker {
                FridaStalkerModeRequest::Off => FridaStalkerMode::Off,
                FridaStalkerModeRequest::Calls => FridaStalkerMode::Calls,
                FridaStalkerModeRequest::Blocks => FridaStalkerMode::Blocks,
                FridaStalkerModeRequest::Instructions => FridaStalkerMode::Instructions,
            },
            stalker_duration_ms: req.stalker_duration_ms,
            max_bytes: req.max_bytes,
        };
        Ok(json(&build_frida_hook(&request)?))
    }

    #[tool(
        name = "analyze_ollvm",
        description = "Build an ASLR-robust dynamic CFG from executed module-relative offsets and rank OLLVM control-flow-flattening dispatcher and opaque-branch candidates. Call-tree node scoping excludes child calls by default. Results are dynamic evidence only: unexecuted blocks and alternate paths are not inferred. Saves an analysis_id."
    )]
    async fn analyze_ollvm(
        &self,
        Parameters(req): Parameters<AnalyzeOllvmRequest>,
    ) -> Result<String, String> {
        let sid = self.resolve_session(req.session_id)?;
        let engine = self.engine.clone();
        blocking(move || {
            let options = OllvmAnalysisOptions {
                node_id: req.node_id,
                module_name: req.module_name,
                start_seq: req.start_seq,
                end_seq: req.end_seq,
                include_child_calls: req.include_child_calls,
                max_blocks: req.max_blocks,
                max_edges: req.max_edges,
            };
            let request_record = serde_json::to_value(&options)
                .map_err(|error| format!("serialize request failed: {error}"))?;
            let report = engine
                .analyze_ollvm(&sid, options)
                .map_err(|error| error.to_string())?;
            let mut evidence = AnalysisEvidence::default();
            push_unique(&mut evidence.modules, report.scope.module_name.clone());
            for candidate in &report.dispatcher_candidates {
                push_unique(&mut evidence.addresses, candidate.start_offset.clone());
                push_unique(
                    &mut evidence.operations,
                    format!("dispatcher_candidate:{}", candidate.start_offset),
                );
            }
            for candidate in &report.opaque_branch_candidates {
                push_unique(&mut evidence.addresses, candidate.branch_offset.clone());
                push_unique(
                    &mut evidence.operations,
                    format!("opaque_branch_candidate:{}", candidate.branch_offset),
                );
            }
            evidence.warnings.extend(report.limitations.clone());
            let mut result = serde_json::to_value(&report)
                .map_err(|error| format!("serialize report failed: {error}"))?;
            let record = engine
                .save_analysis(
                    &sid,
                    "ollvm_dynamic_cfg",
                    "Dynamic CFG and OLLVM candidate analysis",
                    request_record,
                    result.clone(),
                    evidence,
                )
                .map_err(|error| error.to_string())?;
            result["analysisId"] = serde_json::json!(record.analysis_id);
            result["saved"] = serde_json::json!(true);
            Ok(json(&result))
        })
        .await
    }

    #[tool(
        name = "generate_ida_ollvm_script",
        description = "Analyze a trace-scoped function/range and generate a manual IDAPython bridge. The script aligns module offsets to IDA imagebase, adds dynamic CFG and OLLVM candidate comments/colors, keeps user xrefs opt-in, and can export IDA names/comments back as trace-ui/ida-ollvm-v1 JSON."
    )]
    async fn generate_ida_ollvm_script(
        &self,
        Parameters(req): Parameters<GenerateIdaOllvmScriptRequest>,
    ) -> Result<String, String> {
        let sid = self.resolve_session(req.session_id)?;
        let engine = self.engine.clone();
        blocking(move || {
            let report = engine
                .analyze_ollvm(
                    &sid,
                    OllvmAnalysisOptions {
                        node_id: req.node_id,
                        module_name: req.module_name,
                        start_seq: req.start_seq,
                        end_seq: req.end_seq,
                        include_child_calls: req.include_child_calls,
                        max_blocks: req.max_blocks,
                        max_edges: req.max_edges,
                    },
                )
                .map_err(|error| error.to_string())?;
            let generated = generate_ida_ollvm_script(
                &report,
                req.ida_image_base.as_deref(),
                req.add_user_xrefs,
            )?;
            Ok(json(&generated))
        })
        .await
    }

    #[tool(
        name = "inspect_ida_annotations",
        description = "Read and validate a trace-ui/ida-ollvm-v1 JSON file exported manually from IDA. Returns module-relative names and comments without modifying the trace or IDA database."
    )]
    async fn inspect_ida_annotations(
        &self,
        Parameters(req): Parameters<InspectIdaAnnotationsRequest>,
    ) -> Result<String, String> {
        blocking(move || {
            let bytes = std::fs::read(&req.file_path)
                .map_err(|error| format!("failed to read IDA annotations: {error}"))?;
            Ok(json(&parse_ida_annotation_bundle(&bytes)?))
        })
        .await
    }

    #[tool(
        name = "analyze_whitebox_crypto",
        description = "Identify structural candidates for software/table-driven ciphers that leave NO magic \
            constants and use NO hardware crypto instructions — exactly the case where analyze_crypto and \
            analyze_crypto_functions report nothing. Works on a SINGLE trace using recomputable structural \
            evidence: neutral input/output buffers, lookup-table regions (with .so offsets), and a repetition \
            heuristic, dynamic encoding-boundary candidates, and optional static ELF table reconciliation. \
            Structural evidence does NOT prove an algorithm or white-box implementation; verified \
            requires semantic recomputation. Saves an analysis_id."
    )]
    async fn analyze_whitebox_crypto(
        &self,
        Parameters(req): Parameters<AnalyzeWhiteboxRequest>,
    ) -> Result<String, String> {
        let sid = self.resolve_session(req.session_id)?;
        let engine = self.engine.clone();
        let algorithm = req.algorithm;
        let static_binary_path = req.static_binary_path;
        blocking(move || {
            let report = engine
                .analyze_whitebox(
                    &sid,
                    WhiteBoxOptions {
                        algorithm: algorithm.clone(),
                        static_binary_path: static_binary_path.clone(),
                        ..Default::default()
                    },
                )
                .map_err(|e| e.to_string())?;

            let mut result =
                serde_json::to_value(&report).map_err(|e| format!("serialize failed: {e}"))?;

            let mut evidence = AnalysisEvidence::default();
            push_unique(&mut evidence.algorithms, report.verdict.algorithm.clone());
            for t in &report.tables {
                push_unique(&mut evidence.addresses, t.base_addr.clone());
            }
            for output in &report.output_candidates {
                push_unique(&mut evidence.memory_writes, output.base_addr.clone());
            }
            evidence.algorithms.truncate(100);
            evidence.addresses.truncate(200);
            evidence.key_strings.truncate(100);

            let request_record = serde_json::json!({
                "algorithm": algorithm,
                "staticBinaryPath": static_binary_path,
            });
            match engine.save_analysis(
                &sid,
                "whitebox_crypto",
                "White-box / table-driven cipher identification",
                request_record,
                result.clone(),
                evidence,
            ) {
                Ok(record) => {
                    result["analysis_id"] = serde_json::json!(record.analysis_id);
                    result["saved"] = serde_json::json!(true);
                    result["compare_with"] = serde_json::json!("compare_analyses");
                }
                Err(e) => {
                    result["saved"] = serde_json::json!(false);
                    result["save_error"] = serde_json::json!(e.to_string());
                }
            }
            Ok(json(&result))
        })
        .await
    }

    #[tool(
        name = "compare_crypto_table_traces",
        description = "Compare normalized lookup-table fingerprints across a labeled multi-trace key/input matrix. Requires explicit key_group and input_group labels. It can classify input-dependent, input/key-independent, or key-dependent-table candidates, but always keeps verificationGateMet=false because structural table differences do not semantically prove a cipher or key."
    )]
    async fn compare_crypto_table_traces(
        &self,
        Parameters(req): Parameters<CompareWhiteboxTracesRequest>,
    ) -> Result<String, String> {
        let first_session = req
            .cases
            .first()
            .map(|case| case.session_id.clone())
            .ok_or_else(|| "Provide at least two trace cases.".to_string())?;
        let engine = self.engine.clone();
        blocking(move || {
            let request = WhiteBoxMultiTraceRequest {
                cases: req
                    .cases
                    .into_iter()
                    .map(|case| WhiteBoxTraceCaseRequest {
                        session_id: case.session_id,
                        label: case.label,
                        key_group: case.key_group,
                        input_group: case.input_group,
                        static_binary_path: case.static_binary_path,
                    })
                    .collect(),
            };
            let request_record = serde_json::to_value(&request.cases)
                .map_err(|error| format!("serialize request failed: {error}"))?;
            let report = engine
                .compare_whitebox_traces(request)
                .map_err(|error| error.to_string())?;
            let mut result = serde_json::to_value(&report)
                .map_err(|error| format!("serialize report failed: {error}"))?;
            let mut evidence = AnalysisEvidence::default();
            for case in &report.cases {
                push_unique(&mut evidence.key_strings, case.key_group.clone());
                push_unique(&mut evidence.modules, case.session_id.clone());
            }
            evidence.warnings.extend(report.limitations.clone());
            match engine.save_analysis(
                &first_session,
                "multi_trace_crypto_tables",
                "Multi-trace key-dependent table classification",
                request_record,
                result.clone(),
                evidence,
            ) {
                Ok(record) => {
                    result["analysisId"] = serde_json::json!(record.analysis_id);
                    result["saved"] = serde_json::json!(true);
                }
                Err(error) => {
                    result["saved"] = serde_json::json!(false);
                    result["saveError"] = serde_json::json!(error.to_string());
                }
            }
            Ok(json(&result))
        })
        .await
    }

    #[tool(
        name = "analyze_crypto_implementations",
        description = "Analyze software/table/obfuscated crypto implementations and perform semantic AES verification when runtime key, input, and output are observable. Returns implementation kind, key exposure, white-box status, block coverage, and a reproducer."
    )]
    async fn analyze_crypto_implementations(
        &self,
        Parameters(req): Parameters<AnalyzeWhiteboxRequest>,
    ) -> Result<Json<CryptoImplementationResponse>, String> {
        let sid = self.resolve_session(req.session_id)?;
        let engine = self.engine.clone();
        let response = blocking(move || {
            let algorithm = req.algorithm;
            let static_binary_path = req.static_binary_path;
            let report = engine.analyze_whitebox(&sid, WhiteBoxOptions {
                algorithm: algorithm.clone(),
                static_binary_path: static_binary_path.clone(),
                ..Default::default()
            }).map_err(|e| e.to_string())?;
            let mut evidence = AnalysisEvidence::default();
            push_unique(&mut evidence.algorithms, report.verdict.algorithm.clone());
            for table in &report.tables { push_unique(&mut evidence.addresses, table.base_addr.clone()); }
            for output in &report.output_candidates { push_unique(&mut evidence.memory_writes, output.base_addr.clone()); }
            let structural = serde_json::to_value(&report)
                .map_err(|error| format!("serialize failed: {error}"))?;
            let deprecation_notice = "analyze_whitebox_crypto is retained as a compatibility alias; prefer analyze_crypto_implementations".to_string();
            let stored_result = serde_json::json!({
                "structural": structural,
                "deprecationNotice": deprecation_notice,
            });
            let record = engine.save_analysis(
                &sid,
                "crypto_implementation",
                "Crypto implementation analysis",
                serde_json::json!({
                    "algorithm": algorithm,
                    "staticBinaryPath": static_binary_path,
                }),
                stored_result,
                evidence,
            ).map_err(|e| e.to_string())?;
            Ok(CryptoImplementationResponse {
                analysis_id: record.analysis_id,
                saved: true,
                structural,
                deprecation_notice,
            })
        }).await?;
        Ok(Json(response))
    }

    #[tool(
        name = "start_crypto_implementation_analysis",
        description = "Start software/table/obfuscated crypto implementation analysis in the background. Returns task_id immediately; poll get_analysis_task for the persistent analysis_id."
    )]
    fn start_crypto_implementation_analysis(
        &self,
        Parameters(req): Parameters<AnalyzeWhiteboxRequest>,
    ) -> Result<String, String> {
        let sid = self.resolve_session(req.session_id.clone())?;
        let task = self
            .engine
            .create_analysis_task(&sid, "crypto_implementation")
            .map_err(|error| error.to_string())?;
        let task_id = task.task_id.clone();
        let worker_task_id = task_id.clone();
        let engine = self.engine.clone();
        tokio::task::spawn_blocking(move || {
            let outcome = (|| -> Result<(), String> {
                engine
                    .start_analysis_task(&worker_task_id, "analyzing")
                    .map_err(|error| error.to_string())?;
                if engine.analysis_task_cancelled(&worker_task_id) {
                    return Err(TASK_CANCELLED.to_string());
                }
                let algorithm = req.algorithm;
                let static_binary_path = req.static_binary_path;
                let report = engine
                    .analyze_whitebox(
                        &sid,
                        WhiteBoxOptions {
                            algorithm: algorithm.clone(),
                            static_binary_path: static_binary_path.clone(),
                            ..Default::default()
                        },
                    )
                    .map_err(|error| error.to_string())?;
                engine
                    .update_analysis_task(&worker_task_id, "saving", 95)
                    .map_err(|error| error.to_string())?;
                let mut evidence = AnalysisEvidence::default();
                push_unique(&mut evidence.algorithms, report.verdict.algorithm.clone());
                for table in &report.tables {
                    push_unique(&mut evidence.addresses, table.base_addr.clone());
                }
                for output in &report.output_candidates {
                    push_unique(&mut evidence.memory_writes, output.base_addr.clone());
                }
                let record = engine
                    .save_analysis(
                        &sid,
                        "crypto_implementation",
                        "Crypto implementation analysis",
                        serde_json::json!({
                            "algorithm": algorithm,
                            "staticBinaryPath": static_binary_path,
                        }),
                        serde_json::json!({"structural": report}),
                        evidence,
                    )
                    .map_err(|error| error.to_string())?;
                if engine.analysis_task_cancelled(&worker_task_id) {
                    let _ = engine.delete_analysis(&sid, &record.analysis_id);
                    return Err(TASK_CANCELLED.to_string());
                }
                engine
                    .complete_analysis_task(&worker_task_id, &record.analysis_id)
                    .map_err(|error| error.to_string())
            })();
            if let Err(error) = outcome {
                if error == TASK_CANCELLED {
                    let _ = engine.mark_analysis_task_cancelled(&worker_task_id);
                } else {
                    let _ = engine.fail_analysis_task(&worker_task_id, &error);
                }
            }
        });
        Ok(json(&serde_json::json!({
            "task": task,
            "task_id": task_id,
            "poll_with": "get_analysis_task",
            "cancel_with": "cancel_analysis_task"
        })))
    }

    #[tool(
        name = "verify_crypto_hypothesis",
        description = "Verify an AES ECB, CBC, CTR, or GCM encrypt/decrypt hypothesis. CBC requires a 16-byte iv_hex; CTR uses iv_hex as the initial counter; GCM requires a 12-byte iv_hex nonce and 16-byte tag_hex, with optional aad_hex. GCM is VerifiedFull only when payload and authentication tag both match."
    )]
    async fn verify_crypto_hypothesis(
        &self,
        Parameters(req): Parameters<VerifyCryptoHypothesisRequest>,
    ) -> Result<String, String> {
        let key = decode_hex_bytes(&req.key_hex)?;
        let input = decode_hex_bytes(&req.input_hex)?;
        let output = decode_hex_bytes(&req.output_hex)?;
        let direction = if req.direction.eq_ignore_ascii_case("decrypt") {
            trace_core::AesDirection::Decrypt
        } else {
            trace_core::AesDirection::Encrypt
        };
        let result = match req.mode.to_ascii_lowercase().as_str() {
            "ecb" => serde_json::to_value(trace_core::verify_aes_ecb(
                &key, direction, &input, &output,
            )?)
            .map_err(|error| error.to_string())?,
            "cbc" => {
                let iv_hex = req
                    .iv_hex
                    .as_deref()
                    .ok_or_else(|| "CBC verification requires iv_hex".to_string())?;
                let iv = decode_hex_bytes(iv_hex)?;
                serde_json::to_value(trace_core::verify_aes_cbc(
                    &key, direction, &iv, &input, &output,
                )?)
                .map_err(|error| error.to_string())?
            }
            "ctr" => {
                let counter_hex = req.iv_hex.as_deref().ok_or_else(|| {
                    "CTR verification requires iv_hex as initial counter".to_string()
                })?;
                let counter = decode_hex_bytes(counter_hex)?;
                serde_json::to_value(trace_core::verify_aes_ctr(
                    &key, direction, &counter, &input, &output,
                )?)
                .map_err(|error| error.to_string())?
            }
            "gcm" => {
                let nonce_hex = req
                    .iv_hex
                    .as_deref()
                    .ok_or_else(|| "GCM verification requires iv_hex as nonce".to_string())?;
                let tag_hex = req
                    .tag_hex
                    .as_deref()
                    .ok_or_else(|| "GCM verification requires tag_hex".to_string())?;
                let nonce = decode_hex_bytes(nonce_hex)?;
                let tag = decode_hex_bytes(tag_hex)?;
                let aad = req
                    .aad_hex
                    .as_deref()
                    .map(decode_hex_bytes)
                    .transpose()?
                    .unwrap_or_default();
                serde_json::to_value(trace_core::verify_aes_gcm(
                    &key, direction, &nonce, &aad, &input, &output, &tag,
                )?)
                .map_err(|error| error.to_string())?
            }
            mode => {
                return Err(format!(
                    "unsupported AES mode: {mode}; expected ecb, cbc, ctr, or gcm"
                ))
            }
        };
        Ok(json(&result))
    }

    #[tool(
        name = "generate_crypto_reproducer",
        description = "Generate the deterministic Python reproducer for a semantically verified software AES result in the current trace. Refuses when no VerifiedFull result exists."
    )]
    async fn generate_crypto_reproducer(
        &self,
        Parameters(req): Parameters<AnalyzeWhiteboxRequest>,
    ) -> Result<String, String> {
        let sid = self.resolve_session(req.session_id)?;
        let report = self
            .engine
            .analyze_whitebox(
                &sid,
                WhiteBoxOptions {
                    algorithm: req.algorithm,
                    static_binary_path: req.static_binary_path,
                    ..Default::default()
                },
            )
            .map_err(|e| e.to_string())?;
        let software = report
            .software_crypto
            .ok_or_else(|| "no semantically verified software crypto result".to_string())?;
        if software.verification != "VerifiedFull" {
            return Err("reproducer requires VerifiedFull".into());
        }
        Ok(json(
            &serde_json::json!({ "algorithm": software.algorithm, "verification": software.verification, "reproducer": software.reproducer }),
        ))
    }
}

#[tool_handler]
impl ServerHandler for TraceToolHandler {
    fn get_info(&self) -> ServerInfo {
        ServerInfo::new(
            ServerCapabilities::builder()
                .enable_tools()
                .build(),
        )
        .with_instructions(
            "Trace UI MCP Server — analyze ARM64 execution traces.\n\n\
             Workflow:\n\
             1. Start: open_trace with file path → get session overview\n\
             2. Automatic investigation: auto_investigate, or start_auto_investigation for large traces\n\
             3. Overview: analyze_function (no args) to list functions, analyze_crypto to detect algorithms\n\
             4. Background investigation: start_crypto_investigation, then poll get_analysis_task\n\
             5. Synchronous crypto investigation: investigate_crypto_flow for small traces or direct clients\n\
             6. Known values: analyze_known_digest to match digest inputs and score candidate evidence\n\
             7. Recipes: list_analysis_recipes, then run_analysis_recipe for repeatable investigations\n\
             8. Forward flow: forward_taint_analysis, or start_forward_taint_analysis for large traces\n\
             9. Compare analyses: list_analyses then compare_analyses to cross-check evidence\n\
             10. Compare traces: compare_traces, or start_trace_diff for large traces\n\
             11. Locate: search_instructions (supports seq_range/addr_range filtering)\n\
             12. Backward trace: taint_analysis to find origins and save an analysis_id\n\
             13. Report: export_analysis_report for Markdown/JSON evidence packages\n\
             14. Deep dive: use mem:ADDRESS:SIZE@LINE for complete multi-byte buffers\n\
             15. Extract: get_memory to read key buffers, get_trace_lines(full=true) for register details\n\n\
             Tips:\n\
             - session_id is optional when only one trace is open\n\
             - Use data_only=true in forward_taint_analysis and taint_analysis to reduce noise\n\
             - Background tasks are cooperative; cancel_analysis_task stops before later phases and saving\n\
             - Taint source @LINE values are 1-based; start_seq/end_seq filters are 0-based\n\
             - analyze_function with node_id shows entry args (X0-X7) and return value\n\
             - Use addr_range to focus search/taint on a specific address range".to_string(),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn build_session(engine: &TraceEngine, lines: &[&str]) -> (String, std::path::PathBuf) {
        let path = std::env::temp_dir().join(format!(
            "trace-ui-auto-investigate-{}.gumtrace.txt",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::write(&path, lines.join("\n")).unwrap();
        let session = engine.create_session(path.to_str().unwrap()).unwrap();
        engine
            .build_index(
                &session.session_id,
                BuildOptions {
                    force_rebuild: true,
                    skip_strings: false,
                },
                None,
            )
            .unwrap();
        (session.session_id, path)
    }

    #[test]
    fn digest_candidate_scoring_distinguishes_verification_scope() {
        let result = serde_json::json!({
            "string_matches": {
                "matches": [{
                    "queryIndex": 0,
                    "normalizedDigest": "5d41402abc4b2a76b9719d911017c592",
                    "content": "hello",
                    "addr": "0x1000",
                    "seq": 10,
                    "transform": "utf8",
                    "xrefCount": 1
                }]
            },
            "memory_matches": {"matches": []},
            "traced_matches": []
        });
        let assessments = score_known_digest_candidates(&result);
        assert_eq!(assessments.len(), 1);
        assert_eq!(assessments[0]["assessment"]["grade"], "verified");
        assert_eq!(assessments[0]["assessment"]["scope"], "candidate_bytes");
        assert!(assessments[0]["assessment"]["limitations"][0]
            .as_str()
            .unwrap()
            .contains("does not by itself prove"));
    }

    #[test]
    fn auto_investigation_combines_search_and_trace_diff() {
        let engine = TraceEngine::new();
        let (left, left_path) = build_session(
            &engine,
            &[
                "[lib.so] 0x1000!0x10 bl #0x2000",
                "call func: read(3, 0x5000, 4)",
                "ret: 4",
            ],
        );
        let (right, right_path) = build_session(
            &engine,
            &[
                "[lib.so] 0x1000!0x10 bl #0x2000",
                "call func: read(3, 0x5000, 4)",
                "ret: 4",
                "[lib.so] 0x1004!0x14 bl #0x3000",
                "call func: write(3, 0x5000, 4)",
                "ret: 4",
            ],
        );
        let mut checkpoint = |_: &str, _: u8| Ok(());
        let (result, _, _) = run_auto_investigation(
            &engine,
            &left,
            AutoInvestigateRequest {
                session_id: None,
                objective: "Compare input and output behavior".to_string(),
                digests: Vec::new(),
                algorithm: KnownDigestAlgorithm::Auto,
                from_specs: Vec::new(),
                search_terms: vec!["read".to_string()],
                compare_analysis_ids: Vec::new(),
                compare_session_id: Some(right.clone()),
                include_crypto: false,
                data_only: true,
                max_search_results: 20,
                max_trace_matches: 3,
                max_diff_items: 20,
            },
            &mut checkpoint,
        )
        .unwrap();
        assert_eq!(result["assessment"]["grade"], "related");
        assert!(result["steps"]
            .as_array()
            .unwrap()
            .iter()
            .any(|step| step["stage"] == "trace_diff"));

        engine.delete_file_cache(left_path.to_str().unwrap());
        engine.delete_file_cache(right_path.to_str().unwrap());
        engine.close_session(&left).unwrap();
        engine.close_session(&right).unwrap();
        let _ = std::fs::remove_file(left_path);
        let _ = std::fs::remove_file(right_path);
    }
}
