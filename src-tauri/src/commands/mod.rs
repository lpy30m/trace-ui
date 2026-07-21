use std::sync::Arc;

use serde::{Deserialize, Serialize};
use tauri::{AppHandle, Emitter, State};
use trace_core::{
    parse_hex_addr, BuildOptions, DepTreeOptions, ExportConfig, Progress, SearchOptions,
    SliceOptions, StringQueryOptions, TraceEngine,
};

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
//  Session Management
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

/// 前端期望的返回结构（保持兼容）
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateSessionResult {
    session_id: String,
    total_lines: u32,
    file_size: u64,
}

#[tauri::command]
pub async fn create_session(
    path: String,
    engine: State<'_, Arc<TraceEngine>>,
) -> Result<CreateSessionResult, String> {
    let engine = engine.inner().clone();
    let info = tauri::async_runtime::spawn_blocking(move || engine.create_session(&path))
        .await
        .map_err(|e| format!("Task execution failed: {}", e))?
        .map_err(|e| e.to_string())?;

    Ok(CreateSessionResult {
        session_id: info.session_id,
        total_lines: info.total_lines,
        file_size: info.file_size,
    })
}

#[tauri::command]
pub fn close_session(
    session_id: String,
    engine: State<'_, Arc<TraceEngine>>,
) -> Result<(), String> {
    engine.close_session(&session_id).map_err(|e| e.to_string())
}

#[tauri::command]
pub fn delete_file_cache(path: String, engine: State<'_, Arc<TraceEngine>>) -> Result<(), String> {
    engine.delete_file_cache(&path);
    Ok(())
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
//  Index Build (模板 2: async + 进度事件)
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

#[tauri::command]
pub async fn build_index(
    session_id: String,
    app: AppHandle,
    engine: State<'_, Arc<TraceEngine>>,
    force: Option<bool>,
    skip_strings: Option<bool>,
) -> Result<(), String> {
    let engine = engine.inner().clone();
    let sid = session_id.clone();

    // 进度回调 → Tauri 事件
    let app_clone = app.clone();
    let sid_clone = sid.clone();
    let on_progress: Box<dyn Fn(Progress) + Send + Sync> = Box::new(move |p: Progress| {
        let _ = app_clone.emit(
            "index-progress",
            serde_json::json!({
                "sessionId": sid_clone,
                "progress": p.fraction,
                "done": false,
            }),
        );
    });

    let result = tauri::async_runtime::spawn_blocking(move || {
        engine.build_index(
            &sid,
            BuildOptions {
                force_rebuild: force.unwrap_or(false),
                skip_strings: skip_strings.unwrap_or(false),
            },
            Some(on_progress),
        )
    })
    .await
    .map_err(|e| format!("Task execution failed: {}", e))?;

    // 完成事件（成功或失败都发送，防止前端永远卡在 loading）
    match &result {
        Ok(r) => {
            let _ = app.emit(
                "index-progress",
                serde_json::json!({
                    "sessionId": session_id,
                    "progress": 1.0,
                    "done": true,
                    "totalLines": r.total_lines,
                    "hasStringIndex": r.has_string_index,
                }),
            );
        }
        Err(e) => {
            let _ = app.emit(
                "index-progress",
                serde_json::json!({
                    "sessionId": session_id,
                    "progress": 1.0,
                    "done": true,
                    "error": e.to_string(),
                }),
            );
        }
    }

    result.map(|_| ()).map_err(|e| e.to_string())
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
//  Browse (模板 1: 同步查询)
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

#[tauri::command]
pub fn get_lines(
    session_id: String,
    seqs: Vec<u32>,
    engine: State<'_, Arc<TraceEngine>>,
) -> Result<Vec<trace_core::TraceLine>, String> {
    engine
        .get_lines(&session_id, &seqs)
        .map_err(|e| e.to_string())
}

#[tauri::command]
pub fn get_consumed_seqs(
    session_id: String,
    engine: State<'_, Arc<TraceEngine>>,
) -> Result<Vec<u32>, String> {
    engine
        .get_consumed_seqs(&session_id)
        .map_err(|e| e.to_string())
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
//  Search (模板 2: async)
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

#[derive(Deserialize)]
pub struct SearchRequest {
    pub query: String,
    #[serde(default)]
    pub max_results: Option<u32>,
    #[serde(default)]
    pub case_sensitive: bool,
    #[serde(default)]
    pub use_regex: bool,
    #[serde(default)]
    pub fuzzy: bool,
}

#[tauri::command]
pub async fn search_trace(
    session_id: String,
    request: SearchRequest,
    engine: State<'_, Arc<TraceEngine>>,
) -> Result<trace_core::SearchResultLite, String> {
    let engine = engine.inner().clone();
    tauri::async_runtime::spawn_blocking(move || {
        engine
            .search(
                &session_id,
                &request.query,
                SearchOptions {
                    case_sensitive: request.case_sensitive,
                    use_regex: request.use_regex,
                    fuzzy: request.fuzzy,
                    max_results: request.max_results,
                },
            )
            .map_err(|e| e.to_string())
    })
    .await
    .map_err(|e| format!("Task execution failed: {}", e))?
}

#[derive(Serialize)]
pub struct SearchPageResult {
    pub generation: u64,
    pub seqs: Vec<u32>,
}

#[tauri::command]
pub fn fetch_search_page(
    session_id: String,
    offset: u32,
    count: u32,
    engine: State<'_, Arc<TraceEngine>>,
) -> Result<SearchPageResult, String> {
    let (gen, seqs) = engine
        .fetch_search_page(&session_id, offset, count)
        .map_err(|e| e.to_string())?;
    Ok(SearchPageResult {
        generation: gen,
        seqs,
    })
}

#[derive(Deserialize)]
pub struct GetSearchMatchesRequest {
    pub seqs: Vec<u32>,
    pub query: String,
    #[serde(default)]
    pub case_sensitive: bool,
    #[serde(default)]
    pub use_regex: bool,
    #[serde(default)]
    pub fuzzy: bool,
}

#[tauri::command]
pub async fn get_search_matches(
    session_id: String,
    request: GetSearchMatchesRequest,
    engine: State<'_, Arc<TraceEngine>>,
) -> Result<Vec<trace_core::SearchMatch>, String> {
    let engine = engine.inner().clone();
    tauri::async_runtime::spawn_blocking(move || {
        engine
            .get_search_matches(
                &session_id,
                &request.query,
                &request.seqs,
                request.case_sensitive,
                request.use_regex,
                request.fuzzy,
            )
            .map_err(|e| e.to_string())
    })
    .await
    .map_err(|e| format!("Task execution failed: {}", e))?
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
//  Slice (模板 2: async / 模板 1: sync)
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

#[tauri::command]
pub async fn run_slice(
    session_id: String,
    from_specs: Vec<String>,
    start_seq: Option<u32>,
    end_seq: Option<u32>,
    data_only: Option<bool>,
    engine: State<'_, Arc<TraceEngine>>,
) -> Result<trace_core::SliceResult, String> {
    let engine = engine.inner().clone();
    tauri::async_runtime::spawn_blocking(move || {
        engine
            .run_slice(
                &session_id,
                &from_specs,
                SliceOptions {
                    start_seq,
                    end_seq,
                    data_only: data_only.unwrap_or(false),
                },
            )
            .map_err(|e| e.to_string())
    })
    .await
    .map_err(|e| format!("Task execution failed: {}", e))?
}

#[tauri::command]
pub fn get_slice_status(
    session_id: String,
    start_seq: u32,
    count: u32,
    engine: State<'_, Arc<TraceEngine>>,
) -> Result<Vec<bool>, String> {
    engine
        .get_slice_status(&session_id, start_seq, count)
        .map_err(|e| e.to_string())
}

#[tauri::command]
pub fn clear_slice(session_id: String, engine: State<'_, Arc<TraceEngine>>) -> Result<(), String> {
    engine.clear_slice(&session_id).map_err(|e| e.to_string())
}

#[tauri::command]
pub fn get_tainted_seqs(
    session_id: String,
    engine: State<'_, Arc<TraceEngine>>,
) -> Result<Vec<u32>, String> {
    engine
        .get_tainted_seqs(&session_id)
        .map_err(|e| e.to_string())
}

#[tauri::command]
pub async fn export_taint_results(
    session_id: String,
    output_path: String,
    format: String,
    config: ExportConfig,
    engine: State<'_, Arc<TraceEngine>>,
) -> Result<(), String> {
    let engine = engine.inner().clone();
    tauri::async_runtime::spawn_blocking(move || {
        engine
            .export_taint_results(&session_id, &output_path, &format, config)
            .map_err(|e| e.to_string())
    })
    .await
    .map_err(|e| format!("Task execution failed: {}", e))?
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
//  Memory (模板 1: 同步查询, 需要地址转换)
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

#[tauri::command]
pub fn get_memory_at(
    session_id: String,
    seq: u32,
    addr: String,
    length: u32,
    engine: State<'_, Arc<TraceEngine>>,
) -> Result<trace_core::MemorySnapshot, String> {
    let addr_u64 = parse_hex_addr(&addr)?;
    engine
        .get_memory_at(&session_id, addr_u64, seq, length)
        .map_err(|e| e.to_string())
}

#[tauri::command]
pub fn get_mem_history_meta(
    session_id: String,
    addr: String,
    center_seq: u32,
    engine: State<'_, Arc<TraceEngine>>,
) -> Result<trace_core::MemHistoryMeta, String> {
    let addr_u64 = parse_hex_addr(&addr)?;
    engine
        .get_mem_history_meta(&session_id, addr_u64, center_seq)
        .map_err(|e| e.to_string())
}

#[tauri::command]
pub fn get_mem_history_range(
    session_id: String,
    addr: String,
    start_index: usize,
    limit: usize,
    engine: State<'_, Arc<TraceEngine>>,
) -> Result<Vec<trace_core::MemHistoryRecord>, String> {
    let addr_u64 = parse_hex_addr(&addr)?;
    engine
        .get_mem_history_range(&session_id, addr_u64, start_index, limit)
        .map_err(|e| e.to_string())
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
//  Registers (模板 1: 同步查询)
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

#[tauri::command]
pub fn get_registers_at(
    session_id: String,
    seq: u32,
    engine: State<'_, Arc<TraceEngine>>,
) -> Result<std::collections::HashMap<String, String>, String> {
    engine
        .get_registers_at(&session_id, seq)
        .map_err(|e| e.to_string())
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
//  Call Tree (模板 1: 同步查询)
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

#[tauri::command]
pub fn get_call_tree(
    session_id: String,
    engine: State<'_, Arc<TraceEngine>>,
) -> Result<Vec<trace_core::CallTreeNodeDto>, String> {
    engine.get_call_tree(&session_id).map_err(|e| e.to_string())
}

#[tauri::command]
pub fn get_call_tree_node_count(
    session_id: String,
    engine: State<'_, Arc<TraceEngine>>,
) -> Result<u32, String> {
    engine
        .get_call_tree_node_count(&session_id)
        .map_err(|e| e.to_string())
}

#[tauri::command]
pub fn get_call_tree_children(
    session_id: String,
    node_id: u32,
    include_self: bool,
    engine: State<'_, Arc<TraceEngine>>,
) -> Result<Vec<trace_core::CallTreeNodeDto>, String> {
    engine
        .get_call_tree_children(&session_id, node_id, include_self)
        .map_err(|e| e.to_string())
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
//  Strings (模板 1/2/3)
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

#[tauri::command]
pub fn get_strings(
    session_id: String,
    min_len: u32,
    offset: u32,
    limit: u32,
    search: Option<String>,
    engine: State<'_, Arc<TraceEngine>>,
) -> Result<trace_core::StringsResult, String> {
    engine
        .get_strings(
            &session_id,
            StringQueryOptions {
                min_len,
                offset,
                limit,
                search,
            },
        )
        .map_err(|e| e.to_string())
}

#[tauri::command]
pub fn get_string_xrefs(
    session_id: String,
    addr: String,
    byte_len: u32,
    engine: State<'_, Arc<TraceEngine>>,
) -> Result<Vec<trace_core::StringXRef>, String> {
    let addr_u64 = parse_hex_addr(&addr)?;
    engine
        .get_string_xrefs(&session_id, addr_u64, byte_len)
        .map_err(|e| e.to_string())
}

#[tauri::command]
pub async fn scan_strings(
    session_id: String,
    engine: State<'_, Arc<TraceEngine>>,
) -> Result<(), String> {
    let engine = engine.inner().clone();
    tauri::async_runtime::spawn_blocking(move || {
        engine.scan_strings(&session_id).map_err(|e| e.to_string())
    })
    .await
    .map_err(|e| format!("Task execution failed: {}", e))?
}

#[tauri::command]
pub fn cancel_scan_strings(
    session_id: String,
    engine: State<'_, Arc<TraceEngine>>,
) -> Result<(), String> {
    engine.cancel_scan_strings(&session_id);
    Ok(())
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
//  Functions (模板 1: 同步查询)
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

#[tauri::command]
pub fn get_function_calls(
    session_id: String,
    engine: State<'_, Arc<TraceEngine>>,
) -> Result<trace_core::FunctionCallsResult, String> {
    engine
        .get_function_calls(&session_id)
        .map_err(|e| e.to_string())
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
//  Dep Tree (模板 2: async)
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

#[tauri::command]
pub async fn build_dependency_tree(
    session_id: String,
    seq: u32,
    target: String,
    data_only: Option<bool>,
    max_nodes: Option<u32>,
    engine: State<'_, Arc<TraceEngine>>,
) -> Result<trace_core::query::dep_tree::DependencyGraph, String> {
    let engine = engine.inner().clone();
    tauri::async_runtime::spawn_blocking(move || {
        engine
            .build_dep_tree(
                &session_id,
                seq,
                &target,
                DepTreeOptions {
                    data_only: data_only.unwrap_or(false),
                    max_nodes,
                },
            )
            .map_err(|e| e.to_string())
    })
    .await
    .map_err(|e| format!("Task execution failed: {}", e))?
}

#[tauri::command]
pub async fn build_dependency_tree_from_slice(
    session_id: String,
    max_nodes: Option<u32>,
    data_only: Option<bool>,
    engine: State<'_, Arc<TraceEngine>>,
) -> Result<trace_core::query::dep_tree::DependencyGraph, String> {
    let engine = engine.inner().clone();
    tauri::async_runtime::spawn_blocking(move || {
        engine
            .build_dep_tree_from_slice(
                &session_id,
                DepTreeOptions {
                    data_only: data_only.unwrap_or(false),
                    max_nodes,
                },
            )
            .map_err(|e| e.to_string())
    })
    .await
    .map_err(|e| format!("Task execution failed: {}", e))?
}

#[tauri::command]
pub fn get_line_def_registers(
    session_id: String,
    seq: u32,
    engine: State<'_, Arc<TraceEngine>>,
) -> Result<Vec<String>, String> {
    engine
        .get_line_def_registers(&session_id, seq)
        .map_err(|e| e.to_string())
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
//  DEF/USE (模板 1: 同步查询)
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

#[tauri::command]
pub fn get_reg_def_use_chain(
    session_id: String,
    seq: u32,
    reg_name: String,
    engine: State<'_, Arc<TraceEngine>>,
) -> Result<trace_core::DefUseChain, String> {
    engine
        .get_def_use_chain(&session_id, seq, &reg_name)
        .map_err(|e| e.to_string())
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
//  Crypto (模板 2: async / 模板 1: sync)
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

#[tauri::command]
pub async fn scan_crypto(
    session_id: String,
    engine: State<'_, Arc<TraceEngine>>,
) -> Result<trace_core::query::crypto::CryptoScanResult, String> {
    let engine = engine.inner().clone();
    tauri::async_runtime::spawn_blocking(move || {
        engine.scan_crypto(&session_id).map_err(|e| e.to_string())
    })
    .await
    .map_err(|e| format!("Task execution failed: {}", e))?
}

#[tauri::command]
pub async fn analyze_crypto_functions(
    session_id: String,
    max_candidates: Option<u32>,
    engine: State<'_, Arc<TraceEngine>>,
) -> Result<trace_core::CryptoFunctionReport, String> {
    let engine = engine.inner().clone();
    tauri::async_runtime::spawn_blocking(move || {
        engine
            .analyze_crypto_functions(
                &session_id,
                trace_core::CryptoFunctionsOptions {
                    max_candidates: max_candidates.unwrap_or(50),
                },
            )
            .map_err(|e| e.to_string())
    })
    .await
    .map_err(|e| format!("Task execution failed: {}", e))?
}

#[tauri::command]
pub async fn analyze_crypto_materials(
    session_id: String,
    max_materials: Option<u32>,
    include_unknown: Option<bool>,
    engine: State<'_, Arc<TraceEngine>>,
) -> Result<trace_core::CryptoMaterialReport, String> {
    let engine = engine.inner().clone();
    tauri::async_runtime::spawn_blocking(move || {
        engine
            .analyze_crypto_materials(
                &session_id,
                trace_core::CryptoMaterialOptions {
                    max_materials: max_materials.unwrap_or(500),
                    include_unknown: include_unknown.unwrap_or(false),
                },
            )
            .map_err(|error| error.to_string())
    })
    .await
    .map_err(|error| format!("Task execution failed: {error}"))?
}

#[tauri::command]
pub async fn compare_crypto_material_traces(
    request: trace_core::CryptoMaterialMultiTraceRequest,
    engine: State<'_, Arc<TraceEngine>>,
) -> Result<trace_core::CryptoMaterialMultiTraceReport, String> {
    let engine = engine.inner().clone();
    tauri::async_runtime::spawn_blocking(move || {
        engine
            .compare_crypto_material_traces(request)
            .map_err(|error| error.to_string())
    })
    .await
    .map_err(|error| format!("Task execution failed: {error}"))?
}

#[tauri::command]
pub fn generate_frida_hook(
    request: trace_core::FridaHookRequest,
) -> Result<trace_core::FridaHookScript, String> {
    trace_core::generate_frida_hook(&request)
}

#[tauri::command]
pub async fn save_frida_hook(
    path: String,
    request: trace_core::FridaHookRequest,
) -> Result<String, String> {
    tauri::async_runtime::spawn_blocking(move || {
        let generated = trace_core::generate_frida_hook(&request)?;
        let trimmed = path.trim();
        if trimmed.is_empty() {
            return Err("output path must not be empty".to_string());
        }
        let mut output_path = std::path::PathBuf::from(trimmed);
        if output_path.extension().and_then(|value| value.to_str()) != Some("js") {
            output_path.set_extension("js");
        }
        let parent = output_path
            .parent()
            .filter(|value| !value.as_os_str().is_empty())
            .ok_or_else(|| "output path must include a parent directory".to_string())?;
        if !parent.is_dir() {
            return Err(format!(
                "output directory does not exist: {}",
                parent.display()
            ));
        }
        std::fs::write(&output_path, generated.script.as_bytes())
            .map_err(|error| format!("failed to save hook script: {error}"))?;
        Ok(output_path.to_string_lossy().into_owned())
    })
    .await
    .map_err(|error| format!("Task execution failed: {error}"))?
}

#[tauri::command]
pub async fn load_frida_capture(path: String) -> Result<trace_core::FridaCaptureBundle, String> {
    tauri::async_runtime::spawn_blocking(move || {
        let trimmed = path.trim();
        if trimmed.is_empty() {
            return Err("Frida capture path must not be empty".to_string());
        }
        let bytes = std::fs::read(trimmed)
            .map_err(|error| format!("failed to read Frida capture: {error}"))?;
        trace_core::parse_frida_capture_bundle(&bytes)
    })
    .await
    .map_err(|error| format!("Task execution failed: {error}"))?
}

#[tauri::command]
pub fn generate_angr_state_seed(
    bundle: trace_core::FridaCaptureBundle,
    event_index: u64,
    include_sp: Option<bool>,
    include_lr: Option<bool>,
) -> Result<trace_core::AngrStateSeed, String> {
    trace_core::generate_angr_state_seed(
        &bundle,
        event_index,
        include_sp.unwrap_or(false),
        include_lr.unwrap_or(true),
    )
}

#[tauri::command]
pub async fn save_angr_state_seed(
    path: String,
    bundle: trace_core::FridaCaptureBundle,
    event_index: u64,
    include_sp: Option<bool>,
    include_lr: Option<bool>,
) -> Result<String, String> {
    tauri::async_runtime::spawn_blocking(move || {
        let seed = trace_core::generate_angr_state_seed(
            &bundle,
            event_index,
            include_sp.unwrap_or(false),
            include_lr.unwrap_or(true),
        )?;
        let trimmed = path.trim();
        if trimmed.is_empty() {
            return Err("output path must not be empty".to_string());
        }
        let mut output_path = std::path::PathBuf::from(trimmed);
        if output_path.extension().and_then(|value| value.to_str()) != Some("py") {
            output_path.set_extension("py");
        }
        let parent = output_path
            .parent()
            .filter(|value| !value.as_os_str().is_empty())
            .ok_or_else(|| "output path must include a parent directory".to_string())?;
        if !parent.is_dir() {
            return Err(format!(
                "output directory does not exist: {}",
                parent.display()
            ));
        }
        std::fs::write(&output_path, seed.script.as_bytes())
            .map_err(|error| format!("failed to save angr state seed: {error}"))?;
        Ok(output_path.to_string_lossy().into_owned())
    })
    .await
    .map_err(|error| format!("Task execution failed: {error}"))?
}

#[tauri::command]
pub async fn analyze_ollvm(
    session_id: String,
    options: trace_core::OllvmAnalysisOptions,
    engine: State<'_, Arc<TraceEngine>>,
) -> Result<trace_core::OllvmReport, String> {
    let engine = engine.inner().clone();
    tauri::async_runtime::spawn_blocking(move || {
        engine
            .analyze_ollvm(&session_id, options)
            .map_err(|error| error.to_string())
    })
    .await
    .map_err(|error| format!("Task execution failed: {error}"))?
}

#[tauri::command]
pub fn generate_ida_ollvm_script(
    report: trace_core::OllvmReport,
    ida_image_base: Option<String>,
    add_user_xrefs: Option<bool>,
) -> Result<trace_core::IdaOllvmScript, String> {
    trace_core::generate_ida_ollvm_script(
        &report,
        ida_image_base.as_deref(),
        add_user_xrefs.unwrap_or(false),
    )
}

#[tauri::command]
pub async fn save_ida_ollvm_script(
    path: String,
    report: trace_core::OllvmReport,
    ida_image_base: Option<String>,
    add_user_xrefs: Option<bool>,
) -> Result<String, String> {
    tauri::async_runtime::spawn_blocking(move || {
        let generated = trace_core::generate_ida_ollvm_script(
            &report,
            ida_image_base.as_deref(),
            add_user_xrefs.unwrap_or(false),
        )?;
        let trimmed = path.trim();
        if trimmed.is_empty() {
            return Err("output path must not be empty".to_string());
        }
        let mut output_path = std::path::PathBuf::from(trimmed);
        if output_path.extension().and_then(|value| value.to_str()) != Some("py") {
            output_path.set_extension("py");
        }
        let parent = output_path
            .parent()
            .filter(|value| !value.as_os_str().is_empty())
            .ok_or_else(|| "output path must include a parent directory".to_string())?;
        if !parent.is_dir() {
            return Err(format!(
                "output directory does not exist: {}",
                parent.display()
            ));
        }
        std::fs::write(&output_path, generated.script.as_bytes())
            .map_err(|error| format!("failed to save IDAPython script: {error}"))?;
        Ok(output_path.to_string_lossy().into_owned())
    })
    .await
    .map_err(|error| format!("Task execution failed: {error}"))?
}

#[tauri::command]
pub async fn load_ida_annotations(path: String) -> Result<trace_core::IdaAnnotationBundle, String> {
    tauri::async_runtime::spawn_blocking(move || {
        let trimmed = path.trim();
        if trimmed.is_empty() {
            return Err("annotation path must not be empty".to_string());
        }
        let bytes = std::fs::read(trimmed)
            .map_err(|error| format!("failed to read IDA annotations: {error}"))?;
        trace_core::parse_ida_annotation_bundle(&bytes)
    })
    .await
    .map_err(|error| format!("Task execution failed: {error}"))?
}

#[tauri::command]
pub fn generate_angr_ollvm_script(
    report: trace_core::OllvmReport,
    probe_opaque_branches: Option<bool>,
    use_cfg_emulated: Option<bool>,
) -> Result<trace_core::AngrOllvmScript, String> {
    trace_core::generate_angr_ollvm_script(
        &report,
        probe_opaque_branches.unwrap_or(true),
        use_cfg_emulated.unwrap_or(false),
    )
}

#[tauri::command]
pub async fn save_angr_ollvm_script(
    path: String,
    report: trace_core::OllvmReport,
    probe_opaque_branches: Option<bool>,
    use_cfg_emulated: Option<bool>,
) -> Result<String, String> {
    tauri::async_runtime::spawn_blocking(move || {
        let generated = trace_core::generate_angr_ollvm_script(
            &report,
            probe_opaque_branches.unwrap_or(true),
            use_cfg_emulated.unwrap_or(false),
        )?;
        let trimmed = path.trim();
        if trimmed.is_empty() {
            return Err("output path must not be empty".to_string());
        }
        let mut output_path = std::path::PathBuf::from(trimmed);
        if output_path.extension().and_then(|value| value.to_str()) != Some("py") {
            output_path.set_extension("py");
        }
        let parent = output_path
            .parent()
            .filter(|value| !value.as_os_str().is_empty())
            .ok_or_else(|| "output path must include a parent directory".to_string())?;
        if !parent.is_dir() {
            return Err(format!(
                "output directory does not exist: {}",
                parent.display()
            ));
        }
        std::fs::write(&output_path, generated.script.as_bytes())
            .map_err(|error| format!("failed to save angr script: {error}"))?;
        Ok(output_path.to_string_lossy().into_owned())
    })
    .await
    .map_err(|error| format!("Task execution failed: {error}"))?
}

#[tauri::command]
pub async fn load_angr_ollvm_results(
    path: String,
) -> Result<trace_core::AngrOllvmResultBundle, String> {
    tauri::async_runtime::spawn_blocking(move || {
        let trimmed = path.trim();
        if trimmed.is_empty() {
            return Err("angr result path must not be empty".to_string());
        }
        let bytes = std::fs::read(trimmed)
            .map_err(|error| format!("failed to read angr results: {error}"))?;
        trace_core::parse_angr_ollvm_result_bundle(&bytes)
    })
    .await
    .map_err(|error| format!("Task execution failed: {error}"))?
}

#[tauri::command]
pub async fn analyze_whitebox_crypto(
    session_id: String,
    algorithm: Option<String>,
    static_binary_path: Option<String>,
    engine: State<'_, Arc<TraceEngine>>,
) -> Result<trace_core::WhiteBoxReport, String> {
    let engine = engine.inner().clone();
    tauri::async_runtime::spawn_blocking(move || {
        engine
            .analyze_whitebox(
                &session_id,
                trace_core::WhiteBoxOptions {
                    algorithm: algorithm.unwrap_or_else(|| "aes".to_string()),
                    static_binary_path,
                    ..Default::default()
                },
            )
            .map_err(|e| e.to_string())
    })
    .await
    .map_err(|e| format!("Task execution failed: {}", e))?
}

#[tauri::command]
pub async fn compare_whitebox_traces(
    request: trace_core::WhiteBoxMultiTraceRequest,
    engine: State<'_, Arc<TraceEngine>>,
) -> Result<trace_core::WhiteBoxMultiTraceReport, String> {
    let engine = engine.inner().clone();
    tauri::async_runtime::spawn_blocking(move || {
        engine
            .compare_whitebox_traces(request)
            .map_err(|error| error.to_string())
    })
    .await
    .map_err(|error| format!("Task execution failed: {error}"))?
}

#[tauri::command]
pub fn list_trace_sessions(engine: State<'_, Arc<TraceEngine>>) -> Vec<trace_core::SessionInfo> {
    engine.list_sessions()
}

#[tauri::command]
pub async fn match_known_digests(
    session_id: String,
    request: trace_core::HashMatchRequest,
    engine: State<'_, Arc<TraceEngine>>,
) -> Result<trace_core::HashMatchResponse, String> {
    let engine = engine.inner().clone();
    tauri::async_runtime::spawn_blocking(move || {
        engine
            .match_known_digests(&session_id, &request)
            .map_err(|e| e.to_string())
    })
    .await
    .map_err(|e| format!("Task execution failed: {}", e))?
}

#[tauri::command]
pub async fn find_digest_memory(
    session_id: String,
    request: trace_core::HashMatchRequest,
    engine: State<'_, Arc<TraceEngine>>,
) -> Result<trace_core::HashMemoryMatchResponse, String> {
    let engine = engine.inner().clone();
    tauri::async_runtime::spawn_blocking(move || {
        engine
            .find_digest_memory(&session_id, &request)
            .map_err(|e| e.to_string())
    })
    .await
    .map_err(|e| format!("Task execution failed: {}", e))?
}

#[tauri::command]
pub async fn search_value(
    session_id: String,
    request: trace_core::ValueSearchRequest,
    engine: State<'_, Arc<TraceEngine>>,
) -> Result<trace_core::ValueSearchResponse, String> {
    let engine = engine.inner().clone();
    tauri::async_runtime::spawn_blocking(move || {
        engine
            .search_value(&session_id, &request)
            .map_err(|error| error.to_string())
    })
    .await
    .map_err(|error| format!("Task execution failed: {error}"))?
}

#[tauri::command]
pub async fn run_forward_value_taint(
    session_id: String,
    addr: String,
    size: u32,
    seq: u32,
    engine: State<'_, Arc<TraceEngine>>,
) -> Result<trace_core::ForwardSliceResult, String> {
    if size == 0 || size > 4096 {
        return Err("Value taint size must be between 1 and 4096 bytes".to_string());
    }
    parse_hex_addr(&addr)?;
    let engine = engine.inner().clone();
    tauri::async_runtime::spawn_blocking(move || {
        engine
            .run_forward_slice(
                &session_id,
                &[format!("mem:{addr}:{size}@seq:{seq}")],
                trace_core::ForwardSliceOptions {
                    start_seq: Some(seq),
                    end_seq: None,
                    data_only: true,
                    max_nodes: 10_000,
                },
            )
            .map_err(|error| error.to_string())
    })
    .await
    .map_err(|error| format!("Task execution failed: {error}"))?
}

#[tauri::command]
pub fn load_crypto_cache(
    session_id: String,
    engine: State<'_, Arc<TraceEngine>>,
) -> Result<Option<trace_core::query::crypto::CryptoScanResult>, String> {
    engine
        .load_crypto_cache(&session_id)
        .map_err(|e| e.to_string())
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
//  Analysis Store (AI-created analyses; shared with MCP via disk cache)
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

#[tauri::command]
pub fn list_analyses(
    session_id: String,
    kind: Option<String>,
    limit: Option<u32>,
    engine: State<'_, Arc<TraceEngine>>,
) -> Result<Vec<trace_core::AnalysisRecordSummary>, String> {
    engine
        .list_analyses(&session_id, kind.as_deref(), limit.unwrap_or(100))
        .map_err(|e| e.to_string())
}

#[tauri::command]
pub fn get_analysis(
    session_id: String,
    analysis_id: String,
    engine: State<'_, Arc<TraceEngine>>,
) -> Result<trace_core::AnalysisRecord, String> {
    engine
        .get_analysis(&session_id, &analysis_id)
        .map_err(|e| e.to_string())
}

#[tauri::command]
pub fn compare_analyses(
    session_id: String,
    analysis_ids: Vec<String>,
    engine: State<'_, Arc<TraceEngine>>,
) -> Result<trace_core::AnalysisComparison, String> {
    engine
        .compare_analyses(&session_id, &analysis_ids)
        .map_err(|e| e.to_string())
}

#[tauri::command]
pub fn delete_analysis(
    session_id: String,
    analysis_id: String,
    engine: State<'_, Arc<TraceEngine>>,
) -> Result<bool, String> {
    engine
        .delete_analysis(&session_id, &analysis_id)
        .map_err(|e| e.to_string())
}

#[tauri::command]
pub fn render_analysis_report(
    session_id: String,
    analysis_id: String,
    format: String,
    engine: State<'_, Arc<TraceEngine>>,
) -> Result<String, String> {
    engine
        .render_analysis_report(&session_id, &analysis_id, &format)
        .map_err(|e| e.to_string())
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
//  Function Inspector
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

#[tauri::command]
pub fn inspect_function(
    session_id: String,
    node_id: u32,
    engine: State<'_, Arc<TraceEngine>>,
) -> Result<trace_core::FunctionInspection, String> {
    engine
        .inspect_function(&session_id, node_id)
        .map_err(|e| e.to_string())
}

#[tauri::command]
pub fn inspect_function_at_seq(
    session_id: String,
    seq: u32,
    engine: State<'_, Arc<TraceEngine>>,
) -> Result<trace_core::FunctionInspection, String> {
    engine
        .inspect_function_at_seq(&session_id, seq)
        .map_err(|e| e.to_string())
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
//  Cache Management (模板 1: 同步查询)
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

#[tauri::command]
pub fn get_cache_dir(engine: State<'_, Arc<TraceEngine>>) -> trace_core::CacheInfo {
    engine.get_cache_dir()
}

#[tauri::command]
pub fn set_cache_dir(
    path: Option<String>,
    engine: State<'_, Arc<TraceEngine>>,
) -> Result<(), String> {
    engine.set_cache_dir(path).map_err(|e| e.to_string())
}

#[tauri::command]
pub fn clear_all_cache(engine: State<'_, Arc<TraceEngine>>) -> trace_core::ClearResult {
    engine.clear_all_cache()
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
//  MCP Server Management
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

#[tauri::command]
pub async fn start_mcp(
    port: Option<u16>,
    controller: State<'_, crate::mcp::McpController>,
) -> Result<crate::mcp::McpStatusInfo, String> {
    controller.start(port).await
}

/// 同步命令（有意为之）：仅做 lock + cancel + emit，无需 await。
#[tauri::command]
pub fn stop_mcp(controller: State<'_, crate::mcp::McpController>) -> crate::mcp::McpStatusInfo {
    controller.stop()
}

#[tauri::command]
pub fn get_mcp_status(
    controller: State<'_, crate::mcp::McpController>,
) -> crate::mcp::McpStatusInfo {
    controller.status()
}
