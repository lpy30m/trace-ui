use std::sync::Arc;

use serde::{Deserialize, Serialize};
use tauri::{AppHandle, Emitter, State};
use trace_core::{
    parse_hex_addr, BuildOptions, DepTreeOptions, ExportConfig, MemoryObjectOptions, Progress,
    SearchOptions, SliceOptions, StringQueryOptions, TraceEngine,
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

#[tauri::command]
pub async fn reconstruct_memory_objects(
    session_id: String,
    options: Option<MemoryObjectOptions>,
    engine: State<'_, Arc<TraceEngine>>,
) -> Result<trace_core::MemoryObjectGraphReport, String> {
    let engine = engine.inner().clone();
    tauri::async_runtime::spawn_blocking(move || {
        engine
            .reconstruct_memory_objects(&session_id, options.unwrap_or_default())
            .map_err(|error| error.to_string())
    })
    .await
    .map_err(|error| format!("Task execution failed: {error}"))?
}

#[tauri::command]
pub async fn explain_memory_pointer(
    session_id: String,
    address: String,
    seq: Option<u32>,
    include_stack_frames: Option<bool>,
    engine: State<'_, Arc<TraceEngine>>,
) -> Result<trace_core::MemoryPointerExplanation, String> {
    let address = parse_hex_addr(&address)?;
    let engine = engine.inner().clone();
    tauri::async_runtime::spawn_blocking(move || {
        let query_seq = match seq {
            Some(value) => value,
            None => engine
                .get_session_info(&session_id)
                .map_err(|error| error.to_string())?
                .total_lines
                .saturating_sub(1),
        };
        engine
            .explain_memory_pointer(
                &session_id,
                address,
                query_seq,
                include_stack_frames.unwrap_or(true),
            )
            .map_err(|error| error.to_string())
    })
    .await
    .map_err(|error| format!("Task execution failed: {error}"))?
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
pub fn list_frida_hook_recipes() -> Vec<trace_core::FridaHookRecipe> {
    trace_core::list_frida_hook_recipes()
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
pub async fn summarize_exact_calls(
    capture_path: String,
    caller_module_name: String,
    static_binary_path: String,
    max_calls: Option<u32>,
    max_memory_bytes_per_call: Option<u64>,
    output_path: Option<String>,
) -> Result<trace_core::ExactCallSummaryBundle, String> {
    tauri::async_runtime::spawn_blocking(move || {
        let request = trace_core::ExactCallSummaryRequest {
            caller_module_name,
            static_binary_path,
            max_calls: max_calls.unwrap_or(1_024),
            max_memory_bytes_per_call: max_memory_bytes_per_call.unwrap_or(1_048_576),
        };
        match output_path
            .as_deref()
            .filter(|path| !path.trim().is_empty())
        {
            Some(path) => trace_core::save_exact_call_summary(path, &capture_path, &request),
            None => trace_core::summarize_exact_calls(&capture_path, &request),
        }
    })
    .await
    .map_err(|error| format!("Task execution failed: {error}"))?
}

#[tauri::command]
pub async fn authorize_exact_call_replay(
    summary_path: String,
    static_binary_path: String,
    call_ids: Vec<String>,
    assumptions: trace_core::ExactCallReplayAssumptions,
    output_path: Option<String>,
) -> Result<trace_core::ExactCallReplayAuthorizationBundle, String> {
    tauri::async_runtime::spawn_blocking(move || {
        let request = trace_core::ExactCallReplayAuthorizationRequest {
            call_ids,
            assumptions,
        };
        match output_path
            .as_deref()
            .filter(|path| !path.trim().is_empty())
        {
            Some(path) => trace_core::save_exact_call_replay_authorization(
                path,
                &summary_path,
                &static_binary_path,
                &request,
            ),
            None => trace_core::authorize_exact_call_replay(
                &summary_path,
                &static_binary_path,
                &request,
            ),
        }
    })
    .await
    .map_err(|error| format!("Task execution failed: {error}"))?
}

#[tauri::command]
pub async fn generate_frida_runtime_attestation(
    request: trace_core::FridaRuntimeAttestationRequest,
) -> Result<trace_core::FridaRuntimeAttestationScript, String> {
    tauri::async_runtime::spawn_blocking(move || {
        trace_core::generate_frida_runtime_attestation_script(&request)
    })
    .await
    .map_err(|error| format!("Task execution failed: {error}"))?
}

#[tauri::command]
pub async fn save_frida_runtime_attestation(
    path: String,
    request: trace_core::FridaRuntimeAttestationRequest,
) -> Result<String, String> {
    tauri::async_runtime::spawn_blocking(move || {
        let generated = trace_core::generate_frida_runtime_attestation_script(&request)?;
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
            .map_err(|error| format!("failed to save runtime attestation script: {error}"))?;
        Ok(output_path.to_string_lossy().into_owned())
    })
    .await
    .map_err(|error| format!("Task execution failed: {error}"))?
}

#[tauri::command]
pub async fn inspect_runtime_attestation(
    capture_path: String,
    exact_binary_path: String,
) -> Result<trace_core::RuntimeAttestationInspectionReport, String> {
    tauri::async_runtime::spawn_blocking(move || {
        trace_core::inspect_runtime_attestation_capture(&capture_path, &exact_binary_path)
    })
    .await
    .map_err(|error| format!("Task execution failed: {error}"))?
}

#[tauri::command]
pub async fn verify_crypto_semantic_kat(
    request: trace_core::CryptoSemanticKatRequest,
) -> Result<trace_core::CryptoSemanticKatReport, String> {
    tauri::async_runtime::spawn_blocking(move || {
        Ok(trace_core::verify_crypto_semantic_kat(&request))
    })
    .await
    .map_err(|error| format!("Task execution failed: {error}"))?
}

#[tauri::command]
pub async fn save_crypto_semantic_kat(
    path: String,
    request: trace_core::CryptoSemanticKatRequest,
) -> Result<String, String> {
    tauri::async_runtime::spawn_blocking(move || {
        let trimmed = path.trim();
        if trimmed.is_empty() {
            return Err("output path must not be empty".to_string());
        }
        let output_path = std::path::PathBuf::from(trimmed);
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
        trace_core::save_crypto_semantic_kat_report(&output_path.to_string_lossy(), &request)?;
        Ok(output_path.to_string_lossy().into_owned())
    })
    .await
    .map_err(|error| format!("Task execution failed: {error}"))?
}

#[tauri::command]
pub async fn inspect_crypto_semantic_kat(
    path: String,
) -> Result<trace_core::CryptoSemanticKatReport, String> {
    tauri::async_runtime::spawn_blocking(move || {
        trace_core::inspect_crypto_semantic_kat_report(&path)
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
pub async fn infer_frida_abi(
    path: String,
    min_observations: Option<u32>,
    max_functions: Option<u32>,
    max_candidates_per_function: Option<u32>,
    output_path: Option<String>,
) -> Result<trace_core::FridaAbiInferenceReport, String> {
    tauri::async_runtime::spawn_blocking(move || {
        let report = trace_core::inspect_frida_abi_capture(
            &path,
            &trace_core::FridaAbiInferenceOptions {
                min_observations: min_observations.unwrap_or(2),
                max_functions: max_functions.unwrap_or(64),
                max_candidates_per_function: max_candidates_per_function.unwrap_or(128),
            },
        )?;
        if let Some(output_path) = output_path {
            trace_core::save_frida_abi_inference(&output_path, &report)?;
        }
        Ok(report)
    })
    .await
    .map_err(|error| format!("Task execution failed: {error}"))?
}

#[tauri::command]
pub fn generate_frida_ollvm_dispatcher_hook(
    report: trace_core::OllvmReport,
    max_dispatchers: Option<u32>,
    idle_gap_ms: Option<u32>,
    max_events: Option<u32>,
    capture_pointer_registers: Option<Vec<u8>>,
    pointer_capture_bytes: Option<u32>,
    stack_capture_bytes: Option<u32>,
) -> Result<trace_core::FridaOllvmDispatcherHookScript, String> {
    trace_core::generate_frida_ollvm_dispatcher_hook(
        &report,
        &trace_core::FridaOllvmDispatcherHookOptions {
            max_dispatchers: max_dispatchers.unwrap_or(12),
            idle_gap_ms: idle_gap_ms.unwrap_or(1_000),
            max_events: max_events.unwrap_or(50_000),
            capture_pointer_registers: capture_pointer_registers.unwrap_or_default(),
            pointer_capture_bytes: pointer_capture_bytes.unwrap_or(64),
            stack_capture_bytes: stack_capture_bytes.unwrap_or(0),
        },
    )
}

#[tauri::command]
pub async fn save_frida_ollvm_dispatcher_hook(
    path: String,
    report: trace_core::OllvmReport,
    max_dispatchers: Option<u32>,
    idle_gap_ms: Option<u32>,
    max_events: Option<u32>,
    capture_pointer_registers: Option<Vec<u8>>,
    pointer_capture_bytes: Option<u32>,
    stack_capture_bytes: Option<u32>,
) -> Result<String, String> {
    tauri::async_runtime::spawn_blocking(move || {
        let generated = trace_core::generate_frida_ollvm_dispatcher_hook(
            &report,
            &trace_core::FridaOllvmDispatcherHookOptions {
                max_dispatchers: max_dispatchers.unwrap_or(12),
                idle_gap_ms: idle_gap_ms.unwrap_or(1_000),
                max_events: max_events.unwrap_or(50_000),
                capture_pointer_registers: capture_pointer_registers.unwrap_or_default(),
                pointer_capture_bytes: pointer_capture_bytes.unwrap_or(64),
                stack_capture_bytes: stack_capture_bytes.unwrap_or(0),
            },
        )?;
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
            .map_err(|error| format!("failed to save dispatcher hook script: {error}"))?;
        Ok(output_path.to_string_lossy().into_owned())
    })
    .await
    .map_err(|error| format!("Task execution failed: {error}"))?
}

fn frida_ollvm_atlas_options(
    idle_gap_ms: Option<u32>,
    max_events: Option<u32>,
    max_values_per_register: Option<u32>,
    max_state_changes_per_transition: Option<u32>,
    max_flow_length: Option<u32>,
    max_flows: Option<u32>,
) -> trace_core::FridaOllvmDispatcherAtlasOptions {
    trace_core::FridaOllvmDispatcherAtlasOptions {
        idle_gap_ms: idle_gap_ms.unwrap_or(1_000),
        max_events: max_events.unwrap_or(50_000),
        max_values_per_register: max_values_per_register.unwrap_or(64),
        max_state_changes_per_transition: max_state_changes_per_transition.unwrap_or(128),
        max_flow_length: max_flow_length.unwrap_or(256),
        max_flows: max_flows.unwrap_or(2_048),
    }
}

#[tauri::command]
pub async fn analyze_frida_ollvm_dispatcher_capture(
    report: trace_core::OllvmReport,
    bundle: trace_core::FridaCaptureBundle,
    idle_gap_ms: Option<u32>,
    max_events: Option<u32>,
    max_values_per_register: Option<u32>,
    max_state_changes_per_transition: Option<u32>,
    max_flow_length: Option<u32>,
    max_flows: Option<u32>,
) -> Result<trace_core::FridaOllvmDispatcherAtlas, String> {
    tauri::async_runtime::spawn_blocking(move || {
        trace_core::analyze_frida_ollvm_dispatcher_capture(
            &report,
            &bundle,
            &frida_ollvm_atlas_options(
                idle_gap_ms,
                max_events,
                max_values_per_register,
                max_state_changes_per_transition,
                max_flow_length,
                max_flows,
            ),
        )
    })
    .await
    .map_err(|error| format!("Task execution failed: {error}"))?
}

#[tauri::command]
pub async fn save_frida_ollvm_dispatcher_atlas(
    path: String,
    report: trace_core::OllvmReport,
    bundle: trace_core::FridaCaptureBundle,
    idle_gap_ms: Option<u32>,
    max_events: Option<u32>,
    max_values_per_register: Option<u32>,
    max_state_changes_per_transition: Option<u32>,
    max_flow_length: Option<u32>,
    max_flows: Option<u32>,
) -> Result<String, String> {
    tauri::async_runtime::spawn_blocking(move || {
        let atlas = trace_core::analyze_frida_ollvm_dispatcher_capture(
            &report,
            &bundle,
            &frida_ollvm_atlas_options(
                idle_gap_ms,
                max_events,
                max_values_per_register,
                max_state_changes_per_transition,
                max_flow_length,
                max_flows,
            ),
        )?;
        let trimmed = path.trim();
        if trimmed.is_empty() {
            return Err("output path must not be empty".to_string());
        }
        let mut output_path = std::path::PathBuf::from(trimmed);
        if output_path.extension().and_then(|value| value.to_str()) != Some("json") {
            output_path.set_extension("json");
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
        let bytes = serde_json::to_vec_pretty(&atlas)
            .map_err(|error| format!("failed to serialize dispatcher atlas: {error}"))?;
        std::fs::write(&output_path, bytes)
            .map_err(|error| format!("failed to save dispatcher atlas: {error}"))?;
        Ok(output_path.to_string_lossy().into_owned())
    })
    .await
    .map_err(|error| format!("Task execution failed: {error}"))?
}

#[tauri::command]
pub async fn analyze_frida_crypto_materials(
    bundle: trace_core::FridaCaptureBundle,
    max_materials: Option<u32>,
    include_unknown: Option<bool>,
) -> Result<trace_core::CryptoMaterialReport, String> {
    tauri::async_runtime::spawn_blocking(move || {
        trace_core::analyze_frida_crypto_materials(
            &bundle,
            max_materials,
            include_unknown.unwrap_or(false),
        )
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
pub async fn compare_ollvm_traces(
    request: trace_core::OllvmMultiTraceRequest,
    engine: State<'_, Arc<TraceEngine>>,
) -> Result<trace_core::OllvmMultiTraceReport, String> {
    let engine = engine.inner().clone();
    tauri::async_runtime::spawn_blocking(move || {
        engine
            .compare_ollvm_traces(request)
            .map_err(|error| error.to_string())
    })
    .await
    .map_err(|error| format!("Task execution failed: {error}"))?
}

#[tauri::command]
pub async fn map_ollvm_versions(
    request: trace_core::OllvmVersionMapRequest,
    engine: State<'_, Arc<TraceEngine>>,
) -> Result<trace_core::OllvmVersionMapReport, String> {
    let engine = engine.inner().clone();
    tauri::async_runtime::spawn_blocking(move || {
        engine
            .map_ollvm_versions(request)
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

fn build_angr_frida_seeds(
    bundle: Option<&trace_core::FridaCaptureBundle>,
    legacy_event_index: Option<u64>,
    event_indices: Option<Vec<u64>>,
    include_sp: bool,
    include_lr: bool,
) -> Result<Vec<trace_core::AngrStateSeed>, String> {
    let mut indices = event_indices.unwrap_or_default();
    if let Some(index) = legacy_event_index {
        indices.push(index);
    }
    indices.sort_unstable();
    indices.dedup();
    if indices.len() > 32 {
        return Err("at most 32 Frida events may seed one OLLVM angr script".to_string());
    }
    match (bundle, indices.is_empty()) {
        (None, true) => Ok(Vec::new()),
        (Some(_), true) => Err(
            "fridaBundle requires fridaEventIndex or fridaEventIndices for OLLVM seed merging"
                .to_string(),
        ),
        (None, false) => Err(
            "fridaBundle must accompany fridaEventIndex/fridaEventIndices for OLLVM seed merging"
                .to_string(),
        ),
        (Some(bundle), false) => indices
            .into_iter()
            .map(|event_index| {
                trace_core::generate_angr_state_seed(bundle, event_index, include_sp, include_lr)
            })
            .collect(),
    }
}

fn inspect_optional_elf_identity(
    static_binary_path: Option<&str>,
) -> Result<Option<trace_core::ElfBinaryIdentity>, String> {
    let Some(path) = static_binary_path
        .map(str::trim)
        .filter(|path| !path.is_empty())
    else {
        return Ok(None);
    };
    let identity = trace_core::inspect_elf_binary(path)?;
    if identity.elf_machine != 183 {
        return Err(format!(
            "angr OLLVM bridge requires an AArch64 ELF, got {}",
            identity.architecture
        ));
    }
    Ok(Some(identity))
}

#[tauri::command]
pub fn generate_angr_ollvm_script(
    report: trace_core::OllvmReport,
    probe_opaque_branches: Option<bool>,
    use_cfg_emulated: Option<bool>,
    explore_seeded_flows: Option<bool>,
    flow_max_depth: Option<u32>,
    flow_max_states_per_probe: Option<u32>,
    frida_bundle: Option<trace_core::FridaCaptureBundle>,
    frida_event_index: Option<u64>,
    frida_event_indices: Option<Vec<u64>>,
    frida_include_sp: Option<bool>,
    frida_include_lr: Option<bool>,
    static_binary_path: Option<String>,
    checkpoint_result_path: Option<String>,
) -> Result<trace_core::AngrOllvmScript, String> {
    let frida_seeds = build_angr_frida_seeds(
        frida_bundle.as_ref(),
        frida_event_index,
        frida_event_indices,
        frida_include_sp.unwrap_or(false),
        frida_include_lr.unwrap_or(true),
    )?;
    let expected_identity = inspect_optional_elf_identity(static_binary_path.as_deref())?;
    let checkpoint_result = checkpoint_result_path
        .as_deref()
        .filter(|path| !path.trim().is_empty())
        .map(read_unicorn_ollvm_results)
        .transpose()?;
    trace_core::generate_angr_ollvm_script_with_seeds_flow_identity_and_checkpoint(
        &report,
        probe_opaque_branches.unwrap_or(true),
        use_cfg_emulated.unwrap_or(false),
        frida_seeds.iter().collect(),
        trace_core::AngrOllvmFlowConfig {
            enabled: explore_seeded_flows.unwrap_or(true),
            max_depth: flow_max_depth.unwrap_or(8),
            max_states_per_probe: flow_max_states_per_probe.unwrap_or(32),
        },
        expected_identity.as_ref(),
        checkpoint_result.as_ref(),
    )
}

#[tauri::command]
pub async fn save_angr_ollvm_script(
    path: String,
    report: trace_core::OllvmReport,
    probe_opaque_branches: Option<bool>,
    use_cfg_emulated: Option<bool>,
    explore_seeded_flows: Option<bool>,
    flow_max_depth: Option<u32>,
    flow_max_states_per_probe: Option<u32>,
    frida_bundle: Option<trace_core::FridaCaptureBundle>,
    frida_event_index: Option<u64>,
    frida_event_indices: Option<Vec<u64>>,
    frida_include_sp: Option<bool>,
    frida_include_lr: Option<bool>,
    static_binary_path: Option<String>,
    checkpoint_result_path: Option<String>,
) -> Result<String, String> {
    tauri::async_runtime::spawn_blocking(move || {
        let frida_seeds = build_angr_frida_seeds(
            frida_bundle.as_ref(),
            frida_event_index,
            frida_event_indices,
            frida_include_sp.unwrap_or(false),
            frida_include_lr.unwrap_or(true),
        )?;
        let expected_identity = inspect_optional_elf_identity(static_binary_path.as_deref())?;
        let checkpoint_result = checkpoint_result_path
            .as_deref()
            .filter(|path| !path.trim().is_empty())
            .map(read_unicorn_ollvm_results)
            .transpose()?;
        let generated =
            trace_core::generate_angr_ollvm_script_with_seeds_flow_identity_and_checkpoint(
                &report,
                probe_opaque_branches.unwrap_or(true),
                use_cfg_emulated.unwrap_or(false),
                frida_seeds.iter().collect(),
                trace_core::AngrOllvmFlowConfig {
                    enabled: explore_seeded_flows.unwrap_or(true),
                    max_depth: flow_max_depth.unwrap_or(8),
                    max_states_per_probe: flow_max_states_per_probe.unwrap_or(32),
                },
                expected_identity.as_ref(),
                checkpoint_result.as_ref(),
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

fn inspect_required_unicorn_elf(
    static_binary_path: &str,
) -> Result<trace_core::ElfBinaryIdentity, String> {
    let path = static_binary_path.trim();
    if path.is_empty() {
        return Err("Unicorn OLLVM replay requires an exact ELF path".to_string());
    }
    let identity = trace_core::inspect_elf_binary(path)?;
    if identity.elf_machine != 183 {
        return Err(format!(
            "Unicorn OLLVM replay requires an AArch64 ELF, got {}",
            identity.architecture
        ));
    }
    Ok(identity)
}

#[tauri::command]
pub fn generate_unicorn_ollvm_script(
    report: trace_core::OllvmReport,
    max_instructions: Option<u64>,
    timeout_ms: Option<u64>,
    max_memory_writes: Option<u64>,
    max_recorded_offsets: Option<u64>,
    stop_on_call: Option<bool>,
    loop_visit_limit: Option<u32>,
    frida_bundle: Option<trace_core::FridaCaptureBundle>,
    frida_event_index: Option<u64>,
    frida_event_indices: Option<Vec<u64>>,
    static_binary_path: String,
    checkpoint_result_path: Option<String>,
    exact_call_authorization_paths: Vec<String>,
) -> Result<trace_core::UnicornOllvmScript, String> {
    let seeds = build_angr_frida_seeds(
        frida_bundle.as_ref(),
        frida_event_index,
        frida_event_indices,
        true,
        true,
    )?;
    if seeds.is_empty() {
        return Err(
            "Unicorn concrete replay requires at least one selected Frida event".to_string(),
        );
    }
    let identity = inspect_required_unicorn_elf(&static_binary_path)?;
    let checkpoint_result = checkpoint_result_path
        .as_deref()
        .filter(|path| !path.trim().is_empty())
        .map(read_unicorn_ollvm_results)
        .transpose()?;
    let exact_call_authorizations = trace_core::load_authorized_exact_calls(
        &exact_call_authorization_paths,
        &static_binary_path,
        &report.scope.module_name,
    )?;
    trace_core::generate_unicorn_ollvm_script_with_checkpoint_and_exact_calls(
        &report,
        seeds.iter().collect(),
        trace_core::UnicornOllvmConfig {
            max_instructions: max_instructions.unwrap_or(50_000),
            timeout_ms: timeout_ms.unwrap_or(5_000),
            max_memory_writes: max_memory_writes.unwrap_or(4_096),
            max_recorded_offsets: max_recorded_offsets.unwrap_or(50_000),
            stop_on_call: stop_on_call.unwrap_or(true),
            loop_visit_limit: loop_visit_limit.unwrap_or(2),
        },
        &identity,
        checkpoint_result.as_ref(),
        &exact_call_authorizations,
    )
}

#[tauri::command]
pub async fn save_unicorn_ollvm_script(
    path: String,
    report: trace_core::OllvmReport,
    max_instructions: Option<u64>,
    timeout_ms: Option<u64>,
    max_memory_writes: Option<u64>,
    max_recorded_offsets: Option<u64>,
    stop_on_call: Option<bool>,
    loop_visit_limit: Option<u32>,
    frida_bundle: Option<trace_core::FridaCaptureBundle>,
    frida_event_index: Option<u64>,
    frida_event_indices: Option<Vec<u64>>,
    static_binary_path: String,
    checkpoint_result_path: Option<String>,
    exact_call_authorization_paths: Vec<String>,
) -> Result<String, String> {
    tauri::async_runtime::spawn_blocking(move || {
        let seeds = build_angr_frida_seeds(
            frida_bundle.as_ref(),
            frida_event_index,
            frida_event_indices,
            true,
            true,
        )?;
        if seeds.is_empty() {
            return Err(
                "Unicorn concrete replay requires at least one selected Frida event".to_string(),
            );
        }
        let identity = inspect_required_unicorn_elf(&static_binary_path)?;
        let checkpoint_result = checkpoint_result_path
            .as_deref()
            .filter(|path| !path.trim().is_empty())
            .map(read_unicorn_ollvm_results)
            .transpose()?;
        let exact_call_authorizations = trace_core::load_authorized_exact_calls(
            &exact_call_authorization_paths,
            &static_binary_path,
            &report.scope.module_name,
        )?;
        let generated = trace_core::generate_unicorn_ollvm_script_with_checkpoint_and_exact_calls(
            &report,
            seeds.iter().collect(),
            trace_core::UnicornOllvmConfig {
                max_instructions: max_instructions.unwrap_or(50_000),
                timeout_ms: timeout_ms.unwrap_or(5_000),
                max_memory_writes: max_memory_writes.unwrap_or(4_096),
                max_recorded_offsets: max_recorded_offsets.unwrap_or(50_000),
                stop_on_call: stop_on_call.unwrap_or(true),
                loop_visit_limit: loop_visit_limit.unwrap_or(2),
            },
            &identity,
            checkpoint_result.as_ref(),
            &exact_call_authorizations,
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
            .map_err(|error| format!("failed to save Unicorn replay script: {error}"))?;
        Ok(output_path.to_string_lossy().into_owned())
    })
    .await
    .map_err(|error| format!("Task execution failed: {error}"))?
}

#[tauri::command]
pub async fn load_unicorn_ollvm_results(
    path: String,
) -> Result<trace_core::UnicornOllvmResultBundle, String> {
    tauri::async_runtime::spawn_blocking(move || read_unicorn_ollvm_results(&path))
        .await
        .map_err(|error| format!("Task execution failed: {error}"))?
}

#[tauri::command]
pub async fn compare_unicorn_ollvm_rounds(
    paths: Vec<String>,
    round_ids: Option<Vec<String>>,
) -> Result<trace_core::UnicornOllvmRoundComparisonReport, String> {
    tauri::async_runtime::spawn_blocking(move || {
        if !(2..=16).contains(&paths.len()) {
            return Err(
                "Unicorn round comparison requires between 2 and 16 result files".to_string(),
            );
        }
        let round_ids = match round_ids {
            Some(values) if values.len() == paths.len() => values,
            Some(_) => {
                return Err("Unicorn round comparison roundIds count must match paths".to_string())
            }
            None => paths
                .iter()
                .enumerate()
                .map(|(index, _)| format!("round-{}", index + 1))
                .collect(),
        };
        let mut total_bytes = 0u64;
        let mut loaded = Vec::with_capacity(paths.len());
        for (index, path) in paths.iter().enumerate() {
            let trimmed = path.trim();
            if trimmed.is_empty() {
                return Err(format!(
                    "Unicorn comparison path {} must not be empty",
                    index + 1
                ));
            }
            let metadata = std::fs::metadata(trimmed)
                .map_err(|error| format!("failed to inspect Unicorn result {trimmed}: {error}"))?;
            total_bytes = total_bytes.saturating_add(metadata.len());
            if total_bytes > 256 * 1024 * 1024 {
                return Err(
                    "Unicorn round comparison input files exceed the 256 MiB aggregate limit"
                        .to_string(),
                );
            }
            let bundle = read_unicorn_ollvm_results(trimmed)?;
            let source_label = std::path::Path::new(trimmed)
                .file_name()
                .and_then(|value| value.to_str())
                .unwrap_or(trimmed)
                .to_string();
            loaded.push((round_ids[index].clone(), source_label, bundle));
        }
        let inputs = loaded
            .iter()
            .map(
                |(round_id, source_label, bundle)| trace_core::UnicornOllvmRoundInput {
                    round_id,
                    source_label: Some(source_label),
                    bundle,
                },
            )
            .collect::<Vec<_>>();
        trace_core::compare_unicorn_ollvm_rounds(&inputs)
    })
    .await
    .map_err(|error| format!("Task execution failed: {error}"))?
}

fn read_unicorn_ollvm_results(path: &str) -> Result<trace_core::UnicornOllvmResultBundle, String> {
    let trimmed = path.trim();
    if trimmed.is_empty() {
        return Err("Unicorn result path must not be empty".to_string());
    }
    let bytes = std::fs::read(trimmed)
        .map_err(|error| format!("failed to read Unicorn results: {error}"))?;
    trace_core::parse_unicorn_ollvm_result_bundle(&bytes)
}

#[tauri::command]
pub async fn generate_frida_unicorn_recapture_hook(
    unicorn_result_path: String,
    suggestion_indices: Vec<u32>,
    max_events: Option<u32>,
) -> Result<trace_core::FridaUnicornRecaptureHookScript, String> {
    tauri::async_runtime::spawn_blocking(move || {
        let bundle = read_unicorn_ollvm_results(&unicorn_result_path)?;
        trace_core::generate_frida_unicorn_recapture_hook(
            &bundle,
            &suggestion_indices,
            &trace_core::FridaUnicornRecaptureHookOptions {
                max_events: max_events.unwrap_or(5_000),
            },
        )
    })
    .await
    .map_err(|error| format!("Task execution failed: {error}"))?
}

#[tauri::command]
pub async fn save_frida_unicorn_recapture_hook(
    path: String,
    unicorn_result_path: String,
    suggestion_indices: Vec<u32>,
    max_events: Option<u32>,
) -> Result<String, String> {
    tauri::async_runtime::spawn_blocking(move || {
        let bundle = read_unicorn_ollvm_results(&unicorn_result_path)?;
        let generated = trace_core::generate_frida_unicorn_recapture_hook(
            &bundle,
            &suggestion_indices,
            &trace_core::FridaUnicornRecaptureHookOptions {
                max_events: max_events.unwrap_or(5_000),
            },
        )?;
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
            .map_err(|error| format!("failed to save Frida recapture hook: {error}"))?;
        Ok(output_path.to_string_lossy().into_owned())
    })
    .await
    .map_err(|error| format!("Task execution failed: {error}"))?
}

#[tauri::command]
pub async fn generate_frida_unicorn_checkpoint_hook(
    unicorn_result_path: String,
    seed_capture_offsets: Vec<String>,
    max_events: Option<u32>,
) -> Result<trace_core::FridaUnicornCheckpointHookScript, String> {
    tauri::async_runtime::spawn_blocking(move || {
        let bundle = read_unicorn_ollvm_results(&unicorn_result_path)?;
        trace_core::generate_frida_unicorn_checkpoint_hook(
            &bundle,
            &seed_capture_offsets,
            &trace_core::FridaUnicornCheckpointHookOptions {
                max_events: max_events.unwrap_or(5_000),
            },
        )
    })
    .await
    .map_err(|error| format!("Task execution failed: {error}"))?
}

#[tauri::command]
pub async fn save_frida_unicorn_checkpoint_hook(
    path: String,
    unicorn_result_path: String,
    seed_capture_offsets: Vec<String>,
    max_events: Option<u32>,
) -> Result<String, String> {
    tauri::async_runtime::spawn_blocking(move || {
        let bundle = read_unicorn_ollvm_results(&unicorn_result_path)?;
        let generated = trace_core::generate_frida_unicorn_checkpoint_hook(
            &bundle,
            &seed_capture_offsets,
            &trace_core::FridaUnicornCheckpointHookOptions {
                max_events: max_events.unwrap_or(5_000),
            },
        )?;
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
            .map_err(|error| format!("failed to save Frida checkpoint hook: {error}"))?;
        Ok(output_path.to_string_lossy().into_owned())
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

// Analysis Case / Replay Doctor

#[tauri::command]
pub async fn create_analysis_case(
    case_path: String,
    title: String,
    session_id: Option<String>,
    primary_trace_path: Option<String>,
    exact_binary_path: Option<String>,
    engine: State<'_, Arc<TraceEngine>>,
) -> Result<trace_core::TraceAnalysisCaseDocument, String> {
    let engine = engine.inner().clone();
    tauri::async_runtime::spawn_blocking(move || {
        let trace_path = if let Some(session_id) = session_id {
            Some(
                engine
                    .get_session_info(&session_id)
                    .map_err(|error| error.to_string())?
                    .file_path,
            )
        } else {
            primary_trace_path
        };
        trace_core::create_trace_analysis_case(
            &case_path,
            &title,
            trace_path.as_deref(),
            exact_binary_path.as_deref(),
        )
        .map_err(|error| error.to_string())
    })
    .await
    .map_err(|error| format!("Task execution failed: {error}"))?
}

#[tauri::command]
pub async fn load_analysis_case(
    case_path: String,
) -> Result<trace_core::TraceAnalysisCaseDocument, String> {
    tauri::async_runtime::spawn_blocking(move || {
        trace_core::load_trace_analysis_case(&case_path).map_err(|error| error.to_string())
    })
    .await
    .map_err(|error| format!("Task execution failed: {error}"))?
}

#[tauri::command]
pub async fn add_analysis_case_artifact(
    case_path: String,
    artifact_path: String,
    kind_hint: Option<String>,
    label: Option<String>,
    parent_artifact_ids: Option<Vec<String>>,
) -> Result<trace_core::TraceCaseArtifactImportResult, String> {
    tauri::async_runtime::spawn_blocking(move || {
        trace_core::add_trace_case_artifact(
            &case_path,
            &artifact_path,
            kind_hint.as_deref(),
            label.as_deref(),
            parent_artifact_ids.unwrap_or_default(),
        )
        .map_err(|error| error.to_string())
    })
    .await
    .map_err(|error| format!("Task execution failed: {error}"))?
}

#[tauri::command]
pub async fn diagnose_analysis_case(
    case_path: String,
    persist_generated_claims: Option<bool>,
) -> Result<trace_core::ReplayDoctorReport, String> {
    tauri::async_runtime::spawn_blocking(move || {
        let report = trace_core::diagnose_trace_analysis_case(&case_path)
            .map_err(|error| error.to_string())?;
        if persist_generated_claims.unwrap_or(false) {
            for claim in report.generated_claims.iter().cloned() {
                trace_core::upsert_trace_case_claim(&case_path, claim)
                    .map_err(|error| error.to_string())?;
            }
        }
        Ok(report)
    })
    .await
    .map_err(|error| format!("Task execution failed: {error}"))?
}

#[tauri::command]
pub async fn plan_analysis_case_capture(
    case_path: String,
) -> Result<trace_core::InformationGainCapturePlan, String> {
    tauri::async_runtime::spawn_blocking(move || {
        trace_core::diagnose_trace_analysis_case(&case_path)
            .map(|report| report.capture_plan)
            .map_err(|error| error.to_string())
    })
    .await
    .map_err(|error| format!("Task execution failed: {error}"))?
}

#[tauri::command]
pub async fn generate_coverage_reconciliation_script(
    request: trace_core::CoverageReconciliationScriptRequest,
    output_path: Option<String>,
) -> Result<trace_core::CoverageReconciliationScript, String> {
    tauri::async_runtime::spawn_blocking(move || {
        let generated = trace_core::generate_coverage_reconciliation_script(&request)?;
        if let Some(output_path) = output_path
            .as_deref()
            .map(str::trim)
            .filter(|path| !path.is_empty())
        {
            let mut path = std::path::PathBuf::from(output_path);
            if path.extension().and_then(|value| value.to_str()) != Some("py") {
                path.set_extension("py");
            }
            let parent = path
                .parent()
                .filter(|value| !value.as_os_str().is_empty())
                .ok_or_else(|| {
                    "coverage script output path must include a parent directory".to_string()
                })?;
            if !parent.is_dir() {
                return Err(format!(
                    "coverage script output directory does not exist: {}",
                    parent.display()
                ));
            }
            std::fs::write(&path, generated.script.as_bytes()).map_err(|error| {
                format!("failed to save coverage reconciliation script: {error}")
            })?;
        }
        Ok(generated)
    })
    .await
    .map_err(|error| format!("Task execution failed: {error}"))?
}

#[tauri::command]
pub async fn inspect_coverage_reconciliation(
    artifact_path: String,
    static_binary_path: String,
    source_artifact_paths: Option<Vec<String>>,
) -> Result<trace_core::CoverageReconciliationInspectionReport, String> {
    tauri::async_runtime::spawn_blocking(move || {
        trace_core::inspect_coverage_reconciliation(
            &artifact_path,
            &static_binary_path,
            &source_artifact_paths.unwrap_or_default(),
        )
    })
    .await
    .map_err(|error| format!("Task execution failed: {error}"))?
}

#[tauri::command]
pub async fn generate_minimal_evidence_slice(
    request: trace_core::MinimalEvidenceSliceRequest,
    output_path: Option<String>,
    engine: State<'_, Arc<TraceEngine>>,
) -> Result<trace_core::MinimalEvidenceSliceBundle, String> {
    let engine = engine.inner().clone();
    tauri::async_runtime::spawn_blocking(move || {
        let bundle = trace_core::generate_minimal_evidence_slice(&engine, &request)
            .map_err(|error| error.to_string())?;
        if let Some(output_path) = output_path
            .as_deref()
            .map(str::trim)
            .filter(|path| !path.is_empty())
        {
            trace_core::save_minimal_evidence_slice_bundle(&bundle, output_path)
                .map_err(|error| error.to_string())?;
        }
        Ok(bundle)
    })
    .await
    .map_err(|error| format!("Task execution failed: {error}"))?
}

#[tauri::command]
pub async fn inspect_minimal_evidence_slice(
    case_path: String,
    artifact_path: String,
) -> Result<trace_core::MinimalEvidenceSliceInspectionReport, String> {
    tauri::async_runtime::spawn_blocking(move || {
        trace_core::inspect_minimal_evidence_slice(&case_path, &artifact_path)
            .map_err(|error| error.to_string())
    })
    .await
    .map_err(|error| format!("Task execution failed: {error}"))?
}

#[tauri::command]
pub async fn run_accuracy_benchmark(
    suite_path: String,
) -> Result<trace_core::AccuracyBenchmarkReport, String> {
    tauri::async_runtime::spawn_blocking(move || {
        trace_core::run_accuracy_benchmark_file(&suite_path)
    })
    .await
    .map_err(|error| format!("Task execution failed: {error}"))?
}

#[tauri::command]
pub async fn upsert_analysis_case_claim(
    case_path: String,
    claim: trace_core::TraceCaseClaim,
) -> Result<trace_core::TraceAnalysisCaseDocument, String> {
    tauri::async_runtime::spawn_blocking(move || {
        trace_core::upsert_trace_case_claim(&case_path, claim).map_err(|error| error.to_string())
    })
    .await
    .map_err(|error| format!("Task execution failed: {error}"))?
}

#[tauri::command]
pub async fn upsert_analysis_case_experiment(
    case_path: String,
    experiment: trace_core::TraceCaseExperiment,
) -> Result<trace_core::TraceAnalysisCaseDocument, String> {
    tauri::async_runtime::spawn_blocking(move || {
        trace_core::upsert_trace_case_experiment(&case_path, experiment)
            .map_err(|error| error.to_string())
    })
    .await
    .map_err(|error| format!("Task execution failed: {error}"))?
}

#[tauri::command]
pub async fn diagnose_crypto_detection(
    session_id: String,
    target_algorithm: Option<String>,
    static_binary_path: Option<String>,
    engine: State<'_, Arc<TraceEngine>>,
) -> Result<trace_core::CryptoDetectionDoctorReport, String> {
    let engine = engine.inner().clone();
    tauri::async_runtime::spawn_blocking(move || {
        engine
            .diagnose_crypto_detection(
                &session_id,
                target_algorithm.as_deref().unwrap_or("AES"),
                static_binary_path,
            )
            .map_err(|error| error.to_string())
    })
    .await
    .map_err(|error| format!("Task execution failed: {error}"))?
}

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
