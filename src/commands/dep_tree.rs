use tauri::{AppHandle, Manager, State};
use crate::state::AppState;
use crate::taint::dep_tree::{self, DependencyGraph};
use crate::taint::types::TraceFormat;
use crate::taint::parser;
use crate::taint::gumtrace_parser;
use crate::taint::insn_class;
use crate::taint::def_use::determine_def_use;

const DEFAULT_MAX_NODES: u32 = 10_000;

#[tauri::command]
pub async fn build_dependency_tree(
    session_id: String, seq: u32, target: String,
    data_only: Option<bool>, max_nodes: Option<u32>,
    app: AppHandle,
) -> Result<DependencyGraph, String> {
    let data_only = data_only.unwrap_or(false);
    let max_nodes = max_nodes.unwrap_or(DEFAULT_MAX_NODES);
    tauri::async_runtime::spawn_blocking(move || {
        let state = app.state::<AppState>();
        build_graph_inner(&session_id, seq, &target, data_only, max_nodes, &state)
    }).await.map_err(|e| format!("Task execution failed: {}", e))?
}

#[tauri::command]
pub async fn build_dependency_tree_from_slice(
    session_id: String, max_nodes: Option<u32>, data_only: Option<bool>,
    app: AppHandle,
) -> Result<DependencyGraph, String> {
    let max_nodes = max_nodes.unwrap_or(DEFAULT_MAX_NODES);
    tauri::async_runtime::spawn_blocking(move || {
        let state = app.state::<AppState>();
        let sessions = state.sessions.read().map_err(|e| e.to_string())?;
        let session = sessions.get(&session_id)
            .ok_or_else(|| format!("Session {} not found", session_id))?;
        let origin = session.slice_origin.as_ref()
            .ok_or("No active taint analysis result, please run taint tracking first")?;
        let spec = origin.from_specs.first()
            .ok_or("No from_specs in SliceOrigin")?;
        let data_only_val = data_only.unwrap_or(origin.data_only);

        let reg_last_def = session.reg_last_def.as_ref().ok_or("Index not yet built")?;
        let mem_last_def = session.mem_last_def_view().ok_or("Index not yet built")?;
        let lidx_view = session.line_index_view().ok_or("Index not yet built")?;
        let format = session.trace_format;

        let start_idx = crate::commands::slice::resolve_start_index(
            spec, reg_last_def, &mem_last_def, &session.mmap, &lidx_view, format)?;
        let scan_view = session.scan_view().ok_or("Index not yet built")?;

        let mut graph = dep_tree::build_graph(&scan_view, start_idx, data_only_val, max_nodes);
        dep_tree::populate_graph_info(&mut graph, &session.mmap, &lidx_view, format);
        Ok(graph)
    }).await.map_err(|e| format!("Task execution failed: {}", e))?
}

#[tauri::command]
pub fn get_line_def_registers(
    session_id: String, seq: u32, state: State<'_, AppState>,
) -> Result<Vec<String>, String> {
    let sessions = state.sessions.read().map_err(|e| e.to_string())?;
    let session = sessions.get(&session_id)
        .ok_or_else(|| format!("Session {} not found", session_id))?;
    let lidx_view = session.line_index_view().ok_or("Index not yet built")?;
    let format = session.trace_format;

    if let Some(raw) = lidx_view.get_line(&session.mmap, seq) {
        if let Ok(line_str) = std::str::from_utf8(raw) {
            let parsed = match format {
                TraceFormat::Unidbg => parser::parse_line(line_str),
                TraceFormat::Gumtrace => gumtrace_parser::parse_line_gumtrace(line_str),
            };
            if let Some(ref p) = parsed {
                let cls = insn_class::classify_and_refine(p);
                let (defs, _) = determine_def_use(cls, p);
                return Ok(defs.iter().map(|r| format!("{:?}", r)).collect());
            }
        }
    }
    Ok(vec![])
}

fn build_graph_inner(
    session_id: &str, seq: u32, target: &str, data_only: bool, max_nodes: u32, state: &AppState,
) -> Result<DependencyGraph, String> {
    let sessions = state.sessions.read().map_err(|e| e.to_string())?;
    let session = sessions.get(session_id)
        .ok_or_else(|| format!("Session {} not found", session_id))?;
    let format = session.trace_format;
    let lidx_view = session.line_index_view().ok_or("Index not yet built")?;

    let spec = if target.starts_with("mem:") {
        format!("{}@{}", target, seq + 1)
    } else {
        let reg_name = target.strip_prefix("reg:").unwrap_or(target);
        format!("reg:{}@{}", reg_name, seq + 1)
    };

    let reg_last_def = session.reg_last_def.as_ref().ok_or("Index not yet built")?;
    let mem_last_def = session.mem_last_def_view().ok_or("Index not yet built")?;

    let start_idx = crate::commands::slice::resolve_start_index(
        &spec, reg_last_def, &mem_last_def, &session.mmap, &lidx_view, format)?;
    let scan_view = session.scan_view().ok_or("Index not yet built")?;

    let mut graph = dep_tree::build_graph(&scan_view, start_idx, data_only, max_nodes);
    dep_tree::populate_graph_info(&mut graph, &session.mmap, &lidx_view, format);
    Ok(graph)
}
