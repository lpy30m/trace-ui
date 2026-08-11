#![windows_subsystem = "windows"]

mod commands;
mod mcp;

use std::sync::Arc;
use tauri::Manager;
use trace_core::TraceEngine;

#[tauri::command]
fn toggle_devtools(window: tauri::WebviewWindow) {
    if window.is_devtools_open() {
        window.close_devtools();
    } else {
        window.open_devtools();
    }
}

fn main() {
    let engine = Arc::new(TraceEngine::new());

    tauri::Builder::default()
        .plugin(tauri_plugin_dialog::init())
        .plugin(tauri_plugin_opener::init())
        .manage(engine)
        .setup(|app| {
            let _window = app.get_webview_window("main").unwrap();

            // Windows 不支持 titleBarStyle: "Overlay"，需要手动关闭原生装饰
            #[cfg(target_os = "windows")]
            let _ = _window.set_decorations(false);

            // 创建 MCP 控制器（不启动，等前端调用 start_mcp）
            let mcp_engine = app.state::<Arc<TraceEngine>>().inner().clone();
            let controller = mcp::McpController::new(mcp_engine, app.handle().clone());
            app.manage(controller);

            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            toggle_devtools,
            commands::create_session,
            commands::close_session,
            commands::delete_file_cache,
            commands::get_lines,
            commands::build_index,
            commands::get_registers_at,
            commands::get_call_tree,
            commands::get_call_tree_node_count,
            commands::get_call_tree_children,
            commands::search_trace,
            commands::fetch_search_page,
            commands::get_search_matches,
            commands::get_memory_at,
            commands::get_mem_history_meta,
            commands::get_mem_history_range,
            commands::get_reg_def_use_chain,
            commands::run_slice,
            commands::get_slice_status,
            commands::clear_slice,
            commands::get_tainted_seqs,
            commands::export_taint_results,
            commands::get_cache_dir,
            commands::set_cache_dir,
            commands::clear_all_cache,
            commands::get_strings,
            commands::get_string_xrefs,
            commands::scan_strings,
            commands::cancel_scan_strings,
            commands::get_consumed_seqs,
            commands::get_function_calls,
            commands::build_dependency_tree,
            commands::build_dependency_tree_from_slice,
            commands::get_line_def_registers,
            commands::scan_crypto,
            commands::analyze_crypto_functions,
            commands::analyze_crypto_materials,
            commands::compare_crypto_material_traces,
            commands::list_frida_hook_recipes,
            commands::generate_frida_hook,
            commands::save_frida_hook,
            commands::generate_frida_runtime_attestation,
            commands::save_frida_runtime_attestation,
            commands::inspect_runtime_attestation,
            commands::verify_crypto_semantic_kat,
            commands::save_crypto_semantic_kat,
            commands::inspect_crypto_semantic_kat,
            commands::load_frida_capture,
            commands::infer_frida_abi,
            commands::generate_frida_ollvm_dispatcher_hook,
            commands::save_frida_ollvm_dispatcher_hook,
            commands::analyze_frida_ollvm_dispatcher_capture,
            commands::save_frida_ollvm_dispatcher_atlas,
            commands::analyze_frida_crypto_materials,
            commands::generate_angr_state_seed,
            commands::save_angr_state_seed,
            commands::analyze_ollvm,
            commands::compare_ollvm_traces,
            commands::map_ollvm_versions,
            commands::generate_ida_ollvm_script,
            commands::save_ida_ollvm_script,
            commands::load_ida_annotations,
            commands::generate_angr_ollvm_script,
            commands::save_angr_ollvm_script,
            commands::load_angr_ollvm_results,
            commands::generate_unicorn_ollvm_script,
            commands::save_unicorn_ollvm_script,
            commands::load_unicorn_ollvm_results,
            commands::compare_unicorn_ollvm_rounds,
            commands::generate_frida_unicorn_recapture_hook,
            commands::save_frida_unicorn_recapture_hook,
            commands::generate_frida_unicorn_checkpoint_hook,
            commands::save_frida_unicorn_checkpoint_hook,
            commands::analyze_whitebox_crypto,
            commands::compare_whitebox_traces,
            commands::list_trace_sessions,
            commands::match_known_digests,
            commands::find_digest_memory,
            commands::search_value,
            commands::run_forward_value_taint,
            commands::load_crypto_cache,
            commands::list_analyses,
            commands::get_analysis,
            commands::compare_analyses,
            commands::delete_analysis,
            commands::render_analysis_report,
            commands::create_analysis_case,
            commands::load_analysis_case,
            commands::add_analysis_case_artifact,
            commands::diagnose_analysis_case,
            commands::plan_analysis_case_capture,
            commands::run_accuracy_benchmark,
            commands::upsert_analysis_case_claim,
            commands::upsert_analysis_case_experiment,
            commands::diagnose_crypto_detection,
            commands::inspect_function,
            commands::inspect_function_at_seq,
            commands::start_mcp,
            commands::stop_mcp,
            commands::get_mcp_status,
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
