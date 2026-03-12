#![windows_subsystem = "windows"]

mod cache;
mod commands;
mod taint;
mod line_index;
mod phase2;
mod state;

use state::AppState;

fn main() {
    tauri::Builder::default()
        .plugin(tauri_plugin_dialog::init())
        .plugin(tauri_plugin_opener::init())
        .manage(AppState::new())
        .invoke_handler(tauri::generate_handler![
            commands::file::create_session,
            commands::file::close_session,
            commands::file::delete_file_cache,
            commands::browse::get_lines,
            commands::index::build_index,
            commands::registers::get_registers_at,
            commands::call_tree::get_call_tree,
            commands::search::search_trace,
            commands::memory::get_memory_at,
            commands::memory::get_mem_history,
            commands::def_use::get_reg_def_use_chain,
            commands::slice::run_slice,
            commands::slice::get_slice_status,
            commands::slice::clear_slice,
            commands::slice::get_tainted_seqs,
            commands::slice::export_taint_results,
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
