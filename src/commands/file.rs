use std::sync::Arc;
use serde::Serialize;
use tauri::{AppHandle, Emitter, State};
use crate::state::{AppState, SessionState};
use crate::line_index::LineIndex;

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateSessionResult {
    pub session_id: String,
    pub total_lines: u32,
    pub file_size: u64,
}

#[tauri::command]
pub async fn create_session(
    path: String,
    app: AppHandle,
    state: State<'_, AppState>,
) -> Result<CreateSessionResult, String> {
    let path_clone = path.clone();
    let app_clone = app.clone();

    let (mmap, line_index, file_size) = tauri::async_runtime::spawn_blocking(move || {
        let file = std::fs::File::open(&path_clone).map_err(|e| format!("无法打开文件: {}", e))?;
        let metadata = file.metadata().map_err(|e| format!("无法读取文件信息: {}", e))?;
        let file_size = metadata.len();
        let mmap = unsafe { memmap2::Mmap::map(&file) }.map_err(|e| format!("mmap 失败: {}", e))?;
        let progress_cb = |processed: usize, total: usize| {
            let pct = processed as f64 / total as f64;
            let _ = app_clone.emit("file-loading-progress", serde_json::json!({
                "progress": pct,
            }));
        };
        let line_index = LineIndex::build_with_progress(&mmap, Some(&progress_cb));
        Ok::<_, String>((mmap, line_index, file_size))
    })
    .await
    .map_err(|e| format!("线程 panic: {}", e))?
    .map_err(|e: String| e)?;

    let total_lines = line_index.total_lines();
    let session_id = uuid::Uuid::new_v4().to_string();

    {
        let mut sessions = state.sessions.write().map_err(|e| format!("锁获取失败: {}", e))?;
        sessions.insert(session_id.clone(), SessionState {
            mmap: Arc::new(mmap),
            line_index,
            file_path: path,
            total_lines,
            file_size,
            phase2: None,
            scan_state: None,
            slice_result: None,
        });
    }

    Ok(CreateSessionResult { session_id, total_lines, file_size })
}

#[tauri::command]
pub fn close_session(session_id: String, state: State<'_, AppState>) -> Result<(), String> {
    let mut sessions = state.sessions.write().map_err(|e| format!("锁获取失败: {}", e))?;
    sessions.remove(&session_id);
    Ok(())
}

#[tauri::command]
pub fn delete_file_cache(path: String) -> Result<(), String> {
    crate::cache::delete_cache(&path);
    Ok(())
}
