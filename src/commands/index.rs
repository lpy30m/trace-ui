use tauri::{AppHandle, Emitter, State};
use crate::cache;
use crate::state::AppState;
use crate::taint;

#[tauri::command]
pub async fn build_index(
    session_id: String,
    app: AppHandle,
    state: State<'_, AppState>,
    force: Option<bool>,
) -> Result<(), String> {
    let result = build_index_inner(&session_id, &app, &state, force.unwrap_or(false)).await;

    // 无论成功或失败，都发送 done 事件，防止前端永远卡在 loading
    let error = result.as_ref().err().cloned();
    let _ = app.emit("index-progress", serde_json::json!({
        "sessionId": session_id,
        "progress": 1.0,
        "done": true,
        "error": error,
    }));

    result
}

async fn build_index_inner(
    session_id: &str,
    app: &AppHandle,
    state: &State<'_, AppState>,
    force: bool,
) -> Result<(), String> {
    let (mmap_arc, file_path) = {
        let sessions = state.sessions.read().map_err(|e| e.to_string())?;
        let session = sessions.get(session_id)
            .ok_or_else(|| format!("Session {} 不存在", session_id))?;
        (session.mmap.clone(), session.file_path.clone())
    };

    let app_clone = app.clone();
    let session_id_clone = session_id.to_string();
    let progress_fn: taint::ProgressFn = Box::new(move |processed, total| {
        let progress = processed as f64 / total as f64;
        let _ = app_clone.emit("index-progress", serde_json::json!({
            "sessionId": session_id_clone,
            "progress": progress,
            "done": false,
        }));
    });

    let app_for_init = app.clone();
    let sid_for_init = session_id.to_string();

    let result = tauri::async_runtime::spawn_blocking(move || {
        let data: &[u8] = &mmap_arc;

        // 尝试从缓存加载
        if !force {
            if let Some(cached_phase2) = cache::load_cache(&file_path, data) {
                // Phase2 命中，尝试加载 ScanState 缓存
                if let Some(cached_scan) = cache::load_scan_cache(&file_path, data) {
                    // 双缓存命中，跳过所有扫描，不发送任何进度事件
                    return Ok((cached_scan, cached_phase2));
                }
                // 仅 Phase2 命中，需要重建 ScanState — 发送初始进度
                let _ = app_for_init.emit("index-progress", serde_json::json!({
                    "sessionId": sid_for_init,
                    "progress": 0.0,
                    "done": false,
                }));
                let scan_state = taint::scanner::scan_pass1_bytes_with_progress(
                    data, false, 0, None, &Default::default(), false, false,
                    Some(&*progress_fn),
                ).map_err(|e| format!("Scanner 失败: {}", e))?;
                cache::save_scan_cache(&file_path, data, &scan_state);
                return Ok((scan_state, cached_phase2));
            }
        }

        // 无缓存: 统一扫描 — 发送初始进度
        let _ = app_for_init.emit("index-progress", serde_json::json!({
            "sessionId": sid_for_init,
            "progress": 0.0,
            "done": false,
        }));
        let (scan_state, phase2) = taint::scan_unified(data, false, false, Some(progress_fn))
            .map_err(|e| format!("统一扫描失败: {}", e))?;

        // 格式检查：如果没有任何行被成功解析，说明不是有效的 trace 文件
        if scan_state.parsed_count == 0 && scan_state.line_count > 0 {
            return Err("文件格式不正确：未检测到有效的 ARM64 trace 指令行".to_string());
        }

        // 保存缓存
        cache::save_cache(&file_path, data, &phase2);
        cache::save_scan_cache(&file_path, data, &scan_state);

        Ok::<_, String>((scan_state, phase2))
    })
    .await
    .map_err(|e| format!("扫描线程 panic: {}", e))?
    .map_err(|e: String| e)?;

    // 写入结果
    {
        let mut sessions = state.sessions.write().map_err(|e| e.to_string())?;
        if let Some(session) = sessions.get_mut(session_id) {
            session.phase2 = Some(result.1);
            session.scan_state = Some(result.0);
        }
    }

    Ok(())
}
