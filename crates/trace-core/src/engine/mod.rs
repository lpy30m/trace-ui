mod analysis;
mod analysis_task;
mod browse;
mod build;
mod crypto_functions;
mod crypto_material;
mod forward_slice;
mod function_inspect;
mod hash_match;
mod ollvm;
mod query;
mod search;
mod slice;
mod source_sink;
mod trace_diff;
mod value_search;
mod whitebox_aes;

use memmap2::Mmap;
use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, RwLock};

use crate::api_types::*;
use crate::error::{Result, TraceError};
use crate::session::{SessionHandle, SessionState};
use trace_parser::types::TraceFormat;

pub struct TraceEngine {
    sessions: RwLock<HashMap<String, Arc<SessionHandle>>>,
    analyses: RwLock<HashMap<String, crate::analysis::AnalysisRecord>>,
    analysis_tasks: RwLock<HashMap<String, AnalysisTaskEntry>>,
}

pub(crate) struct AnalysisTaskEntry {
    info: crate::analysis_task::AnalysisTaskInfo,
    cancel: Arc<AtomicBool>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn closing_session_marks_all_background_work_cancelled() {
        let path =
            std::env::temp_dir().join(format!("trace-ui-close-{}.txt", uuid::Uuid::new_v4()));
        std::fs::write(&path, b"trace\n").unwrap();
        let engine = TraceEngine::new();
        let session = engine.create_session(path.to_str().unwrap()).unwrap();
        let handle = engine.get_handle(&session.session_id).unwrap();

        engine.close_session(&session.session_id).unwrap();

        assert!(handle.closed.load(Ordering::SeqCst));
        assert!(handle.build_cancel.load(Ordering::SeqCst));
        assert!(handle.scan_strings_cancel.load(Ordering::SeqCst));
        assert!(engine.get_handle(&session.session_id).is_err());
        let _ = std::fs::remove_file(path);
    }
}

impl TraceEngine {
    pub fn new() -> Self {
        Self {
            sessions: RwLock::new(HashMap::new()),
            analyses: RwLock::new(HashMap::new()),
            analysis_tasks: RwLock::new(HashMap::new()),
        }
    }

    pub(crate) fn get_handle(&self, session_id: &str) -> Result<Arc<SessionHandle>> {
        let sessions = self
            .sessions
            .read()
            .map_err(|e| TraceError::Internal(e.to_string()))?;
        sessions
            .get(session_id)
            .cloned()
            .ok_or_else(|| TraceError::SessionNotFound(session_id.to_string()))
    }

    // ━━ 会话管理 ━━

    pub fn create_session(&self, path: &str) -> Result<SessionInfo> {
        let file = std::fs::File::open(path).map_err(|e| TraceError::Io(e))?;
        let metadata = file.metadata().map_err(|e| TraceError::Io(e))?;
        let file_size = metadata.len();
        let mmap = unsafe { Mmap::map(&file) }.map_err(|e| TraceError::Io(e))?;

        #[cfg(unix)]
        let _ = mmap.advise(memmap2::Advice::WillNeed);

        let total_lines_estimate = (file_size / 110).max(1) as u32;
        let session_id = uuid::Uuid::new_v4().to_string();

        let session_state = SessionState {
            mmap: Arc::new(mmap),
            file_path: path.to_string(),
            total_lines: total_lines_estimate,
            file_size,
            trace_format: TraceFormat::Unidbg,
            call_tree: None,
            phase2_store: None,
            string_index: None,
            scan_store: None,
            reg_last_def: None,
            forward_dependency_index: None,
            resource_flow_index: None,
            lidx_store: None,
            slice_result: None,
            slice_origin: None,
            scan_strings_cancelled: Arc::new(AtomicBool::new(false)),
            call_annotations: HashMap::new(),
            consumed_seqs: Vec::new(),
            call_search_texts: HashMap::new(),
            crypto_cache: None,
            crypto_functions_cache: None,
            whitebox_cache: None,
        };

        let handle = Arc::new(SessionHandle {
            file_path: path.to_string(),
            file_size,
            building: AtomicBool::new(false),
            build_cancel: AtomicBool::new(false),
            closed: AtomicBool::new(false),
            lifecycle: std::sync::Mutex::new(()),
            scanning_strings: AtomicBool::new(false),
            scan_strings_cancel: AtomicBool::new(false),
            forward_index_build: std::sync::Mutex::new(()),
            search_cache: std::sync::Mutex::new((0, Vec::new())),
            state: RwLock::new(session_state),
        });

        {
            let mut sessions = self
                .sessions
                .write()
                .map_err(|e| TraceError::Internal(e.to_string()))?;
            sessions.insert(session_id.clone(), handle);
        }
        let _ = self.load_session_analyses(&session_id);

        Ok(SessionInfo {
            session_id,
            file_path: path.to_string(),
            file_size,
            total_lines: total_lines_estimate,
            index_ready: false,
            building: false,
            has_slice_result: false,
            trace_format: Some(TraceFormat::Unidbg),
        })
    }

    pub fn close_session(&self, session_id: &str) -> Result<()> {
        let removed = {
            let mut sessions = self
                .sessions
                .write()
                .map_err(|e| TraceError::Internal(e.to_string()))?;
            sessions.remove(session_id)
        };
        if let Some(handle) = removed {
            self.cancel_session_analysis_tasks(session_id);
            self.remove_session_analyses(session_id);
            handle.closed.store(true, Ordering::SeqCst);
            handle.build_cancel.store(true, Ordering::SeqCst);
            handle.scan_strings_cancel.store(true, Ordering::SeqCst);
            let lifecycle = handle.lifecycle.lock();
            if let Ok(state) = handle.state.read() {
                state.scan_strings_cancelled.store(true, Ordering::SeqCst);
            }
            drop(lifecycle);
            std::thread::spawn(move || drop(handle));
        }
        Ok(())
    }

    pub fn get_session_info(&self, session_id: &str) -> Result<SessionInfo> {
        let handle = self.get_handle(session_id)?;
        let state = handle
            .state
            .read()
            .map_err(|e| TraceError::Internal(e.to_string()))?;

        Ok(SessionInfo {
            session_id: session_id.to_string(),
            file_path: handle.file_path.clone(),
            file_size: handle.file_size,
            total_lines: state.total_lines,
            index_ready: state.scan_store.is_some(),
            building: handle.building.load(Ordering::Relaxed),
            has_slice_result: state.slice_result.is_some(),
            trace_format: Some(state.trace_format),
        })
    }

    pub fn list_sessions(&self) -> Vec<SessionInfo> {
        let sessions = match self.sessions.read() {
            Ok(s) => s,
            Err(_) => return Vec::new(),
        };
        sessions
            .iter()
            .filter_map(|(id, handle)| {
                let state = handle.state.read().ok()?;
                Some(SessionInfo {
                    session_id: id.clone(),
                    file_path: handle.file_path.clone(),
                    file_size: handle.file_size,
                    total_lines: state.total_lines,
                    index_ready: state.scan_store.is_some(),
                    building: handle.building.load(Ordering::Relaxed),
                    has_slice_result: state.slice_result.is_some(),
                    trace_format: Some(state.trace_format),
                })
            })
            .collect()
    }

    // ━━ 缓存管理 ━━

    pub fn get_cache_dir(&self) -> CacheInfo {
        let (path, size) = crate::cache::get_cache_info();
        CacheInfo { path, size }
    }

    pub fn set_cache_dir(&self, path: Option<String>) -> Result<()> {
        let path_buf = path.map(std::path::PathBuf::from);
        if let Some(ref p) = path_buf {
            std::fs::create_dir_all(p).map_err(|e| TraceError::Io(e))?;
        }
        crate::cache::set_cache_dir_override(path_buf);
        Ok(())
    }

    pub fn clear_all_cache(&self) -> ClearResult {
        let (files_deleted, bytes_freed) = crate::cache::clear_all_cache();
        ClearResult {
            files_deleted,
            bytes_freed,
        }
    }

    pub fn delete_file_cache(&self, path: &str) {
        crate::cache::delete_cache(path);
    }
}
