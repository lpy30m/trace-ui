use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::analysis_task::{AnalysisTaskInfo, AnalysisTaskStatus};
use crate::error::{Result, TraceError};

use super::{AnalysisTaskEntry, TraceEngine};

const MAX_TASKS_PER_SESSION: usize = 100;

impl TraceEngine {
    pub fn create_analysis_task(&self, session_id: &str, kind: &str) -> Result<AnalysisTaskInfo> {
        self.get_handle(session_id)?;
        let info = AnalysisTaskInfo {
            task_id: uuid::Uuid::new_v4().to_string(),
            session_id: session_id.to_string(),
            kind: kind.to_string(),
            status: AnalysisTaskStatus::Queued,
            stage: "queued".to_string(),
            progress: 0,
            created_at_ms: now_ms(),
            started_at_ms: None,
            finished_at_ms: None,
            cancel_requested: false,
            analysis_id: None,
            error: None,
        };
        let mut tasks = self
            .analysis_tasks
            .write()
            .map_err(|error| TraceError::Internal(error.to_string()))?;
        tasks.insert(
            info.task_id.clone(),
            AnalysisTaskEntry {
                info: info.clone(),
                cancel: Arc::new(AtomicBool::new(false)),
            },
        );
        trim_session_tasks(&mut tasks, session_id);
        Ok(info)
    }

    pub fn start_analysis_task(&self, task_id: &str, stage: &str) -> Result<()> {
        let mut tasks = self
            .analysis_tasks
            .write()
            .map_err(|error| TraceError::Internal(error.to_string()))?;
        let entry = tasks
            .get_mut(task_id)
            .ok_or_else(|| TraceError::InvalidArgument(format!("Task not found: {task_id}")))?;
        if entry.cancel.load(Ordering::SeqCst) {
            set_cancelled(&mut entry.info);
            return Ok(());
        }
        entry.info.status = AnalysisTaskStatus::Running;
        entry.info.stage = stage.to_string();
        entry.info.started_at_ms.get_or_insert_with(now_ms);
        Ok(())
    }

    pub fn update_analysis_task(&self, task_id: &str, stage: &str, progress: u8) -> Result<()> {
        let mut tasks = self
            .analysis_tasks
            .write()
            .map_err(|error| TraceError::Internal(error.to_string()))?;
        let entry = tasks
            .get_mut(task_id)
            .ok_or_else(|| TraceError::InvalidArgument(format!("Task not found: {task_id}")))?;
        if entry.info.status == AnalysisTaskStatus::Running {
            entry.info.stage = stage.to_string();
            entry.info.progress = progress.min(99);
        }
        Ok(())
    }

    pub fn complete_analysis_task(&self, task_id: &str, analysis_id: &str) -> Result<()> {
        let mut tasks = self
            .analysis_tasks
            .write()
            .map_err(|error| TraceError::Internal(error.to_string()))?;
        let entry = tasks
            .get_mut(task_id)
            .ok_or_else(|| TraceError::InvalidArgument(format!("Task not found: {task_id}")))?;
        if entry.cancel.load(Ordering::SeqCst) {
            set_cancelled(&mut entry.info);
        } else {
            entry.info.status = AnalysisTaskStatus::Completed;
            entry.info.stage = "completed".to_string();
            entry.info.progress = 100;
            entry.info.analysis_id = Some(analysis_id.to_string());
            entry.info.finished_at_ms = Some(now_ms());
        }
        Ok(())
    }

    pub fn fail_analysis_task(&self, task_id: &str, error: &str) -> Result<()> {
        let mut tasks = self
            .analysis_tasks
            .write()
            .map_err(|lock_error| TraceError::Internal(lock_error.to_string()))?;
        let entry = tasks
            .get_mut(task_id)
            .ok_or_else(|| TraceError::InvalidArgument(format!("Task not found: {task_id}")))?;
        if entry.cancel.load(Ordering::SeqCst) {
            set_cancelled(&mut entry.info);
        } else {
            entry.info.status = AnalysisTaskStatus::Failed;
            entry.info.stage = "failed".to_string();
            entry.info.error = Some(error.to_string());
            entry.info.finished_at_ms = Some(now_ms());
        }
        Ok(())
    }

    pub fn mark_analysis_task_cancelled(&self, task_id: &str) -> Result<()> {
        let mut tasks = self
            .analysis_tasks
            .write()
            .map_err(|error| TraceError::Internal(error.to_string()))?;
        let entry = tasks
            .get_mut(task_id)
            .ok_or_else(|| TraceError::InvalidArgument(format!("Task not found: {task_id}")))?;
        set_cancelled(&mut entry.info);
        Ok(())
    }

    pub fn analysis_task_cancelled(&self, task_id: &str) -> bool {
        self.analysis_tasks
            .read()
            .ok()
            .and_then(|tasks| {
                tasks
                    .get(task_id)
                    .map(|entry| entry.cancel.load(Ordering::SeqCst))
            })
            .unwrap_or(true)
    }

    pub fn cancel_analysis_task(&self, session_id: &str, task_id: &str) -> Result<bool> {
        self.get_handle(session_id)?;
        let mut tasks = self
            .analysis_tasks
            .write()
            .map_err(|error| TraceError::Internal(error.to_string()))?;
        let Some(entry) = tasks
            .get_mut(task_id)
            .filter(|entry| entry.info.session_id == session_id)
        else {
            return Ok(false);
        };
        if matches!(
            entry.info.status,
            AnalysisTaskStatus::Completed
                | AnalysisTaskStatus::Failed
                | AnalysisTaskStatus::Cancelled
        ) {
            return Ok(false);
        }
        entry.cancel.store(true, Ordering::SeqCst);
        entry.info.cancel_requested = true;
        entry.info.stage = "cancelling".to_string();
        if entry.info.status == AnalysisTaskStatus::Queued {
            set_cancelled(&mut entry.info);
        }
        Ok(true)
    }

    pub fn get_analysis_task(&self, session_id: &str, task_id: &str) -> Result<AnalysisTaskInfo> {
        self.get_handle(session_id)?;
        self.analysis_tasks
            .read()
            .map_err(|error| TraceError::Internal(error.to_string()))?
            .get(task_id)
            .filter(|entry| entry.info.session_id == session_id)
            .map(|entry| entry.info.clone())
            .ok_or_else(|| TraceError::InvalidArgument(format!("Task not found: {task_id}")))
    }

    pub fn list_analysis_tasks(
        &self,
        session_id: &str,
        limit: u32,
    ) -> Result<Vec<AnalysisTaskInfo>> {
        self.get_handle(session_id)?;
        let tasks = self
            .analysis_tasks
            .read()
            .map_err(|error| TraceError::Internal(error.to_string()))?;
        let mut items: Vec<_> = tasks
            .values()
            .filter(|entry| entry.info.session_id == session_id)
            .map(|entry| entry.info.clone())
            .collect();
        items.sort_by(|left, right| {
            right
                .created_at_ms
                .cmp(&left.created_at_ms)
                .then_with(|| right.task_id.cmp(&left.task_id))
        });
        items.truncate(limit.clamp(1, MAX_TASKS_PER_SESSION as u32) as usize);
        Ok(items)
    }

    pub(crate) fn cancel_session_analysis_tasks(&self, session_id: &str) {
        if let Ok(mut tasks) = self.analysis_tasks.write() {
            for entry in tasks
                .values_mut()
                .filter(|entry| entry.info.session_id == session_id)
            {
                entry.cancel.store(true, Ordering::SeqCst);
                if !matches!(
                    entry.info.status,
                    AnalysisTaskStatus::Completed
                        | AnalysisTaskStatus::Failed
                        | AnalysisTaskStatus::Cancelled
                ) {
                    entry.info.cancel_requested = true;
                    set_cancelled(&mut entry.info);
                }
            }
        }
    }
}

fn set_cancelled(info: &mut AnalysisTaskInfo) {
    info.status = AnalysisTaskStatus::Cancelled;
    info.stage = "cancelled".to_string();
    info.finished_at_ms = Some(now_ms());
    info.error = None;
}

fn trim_session_tasks(
    tasks: &mut std::collections::HashMap<String, AnalysisTaskEntry>,
    session_id: &str,
) {
    let mut completed: Vec<_> = tasks
        .values()
        .filter(|entry| entry.info.session_id == session_id)
        .filter(|entry| {
            matches!(
                entry.info.status,
                AnalysisTaskStatus::Completed
                    | AnalysisTaskStatus::Failed
                    | AnalysisTaskStatus::Cancelled
            )
        })
        .map(|entry| (entry.info.created_at_ms, entry.info.task_id.clone()))
        .collect();
    let session_count = tasks
        .values()
        .filter(|entry| entry.info.session_id == session_id)
        .count();
    if session_count <= MAX_TASKS_PER_SESSION {
        return;
    }
    completed.sort_unstable();
    for (_, task_id) in completed
        .into_iter()
        .take(session_count - MAX_TASKS_PER_SESSION)
    {
        tasks.remove(&task_id);
    }
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
        .min(u64::MAX as u128) as u64
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::TraceEngine;

    #[test]
    fn task_lifecycle_and_cancellation_are_consistent() {
        let path = std::env::temp_dir().join(format!(
            "trace-ui-analysis-task-{}.txt",
            uuid::Uuid::new_v4()
        ));
        std::fs::write(&path, b"trace\n").unwrap();
        let engine = TraceEngine::new();
        let session = engine.create_session(path.to_str().unwrap()).unwrap();

        let task = engine
            .create_analysis_task(&session.session_id, "crypto_flow")
            .unwrap();
        engine
            .start_analysis_task(&task.task_id, "crypto_detection")
            .unwrap();
        engine
            .update_analysis_task(&task.task_id, "digest_search", 50)
            .unwrap();
        let running = engine
            .get_analysis_task(&session.session_id, &task.task_id)
            .unwrap();
        assert_eq!(running.status, AnalysisTaskStatus::Running);
        assert_eq!(running.progress, 50);
        assert!(engine
            .cancel_analysis_task(&session.session_id, &task.task_id)
            .unwrap());
        assert!(engine.analysis_task_cancelled(&task.task_id));
        engine.mark_analysis_task_cancelled(&task.task_id).unwrap();
        let cancelled = engine
            .get_analysis_task(&session.session_id, &task.task_id)
            .unwrap();
        assert_eq!(cancelled.status, AnalysisTaskStatus::Cancelled);

        engine.close_session(&session.session_id).unwrap();
        let _ = std::fs::remove_file(path);
    }
}
