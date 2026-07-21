use serde::Serialize;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AnalysisTaskStatus {
    Queued,
    Running,
    Completed,
    Failed,
    Cancelled,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AnalysisTaskInfo {
    pub task_id: String,
    pub session_id: String,
    pub kind: String,
    pub status: AnalysisTaskStatus,
    pub stage: String,
    pub progress: u8,
    pub created_at_ms: u64,
    pub started_at_ms: Option<u64>,
    pub finished_at_ms: Option<u64>,
    pub cancel_requested: bool,
    pub analysis_id: Option<String>,
    pub error: Option<String>,
}
