use serde::{Deserialize, Serialize};
use serde_json::Value;

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AnalysisEvidence {
    pub algorithms: Vec<String>,
    pub digests: Vec<String>,
    pub functions: Vec<String>,
    pub modules: Vec<String>,
    pub key_strings: Vec<String>,
    pub memory_reads: Vec<String>,
    pub memory_writes: Vec<String>,
    pub addresses: Vec<String>,
    pub operations: Vec<String>,
    pub warnings: Vec<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AnalysisRecord {
    pub analysis_id: String,
    pub session_id: String,
    pub kind: String,
    pub title: String,
    pub created_at_ms: u64,
    pub request: Value,
    pub result: Value,
    pub evidence: AnalysisEvidence,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AnalysisRecordSummary {
    pub analysis_id: String,
    pub session_id: String,
    pub kind: String,
    pub title: String,
    pub created_at_ms: u64,
    pub algorithms: Vec<String>,
    pub functions: Vec<String>,
    pub key_strings: Vec<String>,
    pub warning_count: u32,
}

impl From<&AnalysisRecord> for AnalysisRecordSummary {
    fn from(record: &AnalysisRecord) -> Self {
        Self {
            analysis_id: record.analysis_id.clone(),
            session_id: record.session_id.clone(),
            kind: record.kind.clone(),
            title: record.title.clone(),
            created_at_ms: record.created_at_ms,
            algorithms: record.evidence.algorithms.clone(),
            functions: record.evidence.functions.clone(),
            key_strings: record.evidence.key_strings.clone(),
            warning_count: record.evidence.warnings.len().min(u32::MAX as usize) as u32,
        }
    }
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AnalysisUniqueEvidence {
    pub analysis_id: String,
    pub evidence: AnalysisEvidence,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AnalysisComparison {
    pub analysis_ids: Vec<String>,
    pub kinds: Vec<String>,
    pub common_evidence: AnalysisEvidence,
    pub unique_evidence: Vec<AnalysisUniqueEvidence>,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AnalysisReportExport {
    pub analysis_id: String,
    pub format: String,
    pub output_path: Option<String>,
    pub bytes_written: u64,
    pub content: Option<String>,
}
