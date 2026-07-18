pub mod analysis;
pub mod analysis_task;
pub mod api_types;
pub mod browse;
pub mod cache;
pub mod chunk_scan;
pub mod engine;
pub mod error;
pub mod flat;
pub mod line_index;
pub mod merge;
pub mod parallel;
pub mod parallel_types;
pub mod phase2;
pub mod query;
pub mod scan_unified;
pub mod scanner;
pub mod session;
pub mod utils;

pub use analysis::{
    AnalysisComparison, AnalysisEvidence, AnalysisRecord, AnalysisRecordSummary,
    AnalysisReportExport, AnalysisUniqueEvidence, TraceCountDelta, TraceDiffOptions,
    TraceDiffResult, TraceDiffSection, TraceProfileSummary,
};
pub use analysis_task::{AnalysisTaskInfo, AnalysisTaskStatus};
pub use api_types::*;
pub use engine::TraceEngine;
pub use error::{Result, TraceError};
pub use query::analysis_summary::{
    summarize_dependency_graph, AnalysisKeyStep, AnalysisOperationCount, AnalysisStringEvidence,
    DependencyAnalysisSummary,
};
pub use query::crypto_functions::{
    CryptoFamily, CryptoFunctionCandidate, CryptoFunctionIo, CryptoFunctionReport,
    CryptoFunctionsOptions,
};
pub use query::function_inspect::{
    FunctionCallAnnotation, FunctionInspection, FunctionRef, MemTouch, RegValue,
};
pub use query::evidence_score::{
    score_evidence, EvidenceAssessment, EvidenceScoreFactor, EvidenceScoreSignal,
};
pub use query::hash_match::{
    HashAlgorithm, HashDigestQueryResult, HashMatchRequest, HashMatchResponse, HashMatchResult,
    HashMemoryMatchResponse, HashMemoryMatchResult, HashTransform, HashTransformOptions,
};
pub use query::source_sink::{
    apply_resource_validation, classify_flow_endpoints, CallResourceContext,
    FlowEndpointClassification, ResourceValidation,
};
pub use session::SliceOrigin;
pub use utils::parse_hex_addr;
