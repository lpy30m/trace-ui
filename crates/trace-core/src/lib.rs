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
    TraceDiffResult, TraceDiffSection, TraceFunctionClusterMatch, TraceFunctionClusterSection,
    TraceProfileSummary,
};
pub use analysis_task::{AnalysisTaskInfo, AnalysisTaskStatus};
pub use api_types::*;
pub use engine::TraceEngine;
pub use error::{Result, TraceError};
pub use query::aes_schedule::{expand_aes_key, verify_aes_schedule, AesScheduleVerification};
pub use query::analysis_summary::{
    summarize_dependency_graph, AnalysisKeyStep, AnalysisOperationCount, AnalysisStringEvidence,
    DependencyAnalysisSummary,
};
pub use query::angr::{
    generate_angr_ollvm_script, generate_angr_ollvm_script_with_seed,
    generate_angr_ollvm_script_with_seed_and_flow,
    generate_angr_ollvm_script_with_seeds_flow_and_identity, parse_angr_ollvm_result_bundle,
    AngrBlockResult, AngrBranchProbe, AngrDispatcherProbe, AngrFlowExploration, AngrFlowPath,
    AngrOllvmFlowConfig, AngrOllvmFridaSeedProvenance, AngrOllvmResultBundle, AngrOllvmScript,
    AngrRegisterValue, AngrSuccessor,
};
pub use query::crypto_functions::{
    CryptoFamily, CryptoFunctionCandidate, CryptoFunctionIo, CryptoFunctionReport,
    CryptoFunctionsOptions,
};
pub use query::crypto_material::{
    CryptoFormula, CryptoMaterial, CryptoMaterialCaseSummary, CryptoMaterialKind,
    CryptoMaterialMultiTraceReport, CryptoMaterialMultiTraceRequest, CryptoMaterialOptions,
    CryptoMaterialReport, CryptoMaterialTraceCase, DynamicParameterCandidate,
};
pub use query::crypto_semantic_verify::{
    validate_pkcs7, verify_aes_cbc, verify_aes_ctr, verify_aes_ecb, verify_aes_gcm, AesDirection,
    AesGcmSemanticVerification, AesSemanticVerification, SemanticVerificationStatus,
};
pub use query::elf_identity::{inspect_elf_binary, ElfBinaryIdentity};
pub use query::evidence_score::{
    score_evidence, EvidenceAssessment, EvidenceScoreFactor, EvidenceScoreSignal,
};
pub use query::frida_capture::{
    analyze_frida_crypto_materials, generate_angr_state_seed, get_frida_capture_event,
    parse_frida_capture_bundle, search_frida_capture_events, AngrSeedMemoryRegion,
    AngrSeedRegister, AngrStateSeed, FridaCaptureBundle, FridaCaptureEvent,
    FridaCaptureEventDetail, FridaCaptureEventSearchResult, FridaCaptureEventSummary,
    FridaCaptureSearchOptions, FridaCaptureValueDetail, FridaCapturedValue,
};
pub use query::frida_hook::{
    generate_frida_hook, FridaArgumentKind, FridaArgumentSpec, FridaCaptureDirection,
    FridaHookRequest, FridaHookScript, FridaStalkerMode,
};
pub use query::frida_ollvm::{
    analyze_frida_ollvm_dispatcher_capture, generate_frida_ollvm_dispatcher_hook,
    FridaOllvmDispatcherAtlas, FridaOllvmDispatcherAtlasOptions, FridaOllvmDispatcherFlow,
    FridaOllvmDispatcherHookOptions, FridaOllvmDispatcherHookScript,
    FridaOllvmDispatcherHookTarget, FridaOllvmDispatcherNode, FridaOllvmDispatcherTransition,
    FridaOllvmRegisterValueSummary, FridaOllvmStateChange, FridaOllvmStateValueCount,
};
pub use query::frida_recipe::{list_frida_hook_recipes, FridaHookRecipe};
pub use query::function_inspect::{
    FunctionCallAnnotation, FunctionInspection, FunctionRef, MemTouch, RegValue,
};
pub use query::hash_match::{
    HashAlgorithm, HashDigestQueryResult, HashMatchRequest, HashMatchResponse, HashMatchResult,
    HashMemoryMatchResponse, HashMemoryMatchResult, HashTransform, HashTransformOptions,
};
pub use query::ollvm::{
    generate_ida_ollvm_script, parse_ida_annotation_bundle, BranchConditionOutcomeProfile,
    BranchConditionStateProfile, BranchConditionValueCount, BranchFlagBitProfile,
    BranchStateObservation, DispatcherCandidate, DispatcherStateSnapshot,
    DispatcherStateTransition, DynamicBasicBlock, DynamicBlockInstruction, DynamicBranchProfile,
    DynamicCfgEdge, IdaAnnotation, IdaAnnotationBundle, IdaOllvmScript, OllvmAnalysisOptions,
    OllvmBlockFingerprint, OllvmBranchCaseEvidence, OllvmBranchStability, OllvmCaseSummary,
    OllvmDispatcherCaseEvidence, OllvmDispatcherStability, OllvmMultiTraceReport,
    OllvmMultiTraceRequest, OllvmReport, OllvmScope, OllvmStateRegisterFingerprint,
    OllvmStateRegisterMatch, OllvmTraceCase, OllvmVersionBlockCandidate,
    OllvmVersionDispatcherMapping, OllvmVersionMapReport, OllvmVersionMapRequest,
    OllvmVersionSummary, OllvmVersionTargetMapping, OllvmVersionTraceCase, OpaqueBranchCandidate,
};
pub use query::source_sink::{
    apply_resource_validation, classify_flow_endpoints, CallResourceContext,
    FlowEndpointClassification, ResourceValidation,
};
pub use query::unicorn::{
    generate_unicorn_ollvm_script, parse_unicorn_ollvm_result_bundle, UnicornCallBoundary,
    UnicornMemoryWrite, UnicornMissingMemory, UnicornOllvmConfig, UnicornOllvmResultBundle,
    UnicornOllvmScript, UnicornRecaptureSuggestion, UnicornRegisterChange, UnicornReplayRun,
    UnicornSeedQuality, UnicornStateValue, UnicornTransitionEvidence,
};
pub use query::value_search::{
    ValueEndian, ValueInterpretation, ValueSearchKind, ValueSearchMatch, ValueSearchRequest,
    ValueSearchResponse, ValueSearchSource,
};
pub use query::whitebox_aes::{WhiteBoxOptions, WhiteBoxReport};
pub use query::whitebox_compare::{
    WhiteBoxCrossKeyComparison, WhiteBoxKeyGroupSummary, WhiteBoxMultiTraceReport,
    WhiteBoxMultiTraceRequest, WhiteBoxTraceCaseRequest, WhiteBoxTraceCaseSummary,
};
pub use session::SliceOrigin;
pub use utils::parse_hex_addr;
