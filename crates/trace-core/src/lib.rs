pub mod accuracy_benchmark;
pub mod analysis;
pub mod analysis_case;
pub mod analysis_task;
pub mod api_types;
pub mod browse;
pub mod cache;
pub mod chunk_scan;
pub mod engine;
pub mod error;
pub mod evidence_pack;
pub mod evidence_slice;
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

pub use accuracy_benchmark::{
    run_accuracy_benchmark_file, run_accuracy_benchmark_suite, AccuracyBenchmarkCase,
    AccuracyBenchmarkCaseResult, AccuracyBenchmarkClaimExpectation,
    AccuracyBenchmarkEvidenceSliceExpectation, AccuracyBenchmarkFailure, AccuracyBenchmarkReport,
    AccuracyBenchmarkSuite, ACCURACY_BENCHMARK_REPORT_SCHEMA, ACCURACY_BENCHMARK_SUITE_SCHEMA,
};
pub use analysis::{
    AnalysisComparison, AnalysisEvidence, AnalysisRecord, AnalysisRecordSummary,
    AnalysisReportExport, AnalysisUniqueEvidence, TraceCountDelta, TraceDiffOptions,
    TraceDiffResult, TraceDiffSection, TraceFunctionClusterMatch, TraceFunctionClusterSection,
    TraceProfileSummary,
};
pub use analysis_case::{
    add_trace_case_artifact, create_trace_analysis_case, diagnose_trace_analysis_case,
    load_trace_analysis_case, resolve_trace_case_artifact_path, save_trace_analysis_case,
    upsert_trace_case_claim, upsert_trace_case_experiment, InformationGainCapturePlan,
    InformationGainCaptureTarget, ReplayDoctorNextAction, ReplayDoctorReport,
    ReplayDoctorTimelineEntry, ReplayStateReadinessComponent, ReplayStateReadinessReport,
    TraceAnalysisCase, TraceAnalysisCaseDocument, TraceCaseArtifact, TraceCaseArtifactHealth,
    TraceCaseArtifactImportResult, TraceCaseArtifactKind, TraceCaseArtifactSummary, TraceCaseClaim,
    TraceCaseClaimAuditEntry, TraceCaseClaimLedgerAudit, TraceCaseClaimStatus,
    TraceCaseControlledExperimentPair, TraceCaseCoverageReport, TraceCaseCoverageRequirement,
    TraceCaseCryptoKatReport, TraceCaseEvidenceRef, TraceCaseEvidenceSliceReport,
    TraceCaseExperiment, TraceCaseExperimentAxis, TraceCaseExperimentCell,
    TraceCaseExperimentMatrixReport, TraceCaseExperimentRecommendation,
    TraceCaseRuntimeAttestationReport, CLAIM_LEDGER_AUDIT_SCHEMA, COVERAGE_CLAIM_GATE_SCHEMA,
    EXPERIMENT_MATRIX_SCHEMA, INFORMATION_GAIN_CAPTURE_PLAN_SCHEMA, REPLAY_DOCTOR_SCHEMA,
    REPLAY_STATE_READINESS_SCHEMA, TRACE_ANALYSIS_CASE_SCHEMA,
};
pub use analysis_task::{AnalysisTaskInfo, AnalysisTaskStatus};
pub use api_types::*;
pub use engine::TraceEngine;
pub use error::{Result, TraceError};
pub use evidence_pack::{
    build_analysis_case_evidence_pack, parse_evidence_locator,
    render_analysis_case_evidence_pack_markdown, AnalysisCaseEvidencePack,
    AnalysisCaseEvidencePackRequest, EvidencePackBudget, EvidencePackClaim,
    EvidencePackEvidenceItem, EvidencePackEvidenceSlice, EvidencePackInvalidArtifact,
    EvidencePackLocator, EvidencePackUnknown, AI_EVIDENCE_PACK_SCHEMA,
};
pub use evidence_slice::{
    generate_minimal_evidence_slice, inspect_minimal_evidence_slice,
    inspect_minimal_evidence_slice_bundle, parse_minimal_evidence_slice_bundle,
    save_minimal_evidence_slice_bundle, EvidenceSliceConfig, EvidenceSliceFridaCaptureValue,
    EvidenceSliceFridaEventPayload, EvidenceSliceJsonFragmentPayload, EvidenceSliceLocator,
    EvidenceSliceMemoryByteProvenance, EvidenceSliceMemoryPayload, EvidenceSliceModuleBytesPayload,
    EvidenceSliceRecord, EvidenceSliceRecordPayload, EvidenceSliceReference,
    EvidenceSliceReferenceRole, EvidenceSliceSourceArtifact, EvidenceSliceTraceLine,
    EvidenceSliceTraceLinesPayload, EvidenceSliceTraceSessionBinding, MinimalEvidenceSliceBundle,
    MinimalEvidenceSliceContent, MinimalEvidenceSliceInspectionReport, MinimalEvidenceSliceRequest,
    MinimalEvidenceSliceSummary, ProvenanceNodeKind, ProvenanceRelation, TypedProvenanceEdge,
    TypedProvenanceGraph, TypedProvenanceNode, MAX_MINIMAL_EVIDENCE_SLICE_BYTES,
    MINIMAL_EVIDENCE_SLICE_INSPECTION_SCHEMA, MINIMAL_EVIDENCE_SLICE_SCHEMA,
};
pub use query::aes_schedule::{expand_aes_key, verify_aes_schedule, AesScheduleVerification};
pub use query::analysis_summary::{
    summarize_dependency_graph, AnalysisKeyStep, AnalysisOperationCount, AnalysisStringEvidence,
    DependencyAnalysisSummary,
};
pub use query::angr::{
    generate_angr_ollvm_script, generate_angr_ollvm_script_with_seed,
    generate_angr_ollvm_script_with_seed_and_flow,
    generate_angr_ollvm_script_with_seeds_flow_and_identity,
    generate_angr_ollvm_script_with_seeds_flow_identity_and_checkpoint,
    parse_angr_ollvm_result_bundle, AngrBlockResult, AngrBranchProbe, AngrCheckpointProbe,
    AngrDispatcherProbe, AngrFlowExploration, AngrFlowPath, AngrOllvmFlowConfig,
    AngrOllvmFridaSeedProvenance, AngrOllvmResultBundle, AngrOllvmScript, AngrRegisterValue,
    AngrSuccessor,
};
pub use query::coverage::{
    generate_coverage_reconciliation_script, inspect_coverage_reconciliation,
    inspect_coverage_reconciliation_bundle, parse_coverage_reconciliation_bundle,
    recompute_coverage_reconciliation_summary, save_coverage_reconciliation_bundle,
    CoverageBasisPoints, CoverageCounts, CoverageDynamicRun, CoverageEdge, CoverageFunctionRange,
    CoverageOffsetSamples, CoverageReconciliationBundle, CoverageReconciliationInspectionReport,
    CoverageReconciliationScript, CoverageReconciliationScriptRequest,
    CoverageReconciliationSummary, CoverageScope, CoverageScriptScopeKind, CoverageStaticInventory,
    COVERAGE_RECONCILIATION_INSPECTION_SCHEMA, COVERAGE_RECONCILIATION_SCHEMA,
    MAX_COVERAGE_ARTIFACT_BYTES,
};
pub use query::crypto_functions::{
    CryptoFamily, CryptoFunctionCandidate, CryptoFunctionIo, CryptoFunctionReport,
    CryptoFunctionsOptions,
};
pub use query::crypto_kat::{
    inspect_crypto_semantic_kat_report, parse_crypto_semantic_kat_report,
    save_crypto_semantic_kat_report, verify_crypto_semantic_kat, CryptoKatAlgorithm,
    CryptoKatDirection, CryptoKatMismatch, CryptoKatStatus, CryptoSemanticKatReport,
    CryptoSemanticKatRequest, CRYPTO_SEMANTIC_KAT_SCHEMA, CRYPTO_SEMANTIC_KAT_VERIFICATION_SCHEMA,
    MAX_CRYPTO_KAT_DATA_BYTES, MAX_CRYPTO_KAT_DERIVED_KEY_BYTES, MAX_CRYPTO_KAT_PBKDF2_ITERATIONS,
    MAX_CRYPTO_KAT_SECRET_BYTES,
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
pub use query::detection_doctor::{
    build_crypto_detection_doctor_report, CryptoDetectionDoctorReport, CryptoDetectionStage,
    CRYPTO_DETECTION_DOCTOR_SCHEMA,
};
pub use query::elf_identity::{
    inspect_elf_binary, inspect_elf_layout, inspect_elf_layout_bytes, ElfBinaryIdentity,
    ElfBinaryLayout, ElfBuildIdLocation, ElfLoadSegment,
};
pub use query::evidence_score::{
    score_evidence, EvidenceAssessment, EvidenceScoreFactor, EvidenceScoreSignal,
};
pub use query::exact_call::{
    authorize_exact_call_replay, inspect_exact_call_replay_authorization,
    inspect_exact_call_summary, load_authorized_exact_calls,
    parse_exact_call_replay_authorization_bundle, parse_exact_call_summary_bundle,
    save_exact_call_replay_authorization, save_exact_call_summary, summarize_exact_calls,
    ExactCallCaptureCompleteness, ExactCallChangedRange, ExactCallMemoryEffect, ExactCallRecord,
    ExactCallRegisterEffect, ExactCallRegisterValue, ExactCallReplayAssumptions,
    ExactCallReplayAuthorization, ExactCallReplayAuthorizationBundle,
    ExactCallReplayAuthorizationRequest, ExactCallSummaryBundle, ExactCallSummaryRequest,
    EXACT_CALL_REPLAY_AUTHORIZATION_SCHEMA, EXACT_CALL_SUMMARY_SCHEMA,
    MAX_EXACT_CALL_ARTIFACT_BYTES,
};
pub use query::frida_abi::{
    infer_frida_abi, inspect_frida_abi_capture, save_frida_abi_inference,
    FridaAbiArgumentCandidate, FridaAbiInferenceOptions, FridaAbiInferenceReport,
    FridaContextPointerCandidate, FridaFunctionAbiInference, FridaPointerLengthPairCandidate,
    FridaReturnCandidate, FridaStructFieldCandidate, FRIDA_ABI_INFERENCE_SCHEMA,
};
pub use query::frida_capture::{
    analyze_frida_crypto_materials, generate_angr_state_seed, get_frida_capture_event,
    parse_frida_capture_bundle, search_frida_capture_events, AngrSeedMemoryRegion,
    AngrSeedRegister, AngrStateSeed, FridaCaptureBundle, FridaCaptureEvent,
    FridaCaptureEventDetail, FridaCaptureEventSearchResult, FridaCaptureEventSummary,
    FridaCaptureSearchOptions, FridaCaptureValueDetail, FridaCapturedValue,
};
pub use query::frida_checkpoint::{
    authorize_unicorn_checkpoint_offsets, generate_frida_unicorn_checkpoint_hook,
    unicorn_checkpoint_offsets, FridaUnicornCheckpointHookOptions,
    FridaUnicornCheckpointHookScript, FridaUnicornCheckpointHookTarget,
    FridaUnicornCheckpointMemorySpec,
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
pub use query::frida_recapture::{
    generate_frida_unicorn_recapture_hook, FridaUnicornRecaptureHookOptions,
    FridaUnicornRecaptureHookScript, FridaUnicornRecaptureHookTarget,
    FridaUnicornRecaptureMemorySpec,
};
pub use query::frida_recipe::{list_frida_hook_recipes, FridaHookRecipe};
pub use query::function_inspect::{
    FunctionCallAnnotation, FunctionInspection, FunctionRef, MemTouch, RegValue,
};
pub use query::hash_match::{
    HashAlgorithm, HashDigestQueryResult, HashMatchRequest, HashMatchResponse, HashMatchResult,
    HashMemoryMatchResponse, HashMemoryMatchResult, HashTransform, HashTransformOptions,
};
pub use query::memory_object::{
    explain_memory_pointer_from_report, reconstruct_memory_objects, MemoryAccessKind,
    MemoryAccessObservation, MemoryAccessSample, MemoryAliasObservation, MemoryFieldWindow,
    MemoryObjectAccessSummary, MemoryObjectAnomaly, MemoryObjectGraphReport, MemoryObjectOptions,
    MemoryObjectRecord, MemoryObjectScope, MemoryObjectStatistics, MemoryPointerExplanation,
    MemoryPointerObjectMatch, MemoryRegisterAlias, MemoryRuntimeCluster,
    MemoryStackFrameObservation, MEMORY_OBJECT_GRAPH_SCHEMA, MEMORY_POINTER_EXPLANATION_SCHEMA,
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
pub use query::runtime_attestation::{
    build_runtime_attestation_plan, generate_frida_runtime_attestation_script,
    inspect_runtime_attestation_capture, parse_runtime_attestation_capture_bundle,
    verify_runtime_attestation_bundle, verify_runtime_attestation_record,
    FridaRuntimeAttestationRequest, FridaRuntimeAttestationScript, RuntimeAttestationCaptureBundle,
    RuntimeAttestationExpectedIdentity, RuntimeAttestationInspectionReport, RuntimeAttestationPlan,
    RuntimeAttestationRecord, RuntimeAttestationVerificationReport,
    RuntimeAttestationWindowCapture, RuntimeAttestationWindowKind, RuntimeAttestationWindowPlan,
    RuntimeAttestationWindowVerification, FRIDA_RUNTIME_ATTESTATION_SCHEMA,
    RUNTIME_ATTESTATION_VERIFICATION_SCHEMA,
};
pub use query::software_aes::{
    AesKeyScheduleEvidence, AesSboxFingerprint,
    AesScheduleVerification as DynamicAesScheduleVerification,
    AesSemanticVerification as DynamicAesSemanticVerification,
};
pub use query::source_sink::{
    apply_resource_validation, classify_flow_endpoints, CallResourceContext,
    FlowEndpointClassification, ResourceValidation,
};
pub use query::unicorn::{
    generate_unicorn_ollvm_script, generate_unicorn_ollvm_script_with_checkpoint_and_exact_calls,
    generate_unicorn_ollvm_script_with_checkpoint_result, parse_unicorn_ollvm_result_bundle,
    UnicornCallBoundary, UnicornExactCallAuthorizationProvenance, UnicornExactCallReplay,
    UnicornMemoryWrite, UnicornMissingMemory, UnicornOllvmConfig, UnicornOllvmResultBundle,
    UnicornOllvmScript, UnicornRecaptureSuggestion, UnicornRegisterChange, UnicornReplayRun,
    UnicornSeedQuality, UnicornStateValue, UnicornTransitionEvidence,
};
pub use query::unicorn_compare::{
    compare_unicorn_ollvm_rounds, UnicornOllvmRoundComparisonReport, UnicornOllvmRoundDelta,
    UnicornOllvmRoundInput, UnicornOllvmRoundSummary, UnicornOllvmSeedRoundComparison,
    UnicornOllvmSeedRoundObservation,
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
