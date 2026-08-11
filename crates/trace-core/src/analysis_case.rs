use std::collections::{BTreeMap, BTreeSet, HashSet};
use std::fs::File;
use std::io::{BufReader, Read, Write};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};

use crate::analysis::AnalysisRecord;
use crate::error::{Result, TraceError};
use crate::query::angr::{parse_angr_ollvm_result_bundle, AngrOllvmResultBundle};
use crate::query::coverage::{
    inspect_coverage_reconciliation_bundle, parse_coverage_reconciliation_bundle,
    CoverageBasisPoints, CoverageCounts, CoverageReconciliationBundle,
    CoverageReconciliationInspectionReport, COVERAGE_RECONCILIATION_SCHEMA,
};
use crate::query::crypto_kat::{
    parse_crypto_semantic_kat_report, CryptoKatStatus, CryptoSemanticKatReport,
    CRYPTO_SEMANTIC_KAT_VERIFICATION_SCHEMA,
};
use crate::query::elf_identity::{inspect_elf_binary, ElfBinaryIdentity};
use crate::query::frida_capture::{
    parse_frida_capture_bundle, FridaCaptureBundle, FridaCaptureEvent,
};
use crate::query::frida_checkpoint::unicorn_checkpoint_offsets;
use crate::query::ollvm::{parse_ida_annotation_bundle, IdaAnnotationBundle, OllvmReport};
use crate::query::runtime_attestation::{
    parse_runtime_attestation_capture_bundle, verify_runtime_attestation_bundle,
    RuntimeAttestationCaptureBundle, RuntimeAttestationInspectionReport,
};
use crate::query::unicorn::{parse_unicorn_ollvm_result_bundle, UnicornOllvmResultBundle};
use crate::query::unicorn_compare::{
    compare_unicorn_ollvm_rounds, UnicornOllvmRoundComparisonReport, UnicornOllvmRoundInput,
};
use crate::utils::parse_hex_addr;

pub const TRACE_ANALYSIS_CASE_SCHEMA: &str = "trace-ui/case-v1";
pub const REPLAY_DOCTOR_SCHEMA: &str = "trace-ui/replay-doctor-v1";
pub const CLAIM_LEDGER_AUDIT_SCHEMA: &str = "trace-ui/claim-ledger-audit-v1";
pub const REPLAY_STATE_READINESS_SCHEMA: &str = "trace-ui/replay-state-readiness-v1";
pub const EXPERIMENT_MATRIX_SCHEMA: &str = "trace-ui/experiment-matrix-v1";
pub const INFORMATION_GAIN_CAPTURE_PLAN_SCHEMA: &str = "trace-ui/information-gain-capture-plan-v1";
pub const COVERAGE_CLAIM_GATE_SCHEMA: &str = "trace-ui/coverage-claim-gate-v1";
const MAX_CASE_FILE_BYTES: u64 = 16 * 1024 * 1024;
const MAX_ARTIFACT_IMPORT_BYTES: u64 = 64 * 1024 * 1024;
const MAX_ARTIFACTS: usize = 512;
const MAX_CLAIMS: usize = 1024;
const MAX_EXPERIMENTS: usize = 256;

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
        .min(u64::MAX as u128) as u64
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum TraceCaseArtifactKind {
    Trace,
    StaticBinary,
    RuntimeAttestation,
    FridaCapture,
    UnicornResult,
    AngrResult,
    IdaAnnotations,
    OllvmReport,
    CoverageReport,
    AnalysisReport,
    CryptoKat,
    CryptoReport,
    Other,
}

impl TraceCaseArtifactKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Trace => "trace",
            Self::StaticBinary => "static-binary",
            Self::RuntimeAttestation => "runtime-attestation",
            Self::FridaCapture => "frida-capture",
            Self::UnicornResult => "unicorn-result",
            Self::AngrResult => "angr-result",
            Self::IdaAnnotations => "ida-annotations",
            Self::OllvmReport => "ollvm-report",
            Self::CoverageReport => "coverage-report",
            Self::AnalysisReport => "analysis-report",
            Self::CryptoKat => "crypto-kat",
            Self::CryptoReport => "crypto-report",
            Self::Other => "other",
        }
    }

    fn from_hint(value: &str) -> std::result::Result<Self, String> {
        match value.trim().to_ascii_lowercase().replace('_', "-").as_str() {
            "trace" | "trace-log" | "log" => Ok(Self::Trace),
            "static-binary" | "binary" | "elf" | "so" => Ok(Self::StaticBinary),
            "runtime-attestation" | "attestation" | "runtime-image" => Ok(Self::RuntimeAttestation),
            "frida-capture" | "frida" => Ok(Self::FridaCapture),
            "unicorn-result" | "unicorn" => Ok(Self::UnicornResult),
            "angr-result" | "angr" => Ok(Self::AngrResult),
            "ida-annotations" | "ida" => Ok(Self::IdaAnnotations),
            "ollvm-report" | "ollvm" => Ok(Self::OllvmReport),
            "coverage-report" | "coverage" | "coverage-reconciliation" => Ok(Self::CoverageReport),
            "analysis-report" | "analysis" => Ok(Self::AnalysisReport),
            "crypto-kat" | "kat" | "crypto-semantic-kat" => Ok(Self::CryptoKat),
            "crypto-report" | "crypto" => Ok(Self::CryptoReport),
            "other" => Ok(Self::Other),
            other => Err(format!("unsupported case artifact kind: {other}")),
        }
    }
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TraceCaseArtifactSummary {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub schema: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub module_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub architecture: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub binary_sha256: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expected_binary_sha256: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub exact_identity_matched: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub runtime_attestation_status: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub runtime_attestation_verification_gate_met: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub crypto_kat_algorithm: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub crypto_kat_status: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub crypto_kat_verification_gate_met: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub crypto_kat_claim_scope: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub crypto_kat_bytes_checked: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub coverage_status: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub coverage_gate_met: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub coverage_claim_scope: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub coverage_static_counts: Option<CoverageCounts>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub coverage_observed_static_counts: Option<CoverageCounts>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub coverage_uncovered_counts: Option<CoverageCounts>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub coverage_basis_points: Option<CoverageBasisPoints>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub complete_executable_coverage: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub total_executable_bytes: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub selected_executable_bytes: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub matched_executable_bytes: Option<u64>,
    #[serde(default)]
    pub capture_offsets: Vec<String>,
    #[serde(default)]
    pub event_count: u64,
    #[serde(default)]
    pub run_count: u64,
    #[serde(default)]
    pub warning_count: u64,
    #[serde(default)]
    pub stop_reason_counts: BTreeMap<String, u64>,
    #[serde(default)]
    pub notes: Vec<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TraceCaseArtifact {
    pub artifact_id: String,
    pub kind: TraceCaseArtifactKind,
    pub label: String,
    pub path: String,
    pub sha256: String,
    pub file_size: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub modified_at_ms: Option<u64>,
    pub imported_at_ms: u64,
    #[serde(default)]
    pub parent_artifact_ids: Vec<String>,
    pub summary: TraceCaseArtifactSummary,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum TraceCaseClaimStatus {
    Observed,
    Verified,
    Related,
    Refuted,
    Unknown,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum TraceCaseCoverageRequirement {
    #[default]
    Auto,
    NotRequired,
    ScopeComplete,
    NegativeExistence,
    GlobalInvariance,
    ExhaustiveEnumeration,
    CompleteControlFlow,
}

impl TraceCaseCoverageRequirement {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Auto => "auto",
            Self::NotRequired => "not-required",
            Self::ScopeComplete => "scope-complete",
            Self::NegativeExistence => "negative-existence",
            Self::GlobalInvariance => "global-invariance",
            Self::ExhaustiveEnumeration => "exhaustive-enumeration",
            Self::CompleteControlFlow => "complete-control-flow",
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TraceCaseEvidenceRef {
    pub artifact_id: String,
    pub locator: String,
    pub description: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TraceCaseClaim {
    pub claim_id: String,
    pub statement: String,
    pub scope: String,
    pub status: TraceCaseClaimStatus,
    #[serde(default)]
    pub coverage_requirement: TraceCaseCoverageRequirement,
    #[serde(default)]
    pub supporting_evidence: Vec<TraceCaseEvidenceRef>,
    #[serde(default)]
    pub counter_evidence: Vec<TraceCaseEvidenceRef>,
    #[serde(default)]
    pub missing_evidence: Vec<String>,
    #[serde(default)]
    pub limitations: Vec<String>,
    pub created_by: String,
    pub created_at_ms: u64,
    pub updated_at_ms: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TraceCaseExperiment {
    pub experiment_id: String,
    pub label: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub binary_sha256: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key_group: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub input_group: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub environment_group: Option<String>,
    #[serde(default)]
    pub artifact_ids: Vec<String>,
    #[serde(default)]
    pub controlled_variables: Vec<String>,
    #[serde(default)]
    pub changed_variables: Vec<String>,
    #[serde(default)]
    pub notes: Vec<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TraceAnalysisCase {
    pub schema: String,
    pub case_id: String,
    pub title: String,
    pub created_at_ms: u64,
    pub updated_at_ms: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub primary_trace_artifact_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub exact_binary_artifact_id: Option<String>,
    #[serde(default)]
    pub artifacts: Vec<TraceCaseArtifact>,
    #[serde(default)]
    pub claims: Vec<TraceCaseClaim>,
    #[serde(default)]
    pub experiments: Vec<TraceCaseExperiment>,
    #[serde(default)]
    pub notes: Vec<String>,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TraceAnalysisCaseDocument {
    pub case_path: String,
    pub case: TraceAnalysisCase,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TraceCaseArtifactImportResult {
    pub case_path: String,
    pub artifact: TraceCaseArtifact,
    pub already_present: bool,
    pub case: TraceAnalysisCase,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TraceCaseArtifactHealth {
    pub artifact_id: String,
    pub kind: TraceCaseArtifactKind,
    pub label: String,
    pub resolved_path: String,
    pub status: String,
    pub size_matches: bool,
    pub sha256_matches: bool,
    pub parser_valid: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ReplayDoctorTimelineEntry {
    pub artifact_id: String,
    pub imported_at_ms: u64,
    pub stage: String,
    pub status: String,
    pub summary: String,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ReplayDoctorNextAction {
    pub priority: u8,
    pub action: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tool_name: Option<String>,
    pub artifact_ids: Vec<String>,
    pub seed_capture_offsets: Vec<String>,
    pub reason: String,
    pub instructions: String,
    pub manual_execution_required: bool,
    pub evidence_level: String,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct InformationGainCaptureTarget {
    pub rank: u32,
    pub information_gain_score: u8,
    pub action: String,
    pub target_kind: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tool_name: Option<String>,
    pub artifact_ids: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub module_name: Option<String>,
    pub module_relative_offsets: Vec<String>,
    pub registers: Vec<String>,
    pub memory_requirements: Vec<String>,
    pub controlled_variables: Vec<String>,
    pub resolves_claim_ids: Vec<String>,
    pub competing_hypotheses: Vec<String>,
    pub reason: String,
    pub success_criteria: String,
    pub manual_execution_required: bool,
    pub evidence_level: String,
    pub redundancy_key: String,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct InformationGainCapturePlan {
    pub schema: String,
    pub status: String,
    pub target_count: u64,
    pub omitted_target_count: u64,
    pub targets: Vec<InformationGainCaptureTarget>,
    pub limitations: Vec<String>,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TraceCaseClaimAuditEntry {
    pub claim_id: String,
    pub source: String,
    pub current_status: TraceCaseClaimStatus,
    pub recommended_status: TraceCaseClaimStatus,
    pub gate_status: String,
    pub verification_gate_passed: bool,
    pub valid_supporting_evidence_count: u64,
    pub valid_counter_evidence_count: u64,
    pub invalid_evidence_count: u64,
    pub evidence_artifact_kinds: Vec<TraceCaseArtifactKind>,
    pub coverage_requirement: String,
    pub coverage_requirement_source: String,
    pub coverage_gate_status: String,
    pub coverage_gate_passed: bool,
    pub coverage_max_status: TraceCaseClaimStatus,
    pub coverage_artifact_ids: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub coverage_uncovered_counts: Option<CoverageCounts>,
    pub blockers: Vec<String>,
    pub notes: Vec<String>,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TraceCaseClaimLedgerAudit {
    pub schema: String,
    pub total_claim_count: u64,
    pub passed_claim_count: u64,
    pub blocked_claim_count: u64,
    pub refuted_claim_count: u64,
    pub verified_gate_passed_count: u64,
    pub claims: Vec<TraceCaseClaimAuditEntry>,
    pub contradictions: Vec<String>,
    pub limitations: Vec<String>,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ReplayStateReadinessComponent {
    pub component: String,
    pub status: String,
    pub observed_count: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expected_count: Option<u64>,
    pub source_artifact_ids: Vec<String>,
    pub details: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_action: Option<String>,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ReplayStateReadinessReport {
    pub schema: String,
    pub status: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub selected_frida_artifact_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub selected_frida_event_index: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub selected_unicorn_artifact_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exact_binary_match: Option<bool>,
    pub components: Vec<ReplayStateReadinessComponent>,
    pub blockers: Vec<String>,
    pub limitations: Vec<String>,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TraceCaseExperimentAxis {
    pub axis: String,
    pub values: Vec<String>,
    pub unspecified_experiment_count: u64,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TraceCaseExperimentCell {
    pub binary_sha256: String,
    pub key_group: String,
    pub input_group: String,
    pub environment_group: String,
    pub experiment_ids: Vec<String>,
    pub artifact_ids: Vec<String>,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TraceCaseControlledExperimentPair {
    pub left_experiment_id: String,
    pub right_experiment_id: String,
    pub changed_axis: String,
    pub fixed_axes: Vec<String>,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TraceCaseExperimentRecommendation {
    pub priority: u8,
    pub action: String,
    pub reason: String,
    pub suggested_binary_sha256: Option<String>,
    pub suggested_key_group: Option<String>,
    pub suggested_input_group: Option<String>,
    pub suggested_environment_group: Option<String>,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TraceCaseExperimentMatrixReport {
    pub schema: String,
    pub status: String,
    pub experiment_count: u64,
    pub complete_experiment_count: u64,
    pub axes: Vec<TraceCaseExperimentAxis>,
    pub observed_cells: Vec<TraceCaseExperimentCell>,
    pub missing_cells: Vec<TraceCaseExperimentCell>,
    pub missing_cells_truncated: bool,
    pub controlled_pairs: Vec<TraceCaseControlledExperimentPair>,
    pub confounded_pair_count: u64,
    pub recommendations: Vec<TraceCaseExperimentRecommendation>,
    pub warnings: Vec<String>,
    pub limitations: Vec<String>,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ReplayDoctorReport {
    pub schema: String,
    pub case_id: String,
    pub case_path: String,
    pub generated_at_ms: u64,
    pub status: String,
    pub artifact_health: Vec<TraceCaseArtifactHealth>,
    pub timeline: Vec<ReplayDoctorTimelineEntry>,
    pub generated_claims: Vec<TraceCaseClaim>,
    pub next_actions: Vec<ReplayDoctorNextAction>,
    pub claim_ledger_audit: TraceCaseClaimLedgerAudit,
    pub state_readiness: ReplayStateReadinessReport,
    pub experiment_matrix: TraceCaseExperimentMatrixReport,
    pub capture_plan: InformationGainCapturePlan,
    pub runtime_attestations: Vec<TraceCaseRuntimeAttestationReport>,
    pub crypto_kats: Vec<TraceCaseCryptoKatReport>,
    pub coverage_reconciliations: Vec<TraceCaseCoverageReport>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub unicorn_round_comparison: Option<UnicornOllvmRoundComparisonReport>,
    pub warnings: Vec<String>,
    pub limitations: Vec<String>,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TraceCaseRuntimeAttestationReport {
    pub artifact_id: String,
    pub exact_binary_artifact_id: String,
    pub report: RuntimeAttestationInspectionReport,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TraceCaseCryptoKatReport {
    pub artifact_id: String,
    pub report: CryptoSemanticKatReport,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TraceCaseCoverageReport {
    pub artifact_id: String,
    pub exact_binary_artifact_id: String,
    pub source_artifact_ids: Vec<String>,
    pub report: CoverageReconciliationInspectionReport,
}

enum ParsedCaseArtifact {
    Trace,
    StaticBinary(ElfBinaryIdentity),
    RuntimeAttestation(RuntimeAttestationCaptureBundle),
    Frida(FridaCaptureBundle),
    Unicorn(UnicornOllvmResultBundle),
    Angr(AngrOllvmResultBundle),
    Ida(IdaAnnotationBundle),
    Ollvm(OllvmReport),
    Coverage(CoverageReconciliationBundle),
    Analysis(AnalysisRecord),
    CryptoKat(CryptoSemanticKatReport),
    Crypto(Value),
    Other(Option<Value>),
}

struct ArtifactInspection {
    kind: TraceCaseArtifactKind,
    summary: TraceCaseArtifactSummary,
    parsed: ParsedCaseArtifact,
}

fn valid_sha256(value: &str) -> bool {
    value.len() == 64 && value.chars().all(|character| character.is_ascii_hexdigit())
}

fn file_modified_ms(metadata: &std::fs::Metadata) -> Option<u64> {
    metadata
        .modified()
        .ok()?
        .duration_since(UNIX_EPOCH)
        .ok()
        .map(|duration| duration.as_millis().min(u64::MAX as u128) as u64)
}

fn hash_file(path: &Path) -> Result<(String, u64, Option<u64>)> {
    let file = File::open(path)?;
    let metadata = file.metadata()?;
    if !metadata.is_file() {
        return Err(TraceError::InvalidArgument(format!(
            "case artifact is not a regular file: {}",
            path.display()
        )));
    }
    let mut reader = BufReader::new(file);
    let mut hasher = Sha256::new();
    let mut buffer = vec![0u8; 1024 * 1024];
    loop {
        let read = reader.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    Ok((
        format!("{:x}", hasher.finalize()),
        metadata.len(),
        file_modified_ms(&metadata),
    ))
}

fn read_bounded(path: &Path, max_bytes: u64, label: &str) -> Result<Vec<u8>> {
    let metadata = std::fs::metadata(path)?;
    if metadata.len() > max_bytes {
        return Err(TraceError::InvalidArgument(format!(
            "{label} exceeds the {} MiB import limit",
            max_bytes / (1024 * 1024)
        )));
    }
    std::fs::read(path).map_err(TraceError::Io)
}

fn normalize_offsets(values: impl IntoIterator<Item = String>) -> Vec<String> {
    let mut offsets = values
        .into_iter()
        .filter_map(|value| {
            parse_hex_addr(&value)
                .ok()
                .map(|offset| format!("0x{offset:x}"))
        })
        .collect::<Vec<_>>();
    offsets.sort_by_key(|value| parse_hex_addr(value).unwrap_or(u64::MAX));
    offsets.dedup();
    offsets
}

fn frida_capture_offsets(bundle: &FridaCaptureBundle) -> Vec<String> {
    normalize_offsets(bundle.events.iter().filter_map(|event| {
        if let Some(offset) = &event.dispatcher_offset {
            return Some(offset.clone());
        }
        let target = event
            .target
            .as_deref()
            .and_then(|value| parse_hex_addr(value).ok())?;
        let base = event
            .module_base
            .as_deref()
            .and_then(|value| parse_hex_addr(value).ok())?;
        target
            .checked_sub(base)
            .map(|offset| format!("0x{offset:x}"))
    }))
}

fn runtime_attestation_capture_summary(
    bundle: &RuntimeAttestationCaptureBundle,
) -> TraceCaseArtifactSummary {
    let module_names = bundle
        .records
        .iter()
        .map(|record| record.module_name.clone())
        .collect::<BTreeSet<_>>();
    let expected_hashes = bundle
        .records
        .iter()
        .map(|record| record.expected_binary_sha256.to_ascii_lowercase())
        .collect::<BTreeSet<_>>();
    TraceCaseArtifactSummary {
        schema: Some(bundle.schema.clone()),
        module_name: (module_names.len() == 1)
            .then(|| module_names.iter().next().cloned())
            .flatten(),
        binary_sha256: (expected_hashes.len() == 1)
            .then(|| expected_hashes.iter().next().cloned())
            .flatten(),
        expected_binary_sha256: (expected_hashes.len() == 1)
            .then(|| expected_hashes.iter().next().cloned())
            .flatten(),
        runtime_attestation_status: Some("capture-unverified".to_string()),
        runtime_attestation_verification_gate_met: Some(false),
        complete_executable_coverage: Some(
            !bundle.records.is_empty()
                && bundle
                    .records
                    .iter()
                    .all(|record| record.complete_executable_coverage),
        ),
        total_executable_bytes: bundle
            .records
            .iter()
            .map(|record| record.total_executable_bytes)
            .max(),
        selected_executable_bytes: bundle
            .records
            .iter()
            .map(|record| record.selected_executable_bytes)
            .max(),
        matched_executable_bytes: None,
        event_count: bundle.records.len() as u64,
        warning_count: bundle.warnings.len() as u64
            + bundle
                .records
                .iter()
                .map(|record| record.warnings.len() as u64)
                .sum::<u64>(),
        notes: vec![
            "This is a user-captured runtime-image record; its hashes are recomputed against the bound exact ELF before any claim gate can pass."
                .to_string(),
        ],
        ..Default::default()
    }
}

fn apply_runtime_attestation_report_summary(
    summary: &mut TraceCaseArtifactSummary,
    report: &RuntimeAttestationInspectionReport,
) {
    summary.runtime_attestation_status = Some(report.status.clone());
    summary.runtime_attestation_verification_gate_met = Some(report.verification_gate_met);
    summary.exact_identity_matched = Some(
        !report.records.is_empty()
            && report.records.iter().all(|record| {
                record
                    .exact_binary_sha256
                    .eq_ignore_ascii_case(&record.expected_binary_sha256)
            }),
    );
    summary.complete_executable_coverage = Some(
        !report.records.is_empty()
            && report
                .records
                .iter()
                .all(|record| record.complete_executable_coverage),
    );
    summary.total_executable_bytes = report
        .records
        .iter()
        .map(|record| record.total_executable_bytes)
        .max();
    summary.selected_executable_bytes = report
        .records
        .iter()
        .map(|record| record.selected_executable_bytes)
        .max();
    summary.matched_executable_bytes = report
        .records
        .iter()
        .map(|record| record.matched_executable_bytes)
        .max();
    summary.notes.push(format!(
        "Strict exact-ELF verification status: {} (gateMet={}).",
        report.status, report.verification_gate_met
    ));
}

fn apply_coverage_report_summary(
    summary: &mut TraceCaseArtifactSummary,
    report: &CoverageReconciliationInspectionReport,
) {
    summary.coverage_status = Some(report.status.clone());
    summary.coverage_gate_met = Some(report.coverage_gate_met);
    summary.coverage_claim_scope = Some(report.claim_scope.clone());
    summary.exact_identity_matched = Some(report.identity_matched);
    summary.coverage_static_counts = Some(report.summary.static_counts.clone());
    summary.coverage_observed_static_counts = Some(report.summary.observed_static_counts.clone());
    summary.coverage_uncovered_counts = Some(report.summary.uncovered_counts.clone());
    summary.coverage_basis_points = Some(report.summary.coverage_basis_points.clone());
    let mut offsets = report.uncovered_samples.blocks.clone();
    offsets.extend(report.uncovered_samples.branches.clone());
    offsets.extend(report.uncovered_samples.instructions.clone());
    summary.capture_offsets = normalize_offsets(offsets);
    summary.capture_offsets.truncate(256);
    summary.notes.push(format!(
        "Strict coverage reconciliation status: {} (coverageGateMet={}).",
        report.status, report.coverage_gate_met
    ));
}

fn inspect_with_kind(path: &Path, kind: TraceCaseArtifactKind) -> Result<ArtifactInspection> {
    match kind {
        TraceCaseArtifactKind::Trace => Ok(ArtifactInspection {
            kind,
            summary: TraceCaseArtifactSummary {
                schema: Some("trace-file".to_string()),
                notes: vec![
                    "A dynamic trace contains executed instructions only; missing paths remain unknown."
                        .to_string(),
                ],
                ..Default::default()
            },
            parsed: ParsedCaseArtifact::Trace,
        }),
        TraceCaseArtifactKind::StaticBinary => {
            let identity = inspect_elf_binary(&path.to_string_lossy())
                .map_err(TraceError::InvalidArgument)?;
            if identity.elf_machine != 183 {
                return Err(TraceError::InvalidArgument(format!(
                    "analysis cases accept only AArch64 ELF images (e_machine 183); selected file is {} (e_machine {})",
                    identity.architecture, identity.elf_machine
                )));
            }
            Ok(ArtifactInspection {
                kind,
                summary: TraceCaseArtifactSummary {
                    schema: Some("elf-identity".to_string()),
                    module_name: path.file_name().map(|value| value.to_string_lossy().into_owned()),
                    architecture: Some(identity.architecture.clone()),
                    binary_sha256: Some(identity.binary_sha256.clone()),
                    expected_binary_sha256: Some(identity.binary_sha256.clone()),
                    exact_identity_matched: Some(true),
                    notes: vec![
                        "This SHA-256 identifies the selected file; it is not runtime-image attestation."
                            .to_string(),
                    ],
                    ..Default::default()
                },
                parsed: ParsedCaseArtifact::StaticBinary(identity),
            })
        }
        TraceCaseArtifactKind::RuntimeAttestation => {
            let bytes = read_bounded(path, MAX_ARTIFACT_IMPORT_BYTES, "runtime attestation")?;
            let bundle = parse_runtime_attestation_capture_bundle(&bytes)
                .map_err(TraceError::InvalidArgument)?;
            Ok(ArtifactInspection {
                kind,
                summary: runtime_attestation_capture_summary(&bundle),
                parsed: ParsedCaseArtifact::RuntimeAttestation(bundle),
            })
        }
        TraceCaseArtifactKind::FridaCapture => {
            let bytes = read_bounded(path, MAX_ARTIFACT_IMPORT_BYTES, "Frida capture")?;
            let bundle = parse_frida_capture_bundle(&bytes).map_err(TraceError::InvalidArgument)?;
            let module_names = bundle
                .events
                .iter()
                .filter_map(|event| event.module_name.clone())
                .collect::<BTreeSet<_>>();
            Ok(ArtifactInspection {
                kind,
                summary: TraceCaseArtifactSummary {
                    schema: Some(bundle.schema.clone()),
                    module_name: (module_names.len() == 1)
                        .then(|| module_names.iter().next().cloned())
                        .flatten(),
                    capture_offsets: frida_capture_offsets(&bundle),
                    event_count: bundle.events.len() as u64,
                    warning_count: bundle.warnings.len() as u64,
                    notes: vec![
                        "Frida events are user-captured runtime evidence; Trace UI did not execute the hook."
                            .to_string(),
                    ],
                    ..Default::default()
                },
                parsed: ParsedCaseArtifact::Frida(bundle),
            })
        }
        TraceCaseArtifactKind::UnicornResult => {
            let bytes = read_bounded(path, MAX_ARTIFACT_IMPORT_BYTES, "Unicorn result")?;
            let bundle =
                parse_unicorn_ollvm_result_bundle(&bytes).map_err(TraceError::InvalidArgument)?;
            let stop_reason_counts = bundle.runs.iter().fold(BTreeMap::new(), |mut counts, run| {
                *counts.entry(run.stop_reason.clone()).or_insert(0) += 1;
                counts
            });
            Ok(ArtifactInspection {
                kind,
                summary: TraceCaseArtifactSummary {
                    schema: Some(bundle.schema.clone()),
                    module_name: Some(bundle.module_name.clone()),
                    architecture: Some(bundle.architecture.clone()),
                    binary_sha256: Some(bundle.binary_sha256.clone()),
                    expected_binary_sha256: Some(bundle.expected_binary_sha256.clone()),
                    exact_identity_matched: Some(bundle.binary_identity_matched),
                    capture_offsets: normalize_offsets(
                        bundle.seeds.iter().map(|seed| seed.capture_offset.clone()),
                    ),
                    event_count: bundle.seeds.len() as u64,
                    run_count: bundle.runs.len() as u64,
                    warning_count: bundle.warnings.len() as u64
                        + bundle
                            .runs
                            .iter()
                            .map(|run| run.warnings.len() as u64)
                            .sum::<u64>(),
                    stop_reason_counts,
                    notes: vec![
                        "Unicorn is bounded concrete replay and remains Candidate/Related evidence."
                            .to_string(),
                    ],
                    ..Default::default()
                },
                parsed: ParsedCaseArtifact::Unicorn(bundle),
            })
        }
        TraceCaseArtifactKind::AngrResult => {
            let bytes = read_bounded(path, MAX_ARTIFACT_IMPORT_BYTES, "angr result")?;
            let bundle = parse_angr_ollvm_result_bundle(&bytes).map_err(TraceError::InvalidArgument)?;
            let mut offsets = bundle
                .frida_seeds
                .iter()
                .map(|seed| seed.capture_offset.clone())
                .collect::<Vec<_>>();
            if let Some(seed) = &bundle.frida_seed {
                offsets.push(seed.capture_offset.clone());
            }
            offsets.extend(bundle.checkpoint_probes.iter().map(|probe| probe.offset.clone()));
            Ok(ArtifactInspection {
                kind,
                summary: TraceCaseArtifactSummary {
                    schema: Some(bundle.schema.clone()),
                    module_name: Some(bundle.module_name.clone()),
                    architecture: Some(bundle.architecture.clone()),
                    binary_sha256: Some(bundle.binary_sha256.clone()),
                    expected_binary_sha256: bundle.expected_binary_sha256.clone(),
                    exact_identity_matched: bundle.binary_identity_matched,
                    capture_offsets: normalize_offsets(offsets),
                    event_count: bundle.frida_seeds.len() as u64
                        + u64::from(bundle.frida_seed.is_some()),
                    run_count: (bundle.branch_probes.len()
                        + bundle.dispatcher_probes.len()
                        + bundle.checkpoint_probes.len()) as u64,
                    warning_count: bundle.warnings.len() as u64,
                    notes: vec![
                        "angr paths are bounded symbolic/static candidates and do not prove real-entry reachability."
                            .to_string(),
                    ],
                    ..Default::default()
                },
                parsed: ParsedCaseArtifact::Angr(bundle),
            })
        }
        TraceCaseArtifactKind::IdaAnnotations => {
            let bytes = read_bounded(path, MAX_ARTIFACT_IMPORT_BYTES, "IDA annotations")?;
            let bundle = parse_ida_annotation_bundle(&bytes).map_err(TraceError::InvalidArgument)?;
            Ok(ArtifactInspection {
                kind,
                summary: TraceCaseArtifactSummary {
                    schema: Some(bundle.schema.clone()),
                    module_name: Some(bundle.module_name.clone()),
                    capture_offsets: normalize_offsets(
                        bundle.annotations.iter().map(|item| item.offset.clone()),
                    ),
                    event_count: bundle.annotations.len() as u64,
                    notes: vec![
                        "IDA annotations are manually exported review data, not automatic deobfuscation proof."
                            .to_string(),
                    ],
                    ..Default::default()
                },
                parsed: ParsedCaseArtifact::Ida(bundle),
            })
        }
        TraceCaseArtifactKind::OllvmReport => {
            let bytes = read_bounded(path, MAX_ARTIFACT_IMPORT_BYTES, "OLLVM report")?;
            let report: OllvmReport = serde_json::from_slice(&bytes).map_err(|error| {
                TraceError::InvalidArgument(format!("invalid OLLVM report JSON: {error}"))
            })?;
            if report.schema_version != "trace-ui/ollvm-v1" {
                return Err(TraceError::InvalidArgument(format!(
                    "unsupported OLLVM report schema: {}",
                    report.schema_version
                )));
            }
            let offsets = report
                .dispatcher_candidates
                .iter()
                .map(|candidate| candidate.start_offset.clone())
                .chain(
                    report
                        .opaque_branch_candidates
                        .iter()
                        .map(|candidate| candidate.branch_offset.clone()),
                );
            Ok(ArtifactInspection {
                kind,
                summary: TraceCaseArtifactSummary {
                    schema: Some(report.schema_version.clone()),
                    module_name: Some(report.scope.module_name.clone()),
                    capture_offsets: normalize_offsets(offsets),
                    event_count: report.executed_instruction_count,
                    run_count: report.block_count as u64,
                    warning_count: report.limitations.len() as u64,
                    notes: vec![
                        "OLLVM structural classifications are Candidate/Related until independently proven."
                            .to_string(),
                    ],
                    ..Default::default()
                },
                parsed: ParsedCaseArtifact::Ollvm(report),
            })
        }
        TraceCaseArtifactKind::CoverageReport => {
            let bytes = read_bounded(path, MAX_ARTIFACT_IMPORT_BYTES, "coverage reconciliation")?;
            let bundle = parse_coverage_reconciliation_bundle(&bytes)
                .map_err(TraceError::InvalidArgument)?;
            let capture_offsets = bundle
                .summary
                .uncovered_counts
                .blocks
                .gt(&0)
                .then(|| bundle.static_inventory.block_offsets.iter().cloned())
                .into_iter()
                .flatten()
                .chain(
                    bundle
                        .static_inventory
                        .branch_offsets
                        .iter()
                        .cloned(),
                )
                .take(256);
            Ok(ArtifactInspection {
                kind,
                summary: TraceCaseArtifactSummary {
                    schema: Some(bundle.schema.clone()),
                    module_name: Some(bundle.module_name.clone()),
                    architecture: Some(bundle.architecture.clone()),
                    binary_sha256: Some(bundle.binary_sha256.clone()),
                    expected_binary_sha256: Some(bundle.binary_sha256.clone()),
                    exact_identity_matched: Some(false),
                    coverage_status: Some("unverified-exact-elf".to_string()),
                    coverage_gate_met: Some(false),
                    coverage_claim_scope: Some(bundle.claim_scope.clone()),
                    coverage_static_counts: Some(bundle.summary.static_counts.clone()),
                    coverage_observed_static_counts: Some(
                        bundle.summary.observed_static_counts.clone(),
                    ),
                    coverage_uncovered_counts: Some(bundle.summary.uncovered_counts.clone()),
                    coverage_basis_points: Some(bundle.summary.coverage_basis_points.clone()),
                    capture_offsets: normalize_offsets(capture_offsets),
                    event_count: bundle
                        .summary
                        .observed_static_counts
                        .instructions,
                    run_count: bundle.dynamic_runs.len() as u64,
                    warning_count: bundle.limitations.len() as u64,
                    notes: vec![
                        "Coverage counts are recomputed from explicit static/dynamic offset sets; the gate remains closed until exact-ELF and parent-source provenance are verified."
                            .to_string(),
                        "Coverage only caps a claim's maximum level and never proves semantics by itself."
                            .to_string(),
                    ],
                    ..Default::default()
                },
                parsed: ParsedCaseArtifact::Coverage(bundle),
            })
        }
        TraceCaseArtifactKind::AnalysisReport => {
            let bytes = read_bounded(path, MAX_ARTIFACT_IMPORT_BYTES, "analysis report")?;
            let record: AnalysisRecord = serde_json::from_slice(&bytes).map_err(|error| {
                TraceError::InvalidArgument(format!("invalid analysis report JSON: {error}"))
            })?;
            Ok(ArtifactInspection {
                kind,
                summary: TraceCaseArtifactSummary {
                    schema: Some(format!("trace-ui/analysis/{}", record.kind)),
                    event_count: 1,
                    warning_count: record.evidence.warnings.len() as u64,
                    notes: vec![format!("analysisId={}", record.analysis_id)],
                    ..Default::default()
                },
                parsed: ParsedCaseArtifact::Analysis(record),
            })
        }
        TraceCaseArtifactKind::CryptoKat => {
            let bytes = read_bounded(path, MAX_ARTIFACT_IMPORT_BYTES, "crypto KAT report")?;
            let report = parse_crypto_semantic_kat_report(&bytes)
                .map_err(TraceError::InvalidArgument)?;
            Ok(ArtifactInspection {
                kind,
                summary: TraceCaseArtifactSummary {
                    schema: Some(report.schema.clone()),
                    crypto_kat_algorithm: Some(report.algorithm.as_str().to_string()),
                    crypto_kat_status: Some(report.status.as_str().to_string()),
                    crypto_kat_verification_gate_met: Some(report.verification_gate_met),
                    crypto_kat_claim_scope: Some(report.claim_scope.clone()),
                    crypto_kat_bytes_checked: Some(
                        report.bytes_checked.saturating_add(report.tag_bytes_checked),
                    ),
                    event_count: 1,
                    warning_count: u64::from(report.status == CryptoKatStatus::Invalid),
                    notes: vec![
                        "This report is accepted only after its embedded vector is deterministically recomputed; it proves one exact vector, not function provenance or runtime reachability."
                            .to_string(),
                        "The artifact contains sensitive key/password/input/output material."
                            .to_string(),
                    ],
                    ..Default::default()
                },
                parsed: ParsedCaseArtifact::CryptoKat(report),
            })
        }
        TraceCaseArtifactKind::CryptoReport => {
            let bytes = read_bounded(path, MAX_ARTIFACT_IMPORT_BYTES, "crypto report")?;
            let value: Value = serde_json::from_slice(&bytes).map_err(|error| {
                TraceError::InvalidArgument(format!("invalid crypto report JSON: {error}"))
            })?;
            let schema = value
                .get("schema")
                .or_else(|| value.get("schemaVersion"))
                .and_then(Value::as_str)
                .map(str::to_string)
                .unwrap_or_else(|| "trace-ui/crypto-report".to_string());
            let gate = value
                .pointer("/assessment/verificationGateMet")
                .or_else(|| value.get("verificationGateMet"))
                .and_then(Value::as_bool);
            Ok(ArtifactInspection {
                kind,
                summary: TraceCaseArtifactSummary {
                    schema: Some(schema),
                    exact_identity_matched: gate,
                    event_count: 1,
                    notes: vec![match gate {
                        Some(true) => "The imported report declares its deterministic verification gate met.".to_string(),
                        _ => "The imported crypto report does not open a deterministic verification gate.".to_string(),
                    }],
                    ..Default::default()
                },
                parsed: ParsedCaseArtifact::Crypto(value),
            })
        }
        TraceCaseArtifactKind::Other => {
            let metadata = std::fs::metadata(path)?;
            let value = if metadata.len() <= MAX_ARTIFACT_IMPORT_BYTES {
                std::fs::read(path)
                    .ok()
                    .and_then(|bytes| serde_json::from_slice::<Value>(&bytes).ok())
            } else {
                None
            };
            let schema = value
                .as_ref()
                .and_then(|value| value.get("schema").or_else(|| value.get("schemaVersion")))
                .and_then(Value::as_str)
                .map(str::to_string);
            Ok(ArtifactInspection {
                kind,
                summary: TraceCaseArtifactSummary {
                    schema,
                    notes: vec![
                        "This artifact has no recognized strict parser and cannot support a verified conclusion by itself."
                            .to_string(),
                    ],
                    ..Default::default()
                },
                parsed: ParsedCaseArtifact::Other(value),
            })
        }
    }
}

fn detect_artifact_kind(path: &Path) -> Result<TraceCaseArtifactKind> {
    let mut file = File::open(path)?;
    let mut prefix = [0u8; 4];
    let read = file.read(&mut prefix)?;
    if read == 4 && prefix == [0x7f, b'E', b'L', b'F'] {
        return Ok(TraceCaseArtifactKind::StaticBinary);
    }
    let extension = path
        .extension()
        .and_then(|value| value.to_str())
        .unwrap_or_default()
        .to_ascii_lowercase();
    if ["log", "trace", "txt"].contains(&extension.as_str()) {
        return Ok(TraceCaseArtifactKind::Trace);
    }
    if extension == "traceui-case" {
        return Err(TraceError::InvalidArgument(
            "A .traceui-case manifest cannot be imported as its own artifact".to_string(),
        ));
    }
    let metadata = std::fs::metadata(path)?;
    if metadata.len() > MAX_ARTIFACT_IMPORT_BYTES {
        return Ok(TraceCaseArtifactKind::Other);
    }
    let bytes = std::fs::read(path)?;
    if parse_runtime_attestation_capture_bundle(&bytes).is_ok() {
        return Ok(TraceCaseArtifactKind::RuntimeAttestation);
    }
    if let Ok(value) = serde_json::from_slice::<Value>(&bytes) {
        if value.get("schema").and_then(Value::as_str)
            == Some(CRYPTO_SEMANTIC_KAT_VERIFICATION_SCHEMA)
        {
            return Ok(TraceCaseArtifactKind::CryptoKat);
        }
    }
    if parse_unicorn_ollvm_result_bundle(&bytes).is_ok() {
        return Ok(TraceCaseArtifactKind::UnicornResult);
    }
    if parse_angr_ollvm_result_bundle(&bytes).is_ok() {
        return Ok(TraceCaseArtifactKind::AngrResult);
    }
    if parse_ida_annotation_bundle(&bytes).is_ok() {
        return Ok(TraceCaseArtifactKind::IdaAnnotations);
    }
    if parse_frida_capture_bundle(&bytes).is_ok() {
        return Ok(TraceCaseArtifactKind::FridaCapture);
    }
    if let Ok(bundle) = parse_coverage_reconciliation_bundle(&bytes) {
        if bundle.schema == COVERAGE_RECONCILIATION_SCHEMA {
            return Ok(TraceCaseArtifactKind::CoverageReport);
        }
    }
    if let Ok(report) = serde_json::from_slice::<OllvmReport>(&bytes) {
        if report.schema_version == "trace-ui/ollvm-v1" {
            return Ok(TraceCaseArtifactKind::OllvmReport);
        }
    }
    if serde_json::from_slice::<AnalysisRecord>(&bytes).is_ok() {
        return Ok(TraceCaseArtifactKind::AnalysisReport);
    }
    if let Ok(value) = serde_json::from_slice::<Value>(&bytes) {
        if value.get("verificationGateMet").is_some()
            || value.pointer("/assessment/verificationGateMet").is_some()
            || value.get("softwareCrypto").is_some()
        {
            return Ok(TraceCaseArtifactKind::CryptoReport);
        }
        return Ok(TraceCaseArtifactKind::Other);
    }
    Ok(TraceCaseArtifactKind::Other)
}

fn inspect_artifact(path: &Path, kind_hint: Option<&str>) -> Result<ArtifactInspection> {
    let kind = match kind_hint.map(str::trim).filter(|value| !value.is_empty()) {
        Some(value) => {
            TraceCaseArtifactKind::from_hint(value).map_err(TraceError::InvalidArgument)?
        }
        None => detect_artifact_kind(path)?,
    };
    inspect_with_kind(path, kind)
}

fn validate_case(case: &TraceAnalysisCase) -> Result<()> {
    if case.schema != TRACE_ANALYSIS_CASE_SCHEMA {
        return Err(TraceError::InvalidArgument(format!(
            "unsupported analysis case schema: {}",
            case.schema
        )));
    }
    if case.case_id.trim().is_empty() || case.title.trim().is_empty() {
        return Err(TraceError::InvalidArgument(
            "analysis case ID and title must not be empty".to_string(),
        ));
    }
    if case.title.chars().count() > 200 {
        return Err(TraceError::InvalidArgument(
            "analysis case title exceeds 200 characters".to_string(),
        ));
    }
    if case.artifacts.len() > MAX_ARTIFACTS
        || case.claims.len() > MAX_CLAIMS
        || case.experiments.len() > MAX_EXPERIMENTS
    {
        return Err(TraceError::InvalidArgument(
            "analysis case exceeds artifact, claim, or experiment limits".to_string(),
        ));
    }
    let mut artifact_ids = HashSet::new();
    for artifact in &case.artifacts {
        if artifact.artifact_id.trim().is_empty()
            || artifact.path.trim().is_empty()
            || artifact.label.trim().is_empty()
            || !valid_sha256(&artifact.sha256)
            || !artifact_ids.insert(artifact.artifact_id.as_str())
        {
            return Err(TraceError::InvalidArgument(format!(
                "invalid or duplicate case artifact: {}",
                artifact.artifact_id
            )));
        }
    }
    let artifact_kind_by_id = case
        .artifacts
        .iter()
        .map(|artifact| (artifact.artifact_id.as_str(), artifact.kind))
        .collect::<BTreeMap<_, _>>();
    for artifact in &case.artifacts {
        let mut parents = HashSet::new();
        for parent in &artifact.parent_artifact_ids {
            if parent == &artifact.artifact_id
                || !artifact_ids.contains(parent.as_str())
                || !parents.insert(parent.as_str())
            {
                return Err(TraceError::InvalidArgument(format!(
                    "artifact {} has an invalid parent reference: {parent}",
                    artifact.artifact_id
                )));
            }
        }
        if artifact.kind == TraceCaseArtifactKind::RuntimeAttestation {
            let static_binary_parent_count = artifact
                .parent_artifact_ids
                .iter()
                .filter(|parent| {
                    artifact_kind_by_id.get(parent.as_str())
                        == Some(&TraceCaseArtifactKind::StaticBinary)
                })
                .count();
            if static_binary_parent_count != 1 {
                return Err(TraceError::InvalidArgument(format!(
                    "runtime attestation artifact {} must bind exactly one static-binary parent",
                    artifact.artifact_id
                )));
            }
        }
        if artifact.kind == TraceCaseArtifactKind::CoverageReport {
            let static_binary_parent_count = artifact
                .parent_artifact_ids
                .iter()
                .filter(|parent| {
                    artifact_kind_by_id.get(parent.as_str())
                        == Some(&TraceCaseArtifactKind::StaticBinary)
                })
                .count();
            let dynamic_source_parent_count = artifact
                .parent_artifact_ids
                .iter()
                .filter(|parent| {
                    artifact_kind_by_id
                        .get(parent.as_str())
                        .is_some_and(|kind| *kind != TraceCaseArtifactKind::StaticBinary)
                })
                .count();
            if static_binary_parent_count != 1 || dynamic_source_parent_count == 0 {
                return Err(TraceError::InvalidArgument(format!(
                    "coverage report artifact {} must bind exactly one static-binary parent and at least one dynamic/source artifact parent",
                    artifact.artifact_id
                )));
            }
        }
    }
    for selected in [
        case.primary_trace_artifact_id.as_deref(),
        case.exact_binary_artifact_id.as_deref(),
    ]
    .into_iter()
    .flatten()
    {
        if !artifact_ids.contains(selected) {
            return Err(TraceError::InvalidArgument(format!(
                "case references unknown selected artifact: {selected}"
            )));
        }
    }
    let mut claim_ids = HashSet::new();
    for claim in &case.claims {
        if claim.claim_id.trim().is_empty()
            || claim.statement.trim().is_empty()
            || claim.scope.trim().is_empty()
            || claim.statement.chars().count() > 2_000
            || claim.scope.chars().count() > 500
            || !claim_ids.insert(claim.claim_id.as_str())
        {
            return Err(TraceError::InvalidArgument(format!(
                "invalid or duplicate case claim: {}",
                claim.claim_id
            )));
        }
        for evidence in claim
            .supporting_evidence
            .iter()
            .chain(&claim.counter_evidence)
        {
            if !artifact_ids.contains(evidence.artifact_id.as_str())
                || evidence.locator.trim().is_empty()
                || evidence.description.trim().is_empty()
            {
                return Err(TraceError::InvalidArgument(format!(
                    "claim {} has invalid evidence for artifact {}",
                    claim.claim_id, evidence.artifact_id
                )));
            }
        }
    }
    let mut experiment_ids = HashSet::new();
    for experiment in &case.experiments {
        if experiment.experiment_id.trim().is_empty()
            || experiment.label.trim().is_empty()
            || experiment.label.chars().count() > 200
            || !experiment_ids.insert(experiment.experiment_id.as_str())
            || experiment
                .binary_sha256
                .as_deref()
                .is_some_and(|value| !valid_sha256(value))
        {
            return Err(TraceError::InvalidArgument(format!(
                "invalid or duplicate case experiment: {}",
                experiment.experiment_id
            )));
        }
        let mut experiment_artifact_ids = HashSet::new();
        for artifact_id in &experiment.artifact_ids {
            if !artifact_ids.contains(artifact_id.as_str())
                || !experiment_artifact_ids.insert(artifact_id.as_str())
            {
                return Err(TraceError::InvalidArgument(format!(
                    "experiment {} references an unknown or duplicate artifact {artifact_id}",
                    experiment.experiment_id
                )));
            }
        }
        for value in [
            experiment.key_group.as_deref(),
            experiment.input_group.as_deref(),
            experiment.environment_group.as_deref(),
        ]
        .into_iter()
        .flatten()
        {
            if value.trim().is_empty() || value.chars().count() > 200 {
                return Err(TraceError::InvalidArgument(format!(
                    "experiment {} contains an invalid group label",
                    experiment.experiment_id
                )));
            }
        }
    }
    Ok(())
}

fn absolute_existing_path(path: &str) -> Result<PathBuf> {
    let path = Path::new(path);
    if !path.exists() {
        return Err(TraceError::InvalidArgument(format!(
            "file does not exist: {}",
            path.display()
        )));
    }
    std::fs::canonicalize(path).map_err(TraceError::Io)
}

fn case_parent(case_path: &Path) -> Result<PathBuf> {
    let parent = case_path.parent().ok_or_else(|| {
        TraceError::InvalidArgument(format!(
            "analysis case path has no parent directory: {}",
            case_path.display()
        ))
    })?;
    if !parent.exists() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::canonicalize(parent).map_err(TraceError::Io)
}

fn stored_artifact_path(case_path: &Path, artifact_path: &Path) -> Result<String> {
    let case_dir = case_parent(case_path)?;
    let artifact_path = std::fs::canonicalize(artifact_path)?;
    if let Ok(relative) = artifact_path.strip_prefix(&case_dir) {
        Ok(relative.to_string_lossy().replace('\\', "/"))
    } else {
        Ok(artifact_path.to_string_lossy().into_owned())
    }
}

pub fn resolve_trace_case_artifact_path(case_path: &str, artifact_path: &str) -> Result<PathBuf> {
    let artifact_path = Path::new(artifact_path);
    if artifact_path.is_absolute() {
        return Ok(artifact_path.to_path_buf());
    }
    let case_path = Path::new(case_path);
    let parent = case_path.parent().ok_or_else(|| {
        TraceError::InvalidArgument("analysis case path has no parent directory".to_string())
    })?;
    Ok(parent.join(artifact_path))
}

pub fn save_trace_analysis_case(case_path: &str, case: &TraceAnalysisCase) -> Result<()> {
    validate_case(case)?;
    let case_path = Path::new(case_path);
    if case_path.extension().and_then(|value| value.to_str()) != Some("traceui-case") {
        return Err(TraceError::InvalidArgument(
            "analysis case path must end with .traceui-case".to_string(),
        ));
    }
    case_parent(case_path)?;
    let mut bytes =
        serde_json::to_vec_pretty(case).map_err(|error| TraceError::Internal(error.to_string()))?;
    bytes.push(b'\n');
    let mut file = File::create(case_path)?;
    file.write_all(&bytes)?;
    file.sync_all()?;
    Ok(())
}

pub fn load_trace_analysis_case(case_path: &str) -> Result<TraceAnalysisCaseDocument> {
    let case_path_buf = Path::new(case_path);
    let bytes = read_bounded(case_path_buf, MAX_CASE_FILE_BYTES, "analysis case")?;
    let case: TraceAnalysisCase = serde_json::from_slice(&bytes).map_err(|error| {
        TraceError::InvalidArgument(format!("invalid .traceui-case JSON: {error}"))
    })?;
    validate_case(&case)?;
    Ok(TraceAnalysisCaseDocument {
        case_path: case_path_buf.to_string_lossy().into_owned(),
        case,
    })
}

fn artifact_from_path(
    case_path: &Path,
    artifact_path: &Path,
    kind_hint: Option<&str>,
    label: Option<&str>,
    parent_artifact_ids: Vec<String>,
) -> Result<(TraceCaseArtifact, ParsedCaseArtifact)> {
    let absolute = absolute_existing_path(&artifact_path.to_string_lossy())?;
    let inspection = inspect_artifact(&absolute, kind_hint)?;
    let (sha256, file_size, modified_at_ms) = hash_file(&absolute)?;
    let default_label = absolute
        .file_name()
        .map(|value| value.to_string_lossy().into_owned())
        .unwrap_or_else(|| inspection.kind.as_str().to_string());
    let label = label
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .unwrap_or(&default_label)
        .to_string();
    if label.chars().count() > 200 {
        return Err(TraceError::InvalidArgument(
            "case artifact label exceeds 200 characters".to_string(),
        ));
    }
    Ok((
        TraceCaseArtifact {
            artifact_id: uuid::Uuid::new_v4().to_string(),
            kind: inspection.kind,
            label,
            path: stored_artifact_path(case_path, &absolute)?,
            sha256,
            file_size,
            modified_at_ms,
            imported_at_ms: now_ms(),
            parent_artifact_ids,
            summary: inspection.summary,
        },
        inspection.parsed,
    ))
}

pub fn create_trace_analysis_case(
    case_path: &str,
    title: &str,
    primary_trace_path: Option<&str>,
    exact_binary_path: Option<&str>,
) -> Result<TraceAnalysisCaseDocument> {
    let case_path_buf = Path::new(case_path);
    if case_path_buf.exists() {
        return Err(TraceError::InvalidArgument(format!(
            "analysis case already exists: {}",
            case_path_buf.display()
        )));
    }
    let timestamp = now_ms();
    let mut case = TraceAnalysisCase {
        schema: TRACE_ANALYSIS_CASE_SCHEMA.to_string(),
        case_id: uuid::Uuid::new_v4().to_string(),
        title: title.trim().to_string(),
        created_at_ms: timestamp,
        updated_at_ms: timestamp,
        primary_trace_artifact_id: None,
        exact_binary_artifact_id: None,
        artifacts: Vec::new(),
        claims: Vec::new(),
        experiments: Vec::new(),
        notes: vec![
            "Frida, Unicorn, angr, and IDA remain user-executed manual boundaries.".to_string(),
            "OLLVM, angr, and Unicorn structural conclusions remain Candidate/Related unless independently proven."
                .to_string(),
        ],
    };
    if let Some(path) = primary_trace_path {
        let (artifact, _) = artifact_from_path(
            case_path_buf,
            Path::new(path),
            Some("trace"),
            Some("Primary trace"),
            Vec::new(),
        )?;
        case.primary_trace_artifact_id = Some(artifact.artifact_id.clone());
        case.artifacts.push(artifact);
    }
    if let Some(path) = exact_binary_path {
        let (artifact, _) = artifact_from_path(
            case_path_buf,
            Path::new(path),
            Some("static-binary"),
            Some("Exact AArch64 ELF"),
            Vec::new(),
        )?;
        case.exact_binary_artifact_id = Some(artifact.artifact_id.clone());
        case.artifacts.push(artifact);
    }
    save_trace_analysis_case(case_path, &case)?;
    Ok(TraceAnalysisCaseDocument {
        case_path: case_path.to_string(),
        case,
    })
}

pub fn add_trace_case_artifact(
    case_path: &str,
    artifact_path: &str,
    kind_hint: Option<&str>,
    label: Option<&str>,
    parent_artifact_ids: Vec<String>,
) -> Result<TraceCaseArtifactImportResult> {
    let mut document = load_trace_analysis_case(case_path)?;
    let known_ids = document
        .case
        .artifacts
        .iter()
        .map(|artifact| artifact.artifact_id.as_str())
        .collect::<HashSet<_>>();
    for parent in &parent_artifact_ids {
        if !known_ids.contains(parent.as_str()) {
            return Err(TraceError::InvalidArgument(format!(
                "parent case artifact not found: {parent}"
            )));
        }
    }
    let (mut artifact, parsed) = artifact_from_path(
        Path::new(case_path),
        Path::new(artifact_path),
        kind_hint,
        label,
        parent_artifact_ids.clone(),
    )?;
    if artifact.kind == TraceCaseArtifactKind::RuntimeAttestation {
        let mut static_binary_parent_ids = artifact
            .parent_artifact_ids
            .iter()
            .filter(|parent_id| {
                document.case.artifacts.iter().any(|candidate| {
                    candidate.artifact_id == **parent_id
                        && candidate.kind == TraceCaseArtifactKind::StaticBinary
                })
            })
            .cloned()
            .collect::<Vec<_>>();
        if static_binary_parent_ids.is_empty() {
            let selected = document
                .case
                .exact_binary_artifact_id
                .as_ref()
                .and_then(|artifact_id| {
                    document.case.artifacts.iter().find(|candidate| {
                        candidate.artifact_id == *artifact_id
                            && candidate.kind == TraceCaseArtifactKind::StaticBinary
                    })
                })
                .ok_or_else(|| {
                    TraceError::InvalidArgument(
                        "import the exact AArch64 ELF before importing a runtime attestation, or pass its static-binary artifact ID as the parent"
                            .to_string(),
                    )
                })?;
            artifact
                .parent_artifact_ids
                .push(selected.artifact_id.clone());
            static_binary_parent_ids.push(selected.artifact_id.clone());
        }
        static_binary_parent_ids.sort();
        static_binary_parent_ids.dedup();
        if static_binary_parent_ids.len() != 1 {
            return Err(TraceError::InvalidArgument(
                "a runtime attestation must bind exactly one static-binary parent".to_string(),
            ));
        }
        artifact.parent_artifact_ids.sort();
        artifact.parent_artifact_ids.dedup();
        let exact_binary = document
            .case
            .artifacts
            .iter()
            .find(|candidate| candidate.artifact_id == static_binary_parent_ids[0])
            .ok_or_else(|| {
                TraceError::InvalidArgument(
                    "runtime attestation static-binary parent was not found".to_string(),
                )
            })?;
        let exact_binary_path = resolve_trace_case_artifact_path(case_path, &exact_binary.path)?;
        let capture_path = resolve_trace_case_artifact_path(case_path, &artifact.path)?;
        let ParsedCaseArtifact::RuntimeAttestation(bundle) = &parsed else {
            return Err(TraceError::Internal(
                "runtime attestation parser returned an unexpected artifact type".to_string(),
            ));
        };
        let report = verify_runtime_attestation_bundle(
            bundle,
            &capture_path.to_string_lossy(),
            &exact_binary_path.to_string_lossy(),
        )
        .map_err(TraceError::InvalidArgument)?;
        apply_runtime_attestation_report_summary(&mut artifact.summary, &report);
    }
    if artifact.kind == TraceCaseArtifactKind::CoverageReport {
        let ParsedCaseArtifact::Coverage(bundle) = &parsed else {
            return Err(TraceError::Internal(
                "coverage parser returned an unexpected artifact type".to_string(),
            ));
        };
        let mut static_binary_parent_ids = artifact
            .parent_artifact_ids
            .iter()
            .filter(|parent_id| {
                document.case.artifacts.iter().any(|candidate| {
                    candidate.artifact_id == **parent_id
                        && candidate.kind == TraceCaseArtifactKind::StaticBinary
                })
            })
            .cloned()
            .collect::<Vec<_>>();
        if static_binary_parent_ids.is_empty() {
            let selected = document
                .case
                .exact_binary_artifact_id
                .as_ref()
                .and_then(|artifact_id| {
                    document.case.artifacts.iter().find(|candidate| {
                        candidate.artifact_id == *artifact_id
                            && candidate.kind == TraceCaseArtifactKind::StaticBinary
                            && candidate
                                .summary
                                .binary_sha256
                                .as_deref()
                                .is_some_and(|sha256| {
                                    sha256.eq_ignore_ascii_case(&bundle.binary_sha256)
                                })
                    })
                })
                .or_else(|| {
                    document.case.artifacts.iter().find(|candidate| {
                        candidate.kind == TraceCaseArtifactKind::StaticBinary
                            && candidate
                                .summary
                                .binary_sha256
                                .as_deref()
                                .is_some_and(|sha256| {
                                    sha256.eq_ignore_ascii_case(&bundle.binary_sha256)
                                })
                    })
                })
                .or_else(|| {
                    document.case.exact_binary_artifact_id.as_ref().and_then(|artifact_id| {
                        document.case.artifacts.iter().find(|candidate| {
                            candidate.artifact_id == *artifact_id
                                && candidate.kind == TraceCaseArtifactKind::StaticBinary
                        })
                    })
                })
                .ok_or_else(|| {
                    TraceError::InvalidArgument(
                        "import the exact AArch64 ELF before importing a coverage report, or pass its static-binary artifact ID as the parent"
                            .to_string(),
                    )
                })?;
            artifact
                .parent_artifact_ids
                .push(selected.artifact_id.clone());
            static_binary_parent_ids.push(selected.artifact_id.clone());
        }
        static_binary_parent_ids.sort();
        static_binary_parent_ids.dedup();
        if static_binary_parent_ids.len() != 1 {
            return Err(TraceError::InvalidArgument(
                "a coverage report must bind exactly one static-binary parent".to_string(),
            ));
        }
        let required_source_hashes = bundle
            .dynamic_runs
            .iter()
            .map(|run| run.source_artifact_sha256.to_ascii_lowercase())
            .collect::<BTreeSet<_>>();
        for source_hash in &required_source_hashes {
            let already_parent = artifact.parent_artifact_ids.iter().any(|parent_id| {
                document.case.artifacts.iter().any(|candidate| {
                    candidate.artifact_id == *parent_id
                        && candidate.kind != TraceCaseArtifactKind::StaticBinary
                        && candidate.sha256.eq_ignore_ascii_case(source_hash)
                })
            });
            if already_parent {
                continue;
            }
            let source = document.case.artifacts.iter().find(|candidate| {
                candidate.kind != TraceCaseArtifactKind::StaticBinary
                    && candidate.sha256.eq_ignore_ascii_case(source_hash)
            });
            let Some(source) = source else {
                return Err(TraceError::InvalidArgument(format!(
                    "coverage report requires source artifact SHA-256 {source_hash}; import that exact OLLVM/trace artifact first or pass its artifact ID as a parent"
                )));
            };
            artifact
                .parent_artifact_ids
                .push(source.artifact_id.clone());
        }
        artifact.parent_artifact_ids.sort();
        artifact.parent_artifact_ids.dedup();
        let exact_binary = document
            .case
            .artifacts
            .iter()
            .find(|candidate| candidate.artifact_id == static_binary_parent_ids[0])
            .ok_or_else(|| {
                TraceError::InvalidArgument(
                    "coverage static-binary parent was not found".to_string(),
                )
            })?;
        let source_sha256s = artifact
            .parent_artifact_ids
            .iter()
            .filter_map(|parent_id| {
                document.case.artifacts.iter().find(|candidate| {
                    candidate.artifact_id == *parent_id
                        && candidate.kind != TraceCaseArtifactKind::StaticBinary
                })
            })
            .map(|candidate| candidate.sha256.clone())
            .collect::<Vec<_>>();
        let exact_binary_path = resolve_trace_case_artifact_path(case_path, &exact_binary.path)?;
        let report = inspect_coverage_reconciliation_bundle(
            bundle,
            &exact_binary_path.to_string_lossy(),
            &source_sha256s,
        )
        .map_err(TraceError::InvalidArgument)?;
        apply_coverage_report_summary(&mut artifact.summary, &report);
    }
    if let Some(existing) = document
        .case
        .artifacts
        .iter()
        .find(|existing| {
            existing.kind == artifact.kind
                && existing.sha256 == artifact.sha256
                && (!matches!(
                    artifact.kind,
                    TraceCaseArtifactKind::RuntimeAttestation
                        | TraceCaseArtifactKind::CoverageReport
                ) || existing.parent_artifact_ids == artifact.parent_artifact_ids)
        })
        .cloned()
    {
        return Ok(TraceCaseArtifactImportResult {
            case_path: case_path.to_string(),
            artifact: existing,
            already_present: true,
            case: document.case,
        });
    }
    if document.case.artifacts.len() >= MAX_ARTIFACTS {
        return Err(TraceError::InvalidArgument(format!(
            "analysis case supports at most {MAX_ARTIFACTS} artifacts"
        )));
    }
    if document.case.primary_trace_artifact_id.is_none()
        && artifact.kind == TraceCaseArtifactKind::Trace
    {
        document.case.primary_trace_artifact_id = Some(artifact.artifact_id.clone());
    }
    if document.case.exact_binary_artifact_id.is_none()
        && artifact.kind == TraceCaseArtifactKind::StaticBinary
    {
        document.case.exact_binary_artifact_id = Some(artifact.artifact_id.clone());
    }
    document.case.updated_at_ms = now_ms();
    document.case.artifacts.push(artifact.clone());
    save_trace_analysis_case(case_path, &document.case)?;
    Ok(TraceCaseArtifactImportResult {
        case_path: case_path.to_string(),
        artifact,
        already_present: false,
        case: document.case,
    })
}

pub fn upsert_trace_case_claim(
    case_path: &str,
    mut claim: TraceCaseClaim,
) -> Result<TraceAnalysisCaseDocument> {
    let mut document = load_trace_analysis_case(case_path)?;
    let timestamp = now_ms();
    if claim.claim_id.trim().is_empty() {
        claim.claim_id = uuid::Uuid::new_v4().to_string();
        claim.created_at_ms = timestamp;
    }
    claim.updated_at_ms = timestamp;
    if claim.created_at_ms == 0 {
        claim.created_at_ms = timestamp;
    }
    if let Some(existing) = document
        .case
        .claims
        .iter_mut()
        .find(|existing| existing.claim_id == claim.claim_id)
    {
        *existing = claim;
    } else {
        if document.case.claims.len() >= MAX_CLAIMS {
            return Err(TraceError::InvalidArgument(format!(
                "analysis case supports at most {MAX_CLAIMS} claims"
            )));
        }
        document.case.claims.push(claim);
    }
    document.case.updated_at_ms = timestamp;
    save_trace_analysis_case(case_path, &document.case)?;
    Ok(document)
}

fn normalize_optional_group(value: &mut Option<String>) {
    *value = value
        .take()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty());
}

fn normalize_string_list(values: &mut Vec<String>) {
    for value in values.iter_mut() {
        *value = value.trim().to_string();
    }
    values.retain(|value| !value.is_empty());
    values.sort();
    values.dedup();
}

pub fn upsert_trace_case_experiment(
    case_path: &str,
    mut experiment: TraceCaseExperiment,
) -> Result<TraceAnalysisCaseDocument> {
    let mut document = load_trace_analysis_case(case_path)?;
    experiment.label = experiment.label.trim().to_string();
    normalize_optional_group(&mut experiment.binary_sha256);
    normalize_optional_group(&mut experiment.key_group);
    normalize_optional_group(&mut experiment.input_group);
    normalize_optional_group(&mut experiment.environment_group);
    if let Some(binary_sha256) = &mut experiment.binary_sha256 {
        *binary_sha256 = binary_sha256.to_ascii_lowercase();
    }
    normalize_string_list(&mut experiment.artifact_ids);
    normalize_string_list(&mut experiment.controlled_variables);
    normalize_string_list(&mut experiment.changed_variables);
    normalize_string_list(&mut experiment.notes);

    if experiment.experiment_id.trim().is_empty() {
        let mut hasher = Sha256::new();
        for value in [
            Some(experiment.label.as_str()),
            experiment.binary_sha256.as_deref(),
            experiment.key_group.as_deref(),
            experiment.input_group.as_deref(),
            experiment.environment_group.as_deref(),
        ] {
            hasher.update(value.unwrap_or("<unspecified>").as_bytes());
            hasher.update([0]);
        }
        let digest = format!("{:x}", hasher.finalize());
        experiment.experiment_id = format!("experiment-{}", &digest[..24]);
    } else {
        experiment.experiment_id = experiment.experiment_id.trim().to_string();
    }

    if let Some(existing) = document
        .case
        .experiments
        .iter_mut()
        .find(|existing| existing.experiment_id == experiment.experiment_id)
    {
        *existing = experiment;
    } else {
        if document.case.experiments.len() >= MAX_EXPERIMENTS {
            return Err(TraceError::InvalidArgument(format!(
                "analysis case supports at most {MAX_EXPERIMENTS} experiments"
            )));
        }
        document.case.experiments.push(experiment);
    }
    document.case.updated_at_ms = now_ms();
    save_trace_analysis_case(case_path, &document.case)?;
    Ok(document)
}

fn generated_claim(
    statement: String,
    scope: String,
    status: TraceCaseClaimStatus,
    supporting_evidence: Vec<TraceCaseEvidenceRef>,
    counter_evidence: Vec<TraceCaseEvidenceRef>,
    missing_evidence: Vec<String>,
    limitations: Vec<String>,
) -> TraceCaseClaim {
    let timestamp = now_ms();
    let mut hasher = Sha256::new();
    hasher.update(scope.as_bytes());
    hasher.update([0]);
    hasher.update(statement.as_bytes());
    let digest = format!("{:x}", hasher.finalize());
    TraceCaseClaim {
        claim_id: format!("doctor-{}", &digest[..24]),
        statement,
        scope,
        status,
        coverage_requirement: TraceCaseCoverageRequirement::Auto,
        supporting_evidence,
        counter_evidence,
        missing_evidence,
        limitations,
        created_by: "replay-doctor".to_string(),
        created_at_ms: timestamp,
        updated_at_ms: timestamp,
    }
}

fn evidence_ref(
    artifact: &TraceCaseArtifact,
    locator: impl Into<String>,
    description: impl Into<String>,
) -> TraceCaseEvidenceRef {
    TraceCaseEvidenceRef {
        artifact_id: artifact.artifact_id.clone(),
        locator: locator.into(),
        description: description.into(),
    }
}

fn next_action(
    priority: u8,
    action: &str,
    tool_name: Option<&str>,
    artifact_ids: Vec<String>,
    seed_capture_offsets: Vec<String>,
    reason: impl Into<String>,
    instructions: impl Into<String>,
    manual_execution_required: bool,
) -> ReplayDoctorNextAction {
    ReplayDoctorNextAction {
        priority,
        action: action.to_string(),
        tool_name: tool_name.map(str::to_string),
        artifact_ids,
        seed_capture_offsets: normalize_offsets(seed_capture_offsets),
        reason: reason.into(),
        instructions: instructions.into(),
        manual_execution_required,
        evidence_level: "candidate/related".to_string(),
    }
}

fn timeline_summary(artifact: &TraceCaseArtifact) -> String {
    let mut parts = Vec::new();
    if let Some(module) = &artifact.summary.module_name {
        parts.push(format!("module {module}"));
    }
    if artifact.summary.event_count > 0 {
        parts.push(format!("{} events/seeds", artifact.summary.event_count));
    }
    if artifact.summary.run_count > 0 {
        parts.push(format!("{} runs/probes", artifact.summary.run_count));
    }
    if !artifact.summary.stop_reason_counts.is_empty() {
        parts.push(
            artifact
                .summary
                .stop_reason_counts
                .iter()
                .map(|(reason, count)| format!("{reason}={count}"))
                .collect::<Vec<_>>()
                .join(", "),
        );
    }
    if parts.is_empty() {
        artifact.label.clone()
    } else {
        parts.join(" · ")
    }
}

fn normalized_claim_key(claim: &TraceCaseClaim) -> String {
    let scope = claim
        .scope
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
        .to_ascii_lowercase();
    let statement = claim
        .statement
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
        .to_ascii_lowercase();
    format!("{scope}\0{statement}")
}

fn contains_any(value: &str, needles: &[&str]) -> bool {
    needles.iter().any(|needle| value.contains(needle))
}

fn coverage_requirement_priority(requirement: TraceCaseCoverageRequirement) -> u8 {
    match requirement {
        TraceCaseCoverageRequirement::Auto | TraceCaseCoverageRequirement::NotRequired => 0,
        TraceCaseCoverageRequirement::ScopeComplete => 1,
        TraceCaseCoverageRequirement::NegativeExistence => 2,
        TraceCaseCoverageRequirement::ExhaustiveEnumeration => 3,
        TraceCaseCoverageRequirement::GlobalInvariance => 4,
        TraceCaseCoverageRequirement::CompleteControlFlow => 5,
    }
}

fn auto_coverage_requirement(claim: &TraceCaseClaim) -> TraceCaseCoverageRequirement {
    if claim
        .scope
        .trim()
        .to_ascii_lowercase()
        .starts_with("runtime-image:")
    {
        return TraceCaseCoverageRequirement::NotRequired;
    }
    let text = format!("{} {}", claim.scope, claim.statement).to_ascii_lowercase();
    let negative = contains_any(
        &text,
        &[
            " no ",
            "none",
            "absent",
            "not present",
            "does not contain",
            "doesn't contain",
            "without ",
            "not found",
            "没有",
            "不存在",
            "未发现",
            "不包含",
            "未包含",
            "无 aes",
            "无aes",
        ],
    ) || text.starts_with("no ");
    let completeness_text = text.replace("incomplete", "").replace("不完整", "");
    let complete = contains_any(
        &completeness_text,
        &[
            "complete",
            "fully",
            "entire",
            "exhaustive",
            "all ",
            "every ",
            "完整",
            "全部",
            "所有",
            "完全",
            "穷尽",
            "全量",
        ],
    );
    let invariant = contains_any(
        &text,
        &[
            "always",
            "never",
            "constant",
            "invariant",
            "globally opaque",
            "global opaque",
            "恒定",
            "永远",
            "总是",
            "不变",
            "全局 opaque",
            "全局不透明",
        ],
    );
    let control_flow = contains_any(
        &text,
        &[
            "cfg",
            "control flow",
            "branch",
            "dispatcher",
            "opaque",
            "basic block",
            "控制流",
            "分支",
            "调度器",
            "不透明谓词",
            "基本块",
            "ollvm",
        ],
    );
    let enumeration = contains_any(
        &text,
        &[
            "discovered",
            "identified",
            "recovered",
            "enumerated",
            "found all",
            "全部发现",
            "全部识别",
            "全部恢复",
            "都已发现",
            "均已发现",
        ],
    );

    if invariant && control_flow {
        TraceCaseCoverageRequirement::GlobalInvariance
    } else if complete && control_flow && contains_any(&text, &["cfg", "control flow", "控制流"])
    {
        TraceCaseCoverageRequirement::CompleteControlFlow
    } else if complete && (enumeration || control_flow) {
        TraceCaseCoverageRequirement::ExhaustiveEnumeration
    } else if negative {
        TraceCaseCoverageRequirement::NegativeExistence
    } else if complete {
        TraceCaseCoverageRequirement::ScopeComplete
    } else {
        TraceCaseCoverageRequirement::NotRequired
    }
}

fn effective_coverage_requirement(
    claim: &TraceCaseClaim,
) -> (TraceCaseCoverageRequirement, &'static str) {
    let automatic = auto_coverage_requirement(claim);
    match claim.coverage_requirement {
        TraceCaseCoverageRequirement::Auto => (automatic, "auto-classified"),
        TraceCaseCoverageRequirement::NotRequired
            if automatic != TraceCaseCoverageRequirement::NotRequired =>
        {
            (automatic, "auto-classified-overrode-not-required")
        }
        explicit
            if coverage_requirement_priority(explicit)
                >= coverage_requirement_priority(automatic) =>
        {
            (explicit, "explicit")
        }
        _ => (automatic, "auto-classified-stricter"),
    }
}

fn coverage_max_status(requirement: TraceCaseCoverageRequirement) -> TraceCaseClaimStatus {
    match requirement {
        TraceCaseCoverageRequirement::Auto | TraceCaseCoverageRequirement::NotRequired => {
            TraceCaseClaimStatus::Verified
        }
        TraceCaseCoverageRequirement::ScopeComplete
        | TraceCaseCoverageRequirement::NegativeExistence => TraceCaseClaimStatus::Observed,
        TraceCaseCoverageRequirement::GlobalInvariance
        | TraceCaseCoverageRequirement::ExhaustiveEnumeration
        | TraceCaseCoverageRequirement::CompleteControlFlow => TraceCaseClaimStatus::Related,
    }
}

fn build_claim_ledger_audit(
    persisted_claims: &[TraceCaseClaim],
    generated_claims: &[TraceCaseClaim],
    artifacts: &[TraceCaseArtifact],
    health: &[TraceCaseArtifactHealth],
    runtime_attestations: &[TraceCaseRuntimeAttestationReport],
    crypto_kats: &[TraceCaseCryptoKatReport],
    coverage_reconciliations: &[TraceCaseCoverageReport],
) -> TraceCaseClaimLedgerAudit {
    let artifact_by_id = artifacts
        .iter()
        .map(|artifact| (artifact.artifact_id.as_str(), artifact))
        .collect::<BTreeMap<_, _>>();
    let health_by_id = health
        .iter()
        .map(|item| (item.artifact_id.as_str(), item))
        .collect::<BTreeMap<_, _>>();
    let mut claims = Vec::new();
    let mut contradiction_groups = BTreeMap::<String, Vec<(&TraceCaseClaim, &str)>>::new();

    for (claim, source) in persisted_claims
        .iter()
        .map(|claim| (claim, "persisted"))
        .chain(generated_claims.iter().map(|claim| (claim, "generated")))
    {
        contradiction_groups
            .entry(normalized_claim_key(claim))
            .or_default()
            .push((claim, source));

        let mut valid_supporting = 0u64;
        let mut valid_counter = 0u64;
        let mut invalid_evidence = 0u64;
        let mut evidence_kinds = Vec::new();
        let mut runtime_attestation_gate_met = false;
        let mut crypto_kat_gate_met = false;
        let mut referenced_coverage_artifact_ids = Vec::<String>::new();
        for (evidence, counter) in claim
            .supporting_evidence
            .iter()
            .map(|evidence| (evidence, false))
            .chain(
                claim
                    .counter_evidence
                    .iter()
                    .map(|evidence| (evidence, true)),
            )
        {
            let artifact = artifact_by_id.get(evidence.artifact_id.as_str()).copied();
            let artifact_valid = health_by_id
                .get(evidence.artifact_id.as_str())
                .is_some_and(|item| item.status == "valid");
            if let Some(artifact) = artifact {
                if !evidence_kinds.contains(&artifact.kind) {
                    evidence_kinds.push(artifact.kind);
                }
            }
            if artifact.is_none()
                || !artifact_valid
                || evidence.locator.trim().is_empty()
                || evidence.description.trim().is_empty()
            {
                invalid_evidence += 1;
            } else if counter {
                valid_counter += 1;
            } else {
                valid_supporting += 1;
                if artifact
                    .is_some_and(|artifact| artifact.kind == TraceCaseArtifactKind::CoverageReport)
                {
                    referenced_coverage_artifact_ids.push(evidence.artifact_id.clone());
                }
                runtime_attestation_gate_met |= artifact.is_some_and(|artifact| {
                    artifact.kind == TraceCaseArtifactKind::RuntimeAttestation
                        && runtime_attestations.iter().any(|attestation| {
                            attestation.artifact_id == artifact.artifact_id
                                && attestation.report.status == "verified-full"
                                && attestation.report.verification_gate_met
                        })
                });
                crypto_kat_gate_met |= artifact.is_some_and(|artifact| {
                    artifact.kind == TraceCaseArtifactKind::CryptoKat
                        && crypto_kats.iter().any(|kat| {
                            kat.artifact_id == artifact.artifact_id
                                && kat.report.status == CryptoKatStatus::VerifiedFull
                                && kat.report.verification_gate_met
                                && kat.report.claim_scope == claim.scope
                        })
                });
            }
        }
        evidence_kinds.sort_by_key(|kind| kind.as_str());
        referenced_coverage_artifact_ids.sort();
        referenced_coverage_artifact_ids.dedup();

        let mut blockers = Vec::new();
        let mut notes = Vec::new();
        let (coverage_requirement, coverage_requirement_source) =
            effective_coverage_requirement(claim);
        let coverage_max_status = coverage_max_status(coverage_requirement);
        let matching_coverage = coverage_reconciliations
            .iter()
            .filter(|coverage| {
                referenced_coverage_artifact_ids.contains(&coverage.artifact_id)
                    && coverage.report.claim_scope == claim.scope
            })
            .collect::<Vec<_>>();
        let best_coverage = matching_coverage.iter().copied().max_by(|left, right| {
            left.report
                .coverage_gate_met
                .cmp(&right.report.coverage_gate_met)
                .then_with(|| {
                    left.report
                        .summary
                        .coverage_basis_points
                        .instructions
                        .cmp(&right.report.summary.coverage_basis_points.instructions)
                })
                .then_with(|| {
                    left.report
                        .summary
                        .coverage_basis_points
                        .blocks
                        .cmp(&right.report.summary.coverage_basis_points.blocks)
                })
        });
        let coverage_gate_passed = coverage_requirement
            == TraceCaseCoverageRequirement::NotRequired
            || best_coverage.is_some_and(|coverage| coverage.report.coverage_gate_met);
        let coverage_gate_status =
            if coverage_requirement == TraceCaseCoverageRequirement::NotRequired {
                "not-required"
            } else if referenced_coverage_artifact_ids.is_empty() {
                "missing"
            } else if matching_coverage.is_empty() {
                "scope-mismatch"
            } else if coverage_gate_passed {
                "passed"
            } else {
                "partial"
            };
        let coverage_artifact_ids = matching_coverage
            .iter()
            .map(|coverage| coverage.artifact_id.clone())
            .collect::<Vec<_>>();
        let coverage_uncovered_counts =
            best_coverage.map(|coverage| coverage.report.summary.uncovered_counts.clone());
        let runtime_image_scope = claim
            .scope
            .trim()
            .to_ascii_lowercase()
            .starts_with("runtime-image:");
        let crypto_scope = claim
            .scope
            .trim()
            .to_ascii_lowercase()
            .starts_with("crypto:");
        if invalid_evidence > 0 {
            blockers.push(format!(
                "{invalid_evidence} evidence reference(s) point to an invalid, changed, or malformed artifact."
            ));
        }
        if !claim.missing_evidence.is_empty() {
            blockers.push(format!(
                "{} explicitly declared evidence item(s) are still missing.",
                claim.missing_evidence.len()
            ));
        }
        if valid_supporting == 0 && claim.status != TraceCaseClaimStatus::Unknown {
            blockers.push("The claim has no valid supporting artifact evidence.".to_string());
        }
        if valid_counter > 0 && claim.status != TraceCaseClaimStatus::Refuted {
            blockers.push(format!(
                "{valid_counter} valid counter-evidence reference(s) must be resolved before retaining this status."
            ));
        }
        if coverage_requirement != TraceCaseCoverageRequirement::NotRequired {
            match coverage_gate_status {
                "missing" => blockers.push(format!(
                    "This {} claim requires a valid exact-scope {} artifact in supporting evidence; dynamic absence or structural summaries alone leave unexecuted paths unknown.",
                    coverage_requirement.as_str(), COVERAGE_RECONCILIATION_SCHEMA
                )),
                "scope-mismatch" => blockers.push(format!(
                    "Referenced coverage artifact(s) do not have claimScope exactly equal to '{}'; coverage cannot be reused across a different claim scope.",
                    claim.scope
                )),
                "partial" => {
                    if let Some(counts) = &coverage_uncovered_counts {
                        blockers.push(format!(
                            "Coverage is incomplete for this {} claim: uncovered instructions={}, blocks={}, branches={}, functions={}, edges={}. These sites remain unknown.",
                            coverage_requirement.as_str(),
                            counts.instructions,
                            counts.blocks,
                            counts.branches,
                            counts.functions,
                            counts.edges
                        ));
                    } else {
                        blockers.push(format!(
                            "Coverage is incomplete for this {} claim; unexecuted paths remain unknown.",
                            coverage_requirement.as_str()
                        ));
                    }
                }
                "passed" => notes.push(
                    "Exact-ELF/source-bound listed-site coverage passed, but it is only a maximum-level constraint and not semantic proof."
                        .to_string(),
                ),
                _ => {}
            }
            if claim.status == TraceCaseClaimStatus::Verified
                && coverage_max_status != TraceCaseClaimStatus::Verified
            {
                blockers.push(format!(
                    "Coverage cannot by itself verify this {} claim. Its implemented maximum is {:?}; algorithm absence, global branch invariance, exhaustive discovery, and complete CFG claims need an independent deterministic semantic protocol.",
                    coverage_requirement.as_str(), coverage_max_status
                ));
            }
        }
        if claim.status == TraceCaseClaimStatus::Verified {
            if runtime_image_scope && !runtime_attestation_gate_met {
                blockers.push(
                    "A runtime-image:* Verified claim requires a valid runtime-attestation artifact whose exact-ELF recomputation status is verified-full; evidence descriptions or SHA-only artifacts cannot open this gate."
                        .to_string(),
                );
            } else if crypto_scope && !crypto_kat_gate_met {
                blockers.push(
                    "A crypto:* Verified claim requires a valid crypto-kat artifact whose embedded parameters and output were strictly recomputed as verified-full, and whose exact claimScope matches this claim; evidence locator or description text cannot open this gate."
                        .to_string(),
                );
            } else if !runtime_image_scope && !crypto_scope {
                blockers.push(
                    "This claim scope has no implemented structured Verified gate. Free-text semantic/known-answer markers, structural reports, simulation results, and SHA-only evidence cannot open a gate; retain Observed/Related until a dedicated deterministic protocol exists."
                        .to_string(),
                );
            }
        }
        if claim.status == TraceCaseClaimStatus::Refuted && valid_counter == 0 {
            blockers.push(
                "Refuted requires at least one valid counter-evidence reference.".to_string(),
            );
        }
        if !claim.limitations.is_empty() {
            notes.push(format!(
                "The claim retains {} explicit limitation(s).",
                claim.limitations.len()
            ));
        }

        let structured_verified_gate_met = (runtime_image_scope && runtime_attestation_gate_met)
            || (crypto_scope && crypto_kat_gate_met);
        let recommended_status = if valid_counter > 0 {
            TraceCaseClaimStatus::Refuted
        } else if valid_supporting == 0 {
            TraceCaseClaimStatus::Unknown
        } else if claim.status == TraceCaseClaimStatus::Verified
            && structured_verified_gate_met
            && coverage_gate_passed
            && coverage_max_status == TraceCaseClaimStatus::Verified
            && invalid_evidence == 0
            && claim.missing_evidence.is_empty()
        {
            TraceCaseClaimStatus::Verified
        } else if claim.status == TraceCaseClaimStatus::Verified
            && coverage_max_status == TraceCaseClaimStatus::Related
        {
            TraceCaseClaimStatus::Related
        } else if claim.status == TraceCaseClaimStatus::Related {
            TraceCaseClaimStatus::Related
        } else {
            TraceCaseClaimStatus::Observed
        };
        let verification_gate_passed = claim.status == TraceCaseClaimStatus::Verified
            && recommended_status == TraceCaseClaimStatus::Verified
            && blockers.is_empty();
        let gate_status = if claim.status == TraceCaseClaimStatus::Unknown && blockers.is_empty() {
            "unknown"
        } else if blockers.is_empty() {
            "passed"
        } else {
            "blocked"
        };
        claims.push(TraceCaseClaimAuditEntry {
            claim_id: claim.claim_id.clone(),
            source: source.to_string(),
            current_status: claim.status,
            recommended_status,
            gate_status: gate_status.to_string(),
            verification_gate_passed,
            valid_supporting_evidence_count: valid_supporting,
            valid_counter_evidence_count: valid_counter,
            invalid_evidence_count: invalid_evidence,
            evidence_artifact_kinds: evidence_kinds,
            coverage_requirement: coverage_requirement.as_str().to_string(),
            coverage_requirement_source: coverage_requirement_source.to_string(),
            coverage_gate_status: coverage_gate_status.to_string(),
            coverage_gate_passed,
            coverage_max_status,
            coverage_artifact_ids,
            coverage_uncovered_counts,
            blockers,
            notes,
        });
    }

    let contradictions = contradiction_groups
        .into_values()
        .filter_map(|group| {
            let has_refuted = group
                .iter()
                .any(|(claim, _)| claim.status == TraceCaseClaimStatus::Refuted);
            let has_positive = group.iter().any(|(claim, _)| {
                matches!(
                    claim.status,
                    TraceCaseClaimStatus::Observed
                        | TraceCaseClaimStatus::Verified
                        | TraceCaseClaimStatus::Related
                )
            });
            (has_refuted && has_positive).then(|| {
                format!(
                    "Contradictory statuses exist for claim(s): {}",
                    group
                        .iter()
                        .map(|(claim, source)| format!("{} ({source})", claim.claim_id))
                        .collect::<Vec<_>>()
                        .join(", ")
                )
            })
        })
        .collect::<Vec<_>>();
    let passed_claim_count = claims
        .iter()
        .filter(|claim| claim.gate_status == "passed")
        .count() as u64;
    let blocked_claim_count = claims
        .iter()
        .filter(|claim| claim.gate_status == "blocked")
        .count() as u64;
    let refuted_claim_count = claims
        .iter()
        .filter(|claim| claim.recommended_status == TraceCaseClaimStatus::Refuted)
        .count() as u64;
    let verified_gate_passed_count = claims
        .iter()
        .filter(|claim| claim.verification_gate_passed)
        .count() as u64;
    TraceCaseClaimLedgerAudit {
        schema: CLAIM_LEDGER_AUDIT_SCHEMA.to_string(),
        total_claim_count: claims.len() as u64,
        passed_claim_count,
        blocked_claim_count,
        refuted_claim_count,
        verified_gate_passed_count,
        claims,
        contradictions,
        limitations: vec![
            "The ledger audit checks provenance, artifact integrity, counter-evidence, structured runtime-image/crypto gates, and exact-ELF/source-bound coverage reconciliation; it does not independently prove claim statements outside those bounded scopes."
                .to_string(),
            "runtime-image:* claims require verified-full runtime attestation, while crypto:* claims require an exact-scope verified-full crypto KAT; neither gate can verify OLLVM structure, reachability, or simulator completeness."
                .to_string(),
            format!(
                "{} can only cap the maximum claim level. Negative-existence and scope-complete claims remain at most Observed; global-invariance, exhaustive OLLVM discovery, and complete-control-flow claims remain at most Related without an independent deterministic semantic protocol.",
                COVERAGE_CLAIM_GATE_SCHEMA
            ),
            "OLLVM, Unicorn, and angr structural evidence cannot pass the Verified gate by itself."
                .to_string(),
        ],
    }
}

fn canonical_gpr_name(name: &str) -> Option<String> {
    let name = name.trim().to_ascii_lowercase();
    match name.as_str() {
        "fp" => Some("x29".to_string()),
        "lr" => Some("x30".to_string()),
        "sp" | "pc" => Some(name),
        _ => {
            let index = name
                .strip_prefix('x')
                .or_else(|| name.strip_prefix('w'))?
                .parse::<u8>()
                .ok()?;
            (index <= 30).then(|| format!("x{index}"))
        }
    }
}

fn is_simd_register(name: &str) -> bool {
    let name = name.trim().to_ascii_lowercase();
    let Some(index) = name
        .strip_prefix('v')
        .or_else(|| name.strip_prefix('q'))
        .or_else(|| name.strip_prefix('d'))
        .or_else(|| name.strip_prefix('s'))
        .and_then(|value| value.parse::<u8>().ok())
    else {
        return false;
    };
    index <= 31
}

fn frida_event_offset(event: &FridaCaptureEvent) -> Option<u64> {
    if let Some(offset) = &event.dispatcher_offset {
        return parse_hex_addr(offset).ok();
    }
    let target = event
        .target
        .as_deref()
        .and_then(|value| parse_hex_addr(value).ok())?;
    let base = event
        .module_base
        .as_deref()
        .and_then(|value| parse_hex_addr(value).ok())?;
    target.checked_sub(base)
}

fn state_component(
    component: &str,
    status: &str,
    observed_count: u64,
    expected_count: Option<u64>,
    source_artifact_ids: Vec<String>,
    details: impl Into<String>,
    next_action: Option<&str>,
) -> ReplayStateReadinessComponent {
    ReplayStateReadinessComponent {
        component: component.to_string(),
        status: status.to_string(),
        observed_count,
        expected_count,
        source_artifact_ids,
        details: details.into(),
        next_action: next_action.map(str::to_string),
    }
}

fn build_state_readiness(
    valid_frida: &[(TraceCaseArtifact, FridaCaptureBundle)],
    valid_unicorn: &[(TraceCaseArtifact, UnicornOllvmResultBundle)],
    valid_binaries: &[(TraceCaseArtifact, ElfBinaryIdentity)],
) -> ReplayStateReadinessReport {
    let latest_unicorn = valid_unicorn.last();
    let selected_frida = valid_frida.iter().rev().find_map(|(artifact, bundle)| {
        let event = bundle
            .events
            .iter()
            .filter(|event| {
                matches!(event.event.as_str(), "hook-enter" | "ollvm-dispatcher-hit")
                    && latest_unicorn.is_none_or(|(_, latest)| {
                        event.module_name.as_deref() == Some(latest.module_name.as_str())
                    })
            })
            .max_by_key(|event| {
                let register_score = event
                    .registers
                    .keys()
                    .filter(|name| canonical_gpr_name(name).is_some())
                    .count();
                let readable_capture_score = event
                    .captures
                    .iter()
                    .filter(|capture| {
                        capture.read_error.is_none()
                            && capture
                                .value
                                .as_ref()
                                .is_some_and(|value| !value.is_empty())
                    })
                    .count();
                register_score.saturating_mul(100) + readable_capture_score
            })?;
        Some((artifact, event))
    });

    let mut register_names = BTreeSet::new();
    let mut simd_names = BTreeSet::new();
    let mut selected_sources = Vec::new();
    if let Some((artifact, event)) = selected_frida {
        selected_sources.push(artifact.artifact_id.clone());
        for name in event.registers.keys() {
            if let Some(name) = canonical_gpr_name(name) {
                register_names.insert(name);
            }
            if is_simd_register(name) {
                simd_names.insert(name.to_ascii_lowercase());
            }
        }
    } else if let Some((artifact, bundle)) = latest_unicorn {
        selected_sources.push(artifact.artifact_id.clone());
        for name in bundle
            .seeds
            .iter()
            .flat_map(|seed| seed.registers_seeded.iter())
        {
            if let Some(name) = canonical_gpr_name(name) {
                register_names.insert(name);
            }
            if is_simd_register(name) {
                simd_names.insert(name.to_ascii_lowercase());
            }
        }
    }

    let nzcv_captured = selected_frida.is_some_and(|(_, event)| {
        event
            .registers
            .keys()
            .any(|name| name.eq_ignore_ascii_case("nzcv"))
    }) || latest_unicorn.is_some_and(|(_, bundle)| {
        bundle.seeds.iter().any(|seed| {
            seed.registers_seeded
                .iter()
                .any(|name| name.eq_ignore_ascii_case("nzcv"))
        })
    });
    let gpr_count = register_names.len() as u64;
    let gpr_status = if gpr_count >= 33 {
        "captured"
    } else if gpr_count > 0 {
        "partial"
    } else {
        "not-captured"
    };

    let mut stack_readable = 0u64;
    let mut stack_unreadable = 0u64;
    let mut pointer_readable = 0u64;
    let mut pointer_unreadable = 0u64;
    let mut system_capture_count = 0u64;
    if let Some((_, event)) = selected_frida {
        for capture in &event.captures {
            let label = capture.label.to_ascii_lowercase();
            let base = capture
                .base_register
                .as_deref()
                .unwrap_or_default()
                .to_ascii_lowercase();
            let is_stack = capture.index == 29 || base == "sp" || label.contains("stack");
            let is_system = label.contains("tls")
                || label.contains("tpidr")
                || label.contains("system-state")
                || label.contains("fpcr")
                || label.contains("fpsr");
            let is_pointer = !is_stack
                && (base
                    .strip_prefix('x')
                    .and_then(|value| value.parse::<u8>().ok())
                    .is_some_and(|index| index <= 28)
                    || (capture.index <= 28 && capture.kind.eq_ignore_ascii_case("byteArray")));
            let readable = capture.read_error.is_none()
                && capture.byte_length.unwrap_or_default() > 0
                && capture
                    .value
                    .as_ref()
                    .is_some_and(|value| !value.is_empty());
            if is_stack {
                if readable {
                    stack_readable += 1;
                } else if capture.read_error.is_some() {
                    stack_unreadable += 1;
                }
            } else if is_pointer {
                if readable {
                    pointer_readable += 1;
                } else if capture.read_error.is_some() {
                    pointer_unreadable += 1;
                }
            }
            if is_system && readable {
                system_capture_count += 1;
            }
        }
        system_capture_count += event
            .registers
            .keys()
            .filter(|name| {
                matches!(
                    name.to_ascii_lowercase().as_str(),
                    "tpidr_el0" | "fpcr" | "fpsr"
                )
            })
            .count() as u64;
    }

    let missing_stack_count = latest_unicorn
        .map(|(_, bundle)| {
            bundle
                .runs
                .iter()
                .flat_map(|run| run.missing_memory.iter())
                .filter(|memory| {
                    memory
                        .base_register
                        .as_deref()
                        .is_some_and(|name| name.eq_ignore_ascii_case("sp"))
                })
                .count() as u64
        })
        .unwrap_or_default();
    let missing_pointer_count = latest_unicorn
        .map(|(_, bundle)| {
            bundle
                .runs
                .iter()
                .flat_map(|run| run.missing_memory.iter())
                .filter(|memory| {
                    memory.base_register.as_deref().is_some_and(|name| {
                        name.strip_prefix('x')
                            .or_else(|| name.strip_prefix('X'))
                            .and_then(|value| value.parse::<u8>().ok())
                            .is_some_and(|index| index <= 28)
                    })
                })
                .count() as u64
        })
        .unwrap_or_default();
    let unsupported_simd_count = latest_unicorn
        .map(|(_, bundle)| {
            bundle
                .runs
                .iter()
                .filter(|run| run.stop_reason == "unsupported-simd-state")
                .count() as u64
        })
        .unwrap_or_default();
    let unsupported_system_count = latest_unicorn
        .map(|(_, bundle)| {
            bundle
                .runs
                .iter()
                .filter(|run| run.stop_reason == "unsupported-system-state")
                .count() as u64
        })
        .unwrap_or_default();

    let exact_binary_match = latest_unicorn.and_then(|(_, bundle)| {
        (!valid_binaries.is_empty()).then(|| {
            valid_binaries.iter().any(|(_, identity)| {
                identity
                    .binary_sha256
                    .eq_ignore_ascii_case(&bundle.binary_sha256)
            })
        })
    });
    let exact_status = match (latest_unicorn.is_some(), exact_binary_match) {
        (false, _) => "not-applicable",
        (true, Some(true)) => "matched",
        (true, Some(false)) => "hash-mismatch",
        (true, None) => "not-captured",
    };
    let exact_sources = latest_unicorn
        .iter()
        .map(|(artifact, _)| artifact.artifact_id.clone())
        .chain(
            valid_binaries
                .iter()
                .map(|(artifact, _)| artifact.artifact_id.clone()),
        )
        .collect::<Vec<_>>();

    let stack_status = if stack_readable > 0 {
        "captured"
    } else if stack_unreadable > 0 {
        "unreadable"
    } else if missing_stack_count > 0 {
        "not-captured"
    } else {
        "not-observed"
    };
    let pointer_status = if pointer_readable > 0 {
        "captured"
    } else if pointer_unreadable > 0 {
        "unreadable"
    } else if missing_pointer_count > 0 {
        "not-captured"
    } else {
        "not-observed"
    };
    let simd_status = if !simd_names.is_empty() {
        "captured"
    } else if unsupported_simd_count > 0 {
        "not-captured"
    } else {
        "not-observed"
    };
    let system_status = if system_capture_count > 0 {
        "captured"
    } else if unsupported_system_count > 0 {
        "not-captured"
    } else {
        "not-observed"
    };

    let mut checkpoint_capture_artifact_id = None;
    let call_boundary_count = latest_unicorn
        .map(|(_, bundle)| {
            bundle
                .runs
                .iter()
                .filter(|run| run.stop_reason == "call-boundary")
                .count() as u64
        })
        .unwrap_or_default();
    if let Some((latest_artifact, latest_bundle)) = latest_unicorn {
        let allowed = unicorn_checkpoint_offsets(latest_bundle)
            .unwrap_or_default()
            .into_iter()
            .filter_map(|offset| parse_hex_addr(&offset).ok())
            .collect::<BTreeSet<_>>();
        checkpoint_capture_artifact_id = valid_frida.iter().rev().find_map(|(artifact, bundle)| {
            (artifact.imported_at_ms >= latest_artifact.imported_at_ms
                && bundle.events.iter().any(|event| {
                    event.event == "hook-enter"
                        && event.module_name.as_deref() == Some(latest_bundle.module_name.as_str())
                        && frida_event_offset(event).is_some_and(|offset| allowed.contains(&offset))
                }))
            .then(|| artifact.artifact_id.clone())
        });
    }
    let call_boundary_status = if latest_unicorn.is_none() {
        "not-executed"
    } else if call_boundary_count == 0 {
        "not-observed"
    } else if checkpoint_capture_artifact_id.is_some() {
        "captured"
    } else {
        "not-captured"
    };

    let mut components = vec![
        state_component(
            "exact-elf-identity",
            exact_status,
            u64::from(exact_binary_match == Some(true)),
            Some(1),
            exact_sources,
            match exact_status {
                "matched" => "The latest replay SHA-256 matches an imported AArch64 ELF file.",
                "hash-mismatch" => "Imported AArch64 ELF files do not match the latest replay SHA-256.",
                "not-captured" => "No exact AArch64 ELF file is imported for the latest replay.",
                _ => "No replay result currently requires an ELF identity comparison.",
            },
            (exact_status != "matched" && latest_unicorn.is_some())
                .then_some("Import the exact AArch64 ELF whose SHA-256 matches the replay result."),
        ),
        state_component(
            "general-purpose-registers",
            gpr_status,
            gpr_count,
            Some(33),
            selected_sources.clone(),
            format!("{gpr_count}/33 canonical X0-X30, SP, and PC registers are available in the selected exact seed evidence."),
            (gpr_status != "captured").then_some(
                "Recapture the exact offset with a full ARM64 GPR snapshot before relying on replay absence.",
            ),
        ),
        state_component(
            "nzcv",
            if nzcv_captured { "captured" } else { "not-captured" },
            u64::from(nzcv_captured),
            Some(1),
            selected_sources.clone(),
            if nzcv_captured {
                "NZCV is present for condition-code dependent replay."
            } else {
                "NZCV is absent; conditional branches may diverge before a flag-defining instruction executes."
            },
            (!nzcv_captured).then_some("Capture NZCV at the exact module-relative seed offset."),
        ),
        state_component(
            "simd-fp",
            simd_status,
            simd_names.len() as u64,
            Some(32),
            selected_sources.clone(),
            if unsupported_simd_count > 0 {
                format!("{unsupported_simd_count} replay run(s) stopped because uncaptured SIMD/FP state was read.")
            } else {
                "No bounded run demonstrated that uncaptured SIMD/FP state was required; this is not proof that it is irrelevant.".to_string()
            },
            (unsupported_simd_count > 0).then_some(
                "Capture the required V/Q register state at a closer exact checkpoint or model it manually.",
            ),
        ),
        state_component(
            "stack-memory",
            stack_status,
            stack_readable,
            None,
            selected_sources.clone(),
            format!("Readable stack windows: {stack_readable}; unreadable windows: {stack_unreadable}; replay SP-relative misses: {missing_stack_count}."),
            matches!(stack_status, "not-captured" | "unreadable").then_some(
                "Recapture a bounded SP-relative window at the exact seed/checkpoint offset.",
            ),
        ),
        state_component(
            "pointer-heap-memory",
            pointer_status,
            pointer_readable,
            None,
            selected_sources.clone(),
            format!("Readable pointer windows: {pointer_readable}; unreadable windows: {pointer_unreadable}; replay register-relative misses: {missing_pointer_count}."),
            matches!(pointer_status, "not-captured" | "unreadable").then_some(
                "Use the bounded recapture plan for supported X0-X28-relative missing memory.",
            ),
        ),
        state_component(
            "tls-system-state",
            system_status,
            system_capture_count,
            None,
            selected_sources.clone(),
            if unsupported_system_count > 0 {
                format!("{unsupported_system_count} replay run(s) stopped on unsupported system/TLS state.")
            } else {
                "No bounded run demonstrated a system/TLS-state dependency; unexecuted paths remain unknown.".to_string()
            },
            (unsupported_system_count > 0).then_some(
                "Capture or manually model only the specific system/TLS value read at a closer checkpoint.",
            ),
        ),
    ];
    let mut call_sources = latest_unicorn
        .iter()
        .map(|(artifact, _)| artifact.artifact_id.clone())
        .collect::<Vec<_>>();
    if let Some(artifact_id) = checkpoint_capture_artifact_id {
        call_sources.push(artifact_id);
    }
    components.push(state_component(
        "call-boundary",
        call_boundary_status,
        call_boundary_count,
        None,
        call_sources,
        match call_boundary_status {
            "captured" => "A later same-module hook-enter capture matches a checkpoint offset authorized by the prior replay.",
            "not-captured" => "Replay reached a native call boundary but no later same-module PC+4 checkpoint capture is present.",
            "not-executed" => "No bounded replay has been executed/imported for this case.",
            _ => "The imported bounded replay did not stop at a call boundary.",
        },
        (call_boundary_status == "not-captured").then_some(
            "Capture the real post-call return through the strictly authorized PC+4 checkpoint Hook.",
        ),
    ));

    let blockers = components
        .iter()
        .filter(|component| {
            matches!(
                component.status.as_str(),
                "hash-mismatch" | "partial" | "not-captured" | "unreadable"
            ) && (matches!(
                component.component.as_str(),
                "exact-elf-identity" | "general-purpose-registers" | "nzcv"
            ) || component.next_action.is_some())
        })
        .map(|component| format!("{}: {}", component.component, component.details))
        .collect::<Vec<_>>();
    let status = if exact_binary_match == Some(false) {
        "hash-mismatch"
    } else if latest_unicorn.is_none() && selected_frida.is_none() {
        "needs-capture"
    } else if blockers.is_empty() && latest_unicorn.is_some() {
        "ready"
    } else if selected_frida.is_some() || latest_unicorn.is_some() {
        "partial"
    } else {
        "needs-capture"
    };

    ReplayStateReadinessReport {
        schema: REPLAY_STATE_READINESS_SCHEMA.to_string(),
        status: status.to_string(),
        selected_frida_artifact_id: selected_frida.map(|(artifact, _)| artifact.artifact_id.clone()),
        selected_frida_event_index: selected_frida.map(|(_, event)| event.index),
        selected_unicorn_artifact_id: latest_unicorn
            .map(|(artifact, _)| artifact.artifact_id.clone()),
        exact_binary_match,
        components,
        blockers,
        limitations: vec![
            "Not-observed means the bounded imported execution did not demonstrate a dependency; it never means the state is unnecessary on unexecuted paths."
                .to_string(),
            "Unreadable and not-captured are kept distinct so the AI can recommend recapture instead of declaring absence."
                .to_string(),
            "A matching ELF file does not attest which image was loaded by the runtime process."
                .to_string(),
        ],
    }
}

fn build_experiment_matrix(
    case: &TraceAnalysisCase,
    health: &[TraceCaseArtifactHealth],
) -> TraceCaseExperimentMatrixReport {
    const MAX_ENUMERATED_CELLS: usize = 4_096;
    const MAX_REPORTED_MISSING_CELLS: usize = 128;
    const AXIS_NAMES: [&str; 4] = ["binarySha256", "keyGroup", "inputGroup", "environmentGroup"];

    let artifact_by_id = case
        .artifacts
        .iter()
        .map(|artifact| (artifact.artifact_id.as_str(), artifact))
        .collect::<BTreeMap<_, _>>();
    let health_by_id = health
        .iter()
        .map(|item| (item.artifact_id.as_str(), item.status.as_str()))
        .collect::<BTreeMap<_, _>>();
    let mut warnings = Vec::new();
    let mut axis_values = [
        BTreeSet::<String>::new(),
        BTreeSet::<String>::new(),
        BTreeSet::<String>::new(),
        BTreeSet::<String>::new(),
    ];
    let mut unspecified = [0u64; 4];
    let mut complete = Vec::<(&TraceCaseExperiment, [String; 4])>::new();

    for experiment in &case.experiments {
        let referenced_binary_hashes = experiment
            .artifact_ids
            .iter()
            .filter_map(|artifact_id| artifact_by_id.get(artifact_id.as_str()).copied())
            .filter_map(|artifact| artifact.summary.binary_sha256.clone())
            .collect::<BTreeSet<_>>();
        let inferred_binary = experiment.binary_sha256.clone().or_else(|| {
            (referenced_binary_hashes.len() == 1)
                .then(|| referenced_binary_hashes.iter().next().cloned())
                .flatten()
        });
        if let Some(explicit) = &experiment.binary_sha256 {
            if !referenced_binary_hashes.is_empty()
                && !referenced_binary_hashes
                    .iter()
                    .any(|value| value.eq_ignore_ascii_case(explicit))
            {
                warnings.push(format!(
                    "Experiment {} declares binary SHA-256 {}, but none of its result/static artifacts carries that identity.",
                    experiment.experiment_id, explicit
                ));
            }
        } else if referenced_binary_hashes.len() > 1 {
            warnings.push(format!(
                "Experiment {} references artifacts from multiple binary SHA-256 identities and cannot be placed in one controlled matrix cell.",
                experiment.experiment_id
            ));
        }
        let invalid_artifacts = experiment
            .artifact_ids
            .iter()
            .filter(|artifact_id| {
                health_by_id
                    .get(artifact_id.as_str())
                    .is_none_or(|status| *status != "valid")
            })
            .cloned()
            .collect::<Vec<_>>();
        if !invalid_artifacts.is_empty() {
            warnings.push(format!(
                "Experiment {} contains invalid/currently changed artifact(s): {}.",
                experiment.experiment_id,
                invalid_artifacts.join(", ")
            ));
        }
        if experiment
            .controlled_variables
            .iter()
            .any(|value| experiment.changed_variables.contains(value))
        {
            warnings.push(format!(
                "Experiment {} declares at least one variable as both controlled and changed.",
                experiment.experiment_id
            ));
        }

        let dimensions = [
            inferred_binary,
            experiment.key_group.clone(),
            experiment.input_group.clone(),
            experiment.environment_group.clone(),
        ];
        for (index, value) in dimensions.iter().enumerate() {
            if let Some(value) = value
                .as_ref()
                .map(|value| value.trim())
                .filter(|value| !value.is_empty())
            {
                axis_values[index].insert(if index == 0 {
                    value.to_ascii_lowercase()
                } else {
                    value.to_string()
                });
            } else {
                unspecified[index] += 1;
            }
        }
        if dimensions.iter().all(Option::is_some) {
            complete.push((
                experiment,
                [
                    dimensions[0].clone().unwrap().to_ascii_lowercase(),
                    dimensions[1].clone().unwrap(),
                    dimensions[2].clone().unwrap(),
                    dimensions[3].clone().unwrap(),
                ],
            ));
        }
    }

    let axes = AXIS_NAMES
        .iter()
        .enumerate()
        .map(|(index, axis)| TraceCaseExperimentAxis {
            axis: (*axis).to_string(),
            values: axis_values[index].iter().cloned().collect(),
            unspecified_experiment_count: unspecified[index],
        })
        .collect::<Vec<_>>();

    let mut cells =
        BTreeMap::<(String, String, String, String), (Vec<String>, BTreeSet<String>)>::new();
    for (experiment, dimensions) in &complete {
        let entry = cells
            .entry((
                dimensions[0].clone(),
                dimensions[1].clone(),
                dimensions[2].clone(),
                dimensions[3].clone(),
            ))
            .or_default();
        entry.0.push(experiment.experiment_id.clone());
        entry.1.extend(experiment.artifact_ids.iter().cloned());
    }
    let observed_cells = cells
        .iter()
        .map(
            |((binary, key, input, environment), (experiment_ids, artifact_ids))| {
                TraceCaseExperimentCell {
                    binary_sha256: binary.clone(),
                    key_group: key.clone(),
                    input_group: input.clone(),
                    environment_group: environment.clone(),
                    experiment_ids: experiment_ids.clone(),
                    artifact_ids: artifact_ids.iter().cloned().collect(),
                }
            },
        )
        .collect::<Vec<_>>();

    let possible_cell_count = axis_values.iter().try_fold(1usize, |total, values| {
        (!values.is_empty())
            .then(|| total.checked_mul(values.len()))
            .flatten()
    });
    let mut missing_cells = Vec::new();
    let mut missing_cells_truncated = false;
    if let Some(possible_cell_count) = possible_cell_count {
        if possible_cell_count <= MAX_ENUMERATED_CELLS {
            'binary: for binary in &axis_values[0] {
                for key in &axis_values[1] {
                    for input in &axis_values[2] {
                        for environment in &axis_values[3] {
                            if cells.contains_key(&(
                                binary.clone(),
                                key.clone(),
                                input.clone(),
                                environment.clone(),
                            )) {
                                continue;
                            }
                            if missing_cells.len() >= MAX_REPORTED_MISSING_CELLS {
                                missing_cells_truncated = true;
                                break 'binary;
                            }
                            missing_cells.push(TraceCaseExperimentCell {
                                binary_sha256: binary.clone(),
                                key_group: key.clone(),
                                input_group: input.clone(),
                                environment_group: environment.clone(),
                                experiment_ids: Vec::new(),
                                artifact_ids: Vec::new(),
                            });
                        }
                    }
                }
            }
        } else {
            missing_cells_truncated = true;
            warnings.push(format!(
                "The full controlled experiment Cartesian product has {possible_cell_count} cells and was not enumerated beyond the bounded {MAX_ENUMERATED_CELLS}-cell limit."
            ));
        }
    }

    let mut controlled_pairs = Vec::new();
    let mut confounded_pair_count = 0u64;
    for left_index in 0..complete.len() {
        for right_index in left_index + 1..complete.len() {
            let (left, left_dimensions) = &complete[left_index];
            let (right, right_dimensions) = &complete[right_index];
            let changed = (0..4)
                .filter(|index| left_dimensions[*index] != right_dimensions[*index])
                .collect::<Vec<_>>();
            if changed.len() == 1 {
                let changed_index = changed[0];
                controlled_pairs.push(TraceCaseControlledExperimentPair {
                    left_experiment_id: left.experiment_id.clone(),
                    right_experiment_id: right.experiment_id.clone(),
                    changed_axis: AXIS_NAMES[changed_index].to_string(),
                    fixed_axes: AXIS_NAMES
                        .iter()
                        .enumerate()
                        .filter(|(index, _)| *index != changed_index)
                        .map(|(_, axis)| (*axis).to_string())
                        .collect(),
                });
            } else if changed.len() > 1 {
                confounded_pair_count += 1;
            }
        }
    }

    let has_controlled_axis = |axis: &str| {
        controlled_pairs
            .iter()
            .any(|pair| pair.changed_axis == axis)
    };
    let baseline = complete.first().map(|(_, dimensions)| dimensions);
    let mut recommendations = Vec::new();
    if case.experiments.is_empty() {
        recommendations.push(TraceCaseExperimentRecommendation {
            priority: 100,
            action: "record-baseline-experiment".to_string(),
            reason: "No build/key/input/environment metadata exists, so cross-run differences may be confounded.".to_string(),
            suggested_binary_sha256: None,
            suggested_key_group: Some("key-baseline".to_string()),
            suggested_input_group: Some("input-baseline".to_string()),
            suggested_environment_group: Some("environment-baseline".to_string()),
        });
    }
    let incomplete_count = case.experiments.len().saturating_sub(complete.len());
    if incomplete_count > 0 {
        recommendations.push(TraceCaseExperimentRecommendation {
            priority: 95,
            action: "complete-experiment-metadata".to_string(),
            reason: format!(
                "{incomplete_count} experiment(s) are missing build, key, input, or environment identity."
            ),
            suggested_binary_sha256: None,
            suggested_key_group: None,
            suggested_input_group: None,
            suggested_environment_group: None,
        });
    }
    if !has_controlled_axis("keyGroup") {
        recommendations.push(TraceCaseExperimentRecommendation {
            priority: 85,
            action: "vary-only-key".to_string(),
            reason: "No pair holds build/input/environment fixed while changing only the key; AES key-sensitivity and white-box table claims remain weak.".to_string(),
            suggested_binary_sha256: baseline.map(|values| values[0].clone()),
            suggested_key_group: Some("key-variant".to_string()),
            suggested_input_group: baseline.map(|values| values[2].clone()),
            suggested_environment_group: baseline.map(|values| values[3].clone()),
        });
    }
    if !has_controlled_axis("inputGroup") {
        recommendations.push(TraceCaseExperimentRecommendation {
            priority: 84,
            action: "vary-only-input".to_string(),
            reason: "No pair holds build/key/environment fixed while changing only the input; input-dependent crypto and branch evidence cannot be separated from other variables.".to_string(),
            suggested_binary_sha256: baseline.map(|values| values[0].clone()),
            suggested_key_group: baseline.map(|values| values[1].clone()),
            suggested_input_group: Some("input-variant".to_string()),
            suggested_environment_group: baseline.map(|values| values[3].clone()),
        });
    }
    if axis_values[0].len() > 1 && !has_controlled_axis("binarySha256") {
        recommendations.push(TraceCaseExperimentRecommendation {
            priority: 83,
            action: "align-cross-build-controls".to_string(),
            reason: "Multiple ELF builds are present, but no pair holds key/input/environment fixed; cross-version OLLVM mapping remains structurally confounded.".to_string(),
            suggested_binary_sha256: None,
            suggested_key_group: baseline.map(|values| values[1].clone()),
            suggested_input_group: baseline.map(|values| values[2].clone()),
            suggested_environment_group: baseline.map(|values| values[3].clone()),
        });
    }
    if let Some(cell) = missing_cells.first() {
        recommendations.push(TraceCaseExperimentRecommendation {
            priority: 70,
            action: "fill-missing-matrix-cell".to_string(),
            reason: "A represented build/key/input/environment combination is missing, which can bias comparisons toward only successful or convenient runs.".to_string(),
            suggested_binary_sha256: Some(cell.binary_sha256.clone()),
            suggested_key_group: Some(cell.key_group.clone()),
            suggested_input_group: Some(cell.input_group.clone()),
            suggested_environment_group: Some(cell.environment_group.clone()),
        });
    }
    recommendations.sort_by(|left, right| right.priority.cmp(&left.priority));

    let status = if case.experiments.is_empty() {
        "no-experiments"
    } else if complete.is_empty() {
        "incomplete"
    } else if !missing_cells.is_empty() || missing_cells_truncated {
        "matrix-incomplete"
    } else if controlled_pairs.is_empty() && complete.len() > 1 {
        "confounded"
    } else if !controlled_pairs.is_empty() {
        "controlled-pairs-ready"
    } else {
        "baseline-only"
    };
    TraceCaseExperimentMatrixReport {
        schema: EXPERIMENT_MATRIX_SCHEMA.to_string(),
        status: status.to_string(),
        experiment_count: case.experiments.len() as u64,
        complete_experiment_count: complete.len() as u64,
        axes,
        observed_cells,
        missing_cells,
        missing_cells_truncated,
        controlled_pairs,
        confounded_pair_count,
        recommendations,
        warnings,
        limitations: vec![
            "The matrix validates declared controls and artifact identities; it does not execute samples or infer undeclared environment changes."
                .to_string(),
            "Crypto and OLLVM comparisons should prefer pairs that differ on exactly one declared axis."
                .to_string(),
        ],
    }
}

fn capture_target_kind(action: &str) -> &'static str {
    if action.contains("integrity") {
        "artifact-integrity"
    } else if action.contains("runtime-attestation") || action.contains("runtime-image") {
        "runtime-image"
    } else if action.contains("crypto-kat") {
        "crypto-semantic"
    } else if action.contains("coverage") {
        "coverage-reconciliation"
    } else if action.contains("elf") {
        "exact-binary"
    } else if action.contains("checkpoint") || action.contains("call-boundary") {
        "closer-checkpoint"
    } else if action.contains("recapture") || action.contains("runtime-state") {
        "register-memory-state"
    } else if action.contains("unicorn") || action.contains("angr") {
        "bounded-simulation"
    } else if action.starts_with("vary-only-")
        || action.contains("matrix")
        || action.contains("cross-build")
    {
        "controlled-run"
    } else if action.contains("claim") {
        "claim-resolution"
    } else {
        "evidence-follow-up"
    }
}

fn capture_information_gain_score(action: &str, priority: u8) -> u8 {
    match action {
        "fix-artifact-integrity" | "resolve-runtime-image-mismatch" | "select-exact-elf" => 100,
        "resolve-claim-counter-evidence" => 98,
        "resolve-coverage-exact-elf-mismatch" => 100,
        "replace-invalid-coverage-reconciliation" => 99,
        "bind-coverage-source-provenance" => 97,
        "regenerate-static-coverage-inventory" => 93,
        "capture-uncovered-coverage-sites" => 91,
        "generate-unicorn-from-checkpoint" | "generate-closer-checkpoint-hook" => 96,
        "replace-invalid-crypto-kat" => 95,
        "capture-full-runtime-attestation" | "recapture-runtime-attestation" => 94,
        "generate-frida-recapture-hook" | "capture-exact-runtime-state" => 92,
        "generate-runtime-attestation" => 90,
        "switch-stalled-seeds-to-bounded-angr" => 86,
        "generate-first-unicorn-replay" => 82,
        "vary-only-key" | "vary-only-input" | "align-cross-build-controls" => 80,
        _ => priority,
    }
}

fn controlled_variables_for_action(action: &str) -> Vec<String> {
    match action {
        "vary-only-key" => vec![
            "change:keyGroup".to_string(),
            "hold:binarySha256,inputGroup,environmentGroup".to_string(),
        ],
        "vary-only-input" => vec![
            "change:inputGroup".to_string(),
            "hold:binarySha256,keyGroup,environmentGroup".to_string(),
        ],
        "align-cross-build-controls" => vec![
            "change:binarySha256".to_string(),
            "hold:keyGroup,inputGroup,environmentGroup".to_string(),
        ],
        "fill-missing-matrix-cell" => {
            vec!["use:declared-missing-build/key/input/environment-cell".to_string()]
        }
        _ => Vec::new(),
    }
}

fn competing_hypotheses_for_action(action: &str) -> Vec<String> {
    if action.contains("runtime-attestation") || action.contains("runtime-image") {
        vec![
            "The selected exact ELF is the image mapped for the observed run.".to_string(),
            "A different, patched, repacked, or partially unreadable runtime image produced the evidence."
                .to_string(),
        ]
    } else if action.contains("crypto-kat") {
        vec![
            "The recorded algorithm and parameters reproduce the observed output exactly.".to_string(),
            "At least one algorithm, parameter, direction, input boundary, output, or tag assumption is wrong."
                .to_string(),
        ]
    } else if action.contains("coverage") {
        vec![
            "The exact-ELF static inventory and bound dynamic runs account for every listed site in the claim scope."
                .to_string(),
            "Static discovery is incomplete, a source artifact is mismatched, or one or more paths/sites remain unobserved."
                .to_string(),
        ]
    } else if action.contains("recapture") || action.contains("runtime-state") {
        vec![
            "Replay stopped or diverged because required register/memory state was missing."
                .to_string(),
            "Replay has sufficient state and the divergence reflects unsupported semantics or a wrong seed/ELF."
                .to_string(),
        ]
    } else if action.contains("checkpoint") || action.contains("call-boundary") {
        vec![
            "The real target returns through the authorized continuation with state needed for forward progress."
                .to_string(),
            "The call does not return through that continuation or later behavior depends on uncaptured state."
                .to_string(),
        ]
    } else if action.starts_with("vary-only-") || action.contains("cross-build") {
        vec![
            "The changed controlled axis causes the observed crypto/control-flow difference."
                .to_string(),
            "The difference is explained by an uncontrolled build, input, key, or environment variable."
                .to_string(),
        ]
    } else if action.contains("unicorn") || action.contains("angr") {
        vec![
            "The exact captured state continues to the candidate successor within the bounded model."
                .to_string(),
            "The continuation stalls, diverges, or remains underconstrained within the explicit bounds."
                .to_string(),
        ]
    } else {
        Vec::new()
    }
}

fn success_criteria_for_action(action: &str) -> String {
    match action {
        "fix-artifact-integrity" => {
            "Every referenced artifact again matches its imported size/SHA-256 and strict parser."
                .to_string()
        }
        "resolve-runtime-image-mismatch" | "capture-full-runtime-attestation" => {
            "The strict report is either verified-full across every file-backed executable PT_LOAD byte or retains an exact mismatched/unreadable window as counter-evidence."
                .to_string()
        }
        "generate-runtime-attestation" | "recapture-runtime-attestation" => {
            "A user-captured report binds the module basename and exact ELF plan with explicit complete/sampled coverage."
                .to_string()
        }
        "replace-invalid-crypto-kat" => {
            "The replacement report strictly parses, deterministically recomputes, and returns verified-full or an exact refutation without edited status fields."
                .to_string()
        }
        "resolve-coverage-exact-elf-mismatch" => {
            "The coverage artifact binary SHA-256/build ID matches exactly one imported AArch64 ELF parent; the prior mismatch remains counter-evidence."
                .to_string()
        }
        "bind-coverage-source-provenance" => {
            "Every dynamicRuns.sourceArtifactSha256 exactly matches a valid non-binary parent artifact; textual descriptions cannot substitute for the file hash."
                .to_string()
        }
        "regenerate-static-coverage-inventory" => {
            "The replacement artifact strictly parses without truncation/dynamic-only conflicts and recomputes its counts from canonical exact-ELF offsets."
                .to_string()
        }
        "capture-uncovered-coverage-sites" => {
            "A new controlled run observes previously uncovered exact module offsets or records explicit counter-evidence; the rebuilt coverage report preserves remaining unknown sites."
                .to_string()
        }
        "replace-invalid-coverage-reconciliation" => {
            "The replacement artifact passes strict schema, canonical-set, summary recomputation, exact-ELF range, and source-provenance checks."
                .to_string()
        }
        "select-exact-elf" => {
            "The imported AArch64 ELF SHA-256 exactly matches the replay/result identity."
                .to_string()
        }
        "generate-frida-recapture-hook" | "capture-exact-runtime-state" => {
            "The new exact-offset event contains the requested GPR/NZCV and only the bounded readable register-relative memory needed by the current stop."
                .to_string()
        }
        "generate-closer-checkpoint-hook" | "generate-unicorn-from-checkpoint" => {
            "The authorized closer capture/replay advances beyond the prior stop or returns a new explicit missing-state/terminal reason."
                .to_string()
        }
        "switch-stalled-seeds-to-bounded-angr" => {
            "Bounded symbolic continuation returns explicit candidate paths/constraints or a clear depth/state/dead-end bound without being promoted above Related."
                .to_string()
        }
        "vary-only-key" | "vary-only-input" | "align-cross-build-controls" => {
            "Two valid experiment cells differ on exactly the requested axis and preserve exact artifact identities for comparison."
                .to_string()
        }
        _ => "The requested evidence resolves at least one current blocker or produces explicit counter-evidence without repeating an equivalent unchanged capture."
            .to_string(),
    }
}

fn target_module_name(artifact_ids: &[String], artifacts: &[TraceCaseArtifact]) -> Option<String> {
    let modules = artifact_ids
        .iter()
        .filter_map(|artifact_id| {
            artifacts
                .iter()
                .find(|artifact| artifact.artifact_id == *artifact_id)
                .and_then(|artifact| artifact.summary.module_name.clone())
        })
        .collect::<BTreeSet<_>>();
    (modules.len() == 1)
        .then(|| modules.iter().next().cloned())
        .flatten()
}

fn capture_redundancy_key(
    action: &str,
    tool_name: Option<&str>,
    artifact_ids: &[String],
    offsets: &[String],
    controlled_variables: &[String],
) -> String {
    let mut hasher = Sha256::new();
    for value in std::iter::once(action)
        .chain(tool_name)
        .chain(artifact_ids.iter().map(String::as_str))
        .chain(offsets.iter().map(String::as_str))
        .chain(controlled_variables.iter().map(String::as_str))
    {
        hasher.update(value.as_bytes());
        hasher.update([0]);
    }
    let digest = format!("{:x}", hasher.finalize());
    format!("capture-{}", &digest[..24])
}

fn capture_targets_have_action(targets: &[InformationGainCaptureTarget], needle: &str) -> bool {
    targets.iter().any(|target| target.action.contains(needle))
}

fn build_information_gain_capture_plan(
    next_actions: &[ReplayDoctorNextAction],
    audit: &TraceCaseClaimLedgerAudit,
    readiness: &ReplayStateReadinessReport,
    experiment_matrix: &TraceCaseExperimentMatrixReport,
    artifacts: &[TraceCaseArtifact],
) -> InformationGainCapturePlan {
    const MAX_TARGETS: usize = 32;
    let blocked_claim_ids = audit
        .claims
        .iter()
        .filter(|claim| claim.gate_status == "blocked")
        .map(|claim| claim.claim_id.clone())
        .collect::<Vec<_>>();
    let needs_gpr = readiness.components.iter().any(|component| {
        component.component == "general-purpose-registers" && component.status != "captured"
    });
    let needs_nzcv = readiness
        .components
        .iter()
        .any(|component| component.component == "nzcv" && component.status != "captured");
    let needs_stack = readiness.components.iter().any(|component| {
        component.component == "stack-memory"
            && matches!(component.status.as_str(), "not-captured" | "unreadable")
    });
    let needs_pointer = readiness.components.iter().any(|component| {
        component.component == "pointer-heap-memory"
            && matches!(component.status.as_str(), "not-captured" | "unreadable")
    });

    let mut targets = Vec::<InformationGainCaptureTarget>::new();
    let mut seen = BTreeSet::<String>::new();
    for action in next_actions {
        let mut artifact_ids = action.artifact_ids.clone();
        artifact_ids.sort();
        artifact_ids.dedup();
        let offsets = normalize_offsets(action.seed_capture_offsets.clone());
        let controlled_variables = controlled_variables_for_action(&action.action);
        let redundancy_key = capture_redundancy_key(
            &action.action,
            action.tool_name.as_deref(),
            &artifact_ids,
            &offsets,
            &controlled_variables,
        );
        if !seen.insert(redundancy_key.clone()) {
            continue;
        }
        let is_state_capture = action.action.contains("recapture")
            || action.action.contains("runtime-state")
            || action.action.contains("checkpoint");
        let mut registers = Vec::new();
        let mut memory_requirements = Vec::new();
        if is_state_capture && needs_gpr {
            registers.push("x0-x30,sp,pc".to_string());
        }
        if is_state_capture && needs_nzcv {
            registers.push("nzcv".to_string());
        }
        if is_state_capture && needs_stack {
            memory_requirements
                .push("bounded SP-relative stack window at the exact current offset".to_string());
        }
        if is_state_capture && needs_pointer {
            memory_requirements.push(
                "only current-register X0-X28-relative missing ranges reported by the latest bounded replay"
                    .to_string(),
            );
        }
        let resolves_claim_ids = if action.action.contains("claim") {
            blocked_claim_ids.clone()
        } else {
            Vec::new()
        };
        targets.push(InformationGainCaptureTarget {
            rank: 0,
            information_gain_score: capture_information_gain_score(&action.action, action.priority),
            action: action.action.clone(),
            target_kind: capture_target_kind(&action.action).to_string(),
            tool_name: action.tool_name.clone(),
            artifact_ids: artifact_ids.clone(),
            module_name: target_module_name(&artifact_ids, artifacts),
            module_relative_offsets: offsets,
            registers,
            memory_requirements,
            controlled_variables,
            resolves_claim_ids,
            competing_hypotheses: competing_hypotheses_for_action(&action.action),
            reason: action.reason.clone(),
            success_criteria: success_criteria_for_action(&action.action),
            manual_execution_required: action.manual_execution_required,
            evidence_level: action.evidence_level.clone(),
            redundancy_key,
        });
    }

    for recommendation in experiment_matrix.recommendations.iter().take(4) {
        let controlled_variables = controlled_variables_for_action(&recommendation.action);
        let redundancy_key = capture_redundancy_key(
            &recommendation.action,
            Some("upsert_analysis_case_experiment"),
            &[],
            &[],
            &controlled_variables,
        );
        if !seen.insert(redundancy_key.clone()) {
            continue;
        }
        targets.push(InformationGainCaptureTarget {
            rank: 0,
            information_gain_score: capture_information_gain_score(
                &recommendation.action,
                recommendation.priority,
            ),
            action: recommendation.action.clone(),
            target_kind: "controlled-run".to_string(),
            tool_name: Some("upsert_analysis_case_experiment".to_string()),
            artifact_ids: Vec::new(),
            module_name: None,
            module_relative_offsets: Vec::new(),
            registers: Vec::new(),
            memory_requirements: Vec::new(),
            controlled_variables,
            resolves_claim_ids: Vec::new(),
            competing_hypotheses: competing_hypotheses_for_action(&recommendation.action),
            reason: recommendation.reason.clone(),
            success_criteria: success_criteria_for_action(&recommendation.action),
            manual_execution_required: true,
            evidence_level: "candidate/related".to_string(),
            redundancy_key,
        });
    }

    for component in &readiness.components {
        let Some(next_action) = component.next_action.as_ref() else {
            continue;
        };
        let equivalent = match component.component.as_str() {
            "exact-elf-identity" => capture_targets_have_action(&targets, "exact-elf"),
            "general-purpose-registers" | "nzcv" => {
                capture_targets_have_action(&targets, "runtime-state")
                    || capture_targets_have_action(&targets, "recapture")
            }
            "stack-memory" | "pointer-heap-memory" => {
                capture_targets_have_action(&targets, "recapture")
            }
            "call-boundary" => capture_targets_have_action(&targets, "checkpoint"),
            _ => false,
        };
        if equivalent {
            continue;
        }
        let action = format!("capture-state-{}", component.component);
        let offsets = component
            .source_artifact_ids
            .iter()
            .flat_map(|artifact_id| {
                artifacts
                    .iter()
                    .find(|artifact| artifact.artifact_id == *artifact_id)
                    .into_iter()
                    .flat_map(|artifact| artifact.summary.capture_offsets.clone())
            })
            .collect::<Vec<_>>();
        let offsets = normalize_offsets(offsets);
        let redundancy_key = capture_redundancy_key(
            &action,
            Some("generate_frida_hook"),
            &component.source_artifact_ids,
            &offsets,
            &[],
        );
        if !seen.insert(redundancy_key.clone()) {
            continue;
        }
        let (registers, memory_requirements, score) = match component.component.as_str() {
            "general-purpose-registers" => (vec!["x0-x30,sp,pc".to_string()], Vec::new(), 93),
            "nzcv" => (vec!["nzcv".to_string()], Vec::new(), 92),
            "simd-fp" => (
                vec!["required v/q registers,fpcr,fpsr".to_string()],
                Vec::new(),
                82,
            ),
            "stack-memory" => (
                Vec::new(),
                vec!["bounded SP-relative window".to_string()],
                90,
            ),
            "pointer-heap-memory" => (
                Vec::new(),
                vec!["only reported X0-X28-relative missing ranges".to_string()],
                91,
            ),
            "tls-system-state" => (
                vec!["only the reported TLS/system register".to_string()],
                Vec::new(),
                80,
            ),
            "call-boundary" => (vec!["x0-x30,sp,pc,nzcv".to_string()], Vec::new(), 95),
            "exact-elf-identity" => (Vec::new(), Vec::new(), 100),
            _ => (Vec::new(), Vec::new(), 75),
        };
        targets.push(InformationGainCaptureTarget {
            rank: 0,
            information_gain_score: score,
            action,
            target_kind: if component.component == "exact-elf-identity" {
                "exact-binary".to_string()
            } else {
                "register-memory-state".to_string()
            },
            tool_name: (component.component != "exact-elf-identity")
                .then(|| "generate_frida_hook".to_string()),
            artifact_ids: component.source_artifact_ids.clone(),
            module_name: target_module_name(&component.source_artifact_ids, artifacts),
            module_relative_offsets: offsets,
            registers,
            memory_requirements,
            controlled_variables: Vec::new(),
            resolves_claim_ids: Vec::new(),
            competing_hypotheses: vec![
                format!("{} is required for faithful continuation.", component.component),
                format!("{} is not load-bearing for the tested bounded path.", component.component),
            ],
            reason: format!("{} {next_action}", component.details),
            success_criteria: "The closer exact capture supplies the requested state or records an explicit unreadable/unsupported result without filling bytes with zeros."
                .to_string(),
            manual_execution_required: component.component != "exact-elf-identity",
            evidence_level: "candidate/related".to_string(),
            redundancy_key,
        });
    }

    targets.sort_by(|left, right| {
        right
            .information_gain_score
            .cmp(&left.information_gain_score)
            .then_with(|| left.action.cmp(&right.action))
            .then_with(|| left.redundancy_key.cmp(&right.redundancy_key))
    });
    let omitted_target_count = targets.len().saturating_sub(MAX_TARGETS) as u64;
    targets.truncate(MAX_TARGETS);
    for (index, target) in targets.iter_mut().enumerate() {
        target.rank = index as u32 + 1;
    }
    let status = if targets.is_empty() {
        "no-additional-targets"
    } else if targets[0].information_gain_score >= 95 {
        "critical-evidence-gap"
    } else {
        "ranked-targets-ready"
    };
    InformationGainCapturePlan {
        schema: INFORMATION_GAIN_CAPTURE_PLAN_SCHEMA.to_string(),
        status: status.to_string(),
        target_count: targets.len() as u64,
        omitted_target_count,
        targets,
        limitations: vec![
            "Information-gain scores are deterministic heuristic rankings over current blockers, state gaps, and controlled-run coverage; they are not probabilities or proof."
                .to_string(),
            "A target should be repeated only when its exact offset, requested state, controlled variable, or expected discriminator changes; unchanged captures are deliberately deduplicated."
                .to_string(),
            "Trace UI only plans/generates bounded capture or simulation handoffs. The user manually runs the target, Frida, IDA, angr, and Unicorn."
                .to_string(),
        ],
    }
}

pub fn diagnose_trace_analysis_case(case_path: &str) -> Result<ReplayDoctorReport> {
    let document = load_trace_analysis_case(case_path)?;
    let mut health = Vec::with_capacity(document.case.artifacts.len());
    let mut timeline = Vec::with_capacity(document.case.artifacts.len());
    let mut warnings = Vec::new();
    let mut valid_unicorn = Vec::<(TraceCaseArtifact, UnicornOllvmResultBundle)>::new();
    let mut valid_frida = Vec::<(TraceCaseArtifact, FridaCaptureBundle)>::new();
    let mut valid_runtime_attestations =
        Vec::<(TraceCaseArtifact, RuntimeAttestationCaptureBundle)>::new();
    let mut valid_crypto_kats = Vec::<(TraceCaseArtifact, CryptoSemanticKatReport)>::new();
    let mut valid_coverage = Vec::<(TraceCaseArtifact, CoverageReconciliationBundle)>::new();
    let mut valid_angr = Vec::<(TraceCaseArtifact, AngrOllvmResultBundle)>::new();
    let mut valid_binaries = Vec::<(TraceCaseArtifact, ElfBinaryIdentity)>::new();
    let mut generated_claims = Vec::new();

    for artifact in &document.case.artifacts {
        let resolved = resolve_trace_case_artifact_path(case_path, &artifact.path)?;
        let mut item = TraceCaseArtifactHealth {
            artifact_id: artifact.artifact_id.clone(),
            kind: artifact.kind,
            label: artifact.label.clone(),
            resolved_path: resolved.to_string_lossy().into_owned(),
            status: "valid".to_string(),
            size_matches: false,
            sha256_matches: false,
            parser_valid: false,
            error: None,
        };
        let inspection = (|| -> Result<ArtifactInspection> {
            let (sha256, size, _) = hash_file(&resolved)?;
            item.size_matches = size == artifact.file_size;
            item.sha256_matches = sha256.eq_ignore_ascii_case(&artifact.sha256);
            if !item.size_matches || !item.sha256_matches {
                return Err(TraceError::InvalidArgument(
                    "artifact size or SHA-256 changed after import".to_string(),
                ));
            }
            let inspection = inspect_with_kind(&resolved, artifact.kind)?;
            item.parser_valid = true;
            Ok(inspection)
        })();
        match inspection {
            Ok(inspection) => {
                timeline.push(ReplayDoctorTimelineEntry {
                    artifact_id: artifact.artifact_id.clone(),
                    imported_at_ms: artifact.imported_at_ms,
                    stage: artifact.kind.as_str().to_string(),
                    status: "valid".to_string(),
                    summary: timeline_summary(artifact),
                });
                match inspection.parsed {
                    ParsedCaseArtifact::StaticBinary(identity) => {
                        valid_binaries.push((artifact.clone(), identity));
                    }
                    ParsedCaseArtifact::RuntimeAttestation(bundle) => {
                        valid_runtime_attestations.push((artifact.clone(), bundle));
                    }
                    ParsedCaseArtifact::Frida(bundle) => {
                        valid_frida.push((artifact.clone(), bundle));
                    }
                    ParsedCaseArtifact::Unicorn(bundle) => {
                        valid_unicorn.push((artifact.clone(), bundle));
                    }
                    ParsedCaseArtifact::Angr(bundle) => {
                        valid_angr.push((artifact.clone(), bundle));
                    }
                    ParsedCaseArtifact::Ida(bundle) => {
                        let _ = bundle.annotations.len();
                    }
                    ParsedCaseArtifact::Ollvm(report) => {
                        let _ = report.block_count;
                    }
                    ParsedCaseArtifact::Coverage(bundle) => {
                        valid_coverage.push((artifact.clone(), bundle));
                    }
                    ParsedCaseArtifact::Analysis(record) => {
                        let _ = record.analysis_id;
                    }
                    ParsedCaseArtifact::CryptoKat(report) => {
                        valid_crypto_kats.push((artifact.clone(), report));
                    }
                    ParsedCaseArtifact::Crypto(value) => {
                        let _ = value.is_object();
                    }
                    ParsedCaseArtifact::Other(value) => {
                        let _ = value.as_ref().map(Value::is_object);
                    }
                    ParsedCaseArtifact::Trace => {}
                }
            }
            Err(error) => {
                item.status = if !resolved.exists() {
                    "missing".to_string()
                } else if !item.size_matches || !item.sha256_matches {
                    "integrity-mismatch".to_string()
                } else {
                    "invalid".to_string()
                };
                item.error = Some(error.to_string());
                warnings.push(format!("{}: {error}", artifact.label));
                timeline.push(ReplayDoctorTimelineEntry {
                    artifact_id: artifact.artifact_id.clone(),
                    imported_at_ms: artifact.imported_at_ms,
                    stage: artifact.kind.as_str().to_string(),
                    status: item.status.clone(),
                    summary: error.to_string(),
                });
            }
        }
        health.push(item);
    }
    timeline.sort_by_key(|entry| entry.imported_at_ms);
    valid_unicorn.sort_by_key(|(artifact, _)| artifact.imported_at_ms);
    valid_frida.sort_by_key(|(artifact, _)| artifact.imported_at_ms);
    valid_runtime_attestations.sort_by_key(|(artifact, _)| artifact.imported_at_ms);
    valid_crypto_kats.sort_by_key(|(artifact, _)| artifact.imported_at_ms);
    valid_coverage.sort_by_key(|(artifact, _)| artifact.imported_at_ms);
    valid_angr.sort_by_key(|(artifact, _)| artifact.imported_at_ms);
    valid_binaries.sort_by_key(|(artifact, _)| artifact.imported_at_ms);

    let mut next_actions = Vec::new();
    let mut runtime_attestations = Vec::<TraceCaseRuntimeAttestationReport>::new();
    let mut crypto_kats = Vec::<TraceCaseCryptoKatReport>::new();
    let mut coverage_reconciliations = Vec::<TraceCaseCoverageReport>::new();
    let broken_ids = health
        .iter()
        .filter(|item| item.status != "valid")
        .map(|item| item.artifact_id.clone())
        .collect::<Vec<_>>();
    if !broken_ids.is_empty() {
        next_actions.push(next_action(
            100,
            "fix-artifact-integrity",
            None,
            broken_ids,
            Vec::new(),
            "At least one case artifact is missing, changed, or no longer passes its strict parser.",
            "Restore the exact imported file or remove and re-import the correct artifact before using later replay conclusions.",
            false,
        ));
    }

    for (attestation_artifact, bundle) in &valid_runtime_attestations {
        let exact_binary_parent_id = attestation_artifact
            .parent_artifact_ids
            .iter()
            .find(|parent_id| {
                document.case.artifacts.iter().any(|candidate| {
                    candidate.artifact_id == **parent_id
                        && candidate.kind == TraceCaseArtifactKind::StaticBinary
                })
            })
            .cloned();
        let Some(exact_binary_parent_id) = exact_binary_parent_id else {
            warnings.push(format!(
                "{} has no bound exact static-binary parent.",
                attestation_artifact.label
            ));
            continue;
        };
        let Some((binary_artifact, binary_identity)) = valid_binaries
            .iter()
            .find(|(artifact, _)| artifact.artifact_id == exact_binary_parent_id)
        else {
            warnings.push(format!(
                "{} cannot be verified until its exact ELF parent passes integrity and parser checks.",
                attestation_artifact.label
            ));
            continue;
        };
        let capture_path = resolve_trace_case_artifact_path(case_path, &attestation_artifact.path)?;
        let binary_path = resolve_trace_case_artifact_path(case_path, &binary_artifact.path)?;
        match verify_runtime_attestation_bundle(
            bundle,
            &capture_path.to_string_lossy(),
            &binary_path.to_string_lossy(),
        ) {
            Ok(report) => {
                let module_name = report
                    .records
                    .first()
                    .map(|record| record.module_name.as_str())
                    .or_else(|| attestation_artifact.summary.module_name.as_deref())
                    .unwrap_or("unknown-module");
                let scope = format!(
                    "runtime-image:{}@{}",
                    module_name, binary_identity.binary_sha256
                );
                match report.status.as_str() {
                    "verified-full" if report.verification_gate_met => {
                        generated_claims.push(generated_claim(
                            format!(
                                "The user-captured mapped runtime image for {module_name} matches the bound exact ELF across all file-backed executable PT_LOAD bytes."
                            ),
                            scope,
                            TraceCaseClaimStatus::Verified,
                            vec![
                                evidence_ref(
                                    attestation_artifact,
                                    "runtime-attestation/verified-full",
                                    "Strict verification recomputed all planned runtime windows against the bound exact ELF.",
                                ),
                                evidence_ref(
                                    binary_artifact,
                                    "sha256",
                                    binary_identity.binary_sha256.clone(),
                                ),
                            ],
                            Vec::new(),
                            Vec::new(),
                            report.limitations.clone(),
                        ));
                    }
                    "related-sampled" => {
                        generated_claims.push(generated_claim(
                            format!(
                                "Sampled user-captured executable windows for {module_name} match the bound exact ELF."
                            ),
                            scope,
                            TraceCaseClaimStatus::Related,
                            vec![
                                evidence_ref(
                                    attestation_artifact,
                                    "runtime-attestation/related-sampled",
                                    "Strict verification matched the sampled executable windows.",
                                ),
                                evidence_ref(
                                    binary_artifact,
                                    "sha256",
                                    binary_identity.binary_sha256.clone(),
                                ),
                            ],
                            Vec::new(),
                            vec![
                                "Full coverage of every file-backed executable PT_LOAD byte"
                                    .to_string(),
                            ],
                            report.limitations.clone(),
                        ));
                        next_actions.push(next_action(
                            96,
                            "capture-full-runtime-attestation",
                            Some("generate_frida_runtime_attestation"),
                            vec![
                                binary_artifact.artifact_id.clone(),
                                attestation_artifact.artifact_id.clone(),
                            ],
                            Vec::new(),
                            "The current runtime-image evidence is deterministic but sampled, so it cannot pass the scoped Verified gate.",
                            "Generate a full-coverage runtime attestation for the same module basename and exact ELF, run the Frida 16.x script manually in the intended process, then import the new capture with this exact ELF as its parent.",
                            true,
                        ));
                    }
                    "refuted" => {
                        generated_claims.push(generated_claim(
                            format!(
                                "The user-captured mapped runtime image for {module_name} matches the bound exact ELF."
                            ),
                            scope,
                            TraceCaseClaimStatus::Refuted,
                            vec![evidence_ref(
                                binary_artifact,
                                "sha256",
                                "The selected exact ELF defines the bytes used for comparison.",
                            )],
                            vec![evidence_ref(
                                attestation_artifact,
                                "runtime-attestation/refuted",
                                report
                                    .records
                                    .iter()
                                    .flat_map(|record| record.counter_evidence.iter())
                                    .next()
                                    .cloned()
                                    .unwrap_or_else(|| {
                                        "The runtime attestation conflicts with the bound exact ELF."
                                            .to_string()
                                    }),
                            )],
                            Vec::new(),
                            report.limitations.clone(),
                        ));
                        next_actions.push(next_action(
                            99,
                            "resolve-runtime-image-mismatch",
                            Some("inspect_runtime_attestation"),
                            vec![
                                binary_artifact.artifact_id.clone(),
                                attestation_artifact.artifact_id.clone(),
                            ],
                            Vec::new(),
                            "The user-captured runtime bytes, plan, or expected identity conflict with the bound exact ELF.",
                            "Inspect the mismatched windows and module path. Select the actually loaded module build if different, or generate and run a new manual attestation capture under the controlled target run. Preserve this artifact as counter-evidence.",
                            true,
                        ));
                    }
                    _ => {
                        next_actions.push(next_action(
                            95,
                            "recapture-runtime-attestation",
                            Some("generate_frida_runtime_attestation"),
                            vec![
                                binary_artifact.artifact_id.clone(),
                                attestation_artifact.artifact_id.clone(),
                            ],
                            Vec::new(),
                            "The runtime attestation is incomplete or contains mixed record statuses.",
                            "Review unreadable or missing windows, generate the bounded Frida 16.x attestation script again for the same exact ELF, run it manually, and import the complete capture.",
                            true,
                        ));
                    }
                }
                runtime_attestations.push(TraceCaseRuntimeAttestationReport {
                    artifact_id: attestation_artifact.artifact_id.clone(),
                    exact_binary_artifact_id: binary_artifact.artifact_id.clone(),
                    report,
                });
            }
            Err(error) => warnings.push(format!(
                "Runtime attestation verification failed for {}: {error}",
                attestation_artifact.label
            )),
        }
    }

    if valid_runtime_attestations.is_empty() {
        if let Some((binary_artifact, binary_identity)) = valid_binaries
            .iter()
            .find(|(artifact, _)| {
                document.case.exact_binary_artifact_id.as_deref()
                    == Some(artifact.artifact_id.as_str())
            })
            .or_else(|| valid_binaries.last())
        {
            next_actions.push(next_action(
                94,
                "generate-runtime-attestation",
                Some("generate_frida_runtime_attestation"),
                vec![binary_artifact.artifact_id.clone()],
                Vec::new(),
                "The case has an exact AArch64 ELF but no user-captured evidence that this image was mapped in the target process.",
                format!(
                    "Generate a Frida 16.x runtime-attestation script for the module basename and exact ELF SHA-256 {}, run it manually in the intended process, then import the JSON/NDJSON capture with this ELF as its parent.",
                    binary_identity.binary_sha256
                ),
                true,
            ));
        }
    }

    for (artifact, report) in &valid_crypto_kats {
        let vector_description = format!(
            "{} deterministic vector ({} output bytes{}).",
            report.algorithm.as_str(),
            report.bytes_checked,
            if report.tag_bytes_checked > 0 {
                format!(" + {} tag bytes", report.tag_bytes_checked)
            } else {
                String::new()
            }
        );
        match report.status {
            CryptoKatStatus::VerifiedFull if report.verification_gate_met => {
                generated_claims.push(generated_claim(
                    format!(
                        "The observed output matches the exact recorded {} parameters and input byte-for-byte.",
                        report.algorithm.as_str()
                    ),
                    report.claim_scope.clone(),
                    TraceCaseClaimStatus::Verified,
                    vec![evidence_ref(
                        artifact,
                        "crypto-kat/verified-full",
                        format!(
                            "{vector_description} The embedded request was strictly recomputed during artifact import and Replay Doctor validation."
                        ),
                    )],
                    Vec::new(),
                    Vec::new(),
                    report.limitations.clone(),
                ));
            }
            CryptoKatStatus::Refuted => {
                generated_claims.push(generated_claim(
                    format!(
                        "The observed output matches the exact recorded {} parameters and input byte-for-byte.",
                        report.algorithm.as_str()
                    ),
                    report.claim_scope.clone(),
                    TraceCaseClaimStatus::Refuted,
                    Vec::new(),
                    vec![evidence_ref(
                        artifact,
                        "crypto-kat/refuted",
                        report.refutation_reason.clone().unwrap_or_else(|| {
                            format!(
                                "{vector_description} First mismatch: {:?}.",
                                report.first_mismatch
                            )
                        }),
                    )],
                    Vec::new(),
                    report.limitations.clone(),
                ));
            }
            _ => {
                next_actions.push(next_action(
                    92,
                    "replace-invalid-crypto-kat",
                    Some("verify_crypto_semantic_kat"),
                    vec![artifact.artifact_id.clone()],
                    Vec::new(),
                    report
                        .invalid_reason
                        .clone()
                        .unwrap_or_else(|| "The crypto KAT did not pass its strict gate.".to_string()),
                    "Correct the explicit algorithm parameters or captured bytes, generate a new deterministic KAT report, and import it while preserving this failed attempt as evidence.",
                    false,
                ));
            }
        }
        crypto_kats.push(TraceCaseCryptoKatReport {
            artifact_id: artifact.artifact_id.clone(),
            report: report.clone(),
        });
    }

    for (coverage_artifact, bundle) in &valid_coverage {
        let exact_binary_parent_id = coverage_artifact
            .parent_artifact_ids
            .iter()
            .find(|parent_id| {
                document.case.artifacts.iter().any(|candidate| {
                    candidate.artifact_id == **parent_id
                        && candidate.kind == TraceCaseArtifactKind::StaticBinary
                })
            })
            .cloned();
        let Some(exact_binary_parent_id) = exact_binary_parent_id else {
            warnings.push(format!(
                "{} has no bound exact static-binary parent.",
                coverage_artifact.label
            ));
            continue;
        };
        let Some((binary_artifact, _)) = valid_binaries
            .iter()
            .find(|(artifact, _)| artifact.artifact_id == exact_binary_parent_id)
        else {
            warnings.push(format!(
                "{} cannot be reconciled until its exact ELF parent passes integrity and parser checks.",
                coverage_artifact.label
            ));
            continue;
        };
        let source_artifacts = coverage_artifact
            .parent_artifact_ids
            .iter()
            .filter_map(|parent_id| {
                document.case.artifacts.iter().find(|candidate| {
                    candidate.artifact_id == *parent_id
                        && candidate.kind != TraceCaseArtifactKind::StaticBinary
                        && health.iter().any(|item| {
                            item.artifact_id == candidate.artifact_id && item.status == "valid"
                        })
                })
            })
            .collect::<Vec<_>>();
        let source_sha256s = source_artifacts
            .iter()
            .map(|artifact| artifact.sha256.clone())
            .collect::<Vec<_>>();
        let binary_path = resolve_trace_case_artifact_path(case_path, &binary_artifact.path)?;
        match inspect_coverage_reconciliation_bundle(
            bundle,
            &binary_path.to_string_lossy(),
            &source_sha256s,
        ) {
            Ok(report) => {
                let uncovered = &report.summary.uncovered_counts;
                let dynamic_only = &report.summary.dynamic_only_counts;
                let coverage_description = format!(
                    "observed/static instructions={}/{}, blocks={}/{}, branches={}/{}, functions={}/{}, edges={}/{}",
                    report.summary.observed_static_counts.instructions,
                    report.summary.static_counts.instructions,
                    report.summary.observed_static_counts.blocks,
                    report.summary.static_counts.blocks,
                    report.summary.observed_static_counts.branches,
                    report.summary.static_counts.branches,
                    report.summary.observed_static_counts.functions,
                    report.summary.static_counts.functions,
                    report.summary.observed_static_counts.edges,
                    report.summary.static_counts.edges,
                );
                if report.coverage_gate_met {
                    generated_claims.push(generated_claim(
                        format!(
                            "All explicitly inventoried static sites for the bounded scope were observed across the bound dynamic run set ({coverage_description})."
                        ),
                        report.claim_scope.clone(),
                        TraceCaseClaimStatus::Observed,
                        vec![
                            evidence_ref(
                                coverage_artifact,
                                "coverage-reconciliation/complete-site-coverage",
                                "Trace UI recomputed the explicit static/dynamic sets, exact-ELF identity, and source-parent provenance.",
                            ),
                            evidence_ref(
                                binary_artifact,
                                "sha256",
                                report.exact_binary_identity.binary_sha256.clone(),
                            ),
                        ],
                        Vec::new(),
                        Vec::new(),
                        report.limitations.clone(),
                    ));
                } else {
                    generated_claims.push(generated_claim(
                        format!(
                            "Coverage reconciliation for the bounded scope is incomplete ({coverage_description}); unobserved or inconsistent sites remain unknown."
                        ),
                        report.claim_scope.clone(),
                        TraceCaseClaimStatus::Observed,
                        vec![evidence_ref(
                            coverage_artifact,
                            format!("coverage-reconciliation/{}", report.status),
                            format!(
                                "uncovered instructions={}, blocks={}, branches={}, functions={}, edges={}; dynamic-only instructions={}, blocks={}, branches={}, functions={}, edges={}",
                                uncovered.instructions,
                                uncovered.blocks,
                                uncovered.branches,
                                uncovered.functions,
                                uncovered.edges,
                                dynamic_only.instructions,
                                dynamic_only.blocks,
                                dynamic_only.branches,
                                dynamic_only.functions,
                                dynamic_only.edges,
                            ),
                        )],
                        Vec::new(),
                        Vec::new(),
                        report.limitations.clone(),
                    ));
                    let mut uncovered_offsets = report.uncovered_samples.blocks.clone();
                    uncovered_offsets.extend(report.uncovered_samples.branches.clone());
                    uncovered_offsets.extend(report.uncovered_samples.instructions.clone());
                    uncovered_offsets = normalize_offsets(uncovered_offsets);
                    uncovered_offsets.truncate(64);
                    if !report.identity_matched {
                        next_actions.push(next_action(
                            100,
                            "resolve-coverage-exact-elf-mismatch",
                            Some("inspect_coverage_reconciliation"),
                            vec![
                                coverage_artifact.artifact_id.clone(),
                                binary_artifact.artifact_id.clone(),
                            ],
                            Vec::new(),
                            "The coverage artifact is bound to a different exact ELF identity.",
                            "Select the exact AArch64 ELF used by the static inventory, regenerate the coverage exporter for that build, and preserve this mismatch as counter-evidence.",
                            false,
                        ));
                    } else if !report.source_provenance_matched {
                        next_actions.push(next_action(
                            97,
                            "bind-coverage-source-provenance",
                            Some("ingest_analysis_case_artifact"),
                            vec![coverage_artifact.artifact_id.clone()],
                            Vec::new(),
                            "One or more dynamic run SHA-256 values are not present among the coverage artifact's valid parent artifacts.",
                            "Import the exact OLLVM/trace source files and re-import the coverage report with those artifact IDs plus exactly one static-binary parent; do not substitute a textual locator.",
                            false,
                        ));
                    } else if !report.summary.static_inventory_complete {
                        next_actions.push(next_action(
                            93,
                            "regenerate-static-coverage-inventory",
                            Some("generate_coverage_reconciliation_script"),
                            vec![
                                coverage_artifact.artifact_id.clone(),
                                binary_artifact.artifact_id.clone(),
                            ],
                            uncovered_offsets,
                            "The static inventory is incomplete/truncated or contains dynamic-only sites, so it cannot bound a completeness claim.",
                            "Generate a new exact-ELF coverage reconciliation script for a narrower module/function/range scope, run angr manually, and import the resulting JSON with exact parents.",
                            true,
                        ));
                    } else {
                        next_actions.push(next_action(
                            91,
                            "capture-uncovered-coverage-sites",
                            Some("generate_frida_hook"),
                            vec![coverage_artifact.artifact_id.clone()],
                            uncovered_offsets,
                            "The static inventory is usable, but one or more listed sites were not observed across the bound dynamic runs.",
                            "Prioritize uncovered block/branch offsets in a controlled run, generate bounded exact-offset hooks where appropriate, run them manually, then regenerate the coverage reconciliation with the new dynamic source artifact.",
                            true,
                        ));
                    }
                }
                coverage_reconciliations.push(TraceCaseCoverageReport {
                    artifact_id: coverage_artifact.artifact_id.clone(),
                    exact_binary_artifact_id: binary_artifact.artifact_id.clone(),
                    source_artifact_ids: source_artifacts
                        .iter()
                        .map(|artifact| artifact.artifact_id.clone())
                        .collect(),
                    report,
                });
            }
            Err(error) => {
                warnings.push(format!(
                    "Coverage reconciliation failed for {}: {error}",
                    coverage_artifact.label
                ));
                next_actions.push(next_action(
                    99,
                    "replace-invalid-coverage-reconciliation",
                    Some("inspect_coverage_reconciliation"),
                    vec![coverage_artifact.artifact_id.clone()],
                    Vec::new(),
                    error.to_string(),
                    "Regenerate the coverage artifact from the exact ELF and source OLLVM report. Do not edit counts or percentages manually; Trace UI recomputes them from canonical offset sets.",
                    false,
                ));
            }
        }
    }

    let latest_unicorn = valid_unicorn.last();
    let mut round_comparison = None;
    if let Some((latest_artifact, latest_bundle)) = latest_unicorn {
        let matching_rounds = valid_unicorn
            .iter()
            .filter(|(_, bundle)| {
                bundle.module_name == latest_bundle.module_name
                    && bundle
                        .binary_sha256
                        .eq_ignore_ascii_case(&latest_bundle.binary_sha256)
            })
            .rev()
            .take(16)
            .collect::<Vec<_>>()
            .into_iter()
            .rev()
            .collect::<Vec<_>>();
        if matching_rounds.len() >= 2 {
            let inputs = matching_rounds
                .iter()
                .map(|(artifact, bundle)| UnicornOllvmRoundInput {
                    round_id: artifact.artifact_id.as_str(),
                    source_label: Some(artifact.label.as_str()),
                    bundle,
                })
                .collect::<Vec<_>>();
            match compare_unicorn_ollvm_rounds(&inputs) {
                Ok(comparison) => {
                    generated_claims.push(generated_claim(
                        format!(
                            "Compared {} bounded Unicorn replay rounds for {} with exact ELF SHA-256 {}.",
                            comparison.round_count, comparison.module_name, comparison.binary_sha256
                        ),
                        format!("{}@{}", comparison.module_name, comparison.binary_sha256),
                        TraceCaseClaimStatus::Observed,
                        matching_rounds
                            .iter()
                            .map(|(artifact, _)| {
                                evidence_ref(
                                    artifact,
                                    "unicorn-result",
                                    "Strictly parsed bounded concrete replay result",
                                )
                            })
                            .collect(),
                        Vec::new(),
                        Vec::new(),
                        comparison.limitations.clone(),
                    ));
                    if comparison.progressed_seed_count > 0 {
                        generated_claims.push(generated_claim(
                            "At least one exact seed gained bounded recorded coverage across replay rounds."
                                .to_string(),
                            format!("{}@{}", comparison.module_name, comparison.binary_sha256),
                            TraceCaseClaimStatus::Related,
                            vec![evidence_ref(
                                latest_artifact,
                                "unicorn-round-comparison",
                                format!(
                                    "{} progressed seed(s); status {}",
                                    comparison.progressed_seed_count, comparison.overall_status
                                ),
                            )],
                            Vec::new(),
                            vec![
                                "Independent runtime or semantic verification of the reached behavior"
                                    .to_string(),
                            ],
                            comparison.limitations.clone(),
                        ));
                    }
                    if comparison.stalled_seed_count > 0 || comparison.regressed_seed_count > 0 {
                        generated_claims.push(generated_claim(
                            "At least one exact seed stopped gaining monotonic bounded replay coverage."
                                .to_string(),
                            format!("{}@{}", comparison.module_name, comparison.binary_sha256),
                            TraceCaseClaimStatus::Observed,
                            vec![evidence_ref(
                                latest_artifact,
                                "unicorn-round-comparison",
                                format!(
                                    "{} stalled and {} regressed seed(s)",
                                    comparison.stalled_seed_count, comparison.regressed_seed_count
                                ),
                            )],
                            Vec::new(),
                            Vec::new(),
                            comparison.limitations.clone(),
                        ));
                    }
                    round_comparison = Some(comparison);
                }
                Err(error) => warnings.push(format!("Unicorn round comparison failed: {error}")),
            }
        }

        let matching_binary = valid_binaries.iter().find(|(_, identity)| {
            identity
                .binary_sha256
                .eq_ignore_ascii_case(&latest_bundle.binary_sha256)
        });
        if let Some((binary_artifact, _)) = matching_binary {
            generated_claims.push(generated_claim(
                format!(
                    "The imported exact ELF file matches the latest Unicorn result SHA-256 for {}.",
                    latest_bundle.module_name
                ),
                format!(
                    "{}@{}",
                    latest_bundle.module_name, latest_bundle.binary_sha256
                ),
                TraceCaseClaimStatus::Observed,
                vec![
                    evidence_ref(
                        latest_artifact,
                        "binarySha256",
                        latest_bundle.binary_sha256.clone(),
                    ),
                    evidence_ref(
                        binary_artifact,
                        "sha256",
                        latest_bundle.binary_sha256.clone(),
                    ),
                ],
                Vec::new(),
                Vec::new(),
                vec![
                    "Matching files do not attest which image was loaded in the runtime process."
                        .to_string(),
                ],
            ));
        } else {
            next_actions.push(next_action(
                90,
                "select-exact-elf",
                None,
                vec![latest_artifact.artifact_id.clone()],
                Vec::new(),
                "The latest replay result has no matching imported exact ELF file in this case.",
                format!(
                    "Import the AArch64 ELF whose SHA-256 is {} before generating another replay or angr bridge.",
                    latest_bundle.binary_sha256
                ),
                false,
            ));
        }

        let authorized_offsets = unicorn_checkpoint_offsets(latest_bundle).unwrap_or_default();
        let later_checkpoint_capture = valid_frida.iter().rev().find(|(artifact, bundle)| {
            artifact.imported_at_ms >= latest_artifact.imported_at_ms
                && bundle.events.iter().any(|event| {
                    if event.event != "hook-enter"
                        || event.module_name.as_deref() != Some(latest_bundle.module_name.as_str())
                    {
                        return false;
                    }
                    frida_event_offset(event).is_some_and(|offset| {
                        authorized_offsets
                            .iter()
                            .any(|allowed| parse_hex_addr(allowed).ok() == Some(offset))
                    })
                })
        });
        if let Some((capture_artifact, _)) = later_checkpoint_capture {
            next_actions.push(next_action(
                98,
                "generate-unicorn-from-checkpoint",
                Some("generate_unicorn_ollvm_script"),
                vec![
                    latest_artifact.artifact_id.clone(),
                    capture_artifact.artifact_id.clone(),
                ],
                authorized_offsets.iter().cloned().collect(),
                "A later Frida hook-enter capture matches a checkpoint offset strictly authorized by the latest Unicorn result.",
                "Generate the next Unicorn script with this capture and checkpoint_result_path bound to the same prior result, then run the Python manually.",
                true,
            ));
        } else {
            let comparison_by_offset = round_comparison.as_ref().map(|comparison| {
                comparison
                    .seeds
                    .iter()
                    .map(|seed| {
                        (
                            seed.capture_offset.to_ascii_lowercase(),
                            seed.latest_status.clone(),
                        )
                    })
                    .collect::<BTreeMap<_, _>>()
            });
            let mut recapture_offsets = Vec::new();
            let mut checkpoint_offsets = Vec::new();
            let mut angr_offsets = Vec::new();
            for run in &latest_bundle.runs {
                let status = comparison_by_offset
                    .as_ref()
                    .and_then(|statuses| statuses.get(&run.start_offset.to_ascii_lowercase()));
                let stalled = status.is_some_and(|status| {
                    status.contains("stalled") || status.contains("regressed")
                });
                match run.stop_reason.as_str() {
                    "missing-memory" if !stalled => {
                        let has_supported =
                            latest_bundle.recapture_suggestions.iter().any(|item| {
                                item.source_event_indices.contains(&run.source_event_index)
                                    && item.base_register.as_deref().is_some_and(|register| {
                                        register.eq_ignore_ascii_case("sp")
                                            || register
                                                .strip_prefix('x')
                                                .and_then(|value| value.parse::<u8>().ok())
                                                .is_some_and(|index| index <= 28)
                                    })
                            });
                        if has_supported {
                            recapture_offsets.push(run.start_offset.clone());
                        } else {
                            checkpoint_offsets.push(run.start_offset.clone());
                        }
                    }
                    "call-boundary" => checkpoint_offsets.push(run.start_offset.clone()),
                    "missing-memory" | "missing-register" | "loop-detected"
                    | "instruction-limit" | "timeout" => {
                        checkpoint_offsets.push(run.start_offset.clone());
                        if stalled {
                            angr_offsets.push(run.start_offset.clone());
                        }
                    }
                    _ => {}
                }
            }
            if !recapture_offsets.is_empty() {
                next_actions.push(next_action(
                    85,
                    "generate-frida-recapture-hook",
                    Some("generate_frida_unicorn_recapture_hook"),
                    vec![latest_artifact.artifact_id.clone()],
                    recapture_offsets,
                    "The latest replay stopped on supported X0-X28/SP-relative missing memory and has not yet shown a repeated stall.",
                    "Generate the bounded recapture Hook, run it manually under the same build and controlled input, then import its hook-enter capture as a new seed.",
                    true,
                ));
            }
            if !checkpoint_offsets.is_empty() {
                next_actions.push(next_action(
                    84,
                    "generate-closer-checkpoint-hook",
                    Some("generate_frida_unicorn_checkpoint_hook"),
                    vec![latest_artifact.artifact_id.clone()],
                    checkpoint_offsets,
                    "The latest replay reached a call boundary or a stop that is better captured at the actual missing/terminal PC.",
                    "Generate the strictly authorized closer checkpoint Hook and run it manually. For call-boundary runs it must fire only after the real call returns through PC+4.",
                    true,
                ));
            }
            if !angr_offsets.is_empty() {
                next_actions.push(next_action(
                    75,
                    "switch-stalled-seeds-to-bounded-angr",
                    Some("generate_angr_ollvm_script"),
                    vec![latest_artifact.artifact_id.clone()],
                    angr_offsets,
                    "At least one exact seed is stalled or regressed across replay rounds.",
                    "After capturing a strictly authorized closer checkpoint, generate bounded angr flow with small depth/state caps instead of repeating the unchanged concrete replay.",
                    true,
                ));
            }
        }
    } else if let Some((capture_artifact, bundle)) = valid_frida.last() {
        next_actions.push(next_action(
            80,
            "generate-first-unicorn-replay",
            Some("generate_unicorn_ollvm_script"),
            vec![capture_artifact.artifact_id.clone()],
            frida_capture_offsets(bundle),
            "The case contains a valid user-captured Frida state but no Unicorn replay result.",
            "Select the exact AArch64 ELF and matching OLLVM scope, generate the bounded Unicorn Python, and run it manually.",
            true,
        ));
    } else {
        next_actions.push(next_action(
            70,
            "capture-exact-runtime-state",
            Some("generate_frida_hook"),
            document.case.artifacts.iter().map(|item| item.artifact_id.clone()).collect(),
            Vec::new(),
            "The case does not yet contain a valid exact-offset Frida capture or Unicorn replay result.",
            "Analyze a narrow function/OLLVM scope, generate a bounded exact-offset Frida 16.x Hook, run it manually, and import the resulting JSON/NDJSON capture.",
            true,
        ));
    }

    if let Some((angr_artifact, angr)) = valid_angr.last() {
        let dispatcher_hits = angr
            .checkpoint_probes
            .iter()
            .filter_map(|probe| probe.flow_exploration.as_ref())
            .flat_map(|flow| flow.paths.iter())
            .filter(|path| path.status == "dispatcher-hit")
            .count();
        generated_claims.push(generated_claim(
            format!(
                "The latest bounded angr result contains {} checkpoint probe(s) and {} dispatcher-hit path(s).",
                angr.checkpoint_probes.len(), dispatcher_hits
            ),
            format!("{}@{}", angr.module_name, angr.binary_sha256),
            TraceCaseClaimStatus::Related,
            vec![evidence_ref(
                angr_artifact,
                "checkpointProbes",
                format!("{} bounded checkpoint probes", angr.checkpoint_probes.len()),
            )],
            Vec::new(),
            vec!["Independent runtime reachability evidence".to_string()],
            vec![
                "Bounded symbolic paths do not prove real-entry reachability or complete control flow."
                    .to_string(),
            ],
        ));
    }

    let state_readiness = build_state_readiness(&valid_frida, &valid_unicorn, &valid_binaries);
    let experiment_matrix = build_experiment_matrix(&document.case, &health);
    if let Some(recommendation) = experiment_matrix.recommendations.first() {
        next_actions.push(next_action(
            recommendation.priority.min(60),
            &recommendation.action,
            Some("upsert_analysis_case_experiment"),
            Vec::new(),
            Vec::new(),
            recommendation.reason.clone(),
            "Record the build SHA-256, key group, input group, environment group, and produced artifact IDs. Execute any new target/Frida run manually, then import its artifacts into the case.",
            true,
        ));
    }
    let claim_ledger_audit = build_claim_ledger_audit(
        &document.case.claims,
        &generated_claims,
        &document.case.artifacts,
        &health,
        &runtime_attestations,
        &crypto_kats,
        &coverage_reconciliations,
    );
    let persisted_claim_blockers = claim_ledger_audit
        .claims
        .iter()
        .filter(|claim| claim.source == "persisted" && claim.gate_status == "blocked")
        .map(|claim| claim.claim_id.clone())
        .collect::<Vec<_>>();
    if !persisted_claim_blockers.is_empty() || !claim_ledger_audit.contradictions.is_empty() {
        next_actions.push(next_action(
            88,
            "resolve-claim-counter-evidence",
            Some("audit_analysis_case_claims"),
            Vec::new(),
            Vec::new(),
            format!(
                "{} persisted claim(s) fail the evidence gate and {} contradiction group(s) remain.",
                persisted_claim_blockers.len(),
                claim_ledger_audit.contradictions.len()
            ),
            "Inspect invalid/counter evidence, recapture missing evidence where authorized, and keep the claim Unknown/Observed/Related until the deterministic gate passes.",
            false,
        ));
    }

    next_actions.sort_by(|left, right| right.priority.cmp(&left.priority));
    next_actions.dedup_by(|left, right| {
        left.action == right.action && left.seed_capture_offsets == right.seed_capture_offsets
    });
    let capture_plan = build_information_gain_capture_plan(
        &next_actions,
        &claim_ledger_audit,
        &state_readiness,
        &experiment_matrix,
        &document.case.artifacts,
    );
    let status = if health.iter().any(|item| item.status != "valid") {
        "invalid-artifacts"
    } else if next_actions
        .first()
        .is_some_and(|action| action.action == "generate-unicorn-from-checkpoint")
    {
        "checkpoint-ready"
    } else if round_comparison.as_ref().is_some_and(|comparison| {
        comparison.stalled_seed_count > 0 || comparison.regressed_seed_count > 0
    }) {
        "replay-stalled"
    } else if round_comparison
        .as_ref()
        .is_some_and(|comparison| comparison.progressed_seed_count > 0)
    {
        "candidate-progress"
    } else if latest_unicorn.is_some() {
        "replay-result-ready"
    } else if !valid_frida.is_empty() {
        "seed-ready"
    } else {
        "needs-runtime-capture"
    };

    Ok(ReplayDoctorReport {
        schema: REPLAY_DOCTOR_SCHEMA.to_string(),
        case_id: document.case.case_id,
        case_path: case_path.to_string(),
        generated_at_ms: now_ms(),
        status: status.to_string(),
        artifact_health: health,
        timeline,
        generated_claims,
        next_actions,
        claim_ledger_audit,
        state_readiness,
        experiment_matrix,
        capture_plan,
        runtime_attestations,
        crypto_kats,
        coverage_reconciliations,
        unicorn_round_comparison: round_comparison,
        warnings,
        limitations: vec![
            "An exact ELF SHA-256 alone does not attest the runtime image. A verified-full runtime attestation can verify only the user-captured mapped metadata windows and all file-backed executable PT_LOAD bytes, and is not hardware-backed or remote attestation."
                .to_string(),
            "Dynamic traces contain executed behavior only. Unobserved paths and states remain unknown."
                .to_string(),
            "Frida, Unicorn, angr, and IDA execution remains under explicit user control."
                .to_string(),
            "OLLVM, Unicorn, and angr findings remain Candidate/Related unless independently verified."
                .to_string(),
        ],
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_path(name: &str) -> PathBuf {
        std::env::temp_dir().join(format!("trace-ui-case-{}-{name}", uuid::Uuid::new_v4()))
    }

    fn minimal_elf(machine: u16) -> Vec<u8> {
        let mut elf = vec![0u8; 64];
        elf[..4].copy_from_slice(b"\x7fELF");
        elf[4] = 2;
        elf[5] = 1;
        elf[6] = 1;
        elf[16..18].copy_from_slice(&3u16.to_le_bytes());
        elf[18..20].copy_from_slice(&machine.to_le_bytes());
        elf[20..24].copy_from_slice(&1u32.to_le_bytes());
        elf[52..54].copy_from_slice(&64u16.to_le_bytes());
        elf[54..56].copy_from_slice(&56u16.to_le_bytes());
        elf
    }

    fn write_u32(bytes: &mut [u8], offset: usize, value: u32) {
        bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
    }

    fn write_u64(bytes: &mut [u8], offset: usize, value: u64) {
        bytes[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
    }

    fn runtime_attestable_elf() -> Vec<u8> {
        let mut elf = vec![0u8; 8192];
        elf[..4].copy_from_slice(b"\x7fELF");
        elf[4] = 2;
        elf[5] = 1;
        elf[6] = 1;
        elf[16..18].copy_from_slice(&3u16.to_le_bytes());
        elf[18..20].copy_from_slice(&183u16.to_le_bytes());
        elf[20..24].copy_from_slice(&1u32.to_le_bytes());
        write_u64(&mut elf, 32, 64);
        elf[52..54].copy_from_slice(&64u16.to_le_bytes());
        elf[54..56].copy_from_slice(&56u16.to_le_bytes());
        elf[56..58].copy_from_slice(&1u16.to_le_bytes());
        write_u32(&mut elf, 64, 1);
        write_u32(&mut elf, 68, 5);
        write_u64(&mut elf, 72, 0);
        write_u64(&mut elf, 80, 0);
        let elf_len = elf.len() as u64;
        write_u64(&mut elf, 96, elf_len);
        write_u64(&mut elf, 104, elf_len);
        write_u64(&mut elf, 112, 0x1000);
        for (index, byte) in elf[0x1000..].iter_mut().enumerate() {
            *byte = (index % 251) as u8;
        }
        elf
    }

    fn matching_runtime_attestation_record(
        plan: &crate::query::runtime_attestation::RuntimeAttestationPlan,
    ) -> crate::query::runtime_attestation::RuntimeAttestationRecord {
        use crate::query::runtime_attestation::{
            RuntimeAttestationRecord, RuntimeAttestationWindowCapture,
        };

        RuntimeAttestationRecord {
            protocol: crate::query::runtime_attestation::FRIDA_RUNTIME_ATTESTATION_SCHEMA
                .to_string(),
            event: "runtime-attestation".to_string(),
            attestation_id: plan.attestation_id.clone(),
            timestamp_ms: 1,
            module_name: plan.module_name.clone(),
            module_path: Some("/data/app/libtarget.so".to_string()),
            module_base: Some("0x71000000".to_string()),
            module_size: plan.expected_mapped_size,
            expected_binary_sha256: plan.expected_identity.binary_sha256.clone(),
            expected_file_size: plan.expected_identity.file_size,
            expected_architecture: plan.expected_identity.architecture.clone(),
            expected_elf_machine: plan.expected_identity.elf_machine,
            expected_build_id: plan.expected_identity.build_id.clone(),
            load_base_vaddr: plan.load_base_vaddr.clone(),
            expected_mapped_size: plan.expected_mapped_size,
            window_bytes: plan.window_bytes,
            max_windows: plan.max_windows,
            coverage_strategy: plan.coverage_strategy.clone(),
            complete_executable_coverage: plan.complete_executable_coverage,
            total_executable_bytes: plan.total_executable_bytes,
            selected_executable_bytes: plan.selected_executable_bytes,
            plan_sha256: plan.plan_sha256.clone(),
            fatal_error: None,
            windows: plan
                .windows
                .iter()
                .map(|window| RuntimeAttestationWindowCapture {
                    index: window.index,
                    kind: window.kind,
                    segment_index: window.segment_index,
                    file_offset: window.file_offset.clone(),
                    module_offset: window.module_offset.clone(),
                    length: window.length,
                    expected_sha256: window.expected_sha256.clone(),
                    actual_sha256: Some(window.expected_sha256.clone()),
                    status: "matched".to_string(),
                    address: Some("0x71000000".to_string()),
                    protection: Some("r-x".to_string()),
                    read_error: None,
                })
                .collect(),
            warnings: Vec::new(),
        }
    }

    fn create_case_with_exact_elf(name: &str) -> (PathBuf, PathBuf, PathBuf, ElfBinaryIdentity) {
        let dir = temp_path(name);
        std::fs::create_dir_all(&dir).unwrap();
        let case_path = dir.join("sample.traceui-case");
        let elf_path = dir.join("libtarget.so");
        std::fs::write(&elf_path, minimal_elf(183)).unwrap();
        let identity = inspect_elf_binary(elf_path.to_str().unwrap()).unwrap();
        create_trace_analysis_case(
            case_path.to_str().unwrap(),
            "sample",
            None,
            Some(elf_path.to_str().unwrap()),
        )
        .unwrap();
        (dir, case_path, elf_path, identity)
    }

    fn coverage_bundle(
        identity: &ElfBinaryIdentity,
        source_sha256: &str,
        claim_scope: &str,
        complete: bool,
    ) -> CoverageReconciliationBundle {
        use crate::query::coverage::{
            recompute_coverage_reconciliation_summary, CoverageDynamicRun, CoverageEdge,
            CoverageFunctionRange, CoverageReconciliationSummary, CoverageScope,
            CoverageStaticInventory,
        };

        let mut bundle = CoverageReconciliationBundle {
            schema: COVERAGE_RECONCILIATION_SCHEMA.to_string(),
            module_name: "libtarget.so".to_string(),
            architecture: "AArch64".to_string(),
            binary_sha256: identity.binary_sha256.clone(),
            build_id: identity.build_id.clone(),
            claim_scope: claim_scope.to_string(),
            scope: CoverageScope {
                kind: "function-closure".to_string(),
                start_offset: "0x1000".to_string(),
                end_offset: "0x100c".to_string(),
                function_offsets: vec!["0x1000".to_string()],
            },
            static_inventory: CoverageStaticInventory {
                source_kind: "angr-cfgfast".to_string(),
                source_version: Some("test".to_string()),
                complete_for_scope: true,
                instructions_truncated: false,
                blocks_truncated: false,
                branches_truncated: false,
                functions_truncated: false,
                edges_truncated: false,
                instruction_offsets: vec![
                    "0x1000".to_string(),
                    "0x1004".to_string(),
                    "0x1008".to_string(),
                    "0x100c".to_string(),
                ],
                block_offsets: vec!["0x1000".to_string(), "0x1008".to_string()],
                branch_offsets: vec!["0x1004".to_string()],
                functions: vec![CoverageFunctionRange {
                    start_offset: "0x1000".to_string(),
                    end_offset: "0x100c".to_string(),
                    name: Some("target".to_string()),
                }],
                edges: vec![CoverageEdge {
                    source_offset: "0x1000".to_string(),
                    target_offset: "0x1008".to_string(),
                }],
            },
            dynamic_runs: vec![CoverageDynamicRun {
                run_id: "run-a".to_string(),
                source_artifact_sha256: source_sha256.to_string(),
                capture_complete_for_scope: true,
                instruction_offsets: if complete {
                    vec![
                        "0x1000".to_string(),
                        "0x1004".to_string(),
                        "0x1008".to_string(),
                        "0x100c".to_string(),
                    ]
                } else {
                    vec!["0x1000".to_string(), "0x1004".to_string()]
                },
                block_offsets: if complete {
                    vec!["0x1000".to_string(), "0x1008".to_string()]
                } else {
                    vec!["0x1000".to_string()]
                },
                branch_offsets: vec!["0x1004".to_string()],
                function_offsets: vec!["0x1000".to_string()],
                edges: if complete {
                    vec![CoverageEdge {
                        source_offset: "0x1000".to_string(),
                        target_offset: "0x1008".to_string(),
                    }]
                } else {
                    Vec::new()
                },
            }],
            summary: CoverageReconciliationSummary {
                static_counts: CoverageCounts::default(),
                observed_static_counts: CoverageCounts::default(),
                uncovered_counts: CoverageCounts::default(),
                dynamic_only_counts: CoverageCounts::default(),
                coverage_basis_points: CoverageBasisPoints::default(),
                static_inventory_complete: false,
                dynamic_capture_complete: false,
                coverage_complete: false,
            },
            limitations: Vec::new(),
        };
        bundle.summary = recompute_coverage_reconciliation_summary(&bundle);
        bundle
    }

    fn test_unicorn_bundle(
        identity: &ElfBinaryIdentity,
        stop_reason: &str,
        round_label: &str,
    ) -> UnicornOllvmResultBundle {
        let call_boundary =
            (stop_reason == "call-boundary").then(|| crate::query::unicorn::UnicornCallBoundary {
                pc_offset: "0x180".to_string(),
                mnemonic: "bl 0x40000300".to_string(),
                target_address: Some("0x40000300".to_string()),
                target_offset: Some("0x300".to_string()),
                return_address: Some("0x40000184".to_string()),
                return_offset: Some("0x184".to_string()),
            });
        let missing_memory = (stop_reason == "missing-memory").then(|| {
            crate::query::unicorn::UnicornMissingMemory {
                access: "read".to_string(),
                address: "0x60000020".to_string(),
                size: 16,
                pc_offset: Some("0x180".to_string()),
                instruction: Some("ldr q0, [x19, #0x20]".to_string()),
                base_register: Some("x19".to_string()),
                displacement: Some("0x20".to_string()),
            }
        });
        let registers_seeded = (0..=30)
            .map(|index| format!("x{index}"))
            .chain(["sp".to_string(), "pc".to_string(), "nzcv".to_string()])
            .collect::<Vec<_>>();
        UnicornOllvmResultBundle {
            schema: "trace-ui/unicorn-ollvm-v1".to_string(),
            module_name: "libtarget.so".to_string(),
            binary_sha256: identity.binary_sha256.clone(),
            expected_binary_sha256: identity.binary_sha256.clone(),
            binary_identity_matched: true,
            architecture: "AArch64".to_string(),
            unicorn_version: "2.1.4".to_string(),
            capstone_version: "5.0.6".to_string(),
            config: crate::query::unicorn::UnicornOllvmConfig::default(),
            seeds: vec![crate::query::angr::AngrOllvmFridaSeedProvenance {
                source_event_index: 7,
                hook_id: "seed-100".to_string(),
                call_id: Some("call-7".to_string()),
                module_name: "libtarget.so".to_string(),
                function_name: "dispatcher".to_string(),
                capture_offset: "0x100".to_string(),
                registers_seeded,
                memory_region_count: 1,
                matched_probe_offsets: vec!["0x100".to_string()],
                matched_branch_offsets: Vec::new(),
                matched_dispatcher_offsets: vec!["0x100".to_string()],
            }],
            seed_qualities: vec![crate::query::unicorn::UnicornSeedQuality {
                source_event_index: 7,
                capture_offset: "0x100".to_string(),
                status: "ready".to_string(),
                register_count: 34,
                missing_registers: Vec::new(),
                memory_region_count: 1,
                captured_memory_bytes: 256,
                stack_memory_captured: true,
                warnings: Vec::new(),
            }],
            seed_recapture_plans: Vec::new(),
            runs: vec![crate::query::unicorn::UnicornReplayRun {
                source_event_index: 7,
                seed_kind: "frida-capture-exact-dispatcher".to_string(),
                start_offset: "0x100".to_string(),
                mapped_base: "0x40000000".to_string(),
                stop_reason: stop_reason.to_string(),
                instruction_count: 8,
                elapsed_ms: 1,
                terminal_address: "0x40000180".to_string(),
                terminal_offset: Some("0x180".to_string()),
                matched_dispatcher_offset: None,
                source_state_values: Vec::new(),
                target_state_values: Vec::new(),
                executed_offsets: vec![
                    "0x100".to_string(),
                    "0x140".to_string(),
                    "0x180".to_string(),
                ],
                executed_offsets_truncated: false,
                block_offsets: vec![
                    "0x100".to_string(),
                    "0x140".to_string(),
                    "0x180".to_string(),
                ],
                block_offsets_truncated: false,
                register_changes: Vec::new(),
                memory_writes: Vec::new(),
                memory_writes_truncated: false,
                call_boundaries: call_boundary.into_iter().collect(),
                missing_memory: missing_memory.into_iter().collect(),
                warnings: vec![round_label.to_string()],
                error: None,
            }],
            transition_matrix: Vec::new(),
            recapture_suggestions: (stop_reason == "missing-memory")
                .then(|| crate::query::unicorn::UnicornRecaptureSuggestion {
                    pc_offset: "0x180".to_string(),
                    base_register: Some("x19".to_string()),
                    displacement: Some("0x20".to_string()),
                    byte_length: 16,
                    reason: "capture supported X19-relative window".to_string(),
                    source_event_indices: vec![7],
                })
                .into_iter()
                .collect(),
            warnings: vec![round_label.to_string()],
        }
    }

    fn import_unicorn_result(
        case_path: &Path,
        dir: &Path,
        file_name: &str,
        bundle: &UnicornOllvmResultBundle,
    ) -> TraceCaseArtifactImportResult {
        let path = dir.join(file_name);
        std::fs::write(&path, serde_json::to_vec_pretty(bundle).unwrap()).unwrap();
        add_trace_case_artifact(
            case_path.to_str().unwrap(),
            path.to_str().unwrap(),
            Some("unicorn-result"),
            None,
            Vec::new(),
        )
        .unwrap()
    }

    #[test]
    fn creates_case_with_relative_primary_trace_and_strict_schema() {
        let dir = temp_path("create");
        std::fs::create_dir_all(&dir).unwrap();
        let trace = dir.join("sample.log");
        let case_path = dir.join("sample.traceui-case");
        std::fs::write(&trace, b"0x1000: nop\n").unwrap();

        let document = create_trace_analysis_case(
            case_path.to_str().unwrap(),
            "sample",
            Some(trace.to_str().unwrap()),
            None,
        )
        .unwrap();

        assert_eq!(document.case.schema, TRACE_ANALYSIS_CASE_SCHEMA);
        assert_eq!(document.case.artifacts.len(), 1);
        assert_eq!(
            document.case.artifacts[0].kind,
            TraceCaseArtifactKind::Trace
        );
        assert_eq!(document.case.artifacts[0].path, "sample.log");
        let loaded = load_trace_analysis_case(case_path.to_str().unwrap()).unwrap();
        assert_eq!(loaded.case.case_id, document.case.case_id);
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn rejects_unknown_case_fields() {
        let dir = temp_path("strict");
        std::fs::create_dir_all(&dir).unwrap();
        let case_path = dir.join("bad.traceui-case");
        std::fs::write(
            &case_path,
            format!(
                r#"{{"schema":"{}","caseId":"id","title":"x","createdAtMs":1,"updatedAtMs":1,"artifacts":[],"claims":[],"experiments":[],"notes":[],"unexpected":true}}"#,
                TRACE_ANALYSIS_CASE_SCHEMA
            ),
        )
        .unwrap();
        let error = load_trace_analysis_case(case_path.to_str().unwrap()).unwrap_err();
        assert!(error.to_string().contains("unknown field"));
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn deduplicates_identical_artifacts_and_detects_integrity_change() {
        let dir = temp_path("dedupe");
        std::fs::create_dir_all(&dir).unwrap();
        let trace = dir.join("sample.log");
        let case_path = dir.join("sample.traceui-case");
        std::fs::write(&trace, b"one\n").unwrap();
        create_trace_analysis_case(case_path.to_str().unwrap(), "sample", None, None).unwrap();
        let first = add_trace_case_artifact(
            case_path.to_str().unwrap(),
            trace.to_str().unwrap(),
            Some("trace"),
            None,
            Vec::new(),
        )
        .unwrap();
        let second = add_trace_case_artifact(
            case_path.to_str().unwrap(),
            trace.to_str().unwrap(),
            Some("trace"),
            None,
            Vec::new(),
        )
        .unwrap();
        assert!(!first.already_present);
        assert!(second.already_present);
        assert_eq!(second.case.artifacts.len(), 1);

        std::fs::write(&trace, b"changed\n").unwrap();
        let report = diagnose_trace_analysis_case(case_path.to_str().unwrap()).unwrap();
        assert_eq!(report.status, "invalid-artifacts");
        assert_eq!(report.artifact_health[0].status, "integrity-mismatch");
        assert_eq!(report.next_actions[0].action, "fix-artifact-integrity");
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn empty_case_requests_manual_runtime_capture() {
        let dir = temp_path("doctor");
        std::fs::create_dir_all(&dir).unwrap();
        let case_path = dir.join("sample.traceui-case");
        create_trace_analysis_case(case_path.to_str().unwrap(), "sample", None, None).unwrap();
        let report = diagnose_trace_analysis_case(case_path.to_str().unwrap()).unwrap();
        assert_eq!(report.status, "needs-runtime-capture");
        assert_eq!(report.next_actions[0].action, "capture-exact-runtime-state");
        assert!(report.next_actions[0].manual_execution_required);
        assert_eq!(
            report.capture_plan.schema,
            INFORMATION_GAIN_CAPTURE_PLAN_SCHEMA
        );
        assert_eq!(
            report.capture_plan.targets[0].action,
            "capture-exact-runtime-state"
        );
        assert!(report.capture_plan.targets[0]
            .registers
            .iter()
            .any(|value| value.contains("x0-x30")));
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn rejects_non_aarch64_static_binary_artifacts() {
        let dir = temp_path("wrong-architecture");
        std::fs::create_dir_all(&dir).unwrap();
        let case_path = dir.join("sample.traceui-case");
        let elf_path = dir.join("libx86.so");
        std::fs::write(&elf_path, minimal_elf(62)).unwrap();
        create_trace_analysis_case(case_path.to_str().unwrap(), "sample", None, None).unwrap();
        let error = add_trace_case_artifact(
            case_path.to_str().unwrap(),
            elf_path.to_str().unwrap(),
            Some("static-binary"),
            None,
            Vec::new(),
        )
        .unwrap_err();
        assert!(error.to_string().contains("only AArch64"));
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn missing_memory_recommends_bounded_recapture() {
        let (dir, case_path, _, identity) = create_case_with_exact_elf("missing-memory");
        let bundle = test_unicorn_bundle(&identity, "missing-memory", "round-one");
        import_unicorn_result(&case_path, &dir, "round-one.json", &bundle);

        let report = diagnose_trace_analysis_case(case_path.to_str().unwrap()).unwrap();
        let action = report
            .next_actions
            .iter()
            .find(|action| action.action == "generate-frida-recapture-hook")
            .expect("supported missing memory should request bounded recapture");
        assert_eq!(action.seed_capture_offsets, vec!["0x100"]);
        assert!(action.manual_execution_required);
        let pointer = report
            .state_readiness
            .components
            .iter()
            .find(|component| component.component == "pointer-heap-memory")
            .unwrap();
        assert_eq!(pointer.status, "not-captured");
        let target = report
            .capture_plan
            .targets
            .iter()
            .find(|target| target.action == "generate-frida-recapture-hook")
            .unwrap();
        assert_eq!(target.module_relative_offsets, vec!["0x100"]);
        assert!(target
            .memory_requirements
            .iter()
            .any(|value| value.contains("X0-X28")));
        assert!(
            report
                .capture_plan
                .targets
                .iter()
                .map(|target| target.redundancy_key.as_str())
                .collect::<BTreeSet<_>>()
                .len()
                == report.capture_plan.targets.len()
        );
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn repeated_missing_memory_stall_switches_to_checkpoint_and_bounded_angr() {
        let (dir, case_path, _, identity) = create_case_with_exact_elf("stalled-rounds");
        let first = test_unicorn_bundle(&identity, "missing-memory", "round-one");
        let second = test_unicorn_bundle(&identity, "missing-memory", "round-two");
        import_unicorn_result(&case_path, &dir, "round-one.json", &first);
        import_unicorn_result(&case_path, &dir, "round-two.json", &second);

        let report = diagnose_trace_analysis_case(case_path.to_str().unwrap()).unwrap();
        assert_eq!(report.status, "replay-stalled");
        assert!(report.next_actions.iter().any(|action| {
            action.action == "generate-closer-checkpoint-hook"
                && action.seed_capture_offsets == vec!["0x100".to_string()]
        }));
        assert!(report.next_actions.iter().any(|action| {
            action.action == "switch-stalled-seeds-to-bounded-angr"
                && action.seed_capture_offsets == vec!["0x100".to_string()]
        }));
        assert!(!report
            .next_actions
            .iter()
            .any(|action| action.action == "generate-frida-recapture-hook"));
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn call_boundary_requires_pc_plus_four_then_accepts_same_module_capture() {
        let (dir, case_path, _, identity) = create_case_with_exact_elf("call-boundary");
        let bundle = test_unicorn_bundle(&identity, "call-boundary", "round-one");
        import_unicorn_result(&case_path, &dir, "call-boundary.json", &bundle);

        let before = diagnose_trace_analysis_case(case_path.to_str().unwrap()).unwrap();
        let checkpoint = before
            .next_actions
            .iter()
            .find(|action| action.action == "generate-closer-checkpoint-hook")
            .unwrap();
        assert!(checkpoint.instructions.contains("PC+4"));

        let capture_path = dir.join("post-call.ndjson");
        let capture = serde_json::json!({
            "protocol": "trace-ui/frida-hook-v1",
            "eventId": "post-call-one",
            "hookId": "unicorn-checkpoint-184",
            "event": "hook-enter",
            "functionName": "checkpoint-184",
            "timestampMs": 2,
            "threadId": 1,
            "moduleName": "libtarget.so",
            "moduleBase": "0x71000000",
            "moduleSize": 4096,
            "target": "0x71000184",
            "registers": {"x0":"0x1","sp":"0x72000000","pc":"0x71000184","nzcv":"0x0"}
        });
        std::fs::write(&capture_path, serde_json::to_vec(&capture).unwrap()).unwrap();
        add_trace_case_artifact(
            case_path.to_str().unwrap(),
            capture_path.to_str().unwrap(),
            Some("frida-capture"),
            None,
            Vec::new(),
        )
        .unwrap();

        let after = diagnose_trace_analysis_case(case_path.to_str().unwrap()).unwrap();
        assert!(after
            .next_actions
            .iter()
            .any(|action| action.action == "generate-unicorn-from-checkpoint"));
        let boundary = after
            .state_readiness
            .components
            .iter()
            .find(|component| component.component == "call-boundary")
            .unwrap();
        assert_eq!(boundary.status, "captured");
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn mismatched_imported_elf_is_reported_separately_from_missing_capture() {
        let (dir, case_path, elf_path, _) = create_case_with_exact_elf("hash-mismatch");
        let mut foreign_elf = minimal_elf(183);
        foreign_elf.push(1);
        let foreign_identity =
            crate::query::elf_identity::inspect_elf_bytes("foreign.so", &foreign_elf).unwrap();
        let bundle = test_unicorn_bundle(&foreign_identity, "missing-memory", "foreign-round");
        import_unicorn_result(&case_path, &dir, "foreign.json", &bundle);

        let report = diagnose_trace_analysis_case(case_path.to_str().unwrap()).unwrap();
        assert_eq!(report.state_readiness.status, "hash-mismatch");
        assert_eq!(report.state_readiness.exact_binary_match, Some(false));
        assert!(report
            .next_actions
            .iter()
            .any(|action| action.action == "select-exact-elf"));
        assert!(elf_path.exists());
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn runtime_attestation_auto_binds_exact_elf_and_opens_only_scoped_gate() {
        use crate::query::runtime_attestation::{
            build_runtime_attestation_plan, FridaRuntimeAttestationRequest,
        };

        let dir = temp_path("runtime-attestation-case");
        std::fs::create_dir_all(&dir).unwrap();
        let case_path = dir.join("sample.traceui-case");
        let elf_path = dir.join("libtarget.so");
        let capture_path = dir.join("runtime-attestation.json");
        std::fs::write(&elf_path, runtime_attestable_elf()).unwrap();
        let document = create_trace_analysis_case(
            case_path.to_str().unwrap(),
            "runtime attestation",
            None,
            Some(elf_path.to_str().unwrap()),
        )
        .unwrap();
        let exact_artifact_id = document.case.exact_binary_artifact_id.unwrap();
        let plan = build_runtime_attestation_plan(&FridaRuntimeAttestationRequest {
            module_name: "libtarget.so".to_string(),
            static_binary_path: elf_path.to_string_lossy().into_owned(),
            window_bytes: 4096,
            max_windows: 8,
        })
        .unwrap();
        assert!(plan.complete_executable_coverage);
        let record = matching_runtime_attestation_record(&plan);
        std::fs::write(&capture_path, serde_json::to_vec_pretty(&record).unwrap()).unwrap();

        let imported = add_trace_case_artifact(
            case_path.to_str().unwrap(),
            capture_path.to_str().unwrap(),
            None,
            Some("Runtime image attestation"),
            Vec::new(),
        )
        .unwrap();
        assert_eq!(
            imported.artifact.kind,
            TraceCaseArtifactKind::RuntimeAttestation
        );
        assert_eq!(
            imported.artifact.parent_artifact_ids,
            vec![exact_artifact_id.clone()]
        );
        assert_eq!(
            imported
                .artifact
                .summary
                .runtime_attestation_status
                .as_deref(),
            Some("verified-full")
        );
        assert_eq!(
            imported
                .artifact
                .summary
                .runtime_attestation_verification_gate_met,
            Some(true)
        );

        let report = diagnose_trace_analysis_case(case_path.to_str().unwrap()).unwrap();
        assert_eq!(report.runtime_attestations.len(), 1);
        assert!(report.runtime_attestations[0].report.verification_gate_met);
        let generated = report
            .generated_claims
            .iter()
            .find(|claim| claim.scope.starts_with("runtime-image:"))
            .unwrap();
        assert_eq!(generated.status, TraceCaseClaimStatus::Verified);
        let audit = report
            .claim_ledger_audit
            .claims
            .iter()
            .find(|claim| claim.claim_id == generated.claim_id)
            .unwrap();
        assert!(audit.verification_gate_passed);

        let forged = TraceCaseClaim {
            claim_id: "forged-runtime-marker".to_string(),
            statement: "The runtime image matches.".to_string(),
            scope: format!(
                "runtime-image:libtarget.so@{}",
                plan.expected_identity.binary_sha256
            ),
            status: TraceCaseClaimStatus::Verified,
            coverage_requirement: TraceCaseCoverageRequirement::Auto,
            supporting_evidence: vec![TraceCaseEvidenceRef {
                artifact_id: exact_artifact_id,
                locator: "runtime-attestation/verified-full semantic-known-answer".to_string(),
                description: "A description alone claims the gate passed.".to_string(),
            }],
            counter_evidence: Vec::new(),
            missing_evidence: Vec::new(),
            limitations: Vec::new(),
            created_by: "test".to_string(),
            created_at_ms: 1,
            updated_at_ms: 1,
        };
        upsert_trace_case_claim(case_path.to_str().unwrap(), forged).unwrap();
        let blocked = diagnose_trace_analysis_case(case_path.to_str().unwrap()).unwrap();
        let forged_audit = blocked
            .claim_ledger_audit
            .claims
            .iter()
            .find(|claim| claim.claim_id == "forged-runtime-marker")
            .unwrap();
        assert_eq!(forged_audit.gate_status, "blocked");
        assert!(!forged_audit.verification_gate_passed);
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn runtime_attestation_mismatch_is_imported_as_counter_evidence() {
        use crate::query::runtime_attestation::{
            build_runtime_attestation_plan, FridaRuntimeAttestationRequest,
            RuntimeAttestationWindowKind,
        };

        let dir = temp_path("runtime-attestation-refuted");
        std::fs::create_dir_all(&dir).unwrap();
        let case_path = dir.join("sample.traceui-case");
        let elf_path = dir.join("libtarget.so");
        let capture_path = dir.join("runtime-attestation.json");
        std::fs::write(&elf_path, runtime_attestable_elf()).unwrap();
        create_trace_analysis_case(
            case_path.to_str().unwrap(),
            "runtime attestation mismatch",
            None,
            Some(elf_path.to_str().unwrap()),
        )
        .unwrap();
        let plan = build_runtime_attestation_plan(&FridaRuntimeAttestationRequest {
            module_name: "libtarget.so".to_string(),
            static_binary_path: elf_path.to_string_lossy().into_owned(),
            window_bytes: 4096,
            max_windows: 8,
        })
        .unwrap();
        let mut record = matching_runtime_attestation_record(&plan);
        let executable = record
            .windows
            .iter_mut()
            .find(|window| window.kind == RuntimeAttestationWindowKind::Executable)
            .unwrap();
        executable.actual_sha256 = Some("ff".repeat(32));
        executable.status = "mismatch".to_string();
        std::fs::write(&capture_path, serde_json::to_vec_pretty(&record).unwrap()).unwrap();

        let imported = add_trace_case_artifact(
            case_path.to_str().unwrap(),
            capture_path.to_str().unwrap(),
            None,
            None,
            Vec::new(),
        )
        .unwrap();
        assert_eq!(
            imported
                .artifact
                .summary
                .runtime_attestation_status
                .as_deref(),
            Some("refuted")
        );
        let report = diagnose_trace_analysis_case(case_path.to_str().unwrap()).unwrap();
        assert_eq!(report.runtime_attestations[0].report.status, "refuted");
        assert!(report.generated_claims.iter().any(|claim| {
            claim.scope.starts_with("runtime-image:")
                && claim.status == TraceCaseClaimStatus::Refuted
                && !claim.counter_evidence.is_empty()
        }));
        assert!(report
            .next_actions
            .iter()
            .any(|action| action.action == "resolve-runtime-image-mismatch"));
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn crypto_verified_claim_requires_strict_matching_kat_not_forged_text() {
        use crate::query::crypto_kat::{
            save_crypto_semantic_kat_report, CryptoKatAlgorithm, CryptoSemanticKatRequest,
            CRYPTO_SEMANTIC_KAT_SCHEMA,
        };

        let dir = temp_path("claim-gate");
        std::fs::create_dir_all(&dir).unwrap();
        let trace = dir.join("sample.log");
        let case_path = dir.join("sample.traceui-case");
        let kat_path = dir.join("sha256-kat.json");
        std::fs::write(&trace, b"trace\n").unwrap();
        let document = create_trace_analysis_case(
            case_path.to_str().unwrap(),
            "sample",
            Some(trace.to_str().unwrap()),
            None,
        )
        .unwrap();
        let trace_artifact_id = document.case.artifacts[0].artifact_id.clone();
        let kat_request = CryptoSemanticKatRequest {
            schema: CRYPTO_SEMANTIC_KAT_SCHEMA.to_string(),
            algorithm: CryptoKatAlgorithm::Sha256,
            direction: None,
            key_hex: None,
            input_hex: Some("68656c6c6f".to_string()),
            observed_output_hex: "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
                .to_string(),
            iv_hex: None,
            aad_hex: None,
            observed_tag_hex: None,
            password_hex: None,
            salt_hex: None,
            iterations: None,
            derived_key_length: None,
        };
        let kat_report =
            save_crypto_semantic_kat_report(kat_path.to_str().unwrap(), &kat_request).unwrap();
        let mut claim = TraceCaseClaim {
            claim_id: "claim-aes".to_string(),
            statement: "SHA-256 output is verified for this exact vector.".to_string(),
            scope: kat_report.claim_scope.clone(),
            status: TraceCaseClaimStatus::Verified,
            coverage_requirement: TraceCaseCoverageRequirement::Auto,
            supporting_evidence: vec![TraceCaseEvidenceRef {
                artifact_id: trace_artifact_id,
                locator: "semantic-known-answer".to_string(),
                description:
                    "Byte-for-byte exact output allegedly matches the known-answer vector."
                        .to_string(),
            }],
            counter_evidence: Vec::new(),
            missing_evidence: Vec::new(),
            limitations: Vec::new(),
            created_by: "test".to_string(),
            created_at_ms: 1,
            updated_at_ms: 1,
        };
        upsert_trace_case_claim(case_path.to_str().unwrap(), claim.clone()).unwrap();
        let blocked = diagnose_trace_analysis_case(case_path.to_str().unwrap()).unwrap();
        let audit = blocked
            .claim_ledger_audit
            .claims
            .iter()
            .find(|item| item.claim_id == "claim-aes")
            .unwrap();
        assert_eq!(audit.gate_status, "blocked");
        assert_eq!(audit.recommended_status, TraceCaseClaimStatus::Observed);

        let imported = add_trace_case_artifact(
            case_path.to_str().unwrap(),
            kat_path.to_str().unwrap(),
            None,
            None,
            Vec::new(),
        )
        .unwrap();
        assert_eq!(imported.artifact.kind, TraceCaseArtifactKind::CryptoKat);
        claim.supporting_evidence[0] = TraceCaseEvidenceRef {
            artifact_id: imported.artifact.artifact_id,
            locator: "crypto-kat/verified-full".to_string(),
            description: "Strict report recomputation passed for this exact claimScope."
                .to_string(),
        };
        upsert_trace_case_claim(case_path.to_str().unwrap(), claim).unwrap();
        let passed = diagnose_trace_analysis_case(case_path.to_str().unwrap()).unwrap();
        let audit = passed
            .claim_ledger_audit
            .claims
            .iter()
            .find(|item| item.claim_id == "claim-aes")
            .unwrap();
        assert!(audit.verification_gate_passed);
        assert_eq!(audit.gate_status, "passed");
        assert_eq!(passed.crypto_kats.len(), 1);
        assert!(passed.generated_claims.iter().any(|claim| {
            claim.scope == kat_report.claim_scope && claim.status == TraceCaseClaimStatus::Verified
        }));
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn unsupported_and_structural_scopes_cannot_be_promoted_by_text_markers() {
        let dir = temp_path("unsupported-verified-gate");
        std::fs::create_dir_all(&dir).unwrap();
        let trace = dir.join("sample.log");
        let case_path = dir.join("sample.traceui-case");
        std::fs::write(&trace, b"trace\n").unwrap();
        let document = create_trace_analysis_case(
            case_path.to_str().unwrap(),
            "structural gate",
            Some(trace.to_str().unwrap()),
            None,
        )
        .unwrap();
        upsert_trace_case_claim(
            case_path.to_str().unwrap(),
            TraceCaseClaim {
                claim_id: "forged-ollvm-verified".to_string(),
                statement: "The complete OLLVM CFG was recovered.".to_string(),
                scope: "ollvm:libtarget.so@0x100".to_string(),
                status: TraceCaseClaimStatus::Verified,
                coverage_requirement: TraceCaseCoverageRequirement::Auto,
                supporting_evidence: vec![TraceCaseEvidenceRef {
                    artifact_id: document.case.artifacts[0].artifact_id.clone(),
                    locator: "semantic-known-answer verification-gate".to_string(),
                    description: "Free text alleges exact output and complete recovery."
                        .to_string(),
                }],
                counter_evidence: Vec::new(),
                missing_evidence: Vec::new(),
                limitations: Vec::new(),
                created_by: "test".to_string(),
                created_at_ms: 1,
                updated_at_ms: 1,
            },
        )
        .unwrap();
        let report = diagnose_trace_analysis_case(case_path.to_str().unwrap()).unwrap();
        let audit = report
            .claim_ledger_audit
            .claims
            .iter()
            .find(|claim| claim.claim_id == "forged-ollvm-verified")
            .unwrap();
        assert_eq!(audit.gate_status, "blocked");
        assert_eq!(audit.recommended_status, TraceCaseClaimStatus::Related);
        assert_eq!(audit.coverage_requirement, "complete-control-flow");
        assert_eq!(audit.coverage_gate_status, "missing");
        assert_eq!(audit.coverage_max_status, TraceCaseClaimStatus::Related);
        assert!(!audit.verification_gate_passed);
        assert!(audit
            .blockers
            .iter()
            .any(|blocker| blocker.contains("no implemented structured Verified gate")));
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn complete_site_coverage_caps_negative_aes_claim_at_observed() {
        let dir = temp_path("coverage-negative-aes");
        std::fs::create_dir_all(&dir).unwrap();
        let case_path = dir.join("sample.traceui-case");
        let trace_path = dir.join("sample.log");
        let elf_path = dir.join("libtarget.so");
        let coverage_path = dir.join("coverage.json");
        std::fs::write(&trace_path, b"trace\n").unwrap();
        std::fs::write(&elf_path, runtime_attestable_elf()).unwrap();
        let identity = inspect_elf_binary(elf_path.to_str().unwrap()).unwrap();
        let document = create_trace_analysis_case(
            case_path.to_str().unwrap(),
            "coverage negative AES",
            Some(trace_path.to_str().unwrap()),
            Some(elf_path.to_str().unwrap()),
        )
        .unwrap();
        let trace_artifact = document
            .case
            .artifacts
            .iter()
            .find(|artifact| artifact.kind == TraceCaseArtifactKind::Trace)
            .unwrap();
        let claim_scope = format!("crypto:libtarget.so@{}", identity.binary_sha256);
        let bundle = coverage_bundle(&identity, &trace_artifact.sha256, &claim_scope, true);
        std::fs::write(&coverage_path, serde_json::to_vec_pretty(&bundle).unwrap()).unwrap();
        let imported = add_trace_case_artifact(
            case_path.to_str().unwrap(),
            coverage_path.to_str().unwrap(),
            None,
            Some("complete coverage"),
            Vec::new(),
        )
        .unwrap();
        assert_eq!(
            imported.artifact.kind,
            TraceCaseArtifactKind::CoverageReport
        );
        assert_eq!(imported.artifact.parent_artifact_ids.len(), 2);
        assert_eq!(imported.artifact.summary.coverage_gate_met, Some(true));
        upsert_trace_case_claim(
            case_path.to_str().unwrap(),
            TraceCaseClaim {
                claim_id: "negative-aes".to_string(),
                statement: "当前范围没有 AES 算法。".to_string(),
                scope: claim_scope,
                status: TraceCaseClaimStatus::Verified,
                coverage_requirement: TraceCaseCoverageRequirement::Auto,
                supporting_evidence: vec![TraceCaseEvidenceRef {
                    artifact_id: imported.artifact.artifact_id,
                    locator: "coverage-reconciliation/complete-site-coverage".to_string(),
                    description: "Exact-ELF-bound listed-site coverage.".to_string(),
                }],
                counter_evidence: Vec::new(),
                missing_evidence: Vec::new(),
                limitations: Vec::new(),
                created_by: "test".to_string(),
                created_at_ms: 1,
                updated_at_ms: 1,
            },
        )
        .unwrap();
        let report = diagnose_trace_analysis_case(case_path.to_str().unwrap()).unwrap();
        assert_eq!(report.coverage_reconciliations.len(), 1);
        assert!(report.coverage_reconciliations[0].report.coverage_gate_met);
        let audit = report
            .claim_ledger_audit
            .claims
            .iter()
            .find(|claim| claim.claim_id == "negative-aes")
            .unwrap();
        assert_eq!(audit.coverage_requirement, "negative-existence");
        assert_eq!(audit.coverage_gate_status, "passed");
        assert!(audit.coverage_gate_passed);
        assert_eq!(audit.coverage_max_status, TraceCaseClaimStatus::Observed);
        assert_eq!(audit.recommended_status, TraceCaseClaimStatus::Observed);
        assert!(!audit.verification_gate_passed);
        assert!(audit.blockers.iter().any(|blocker| {
            blocker.contains("Coverage cannot by itself verify this negative-existence claim")
        }));
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn partial_coverage_keeps_uncovered_offsets_and_capture_action() {
        let dir = temp_path("coverage-partial");
        std::fs::create_dir_all(&dir).unwrap();
        let case_path = dir.join("sample.traceui-case");
        let trace_path = dir.join("sample.log");
        let elf_path = dir.join("libtarget.so");
        let coverage_path = dir.join("coverage.json");
        std::fs::write(&trace_path, b"trace\n").unwrap();
        std::fs::write(&elf_path, runtime_attestable_elf()).unwrap();
        let identity = inspect_elf_binary(elf_path.to_str().unwrap()).unwrap();
        let document = create_trace_analysis_case(
            case_path.to_str().unwrap(),
            "partial coverage",
            Some(trace_path.to_str().unwrap()),
            Some(elf_path.to_str().unwrap()),
        )
        .unwrap();
        let trace_artifact = document
            .case
            .artifacts
            .iter()
            .find(|artifact| artifact.kind == TraceCaseArtifactKind::Trace)
            .unwrap();
        let claim_scope = format!("ollvm:libtarget.so@{}", identity.binary_sha256);
        let bundle = coverage_bundle(&identity, &trace_artifact.sha256, &claim_scope, false);
        std::fs::write(&coverage_path, serde_json::to_vec_pretty(&bundle).unwrap()).unwrap();
        let imported = add_trace_case_artifact(
            case_path.to_str().unwrap(),
            coverage_path.to_str().unwrap(),
            None,
            Some("partial coverage"),
            Vec::new(),
        )
        .unwrap();
        upsert_trace_case_claim(
            case_path.to_str().unwrap(),
            TraceCaseClaim {
                claim_id: "complete-cfg".to_string(),
                statement: "The complete CFG was recovered.".to_string(),
                scope: claim_scope,
                status: TraceCaseClaimStatus::Observed,
                coverage_requirement: TraceCaseCoverageRequirement::Auto,
                supporting_evidence: vec![TraceCaseEvidenceRef {
                    artifact_id: imported.artifact.artifact_id,
                    locator: "coverage-reconciliation/partial-site-coverage".to_string(),
                    description: "Partial listed-site coverage.".to_string(),
                }],
                counter_evidence: Vec::new(),
                missing_evidence: Vec::new(),
                limitations: Vec::new(),
                created_by: "test".to_string(),
                created_at_ms: 1,
                updated_at_ms: 1,
            },
        )
        .unwrap();
        let report = diagnose_trace_analysis_case(case_path.to_str().unwrap()).unwrap();
        let coverage = &report.coverage_reconciliations[0].report;
        assert_eq!(coverage.status, "partial-site-coverage");
        assert_eq!(coverage.summary.uncovered_counts.instructions, 2);
        assert!(coverage
            .uncovered_samples
            .blocks
            .contains(&"0x1008".to_string()));
        let audit = report
            .claim_ledger_audit
            .claims
            .iter()
            .find(|claim| claim.claim_id == "complete-cfg")
            .unwrap();
        assert_eq!(audit.coverage_gate_status, "partial");
        assert!(!audit.coverage_gate_passed);
        assert_eq!(
            audit
                .coverage_uncovered_counts
                .as_ref()
                .unwrap()
                .instructions,
            2
        );
        assert!(report
            .next_actions
            .iter()
            .any(|action| action.action == "capture-uncovered-coverage-sites"));
        assert!(report.capture_plan.targets.iter().any(|target| {
            target.action == "capture-uncovered-coverage-sites"
                && target
                    .module_relative_offsets
                    .contains(&"0x1008".to_string())
        }));
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn experiment_matrix_finds_single_variable_key_pair() {
        let dir = temp_path("experiment-matrix");
        std::fs::create_dir_all(&dir).unwrap();
        let case_path = dir.join("sample.traceui-case");
        create_trace_analysis_case(case_path.to_str().unwrap(), "sample", None, None).unwrap();
        for (id, key_group) in [("baseline", "key-a"), ("key-variant", "key-b")] {
            upsert_trace_case_experiment(
                case_path.to_str().unwrap(),
                TraceCaseExperiment {
                    experiment_id: id.to_string(),
                    label: id.to_string(),
                    binary_sha256: Some("a".repeat(64)),
                    key_group: Some(key_group.to_string()),
                    input_group: Some("input-a".to_string()),
                    environment_group: Some("env-a".to_string()),
                    artifact_ids: Vec::new(),
                    controlled_variables: vec![
                        "binarySha256".to_string(),
                        "inputGroup".to_string(),
                        "environmentGroup".to_string(),
                    ],
                    changed_variables: (id == "key-variant")
                        .then(|| vec!["keyGroup".to_string()])
                        .unwrap_or_default(),
                    notes: Vec::new(),
                },
            )
            .unwrap();
        }
        let report = diagnose_trace_analysis_case(case_path.to_str().unwrap()).unwrap();
        assert_eq!(report.experiment_matrix.complete_experiment_count, 2);
        assert!(report
            .experiment_matrix
            .controlled_pairs
            .iter()
            .any(|pair| pair.changed_axis == "keyGroup"));
        assert!(!report
            .experiment_matrix
            .recommendations
            .iter()
            .any(|recommendation| recommendation.action == "vary-only-key"));
        let _ = std::fs::remove_dir_all(dir);
    }
}
