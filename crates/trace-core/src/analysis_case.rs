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
use crate::query::elf_identity::{inspect_elf_binary, ElfBinaryIdentity};
use crate::query::frida_capture::{
    parse_frida_capture_bundle, FridaCaptureBundle, FridaCaptureEvent,
};
use crate::query::frida_checkpoint::unicorn_checkpoint_offsets;
use crate::query::ollvm::{parse_ida_annotation_bundle, IdaAnnotationBundle, OllvmReport};
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
    FridaCapture,
    UnicornResult,
    AngrResult,
    IdaAnnotations,
    OllvmReport,
    AnalysisReport,
    CryptoReport,
    Other,
}

impl TraceCaseArtifactKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Trace => "trace",
            Self::StaticBinary => "static-binary",
            Self::FridaCapture => "frida-capture",
            Self::UnicornResult => "unicorn-result",
            Self::AngrResult => "angr-result",
            Self::IdaAnnotations => "ida-annotations",
            Self::OllvmReport => "ollvm-report",
            Self::AnalysisReport => "analysis-report",
            Self::CryptoReport => "crypto-report",
            Self::Other => "other",
        }
    }

    fn from_hint(value: &str) -> std::result::Result<Self, String> {
        match value.trim().to_ascii_lowercase().replace('_', "-").as_str() {
            "trace" | "trace-log" | "log" => Ok(Self::Trace),
            "static-binary" | "binary" | "elf" | "so" => Ok(Self::StaticBinary),
            "frida-capture" | "frida" => Ok(Self::FridaCapture),
            "unicorn-result" | "unicorn" => Ok(Self::UnicornResult),
            "angr-result" | "angr" => Ok(Self::AngrResult),
            "ida-annotations" | "ida" => Ok(Self::IdaAnnotations),
            "ollvm-report" | "ollvm" => Ok(Self::OllvmReport),
            "analysis-report" | "analysis" => Ok(Self::AnalysisReport),
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
    #[serde(skip_serializing_if = "Option::is_none")]
    pub unicorn_round_comparison: Option<UnicornOllvmRoundComparisonReport>,
    pub warnings: Vec<String>,
    pub limitations: Vec<String>,
}

enum ParsedCaseArtifact {
    Trace,
    StaticBinary(ElfBinaryIdentity),
    Frida(FridaCaptureBundle),
    Unicorn(UnicornOllvmResultBundle),
    Angr(AngrOllvmResultBundle),
    Ida(IdaAnnotationBundle),
    Ollvm(OllvmReport),
    Analysis(AnalysisRecord),
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
    let (artifact, _) = artifact_from_path(
        Path::new(case_path),
        Path::new(artifact_path),
        kind_hint,
        label,
        parent_artifact_ids,
    )?;
    if let Some(existing) = document
        .case
        .artifacts
        .iter()
        .find(|existing| existing.kind == artifact.kind && existing.sha256 == artifact.sha256)
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

fn evidence_has_semantic_verification_marker(evidence: &TraceCaseEvidenceRef) -> bool {
    let text = format!("{} {}", evidence.locator, evidence.description).to_ascii_lowercase();
    [
        "semantic",
        "known-answer",
        "known answer",
        "byte-for-byte",
        "exact output",
        "digest match",
        "mac verified",
        "verification gate",
        "round-trip",
    ]
    .iter()
    .any(|marker| text.contains(marker))
}

fn build_claim_ledger_audit(
    persisted_claims: &[TraceCaseClaim],
    generated_claims: &[TraceCaseClaim],
    artifacts: &[TraceCaseArtifact],
    health: &[TraceCaseArtifactHealth],
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
        let mut semantic_marker = false;
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
                semantic_marker |= evidence_has_semantic_verification_marker(evidence);
            }
        }
        evidence_kinds.sort_by_key(|kind| kind.as_str());

        let mut blockers = Vec::new();
        let mut notes = Vec::new();
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
        if claim.status == TraceCaseClaimStatus::Verified && !semantic_marker {
            blockers.push(
                "Verified requires an explicit deterministic semantic/known-answer/output-match evidence locator; structural or SHA-only evidence is insufficient."
                    .to_string(),
            );
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

        let recommended_status = if valid_counter > 0 {
            TraceCaseClaimStatus::Refuted
        } else if valid_supporting == 0 {
            TraceCaseClaimStatus::Unknown
        } else if claim.status == TraceCaseClaimStatus::Verified
            && semantic_marker
            && invalid_evidence == 0
            && claim.missing_evidence.is_empty()
        {
            TraceCaseClaimStatus::Verified
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
            "The ledger audit checks provenance, artifact integrity, counter-evidence, and explicit semantic markers; it does not independently prove the claim statement."
                .to_string(),
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

pub fn diagnose_trace_analysis_case(case_path: &str) -> Result<ReplayDoctorReport> {
    let document = load_trace_analysis_case(case_path)?;
    let mut health = Vec::with_capacity(document.case.artifacts.len());
    let mut timeline = Vec::with_capacity(document.case.artifacts.len());
    let mut warnings = Vec::new();
    let mut valid_unicorn = Vec::<(TraceCaseArtifact, UnicornOllvmResultBundle)>::new();
    let mut valid_frida = Vec::<(TraceCaseArtifact, FridaCaptureBundle)>::new();
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
                    ParsedCaseArtifact::Analysis(record) => {
                        let _ = record.analysis_id;
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
    valid_angr.sort_by_key(|(artifact, _)| artifact.imported_at_ms);

    let mut next_actions = Vec::new();
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
        unicorn_round_comparison: round_comparison,
        warnings,
        limitations: vec![
            "Replay Doctor validates files, schemas, offsets, and supplied ELF identities; it does not attest the image loaded at runtime."
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
    fn verified_claim_requires_explicit_semantic_evidence_marker() {
        let dir = temp_path("claim-gate");
        std::fs::create_dir_all(&dir).unwrap();
        let trace = dir.join("sample.log");
        let case_path = dir.join("sample.traceui-case");
        std::fs::write(&trace, b"trace\n").unwrap();
        let document = create_trace_analysis_case(
            case_path.to_str().unwrap(),
            "sample",
            Some(trace.to_str().unwrap()),
            None,
        )
        .unwrap();
        let artifact_id = document.case.artifacts[0].artifact_id.clone();
        let mut claim = TraceCaseClaim {
            claim_id: "claim-aes".to_string(),
            statement: "AES output is verified for this exact call.".to_string(),
            scope: "libtarget.so@build".to_string(),
            status: TraceCaseClaimStatus::Verified,
            supporting_evidence: vec![TraceCaseEvidenceRef {
                artifact_id,
                locator: "sha256".to_string(),
                description: "The trace artifact remained unchanged.".to_string(),
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

        claim.supporting_evidence[0].locator = "semantic-known-answer".to_string();
        claim.supporting_evidence[0].description =
            "Byte-for-byte exact output matches the known-answer vector.".to_string();
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
