use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::fs::File;
use std::io::{BufReader, Read, Write};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};

use crate::analysis_case::{
    diagnose_trace_analysis_case, load_trace_analysis_case, resolve_trace_case_artifact_path,
    TraceAnalysisCase, TraceCaseArtifact, TraceCaseArtifactKind, TraceCaseClaim,
    TraceCaseEvidenceRef,
};
use crate::api_types::BuildOptions;
use crate::error::{Result, TraceError};
use crate::evidence_pack::{parse_evidence_locator, EvidencePackLocator};
use crate::query::elf_identity::{inspect_elf_layout, ElfBinaryLayout, ElfLoadSegment};
use crate::query::frida_capture::{
    parse_frida_capture_bundle, FridaCaptureEvent, FridaCapturedValue,
};
use crate::utils::parse_hex_addr;
use crate::TraceEngine;

pub const MINIMAL_EVIDENCE_SLICE_SCHEMA: &str = "trace-ui/minimal-evidence-slice-v1";
pub const MINIMAL_EVIDENCE_SLICE_INSPECTION_SCHEMA: &str =
    "trace-ui/minimal-evidence-slice-inspection-v1";
pub const MAX_MINIMAL_EVIDENCE_SLICE_BYTES: u64 = 16 * 1024 * 1024;

const MAX_SOURCE_ARTIFACTS: usize = 512;
const MAX_REFERENCES: usize = 2_048;
const MAX_RECORDS_LIMIT: u32 = 512;
const MAX_TRACE_BINDINGS: usize = 16;
const MAX_CONTEXT_LINES: u32 = 16;
const MAX_MODULE_CONTEXT_BYTES: u32 = 128;
const MAX_MEMORY_RECORD_BYTES: u32 = 65_536;
const MIN_TOTAL_PAYLOAD_BYTES: u64 = 64 * 1024;
const MAX_TOTAL_PAYLOAD_BYTES: u64 = MAX_MINIMAL_EVIDENCE_SLICE_BYTES;
const MAX_TEXT_CHARS: usize = 4_096;
const MAX_CAPTURE_VALUE_CHARS: usize = 8_192;
const MAX_JSON_FRAGMENT_BYTES: usize = 256 * 1024;
const MAX_JSON_MATCHES_PER_REFERENCE: usize = 8;

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
        .min(u64::MAX as u128) as u64
}

fn default_true() -> bool {
    true
}

fn default_context_lines() -> u32 {
    2
}

fn default_module_bytes_before() -> u32 {
    16
}

fn default_module_bytes_after() -> u32 {
    32
}

fn default_max_memory_bytes() -> u32 {
    4_096
}

fn default_max_records() -> u32 {
    256
}

fn default_max_total_payload_bytes() -> u64 {
    8 * 1024 * 1024
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct EvidenceSliceTraceSessionBinding {
    pub artifact_id: String,
    pub session_id: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MinimalEvidenceSliceRequest {
    pub case_path: String,
    #[serde(default)]
    pub trace_session_bindings: Vec<EvidenceSliceTraceSessionBinding>,
    #[serde(default)]
    pub claim_ids: Vec<String>,
    #[serde(default = "default_true")]
    pub include_generated_claims: bool,
    #[serde(default)]
    pub include_sensitive_values: bool,
    #[serde(default = "default_context_lines")]
    pub context_before: u32,
    #[serde(default = "default_context_lines")]
    pub context_after: u32,
    #[serde(default = "default_module_bytes_before")]
    pub module_bytes_before: u32,
    #[serde(default = "default_module_bytes_after")]
    pub module_bytes_after: u32,
    #[serde(default = "default_max_memory_bytes")]
    pub max_memory_bytes_per_record: u32,
    #[serde(default = "default_max_records")]
    pub max_records: u32,
    #[serde(default = "default_max_total_payload_bytes")]
    pub max_total_payload_bytes: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct EvidenceSliceConfig {
    pub include_generated_claims: bool,
    pub include_sensitive_values: bool,
    pub context_before: u32,
    pub context_after: u32,
    pub module_bytes_before: u32,
    pub module_bytes_after: u32,
    pub max_memory_bytes_per_record: u32,
    pub max_records: u32,
    pub max_total_payload_bytes: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum EvidenceSliceReferenceRole {
    Supporting,
    Counter,
}

impl EvidenceSliceReferenceRole {
    fn as_str(self) -> &'static str {
        match self {
            Self::Supporting => "supporting",
            Self::Counter => "counter",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct EvidenceSliceLocator {
    pub raw: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub trace_seq: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub trace_line: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub memory_address: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub memory_size: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub memory_range: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub module_offset: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub event_index: Option<u64>,
}

impl From<EvidencePackLocator> for EvidenceSliceLocator {
    fn from(value: EvidencePackLocator) -> Self {
        Self {
            raw: value.raw,
            trace_seq: value.trace_seq,
            trace_line: value.trace_line,
            memory_address: value.memory_address,
            memory_size: value.memory_size,
            memory_range: value.memory_range,
            module_offset: value.module_offset,
            event_index: value.event_index,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct EvidenceSliceSourceArtifact {
    pub artifact_id: String,
    pub kind: TraceCaseArtifactKind,
    pub label: String,
    pub stored_path: String,
    pub sha256: String,
    pub file_size: u64,
    pub parent_artifact_ids: Vec<String>,
    pub role: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct EvidenceSliceReference {
    pub reference_id: String,
    pub claim_id: String,
    pub claim_source: String,
    pub claim_fingerprint: String,
    pub role: EvidenceSliceReferenceRole,
    pub artifact_id: String,
    pub locator: EvidenceSliceLocator,
    pub description: String,
    pub reference_fingerprint: String,
    pub status: String,
    pub record_ids: Vec<String>,
    pub warnings: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct EvidenceSliceTraceLine {
    pub seq: u32,
    pub line: u64,
    pub focus: bool,
    pub address: String,
    pub module_offset: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub module_name: Option<String>,
    pub disasm: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub changes: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub registers_before: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub raw: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub memory_access: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub memory_address: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub memory_size: Option<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct EvidenceSliceTraceLinesPayload {
    pub focus_seq: u32,
    pub values_omitted: bool,
    pub lines: Vec<EvidenceSliceTraceLine>,
}

#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct EvidenceSliceMemoryByteProvenance {
    pub offset: u32,
    pub address: String,
    pub source: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub seq: Option<u32>,
    pub confidence: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct EvidenceSliceMemoryPayload {
    pub trace_seq: u32,
    pub address: String,
    pub length: u32,
    pub bytes_hex: String,
    pub known_mask_hex: String,
    pub known_byte_count: u32,
    pub provenance: Vec<EvidenceSliceMemoryByteProvenance>,
}

#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct EvidenceSliceFridaCaptureValue {
    pub index: u8,
    pub label: String,
    pub kind: String,
    pub direction: String,
    pub phase: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pointer: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub value: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub byte_length: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub requested_length: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub read_error: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub base_register: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub displacement: Option<String>,
    pub truncated: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct EvidenceSliceFridaEventPayload {
    pub event_index: u64,
    pub event: String,
    pub function_name: String,
    pub timestamp_ms: u64,
    pub thread_id: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub event_id: Option<String>,
    pub hook_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub call_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub module_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub module_offset: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub capture_session_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub flow_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hit_sequence: Option<u64>,
    pub sensitive_values_included: bool,
    pub registers: BTreeMap<String, String>,
    pub captures: Vec<EvidenceSliceFridaCaptureValue>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub return_value: Option<String>,
    pub backtrace: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    pub truncated: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct EvidenceSliceModuleBytesPayload {
    pub requested_module_offset: String,
    pub start_module_offset: String,
    pub file_offset: u64,
    pub virtual_address: String,
    pub segment_index: u32,
    pub readable: bool,
    pub writable: bool,
    pub executable: bool,
    pub bytes_hex: String,
    pub binary_sha256: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub build_id: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct EvidenceSliceJsonFragmentPayload {
    pub source_json_pointer: String,
    pub matched_field: String,
    pub fragment: Value,
    pub truncated: bool,
}

#[derive(Clone, Debug, PartialEq, Deserialize, Serialize)]
#[serde(tag = "kind", content = "data", rename_all = "kebab-case")]
pub enum EvidenceSliceRecordPayload {
    TraceLines(EvidenceSliceTraceLinesPayload),
    Memory(EvidenceSliceMemoryPayload),
    FridaEvent(EvidenceSliceFridaEventPayload),
    ModuleBytes(EvidenceSliceModuleBytesPayload),
    JsonFragment(EvidenceSliceJsonFragmentPayload),
}

#[derive(Clone, Debug, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct EvidenceSliceRecord {
    pub record_id: String,
    pub source_artifact_id: String,
    pub locator: EvidenceSliceLocator,
    pub content_sha256: String,
    pub truncated: bool,
    pub payload: EvidenceSliceRecordPayload,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum ProvenanceNodeKind {
    Case,
    Claim,
    Artifact,
    Build,
    ProcessRun,
    Thread,
    Event,
    EvidenceReference,
    EvidenceRecord,
}

#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TypedProvenanceNode {
    pub node_id: String,
    pub kind: ProvenanceNodeKind,
    pub label: String,
    pub attributes: BTreeMap<String, String>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum ProvenanceRelation {
    Contains,
    ParentOf,
    Supports,
    Counters,
    MaterializedAs,
    DerivedFrom,
    BoundToBuild,
    ObservedIn,
    ExecutedOnThread,
}

#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TypedProvenanceEdge {
    pub edge_id: String,
    pub from_node_id: String,
    pub to_node_id: String,
    pub relation: ProvenanceRelation,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TypedProvenanceGraph {
    pub nodes: Vec<TypedProvenanceNode>,
    pub edges: Vec<TypedProvenanceEdge>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MinimalEvidenceSliceSummary {
    pub selected_claim_count: u64,
    pub selected_reference_count: u64,
    pub materialized_reference_count: u64,
    pub unresolved_reference_count: u64,
    pub source_artifact_count: u64,
    pub record_count: u64,
    pub truncated_record_count: u64,
    pub trace_line_record_count: u64,
    pub memory_record_count: u64,
    pub frida_event_record_count: u64,
    pub module_bytes_record_count: u64,
    pub json_fragment_record_count: u64,
    pub contains_sensitive_values: bool,
    pub payload_bytes: u64,
    pub materialization_complete: bool,
}

#[derive(Clone, Debug, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MinimalEvidenceSliceContent {
    pub case_id: String,
    pub case_title: String,
    pub config: EvidenceSliceConfig,
    pub selected_claim_ids: Vec<String>,
    pub source_artifacts: Vec<EvidenceSliceSourceArtifact>,
    pub references: Vec<EvidenceSliceReference>,
    pub records: Vec<EvidenceSliceRecord>,
    pub provenance: TypedProvenanceGraph,
    pub summary: MinimalEvidenceSliceSummary,
    pub warnings: Vec<String>,
    pub limitations: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MinimalEvidenceSliceBundle {
    pub schema: String,
    pub slice_id: String,
    pub generated_at_ms: u64,
    pub content_sha256: String,
    pub content: MinimalEvidenceSliceContent,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MinimalEvidenceSliceInspectionReport {
    pub schema: String,
    pub slice_id: String,
    pub status: String,
    pub content_sha256_matched: bool,
    pub source_artifacts_matched: bool,
    pub claim_bindings_matched: bool,
    pub generated_claim_bindings_revalidated: bool,
    pub record_content_matched: bool,
    pub provenance_graph_valid: bool,
    pub summary_recomputed: MinimalEvidenceSliceSummary,
    pub source_artifact_ids: Vec<String>,
    pub stale_claim_ids: Vec<String>,
    pub unrevalidated_generated_claim_ids: Vec<String>,
    pub mismatched_record_ids: Vec<String>,
    pub blockers: Vec<String>,
    pub warnings: Vec<String>,
    pub limitations: Vec<String>,
}

#[derive(Clone)]
struct ClaimSource {
    source: String,
    claim: TraceCaseClaim,
}

#[derive(Default)]
struct MaterializationResult {
    records: Vec<EvidenceSliceRecord>,
    warnings: Vec<String>,
}

#[derive(Clone)]
struct JsonMatch {
    pointer: String,
    field: String,
    value: Value,
}

fn validate_request(request: &MinimalEvidenceSliceRequest) -> Result<()> {
    if request.case_path.trim().is_empty() {
        return Err(TraceError::InvalidArgument(
            "case_path must not be empty".to_string(),
        ));
    }
    if request.trace_session_bindings.len() > MAX_TRACE_BINDINGS {
        return Err(TraceError::InvalidArgument(format!(
            "at most {MAX_TRACE_BINDINGS} trace session bindings are supported"
        )));
    }
    if request.context_before > MAX_CONTEXT_LINES || request.context_after > MAX_CONTEXT_LINES {
        return Err(TraceError::InvalidArgument(format!(
            "trace context before/after must not exceed {MAX_CONTEXT_LINES} lines"
        )));
    }
    if request.module_bytes_before > MAX_MODULE_CONTEXT_BYTES
        || request.module_bytes_after > MAX_MODULE_CONTEXT_BYTES
    {
        return Err(TraceError::InvalidArgument(format!(
            "module byte context before/after must not exceed {MAX_MODULE_CONTEXT_BYTES}"
        )));
    }
    if request.max_memory_bytes_per_record == 0
        || request.max_memory_bytes_per_record > MAX_MEMORY_RECORD_BYTES
    {
        return Err(TraceError::InvalidArgument(format!(
            "max_memory_bytes_per_record must be from 1 through {MAX_MEMORY_RECORD_BYTES}"
        )));
    }
    if request.max_records == 0 || request.max_records > MAX_RECORDS_LIMIT {
        return Err(TraceError::InvalidArgument(format!(
            "max_records must be from 1 through {MAX_RECORDS_LIMIT}"
        )));
    }
    if !(MIN_TOTAL_PAYLOAD_BYTES..=MAX_TOTAL_PAYLOAD_BYTES)
        .contains(&request.max_total_payload_bytes)
    {
        return Err(TraceError::InvalidArgument(format!(
            "max_total_payload_bytes must be from {MIN_TOTAL_PAYLOAD_BYTES} through {MAX_TOTAL_PAYLOAD_BYTES}"
        )));
    }
    let mut binding_artifact_ids = HashSet::new();
    let mut binding_session_ids = HashSet::new();
    for binding in &request.trace_session_bindings {
        if binding.artifact_id.trim().is_empty() || binding.session_id.trim().is_empty() {
            return Err(TraceError::InvalidArgument(
                "trace session bindings require non-empty artifact_id and session_id".to_string(),
            ));
        }
        if !binding_artifact_ids.insert(binding.artifact_id.as_str()) {
            return Err(TraceError::InvalidArgument(format!(
                "duplicate trace artifact binding: {}",
                binding.artifact_id
            )));
        }
        if !binding_session_ids.insert(binding.session_id.as_str()) {
            return Err(TraceError::InvalidArgument(format!(
                "one trace session cannot be bound to multiple artifacts: {}",
                binding.session_id
            )));
        }
    }
    Ok(())
}

fn config_from_request(request: &MinimalEvidenceSliceRequest) -> EvidenceSliceConfig {
    EvidenceSliceConfig {
        include_generated_claims: request.include_generated_claims,
        include_sensitive_values: request.include_sensitive_values,
        context_before: request.context_before,
        context_after: request.context_after,
        module_bytes_before: request.module_bytes_before,
        module_bytes_after: request.module_bytes_after,
        max_memory_bytes_per_record: request.max_memory_bytes_per_record,
        max_records: request.max_records,
        max_total_payload_bytes: request.max_total_payload_bytes,
    }
}

fn request_from_config(
    case_path: &str,
    config: &EvidenceSliceConfig,
) -> MinimalEvidenceSliceRequest {
    MinimalEvidenceSliceRequest {
        case_path: case_path.to_string(),
        trace_session_bindings: Vec::new(),
        claim_ids: Vec::new(),
        include_generated_claims: config.include_generated_claims,
        include_sensitive_values: config.include_sensitive_values,
        context_before: config.context_before,
        context_after: config.context_after,
        module_bytes_before: config.module_bytes_before,
        module_bytes_after: config.module_bytes_after,
        max_memory_bytes_per_record: config.max_memory_bytes_per_record,
        max_records: config.max_records,
        max_total_payload_bytes: config.max_total_payload_bytes,
    }
}

fn truncate_text(value: &str, max_chars: usize) -> (String, bool) {
    if value.chars().count() <= max_chars {
        return (value.to_string(), false);
    }
    let mut output = value.chars().take(max_chars).collect::<String>();
    output.push_str("...[truncated]");
    (output, true)
}

fn sha256_bytes(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn sha256_json(value: &impl Serialize) -> Result<String> {
    let bytes = serde_json::to_vec(value).map_err(|error| {
        TraceError::Internal(format!("failed to serialize evidence slice: {error}"))
    })?;
    Ok(sha256_bytes(&bytes))
}

fn stable_id(prefix: &str, components: &[&str]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(prefix.as_bytes());
    for component in components {
        hasher.update([0]);
        hasher.update(component.as_bytes());
    }
    let digest = format!("{:x}", hasher.finalize());
    format!("{prefix}-{}", &digest[..24])
}

fn hash_file(path: &Path) -> Result<(String, u64)> {
    let file = File::open(path)?;
    let metadata = file.metadata()?;
    if !metadata.is_file() {
        return Err(TraceError::InvalidArgument(format!(
            "evidence source is not a regular file: {}",
            path.display()
        )));
    }
    let mut reader = BufReader::new(file);
    let mut hasher = Sha256::new();
    let mut buffer = vec![0u8; 1024 * 1024];
    loop {
        let count = reader.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        hasher.update(&buffer[..count]);
    }
    Ok((format!("{:x}", hasher.finalize()), metadata.len()))
}

fn canonical_path(path: &Path) -> Result<PathBuf> {
    std::fs::canonicalize(path).map_err(TraceError::Io)
}

fn same_path(left: &Path, right: &Path) -> bool {
    let left = canonical_path(left).unwrap_or_else(|_| left.to_path_buf());
    let right = canonical_path(right).unwrap_or_else(|_| right.to_path_buf());
    if cfg!(windows) {
        left.to_string_lossy()
            .eq_ignore_ascii_case(&right.to_string_lossy())
    } else {
        left == right
    }
}

fn collect_claims(case_path: &str, include_generated: bool) -> Result<Vec<ClaimSource>> {
    let document = load_trace_analysis_case(case_path)?;
    let mut output = persisted_claims(&document.case);
    if include_generated {
        let report = diagnose_trace_analysis_case(case_path)?;
        let persisted_ids = output
            .iter()
            .map(|item| item.claim.claim_id.clone())
            .collect::<HashSet<_>>();
        output.extend(
            report
                .generated_claims
                .into_iter()
                .filter(|claim| !persisted_ids.contains(&claim.claim_id))
                .map(|claim| ClaimSource {
                    source: "generated".to_string(),
                    claim,
                }),
        );
    }
    output.sort_by(|left, right| {
        left.claim
            .claim_id
            .cmp(&right.claim.claim_id)
            .then_with(|| left.source.cmp(&right.source))
    });
    Ok(output)
}

fn persisted_claims(case: &TraceAnalysisCase) -> Vec<ClaimSource> {
    let mut output = case
        .claims
        .iter()
        .cloned()
        .map(|claim| ClaimSource {
            source: "persisted".to_string(),
            claim,
        })
        .collect::<Vec<_>>();
    output.sort_by(|left, right| {
        left.claim
            .claim_id
            .cmp(&right.claim.claim_id)
            .then_with(|| left.source.cmp(&right.source))
    });
    output
}

fn generated_claim_from_graph(
    bundle: &MinimalEvidenceSliceBundle,
    claim_id: &str,
) -> Option<ClaimSource> {
    let node = bundle.content.provenance.nodes.iter().find(|node| {
        node.kind == ProvenanceNodeKind::Claim
            && node.node_id == format!("claim:{claim_id}")
            && node.attributes.get("claimId").map(String::as_str) == Some(claim_id)
            && node.attributes.get("source").map(String::as_str) == Some("generated")
    })?;
    Some(ClaimSource {
        source: "generated".to_string(),
        claim: TraceCaseClaim {
            claim_id: claim_id.to_string(),
            statement: node.label.clone(),
            scope: node.attributes.get("scope")?.clone(),
            status: crate::analysis_case::TraceCaseClaimStatus::Unknown,
            coverage_requirement: crate::analysis_case::TraceCaseCoverageRequirement::Auto,
            supporting_evidence: Vec::new(),
            counter_evidence: Vec::new(),
            missing_evidence: Vec::new(),
            limitations: Vec::new(),
            created_by: "evidence-slice-provenance".to_string(),
            created_at_ms: 0,
            updated_at_ms: 0,
        },
    })
}

fn claim_fingerprint(claim: &TraceCaseClaim) -> Result<String> {
    #[derive(Serialize)]
    #[serde(rename_all = "camelCase")]
    struct Fingerprint<'a> {
        claim_id: &'a str,
        statement: &'a str,
        scope: &'a str,
        status: crate::analysis_case::TraceCaseClaimStatus,
        coverage_requirement: crate::analysis_case::TraceCaseCoverageRequirement,
    }
    sha256_json(&Fingerprint {
        claim_id: &claim.claim_id,
        statement: &claim.statement,
        scope: &claim.scope,
        status: claim.status,
        coverage_requirement: claim.coverage_requirement,
    })
}

fn reference_fingerprint(
    claim_fingerprint: &str,
    role: EvidenceSliceReferenceRole,
    evidence: &TraceCaseEvidenceRef,
) -> Result<String> {
    #[derive(Serialize)]
    #[serde(rename_all = "camelCase")]
    struct Fingerprint<'a> {
        claim_fingerprint: &'a str,
        role: EvidenceSliceReferenceRole,
        artifact_id: &'a str,
        locator: &'a str,
        description: &'a str,
    }
    sha256_json(&Fingerprint {
        claim_fingerprint,
        role,
        artifact_id: &evidence.artifact_id,
        locator: &evidence.locator,
        description: &evidence.description,
    })
}

fn make_reference(
    source: &str,
    claim: &TraceCaseClaim,
    role: EvidenceSliceReferenceRole,
    evidence: &TraceCaseEvidenceRef,
) -> Result<EvidenceSliceReference> {
    let claim_fingerprint = claim_fingerprint(claim)?;
    let reference_fingerprint = reference_fingerprint(&claim_fingerprint, role, evidence)?;
    let (description, description_truncated) = truncate_text(&evidence.description, MAX_TEXT_CHARS);
    let mut warnings = Vec::new();
    if description_truncated {
        warnings.push(
            "Evidence description exceeded the slice text limit and was truncated.".to_string(),
        );
    }
    Ok(EvidenceSliceReference {
        reference_id: stable_id("reference", &[&reference_fingerprint]),
        claim_id: claim.claim_id.clone(),
        claim_source: source.to_string(),
        claim_fingerprint,
        role,
        artifact_id: evidence.artifact_id.clone(),
        locator: parse_evidence_locator(&evidence.locator).into(),
        description,
        reference_fingerprint,
        status: "pending".to_string(),
        record_ids: Vec::new(),
        warnings,
    })
}

fn source_artifacts(
    case: &TraceAnalysisCase,
    selected_ids: &BTreeSet<String>,
) -> Result<Vec<EvidenceSliceSourceArtifact>> {
    let by_id = case
        .artifacts
        .iter()
        .map(|artifact| (artifact.artifact_id.as_str(), artifact))
        .collect::<HashMap<_, _>>();
    let mut included = selected_ids.clone();
    let mut queue = selected_ids.iter().cloned().collect::<Vec<_>>();
    while let Some(artifact_id) = queue.pop() {
        let Some(artifact) = by_id.get(artifact_id.as_str()) else {
            continue;
        };
        for parent_id in &artifact.parent_artifact_ids {
            if included.insert(parent_id.clone()) {
                queue.push(parent_id.clone());
            }
        }
    }
    if included.len() > MAX_SOURCE_ARTIFACTS {
        return Err(TraceError::InvalidArgument(format!(
            "minimal evidence slice references more than {MAX_SOURCE_ARTIFACTS} source artifacts"
        )));
    }
    let mut output = included
        .into_iter()
        .filter_map(|artifact_id| {
            by_id
                .get(artifact_id.as_str())
                .map(|artifact| EvidenceSliceSourceArtifact {
                    artifact_id: artifact.artifact_id.clone(),
                    kind: artifact.kind,
                    label: artifact.label.clone(),
                    stored_path: artifact.path.clone(),
                    sha256: artifact.sha256.to_ascii_lowercase(),
                    file_size: artifact.file_size,
                    parent_artifact_ids: artifact.parent_artifact_ids.clone(),
                    role: if selected_ids.contains(&artifact.artifact_id) {
                        "selected-evidence-source".to_string()
                    } else {
                        "provenance-parent".to_string()
                    },
                })
        })
        .collect::<Vec<_>>();
    output.sort_by(|left, right| left.artifact_id.cmp(&right.artifact_id));
    Ok(output)
}

fn trace_binding_map<'a>(
    engine: &TraceEngine,
    case_path: &str,
    case: &TraceAnalysisCase,
    bindings: &'a [EvidenceSliceTraceSessionBinding],
) -> Result<HashMap<&'a str, &'a str>> {
    let mut output = HashMap::new();
    for binding in bindings {
        let artifact = case
            .artifacts
            .iter()
            .find(|artifact| artifact.artifact_id == binding.artifact_id)
            .ok_or_else(|| {
                TraceError::InvalidArgument(format!(
                    "trace session binding references unknown artifact {}",
                    binding.artifact_id
                ))
            })?;
        if artifact.kind != TraceCaseArtifactKind::Trace {
            return Err(TraceError::InvalidArgument(format!(
                "trace session binding {} does not reference a trace artifact",
                binding.artifact_id
            )));
        }
        let source_path = resolve_trace_case_artifact_path(case_path, &artifact.path)?;
        let session = engine.get_session_info(&binding.session_id)?;
        if !same_path(&source_path, Path::new(&session.file_path)) {
            return Err(TraceError::InvalidArgument(format!(
                "trace session {} is open for a different file than artifact {}",
                binding.session_id, binding.artifact_id
            )));
        }
        let (sha256, size) = hash_file(&source_path)?;
        if size != artifact.file_size || !sha256.eq_ignore_ascii_case(&artifact.sha256) {
            return Err(TraceError::InvalidArgument(format!(
                "trace artifact {} changed after import",
                binding.artifact_id
            )));
        }
        if !session.index_ready {
            return Err(TraceError::IndexNotReady);
        }
        output.insert(binding.artifact_id.as_str(), binding.session_id.as_str());
    }
    Ok(output)
}

fn trace_focus_seq(locator: &EvidenceSliceLocator) -> Option<u32> {
    locator
        .trace_seq
        .or_else(|| locator.trace_line.and_then(|line| line.checked_sub(1)))
        .and_then(|value| u32::try_from(value).ok())
}

fn bools_to_hex(values: &[bool]) -> String {
    let mut bytes = vec![0u8; values.len().div_ceil(8)];
    for (index, value) in values.iter().enumerate() {
        if *value {
            bytes[index / 8] |= 1 << (index % 8);
        }
    }
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn bytes_to_hex(values: &[u8]) -> String {
    values.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn make_record(
    source_artifact_id: &str,
    locator: &EvidenceSliceLocator,
    truncated: bool,
    payload: EvidenceSliceRecordPayload,
) -> Result<EvidenceSliceRecord> {
    let content_sha256 = sha256_json(&payload)?;
    let record_id = stable_id(
        "record",
        &[source_artifact_id, &locator.raw, &content_sha256],
    );
    Ok(EvidenceSliceRecord {
        record_id,
        source_artifact_id: source_artifact_id.to_string(),
        locator: locator.clone(),
        content_sha256,
        truncated,
        payload,
    })
}

fn materialize_trace(
    engine: &TraceEngine,
    session_id: Option<&str>,
    artifact: &TraceCaseArtifact,
    locator: &EvidenceSliceLocator,
    config: &EvidenceSliceConfig,
) -> Result<MaterializationResult> {
    let mut output = MaterializationResult::default();
    let Some(session_id) = session_id else {
        output.warnings.push(format!(
            "Trace artifact {} has no exact open-session binding; raw trace and memory evidence were not materialized.",
            artifact.artifact_id
        ));
        return Ok(output);
    };
    let Some(focus_seq) = trace_focus_seq(locator) else {
        output
            .warnings
            .push("Trace evidence requires an explicit seq:N or line:N locator.".to_string());
        return Ok(output);
    };
    let session = engine.get_session_info(session_id)?;
    if focus_seq >= session.total_lines {
        output.warnings.push(format!(
            "Trace locator seq:{focus_seq} exceeds the indexed trace line count {}.",
            session.total_lines
        ));
        return Ok(output);
    }
    let start = focus_seq.saturating_sub(config.context_before);
    let end = focus_seq
        .saturating_add(config.context_after)
        .min(session.total_lines.saturating_sub(1));
    let seqs = (start..=end).collect::<Vec<_>>();
    let lines = engine.get_lines(session_id, &seqs)?;
    let values_omitted = !config.include_sensitive_values;
    let lines = lines
        .into_iter()
        .map(|line| EvidenceSliceTraceLine {
            seq: line.seq,
            line: u64::from(line.seq) + 1,
            focus: line.seq == focus_seq,
            address: line.address,
            module_offset: line.so_offset,
            module_name: line.so_name,
            disasm: line.disasm,
            changes: config.include_sensitive_values.then_some(line.changes),
            registers_before: config.include_sensitive_values.then_some(line.reg_before),
            raw: config.include_sensitive_values.then_some(line.raw),
            memory_access: line.mem_rw,
            memory_address: config
                .include_sensitive_values
                .then_some(line.mem_addr)
                .flatten(),
            memory_size: line.mem_size,
        })
        .collect::<Vec<_>>();
    output.records.push(make_record(
        &artifact.artifact_id,
        locator,
        values_omitted,
        EvidenceSliceRecordPayload::TraceLines(EvidenceSliceTraceLinesPayload {
            focus_seq,
            values_omitted,
            lines,
        }),
    )?);

    if locator.memory_address.is_some() || locator.memory_size.is_some() {
        if !config.include_sensitive_values {
            output.warnings.push(
                "Memory bytes were omitted because includeSensitiveValues is false.".to_string(),
            );
        } else if let (Some(address), Some(size)) =
            (locator.memory_address.as_deref(), locator.memory_size)
        {
            let address_value = parse_hex_addr(address).map_err(|error| {
                TraceError::InvalidArgument(format!("invalid memory locator address: {error}"))
            })?;
            let requested = u32::try_from(size)
                .unwrap_or(u32::MAX)
                .min(config.max_memory_bytes_per_record);
            if requested == 0 {
                output
                    .warnings
                    .push("Memory locator requested zero bytes.".to_string());
            } else {
                let snapshot =
                    engine.get_memory_at(session_id, address_value, focus_seq, requested)?;
                let base = parse_hex_addr(&snapshot.base_addr).map_err(|error| {
                    TraceError::Internal(format!("invalid memory snapshot base: {error}"))
                })?;
                let start_offset = address_value
                    .checked_sub(base)
                    .and_then(|value| usize::try_from(value).ok())
                    .ok_or_else(|| {
                        TraceError::Internal(
                            "memory snapshot does not cover the requested address".to_string(),
                        )
                    })?;
                let available = snapshot.bytes.len().saturating_sub(start_offset);
                let length = usize::try_from(requested)
                    .unwrap_or(usize::MAX)
                    .min(available);
                let bytes = &snapshot.bytes[start_offset..start_offset + length];
                let known = &snapshot.known[start_offset..start_offset + length];
                let provenance = snapshot
                    .provenance
                    .into_iter()
                    .filter_map(|item| {
                        let item_address = parse_hex_addr(&item.address).ok()?;
                        if item_address < address_value
                            || item_address >= address_value.saturating_add(length as u64)
                        {
                            return None;
                        }
                        Some(EvidenceSliceMemoryByteProvenance {
                            offset: item_address.saturating_sub(address_value) as u32,
                            address: item.address,
                            source: item.source,
                            seq: item.seq,
                            confidence: item.confidence,
                        })
                    })
                    .collect::<Vec<_>>();
                let truncated = size > u64::from(requested) || length < requested as usize;
                output.records.push(make_record(
                    &artifact.artifact_id,
                    locator,
                    truncated,
                    EvidenceSliceRecordPayload::Memory(EvidenceSliceMemoryPayload {
                        trace_seq: focus_seq,
                        address: format!("0x{address_value:x}"),
                        length: length as u32,
                        bytes_hex: bytes_to_hex(bytes),
                        known_mask_hex: bools_to_hex(known),
                        known_byte_count: known.iter().filter(|value| **value).count() as u32,
                        provenance,
                    }),
                )?);
            }
        }
    }
    Ok(output)
}

fn event_module_offset(event: &FridaCaptureEvent) -> Option<String> {
    if let Some(offset) = &event.dispatcher_offset {
        return parse_hex_addr(offset)
            .ok()
            .map(|value| format!("0x{value:x}"));
    }
    let target = event
        .target
        .as_deref()
        .and_then(|value| parse_hex_addr(value).ok())?;
    let base = event
        .module_base
        .as_deref()
        .and_then(|value| parse_hex_addr(value).ok())?;
    target.checked_sub(base).map(|value| format!("0x{value:x}"))
}

fn captured_value(
    value: &FridaCapturedValue,
    include_sensitive: bool,
) -> EvidenceSliceFridaCaptureValue {
    let (captured, truncated) = value
        .value
        .as_deref()
        .map(|value| truncate_text(value, MAX_CAPTURE_VALUE_CHARS))
        .unwrap_or_default();
    EvidenceSliceFridaCaptureValue {
        index: value.index,
        label: value.label.clone(),
        kind: value.kind.clone(),
        direction: value.direction.clone(),
        phase: value.phase.clone(),
        pointer: include_sensitive.then(|| value.pointer.clone()).flatten(),
        value: include_sensitive
            .then_some(captured)
            .filter(|value| !value.is_empty()),
        byte_length: value.byte_length,
        requested_length: value.requested_length,
        read_error: value.read_error.clone(),
        base_register: value.base_register.clone(),
        displacement: value.displacement.clone(),
        truncated: include_sensitive && truncated,
    }
}

fn frida_event_payload(
    event: &FridaCaptureEvent,
    include_sensitive: bool,
) -> EvidenceSliceFridaEventPayload {
    let captures = event
        .captures
        .iter()
        .map(|value| captured_value(value, include_sensitive))
        .collect::<Vec<_>>();
    let truncated = captures.iter().any(|value| value.truncated);
    EvidenceSliceFridaEventPayload {
        event_index: event.index,
        event: event.event.clone(),
        function_name: event.function_name.clone(),
        timestamp_ms: event.timestamp_ms,
        thread_id: event.thread_id,
        event_id: event.event_id.clone(),
        hook_id: event.hook_id.clone(),
        call_id: event.call_id.clone(),
        module_name: event.module_name.clone(),
        module_offset: event_module_offset(event),
        capture_session_id: event.capture_session_id.clone(),
        flow_id: event.flow_id.clone(),
        hit_sequence: event.hit_sequence,
        sensitive_values_included: include_sensitive,
        registers: if include_sensitive {
            event.registers.clone()
        } else {
            BTreeMap::new()
        },
        captures,
        return_value: include_sensitive
            .then(|| event.return_value.clone())
            .flatten(),
        backtrace: event.backtrace.clone(),
        error: event.error.clone(),
        truncated,
    }
}

fn read_bounded(path: &Path, max_bytes: u64, label: &str) -> Result<Vec<u8>> {
    let metadata = std::fs::metadata(path)?;
    if metadata.len() > max_bytes {
        return Err(TraceError::InvalidArgument(format!(
            "{label} exceeds the {} MiB limit",
            max_bytes / (1024 * 1024)
        )));
    }
    std::fs::read(path).map_err(TraceError::Io)
}

fn materialize_frida(
    path: &Path,
    artifact: &TraceCaseArtifact,
    locator: &EvidenceSliceLocator,
    config: &EvidenceSliceConfig,
) -> Result<MaterializationResult> {
    let bytes = read_bounded(path, MAX_MINIMAL_EVIDENCE_SLICE_BYTES * 4, "Frida capture")?;
    let bundle = parse_frida_capture_bundle(&bytes).map_err(TraceError::InvalidArgument)?;
    let requested_offset = locator
        .module_offset
        .as_deref()
        .and_then(|value| parse_hex_addr(value).ok());
    let mut events = if let Some(event_index) = locator.event_index {
        bundle
            .events
            .iter()
            .filter(|event| event.index == event_index)
            .collect::<Vec<_>>()
    } else if let Some(requested_offset) = requested_offset {
        bundle
            .events
            .iter()
            .filter(|event| {
                event_module_offset(event)
                    .as_deref()
                    .and_then(|value| parse_hex_addr(value).ok())
                    == Some(requested_offset)
            })
            .take(4)
            .collect::<Vec<_>>()
    } else {
        Vec::new()
    };
    events.sort_by_key(|event| event.index);
    let mut output = MaterializationResult::default();
    if events.is_empty() {
        output.warnings.push(
            "Frida evidence requires an exact event index or a module offset observed by the capture."
                .to_string(),
        );
        return Ok(output);
    }
    for event in events {
        let payload = frida_event_payload(event, config.include_sensitive_values);
        output.records.push(make_record(
            &artifact.artifact_id,
            locator,
            payload.truncated || !config.include_sensitive_values,
            EvidenceSliceRecordPayload::FridaEvent(payload),
        )?);
    }
    if !config.include_sensitive_values {
        output.warnings.push(
            "Frida registers, pointers, captured values, and returns were omitted because includeSensitiveValues is false."
                .to_string(),
        );
    }
    Ok(output)
}

fn segment_for_offset(
    layout: &ElfBinaryLayout,
    module_offset: u64,
) -> Option<(&ElfLoadSegment, u64, u64)> {
    let virtual_address = layout.load_base_vaddr.checked_add(module_offset)?;
    layout.load_segments.iter().find_map(|segment| {
        let file_end = segment.virtual_address.checked_add(segment.file_size)?;
        if virtual_address < segment.virtual_address || virtual_address >= file_end {
            return None;
        }
        let file_offset = segment
            .file_offset
            .checked_add(virtual_address - segment.virtual_address)?;
        Some((segment, virtual_address, file_offset))
    })
}

fn materialize_static_binary(
    path: &Path,
    artifact: &TraceCaseArtifact,
    locator: &EvidenceSliceLocator,
    config: &EvidenceSliceConfig,
) -> Result<MaterializationResult> {
    let mut output = MaterializationResult::default();
    let Some(offset) = locator
        .module_offset
        .as_deref()
        .and_then(|value| parse_hex_addr(value).ok())
    else {
        output
            .warnings
            .push("Static binary evidence requires an exact module offset.".to_string());
        return Ok(output);
    };
    let layout =
        inspect_elf_layout(&path.to_string_lossy()).map_err(TraceError::InvalidArgument)?;
    let bytes = std::fs::read(path)?;
    let start_offset = offset.saturating_sub(u64::from(config.module_bytes_before));
    let Some((segment, virtual_address, file_offset)) = segment_for_offset(&layout, start_offset)
    else {
        output.warnings.push(format!(
            "Module offset 0x{offset:x} does not map to file-backed PT_LOAD bytes."
        ));
        return Ok(output);
    };
    let requested_length = u64::from(config.module_bytes_before)
        .saturating_add(u64::from(config.module_bytes_after))
        .saturating_add(1);
    let available = segment
        .file_offset
        .saturating_add(segment.file_size)
        .saturating_sub(file_offset);
    let length = requested_length.min(available);
    let file_start = usize::try_from(file_offset).map_err(|_| {
        TraceError::InvalidArgument("ELF evidence file offset exceeds host limits".to_string())
    })?;
    let file_end = file_start
        .checked_add(usize::try_from(length).unwrap_or(usize::MAX))
        .filter(|end| *end <= bytes.len())
        .ok_or_else(|| {
            TraceError::InvalidArgument("ELF evidence byte range exceeds the file".to_string())
        })?;
    let payload = EvidenceSliceModuleBytesPayload {
        requested_module_offset: format!("0x{offset:x}"),
        start_module_offset: format!("0x{start_offset:x}"),
        file_offset,
        virtual_address: format!("0x{virtual_address:x}"),
        segment_index: segment.index,
        readable: segment.readable,
        writable: segment.writable,
        executable: segment.executable,
        bytes_hex: bytes_to_hex(&bytes[file_start..file_end]),
        binary_sha256: layout.identity.binary_sha256,
        build_id: layout.identity.build_id,
    };
    output.records.push(make_record(
        &artifact.artifact_id,
        locator,
        length < requested_length,
        EvidenceSliceRecordPayload::ModuleBytes(payload),
    )?);
    Ok(output)
}

fn json_pointer_escape(value: &str) -> String {
    value.replace('~', "~0").replace('/', "~1")
}

fn scalar_matches_locator(key: &str, value: &Value, locator: &EvidenceSliceLocator) -> bool {
    let key = key.to_ascii_lowercase();
    if key.contains("offset") {
        if let Some(expected) = locator
            .module_offset
            .as_deref()
            .and_then(|value| parse_hex_addr(value).ok())
        {
            let observed = value
                .as_str()
                .and_then(|value| parse_hex_addr(value).ok())
                .or_else(|| value.as_u64());
            if observed == Some(expected) {
                return true;
            }
        }
    }
    if (key == "index" || (key.contains("event") && key.contains("index")))
        && locator.event_index.is_some()
        && value.as_u64() == locator.event_index
    {
        return true;
    }
    if key.contains("seq") {
        let expected = locator
            .trace_seq
            .or_else(|| locator.trace_line.and_then(|line| line.checked_sub(1)));
        if expected.is_some() && value.as_u64() == expected {
            return true;
        }
    }
    false
}

fn find_json_matches(
    value: &Value,
    locator: &EvidenceSliceLocator,
    pointer: &str,
    matches: &mut Vec<JsonMatch>,
) {
    if matches.len() >= MAX_JSON_MATCHES_PER_REFERENCE {
        return;
    }
    match value {
        Value::Object(object) => {
            if let Some((field, _)) = object
                .iter()
                .find(|(key, value)| scalar_matches_locator(key, value, locator))
            {
                matches.push(JsonMatch {
                    pointer: pointer.to_string(),
                    field: field.clone(),
                    value: value.clone(),
                });
                if matches.len() >= MAX_JSON_MATCHES_PER_REFERENCE {
                    return;
                }
            }
            for (key, child) in object {
                let child_pointer = format!("{pointer}/{}", json_pointer_escape(key));
                find_json_matches(child, locator, &child_pointer, matches);
                if matches.len() >= MAX_JSON_MATCHES_PER_REFERENCE {
                    return;
                }
            }
        }
        Value::Array(array) => {
            for (index, child) in array.iter().enumerate() {
                let child_pointer = format!("{pointer}/{index}");
                find_json_matches(child, locator, &child_pointer, matches);
                if matches.len() >= MAX_JSON_MATCHES_PER_REFERENCE {
                    return;
                }
            }
        }
        _ => {}
    }
}

fn semantic_json_match(value: &Value, locator: &EvidenceSliceLocator) -> Option<JsonMatch> {
    let raw = locator.raw.trim();
    let pointer = raw
        .strip_prefix("json-pointer:")
        .or_else(|| raw.starts_with('/').then_some(raw));
    if let Some(pointer) = pointer {
        let fragment = value.pointer(pointer)?;
        return Some(JsonMatch {
            pointer: pointer.to_string(),
            field: "json-pointer".to_string(),
            value: fragment.clone(),
        });
    }
    let family = raw
        .split_once('/')
        .map(|(family, _)| family)
        .unwrap_or(raw)
        .trim()
        .to_ascii_lowercase();
    matches!(
        family.as_str(),
        "runtime-attestation"
            | "crypto-kat"
            | "coverage-reconciliation"
            | "analysis"
            | "analysis-report"
            | "unicorn"
            | "angr"
            | "ida"
            | "ollvm"
            | "record"
    )
    .then(|| JsonMatch {
        pointer: "".to_string(),
        field: format!("semantic-locator:{family}"),
        value: value.clone(),
    })
}

fn truncate_json_value(value: &Value, depth: usize, truncated: &mut bool) -> Value {
    if depth >= 8 {
        *truncated = true;
        return Value::String("[depth-truncated]".to_string());
    }
    match value {
        Value::String(value) => {
            let (value, was_truncated) = truncate_text(value, MAX_CAPTURE_VALUE_CHARS);
            *truncated |= was_truncated;
            Value::String(value)
        }
        Value::Array(values) => {
            if values.len() > 128 {
                *truncated = true;
            }
            Value::Array(
                values
                    .iter()
                    .take(128)
                    .map(|value| truncate_json_value(value, depth + 1, truncated))
                    .collect(),
            )
        }
        Value::Object(values) => {
            if values.len() > 128 {
                *truncated = true;
            }
            Value::Object(
                values
                    .iter()
                    .take(128)
                    .map(|(key, value)| {
                        (
                            key.clone(),
                            truncate_json_value(value, depth + 1, truncated),
                        )
                    })
                    .collect(),
            )
        }
        _ => value.clone(),
    }
}

fn materialize_json(
    path: &Path,
    artifact: &TraceCaseArtifact,
    locator: &EvidenceSliceLocator,
    config: &EvidenceSliceConfig,
) -> Result<MaterializationResult> {
    let mut output = MaterializationResult::default();
    if !config.include_sensitive_values
        && matches!(
            artifact.kind,
            TraceCaseArtifactKind::RuntimeAttestation
                | TraceCaseArtifactKind::UnicornResult
                | TraceCaseArtifactKind::AngrResult
                | TraceCaseArtifactKind::AnalysisReport
                | TraceCaseArtifactKind::CryptoKat
                | TraceCaseArtifactKind::CryptoReport
                | TraceCaseArtifactKind::EvidenceSlice
                | TraceCaseArtifactKind::Other
        )
    {
        output.warnings.push(format!(
            "{} JSON fragments were omitted because includeSensitiveValues is false.",
            artifact.kind.as_str()
        ));
        return Ok(output);
    }
    let bytes = read_bounded(path, MAX_MINIMAL_EVIDENCE_SLICE_BYTES * 4, "JSON evidence")?;
    let value: Value = serde_json::from_slice(&bytes).map_err(|error| {
        TraceError::InvalidArgument(format!("evidence source is not strict JSON: {error}"))
    })?;
    let mut matches = Vec::new();
    find_json_matches(&value, locator, "", &mut matches);
    if matches.is_empty() {
        matches.extend(semantic_json_match(&value, locator));
    }
    if matches.is_empty() {
        output.warnings.push(
            "No JSON object matched the exact JSON pointer, structured semantic locator, module offset, event index, or trace sequence locator."
                .to_string(),
        );
        return Ok(output);
    }
    for item in matches {
        let mut truncated = false;
        let fragment = truncate_json_value(&item.value, 0, &mut truncated);
        let serialized = serde_json::to_vec(&fragment)
            .map_err(|error| TraceError::Internal(error.to_string()))?;
        if serialized.len() > MAX_JSON_FRAGMENT_BYTES {
            truncated = true;
        }
        let payload = EvidenceSliceJsonFragmentPayload {
            source_json_pointer: item.pointer,
            matched_field: item.field,
            fragment,
            truncated,
        };
        output.records.push(make_record(
            &artifact.artifact_id,
            locator,
            truncated,
            EvidenceSliceRecordPayload::JsonFragment(payload),
        )?);
    }
    Ok(output)
}

fn materialize_artifact_identity(
    artifact: &TraceCaseArtifact,
    locator: &EvidenceSliceLocator,
) -> Result<MaterializationResult> {
    let payload = EvidenceSliceJsonFragmentPayload {
        source_json_pointer: format!("case.artifacts/{}", artifact.artifact_id),
        matched_field: "artifact-sha256".to_string(),
        fragment: serde_json::json!({
            "artifactId": artifact.artifact_id,
            "kind": artifact.kind,
            "storedPath": artifact.path,
            "sha256": artifact.sha256,
            "fileSize": artifact.file_size,
            "parentArtifactIds": artifact.parent_artifact_ids,
        }),
        truncated: false,
    };
    Ok(MaterializationResult {
        records: vec![make_record(
            &artifact.artifact_id,
            locator,
            false,
            EvidenceSliceRecordPayload::JsonFragment(payload),
        )?],
        warnings: Vec::new(),
    })
}

fn materialize_reference(
    engine: &TraceEngine,
    case_path: &str,
    artifact: &TraceCaseArtifact,
    reference: &EvidenceSliceReference,
    trace_session_id: Option<&str>,
    config: &EvidenceSliceConfig,
) -> Result<MaterializationResult> {
    if matches!(
        reference.locator.raw.trim().to_ascii_lowercase().as_str(),
        "sha256" | "file-sha256" | "artifact-sha256"
    ) {
        return materialize_artifact_identity(artifact, &reference.locator);
    }
    let path = resolve_trace_case_artifact_path(case_path, &artifact.path)?;
    match artifact.kind {
        TraceCaseArtifactKind::Trace => materialize_trace(
            engine,
            trace_session_id,
            artifact,
            &reference.locator,
            config,
        ),
        TraceCaseArtifactKind::FridaCapture => {
            materialize_frida(&path, artifact, &reference.locator, config)
        }
        TraceCaseArtifactKind::StaticBinary => {
            materialize_static_binary(&path, artifact, &reference.locator, config)
        }
        _ => materialize_json(&path, artifact, &reference.locator, config),
    }
}

fn record_kind(record: &EvidenceSliceRecord) -> &'static str {
    match record.payload {
        EvidenceSliceRecordPayload::TraceLines(_) => "trace-lines",
        EvidenceSliceRecordPayload::Memory(_) => "memory",
        EvidenceSliceRecordPayload::FridaEvent(_) => "frida-event",
        EvidenceSliceRecordPayload::ModuleBytes(_) => "module-bytes",
        EvidenceSliceRecordPayload::JsonFragment(_) => "json-fragment",
    }
}

fn recompute_summary(
    selected_claim_ids: &[String],
    sources: &[EvidenceSliceSourceArtifact],
    references: &[EvidenceSliceReference],
    records: &[EvidenceSliceRecord],
    payload_bytes: u64,
) -> MinimalEvidenceSliceSummary {
    let materialized_reference_count = references
        .iter()
        .filter(|reference| !reference.record_ids.is_empty())
        .count() as u64;
    let unresolved_reference_count = references.len() as u64 - materialized_reference_count;
    let truncated_record_count = records.iter().filter(|record| record.truncated).count() as u64;
    let mut summary = MinimalEvidenceSliceSummary {
        selected_claim_count: selected_claim_ids.len() as u64,
        selected_reference_count: references.len() as u64,
        materialized_reference_count,
        unresolved_reference_count,
        source_artifact_count: sources.len() as u64,
        record_count: records.len() as u64,
        truncated_record_count,
        contains_sensitive_values: records.iter().any(|record| match &record.payload {
            EvidenceSliceRecordPayload::TraceLines(payload) => !payload.values_omitted,
            EvidenceSliceRecordPayload::Memory(_) => true,
            EvidenceSliceRecordPayload::FridaEvent(payload) => payload.sensitive_values_included,
            EvidenceSliceRecordPayload::ModuleBytes(_) => false,
            EvidenceSliceRecordPayload::JsonFragment(_) => true,
        }),
        payload_bytes,
        materialization_complete: unresolved_reference_count == 0 && truncated_record_count == 0,
        ..Default::default()
    };
    for record in records {
        match record.payload {
            EvidenceSliceRecordPayload::TraceLines(_) => summary.trace_line_record_count += 1,
            EvidenceSliceRecordPayload::Memory(_) => summary.memory_record_count += 1,
            EvidenceSliceRecordPayload::FridaEvent(_) => summary.frida_event_record_count += 1,
            EvidenceSliceRecordPayload::ModuleBytes(_) => summary.module_bytes_record_count += 1,
            EvidenceSliceRecordPayload::JsonFragment(_) => summary.json_fragment_record_count += 1,
        }
    }
    summary
}

fn node(
    node_id: String,
    kind: ProvenanceNodeKind,
    label: String,
    attributes: impl IntoIterator<Item = (String, String)>,
) -> TypedProvenanceNode {
    TypedProvenanceNode {
        node_id,
        kind,
        label,
        attributes: attributes.into_iter().collect(),
    }
}

fn edge(from_node_id: &str, to_node_id: &str, relation: ProvenanceRelation) -> TypedProvenanceEdge {
    TypedProvenanceEdge {
        edge_id: stable_id(
            "edge",
            &[from_node_id, to_node_id, &format!("{relation:?}")],
        ),
        from_node_id: from_node_id.to_string(),
        to_node_id: to_node_id.to_string(),
        relation,
    }
}

fn build_provenance_graph(
    case: &TraceAnalysisCase,
    claims: &[ClaimSource],
    sources: &[EvidenceSliceSourceArtifact],
    references: &[EvidenceSliceReference],
    records: &[EvidenceSliceRecord],
) -> TypedProvenanceGraph {
    let case_node_id = format!("case:{}", case.case_id);
    let mut nodes = BTreeMap::<String, TypedProvenanceNode>::new();
    let mut edges = BTreeMap::<String, TypedProvenanceEdge>::new();
    nodes.insert(
        case_node_id.clone(),
        node(
            case_node_id.clone(),
            ProvenanceNodeKind::Case,
            case.title.clone(),
            [("caseId".to_string(), case.case_id.clone())],
        ),
    );

    for claim in claims {
        let claim_node_id = format!("claim:{}", claim.claim.claim_id);
        nodes.entry(claim_node_id.clone()).or_insert_with(|| {
            node(
                claim_node_id.clone(),
                ProvenanceNodeKind::Claim,
                claim.claim.statement.clone(),
                [
                    ("claimId".to_string(), claim.claim.claim_id.clone()),
                    ("scope".to_string(), claim.claim.scope.clone()),
                    ("source".to_string(), claim.source.clone()),
                ],
            )
        });
        let item = edge(&case_node_id, &claim_node_id, ProvenanceRelation::Contains);
        edges.insert(item.edge_id.clone(), item);
    }

    let source_by_id = sources
        .iter()
        .map(|source| (source.artifact_id.as_str(), source))
        .collect::<HashMap<_, _>>();
    for source in sources {
        let artifact_node_id = format!("artifact:{}", source.artifact_id);
        nodes.insert(
            artifact_node_id.clone(),
            node(
                artifact_node_id.clone(),
                ProvenanceNodeKind::Artifact,
                source.label.clone(),
                [
                    ("artifactId".to_string(), source.artifact_id.clone()),
                    ("kind".to_string(), source.kind.as_str().to_string()),
                    ("sha256".to_string(), source.sha256.clone()),
                    ("role".to_string(), source.role.clone()),
                ],
            ),
        );
        let item = edge(
            &case_node_id,
            &artifact_node_id,
            ProvenanceRelation::Contains,
        );
        edges.insert(item.edge_id.clone(), item);
        for parent_id in &source.parent_artifact_ids {
            if source_by_id.contains_key(parent_id.as_str()) {
                let item = edge(
                    &format!("artifact:{parent_id}"),
                    &artifact_node_id,
                    ProvenanceRelation::ParentOf,
                );
                edges.insert(item.edge_id.clone(), item);
            }
        }
        if source.kind == TraceCaseArtifactKind::StaticBinary {
            let build_node_id = format!("build:{}", source.sha256);
            nodes.entry(build_node_id.clone()).or_insert_with(|| {
                node(
                    build_node_id.clone(),
                    ProvenanceNodeKind::Build,
                    source.label.clone(),
                    [
                        ("binarySha256".to_string(), source.sha256.clone()),
                        (
                            "identityScope".to_string(),
                            "selected-file-only".to_string(),
                        ),
                    ],
                )
            });
            let item = edge(
                &artifact_node_id,
                &build_node_id,
                ProvenanceRelation::BoundToBuild,
            );
            edges.insert(item.edge_id.clone(), item);
        }
    }

    let claim_by_id = claims
        .iter()
        .map(|item| (item.claim.claim_id.as_str(), item))
        .collect::<HashMap<_, _>>();
    let record_by_id = records
        .iter()
        .map(|record| (record.record_id.as_str(), record))
        .collect::<HashMap<_, _>>();
    for reference in references {
        let reference_node_id = format!("reference:{}", reference.reference_id);
        nodes.insert(
            reference_node_id.clone(),
            node(
                reference_node_id.clone(),
                ProvenanceNodeKind::EvidenceReference,
                reference.description.clone(),
                [
                    ("referenceId".to_string(), reference.reference_id.clone()),
                    ("role".to_string(), reference.role.as_str().to_string()),
                    ("locator".to_string(), reference.locator.raw.clone()),
                ],
            ),
        );
        if claim_by_id.contains_key(reference.claim_id.as_str()) {
            let item = edge(
                &format!("claim:{}", reference.claim_id),
                &reference_node_id,
                if reference.role == EvidenceSliceReferenceRole::Supporting {
                    ProvenanceRelation::Supports
                } else {
                    ProvenanceRelation::Counters
                },
            );
            edges.insert(item.edge_id.clone(), item);
        }
        for record_id in &reference.record_ids {
            if record_by_id.contains_key(record_id.as_str()) {
                let item = edge(
                    &reference_node_id,
                    &format!("record:{record_id}"),
                    ProvenanceRelation::MaterializedAs,
                );
                edges.insert(item.edge_id.clone(), item);
            }
        }
    }

    for record in records {
        let record_node_id = format!("record:{}", record.record_id);
        nodes.insert(
            record_node_id.clone(),
            node(
                record_node_id.clone(),
                ProvenanceNodeKind::EvidenceRecord,
                record_kind(record).to_string(),
                [
                    ("recordId".to_string(), record.record_id.clone()),
                    ("contentSha256".to_string(), record.content_sha256.clone()),
                    ("locator".to_string(), record.locator.raw.clone()),
                ],
            ),
        );
        let item = edge(
            &record_node_id,
            &format!("artifact:{}", record.source_artifact_id),
            ProvenanceRelation::DerivedFrom,
        );
        edges.insert(item.edge_id.clone(), item);

        match &record.payload {
            EvidenceSliceRecordPayload::TraceLines(_) => {
                let process_node_id = format!("process-run:trace:{}", record.source_artifact_id);
                nodes.entry(process_node_id.clone()).or_insert_with(|| {
                    node(
                        process_node_id.clone(),
                        ProvenanceNodeKind::ProcessRun,
                        "Trace-file execution context".to_string(),
                        [
                            ("identityStatus".to_string(), "trace-file-only".to_string()),
                            (
                                "warning".to_string(),
                                "No cryptographic OS process identity is present.".to_string(),
                            ),
                        ],
                    )
                });
                let item = edge(
                    &record_node_id,
                    &process_node_id,
                    ProvenanceRelation::ObservedIn,
                );
                edges.insert(item.edge_id.clone(), item);
            }
            EvidenceSliceRecordPayload::Memory(_) => {
                let process_node_id = format!("process-run:trace:{}", record.source_artifact_id);
                nodes.entry(process_node_id.clone()).or_insert_with(|| {
                    node(
                        process_node_id.clone(),
                        ProvenanceNodeKind::ProcessRun,
                        "Trace-file execution context".to_string(),
                        [("identityStatus".to_string(), "trace-file-only".to_string())],
                    )
                });
                let item = edge(
                    &record_node_id,
                    &process_node_id,
                    ProvenanceRelation::ObservedIn,
                );
                edges.insert(item.edge_id.clone(), item);
            }
            EvidenceSliceRecordPayload::FridaEvent(payload) => {
                let session = payload
                    .capture_session_id
                    .clone()
                    .unwrap_or_else(|| "unknown-capture-session".to_string());
                let process_node_id =
                    stable_id("process-run", &[&record.source_artifact_id, &session]);
                nodes.entry(process_node_id.clone()).or_insert_with(|| {
                    node(
                        process_node_id.clone(),
                        ProvenanceNodeKind::ProcessRun,
                        "Frida capture execution context".to_string(),
                        [
                            ("captureSessionId".to_string(), session.clone()),
                            (
                                "identityStatus".to_string(),
                                "capture-session-only".to_string(),
                            ),
                            (
                                "warning".to_string(),
                                "captureSessionId is not OS process attestation.".to_string(),
                            ),
                        ],
                    )
                });
                let thread_node_id = stable_id(
                    "thread",
                    &[&process_node_id, &payload.thread_id.to_string()],
                );
                nodes.entry(thread_node_id.clone()).or_insert_with(|| {
                    node(
                        thread_node_id.clone(),
                        ProvenanceNodeKind::Thread,
                        format!("thread {}", payload.thread_id),
                        [("threadId".to_string(), payload.thread_id.to_string())],
                    )
                });
                let event_node_id = stable_id(
                    "event",
                    &[&record.source_artifact_id, &payload.event_index.to_string()],
                );
                nodes.insert(
                    event_node_id.clone(),
                    node(
                        event_node_id.clone(),
                        ProvenanceNodeKind::Event,
                        format!("{} {}", payload.event, payload.function_name),
                        [
                            ("eventIndex".to_string(), payload.event_index.to_string()),
                            ("hookId".to_string(), payload.hook_id.clone()),
                        ],
                    ),
                );
                for item in [
                    edge(
                        &record_node_id,
                        &event_node_id,
                        ProvenanceRelation::DerivedFrom,
                    ),
                    edge(
                        &event_node_id,
                        &process_node_id,
                        ProvenanceRelation::ObservedIn,
                    ),
                    edge(
                        &event_node_id,
                        &thread_node_id,
                        ProvenanceRelation::ExecutedOnThread,
                    ),
                ] {
                    edges.insert(item.edge_id.clone(), item);
                }
            }
            EvidenceSliceRecordPayload::ModuleBytes(payload) => {
                let build_node_id = format!("build:{}", payload.binary_sha256);
                nodes.entry(build_node_id.clone()).or_insert_with(|| {
                    node(
                        build_node_id.clone(),
                        ProvenanceNodeKind::Build,
                        "Exact ELF build".to_string(),
                        [
                            ("binarySha256".to_string(), payload.binary_sha256.clone()),
                            (
                                "identityScope".to_string(),
                                "selected-file-only".to_string(),
                            ),
                        ],
                    )
                });
                let item = edge(
                    &record_node_id,
                    &build_node_id,
                    ProvenanceRelation::BoundToBuild,
                );
                edges.insert(item.edge_id.clone(), item);
            }
            EvidenceSliceRecordPayload::JsonFragment(_) => {}
        }
    }

    TypedProvenanceGraph {
        nodes: nodes.into_values().collect(),
        edges: edges.into_values().collect(),
    }
}

fn serialized_content_bytes(content: &MinimalEvidenceSliceContent) -> Result<u64> {
    let mut canonical = content.clone();
    canonical.summary.payload_bytes = 0;
    let bytes =
        serde_json::to_vec(&canonical).map_err(|error| TraceError::Internal(error.to_string()))?;
    Ok(bytes.len().min(u64::MAX as usize) as u64)
}

pub fn generate_minimal_evidence_slice(
    engine: &TraceEngine,
    request: &MinimalEvidenceSliceRequest,
) -> Result<MinimalEvidenceSliceBundle> {
    validate_request(request)?;
    let document = load_trace_analysis_case(&request.case_path)?;
    let claims = collect_claims(&request.case_path, request.include_generated_claims)?;
    let selected_claim_ids = if request.claim_ids.is_empty() {
        claims
            .iter()
            .map(|item| item.claim.claim_id.clone())
            .collect::<BTreeSet<_>>()
    } else {
        let requested = request
            .claim_ids
            .iter()
            .map(|value| value.trim().to_string())
            .filter(|value| !value.is_empty())
            .collect::<BTreeSet<_>>();
        let known = claims
            .iter()
            .map(|item| item.claim.claim_id.as_str())
            .collect::<HashSet<_>>();
        if let Some(missing) = requested
            .iter()
            .find(|claim_id| !known.contains(claim_id.as_str()))
        {
            return Err(TraceError::InvalidArgument(format!(
                "selected claim not found in the case or current Replay Doctor output: {missing}"
            )));
        }
        requested
    };
    let selected_claims = claims
        .iter()
        .filter(|item| selected_claim_ids.contains(&item.claim.claim_id))
        .cloned()
        .collect::<Vec<_>>();
    let mut references = Vec::new();
    for item in &selected_claims {
        for evidence in &item.claim.supporting_evidence {
            references.push(make_reference(
                &item.source,
                &item.claim,
                EvidenceSliceReferenceRole::Supporting,
                evidence,
            )?);
        }
        for evidence in &item.claim.counter_evidence {
            references.push(make_reference(
                &item.source,
                &item.claim,
                EvidenceSliceReferenceRole::Counter,
                evidence,
            )?);
        }
    }
    references.sort_by(|left, right| {
        left.claim_id
            .cmp(&right.claim_id)
            .then_with(|| left.role.cmp(&right.role))
            .then_with(|| left.reference_id.cmp(&right.reference_id))
    });
    references.dedup_by(|left, right| left.reference_id == right.reference_id);
    if references.len() > MAX_REFERENCES {
        return Err(TraceError::InvalidArgument(format!(
            "selected claims contain more than {MAX_REFERENCES} evidence references"
        )));
    }
    let selected_artifact_ids = references
        .iter()
        .map(|reference| reference.artifact_id.clone())
        .collect::<BTreeSet<_>>();
    let sources = source_artifacts(&document.case, &selected_artifact_ids)?;
    let artifact_by_id = document
        .case
        .artifacts
        .iter()
        .map(|artifact| (artifact.artifact_id.as_str(), artifact))
        .collect::<HashMap<_, _>>();
    let bindings = trace_binding_map(
        engine,
        &request.case_path,
        &document.case,
        &request.trace_session_bindings,
    )?;
    let config = config_from_request(request);
    let mut records_by_id = BTreeMap::<String, EvidenceSliceRecord>::new();
    let mut warnings = Vec::new();
    for reference in &mut references {
        let Some(artifact) = artifact_by_id.get(reference.artifact_id.as_str()) else {
            reference.status = "unresolved-artifact".to_string();
            reference.warnings.push(format!(
                "Case artifact {} does not exist.",
                reference.artifact_id
            ));
            continue;
        };
        if records_by_id.len() >= config.max_records as usize {
            reference.status = "truncated-record-budget".to_string();
            reference.warnings.push(
                "The slice record budget was exhausted before this reference could be materialized."
                    .to_string(),
            );
            continue;
        }
        let result = materialize_reference(
            engine,
            &request.case_path,
            artifact,
            reference,
            bindings.get(reference.artifact_id.as_str()).copied(),
            &config,
        )?;
        reference.warnings.extend(result.warnings.clone());
        warnings.extend(
            result
                .warnings
                .into_iter()
                .map(|warning| format!("{}: {warning}", reference.reference_id)),
        );
        for record in result.records {
            if records_by_id.len() >= config.max_records as usize {
                reference.status = "truncated-record-budget".to_string();
                reference
                    .warnings
                    .push("The slice record budget truncated this reference.".to_string());
                break;
            }
            reference.record_ids.push(record.record_id.clone());
            records_by_id
                .entry(record.record_id.clone())
                .or_insert(record);
        }
        reference.record_ids.sort();
        reference.record_ids.dedup();
        if reference.record_ids.is_empty() {
            reference.status = "unresolved".to_string();
        } else if reference.record_ids.iter().any(|record_id| {
            records_by_id
                .get(record_id)
                .is_some_and(|record| record.truncated)
        }) {
            reference.status = "materialized-partial".to_string();
        } else {
            reference.status = "materialized".to_string();
        }
    }
    let records = records_by_id.into_values().collect::<Vec<_>>();
    let selected_claim_ids = selected_claim_ids.into_iter().collect::<Vec<_>>();
    let provenance = build_provenance_graph(
        &document.case,
        &selected_claims,
        &sources,
        &references,
        &records,
    );
    let limitations = vec![
        "A minimal evidence slice preserves exact selected bytes/records and provenance; it does not prove that a claim is semantically true."
            .to_string(),
        "Dynamic trace and Frida records cover only executed/captured states. Missing paths, uncaptured memory, and alternate inputs remain unknown."
            .to_string(),
        "Build nodes identify selected files only. A runtime-image attestation is still required to prove that an exact ELF was mapped in a process."
            .to_string(),
        "Process-run nodes based on trace files or captureSessionId are scoped execution contexts, not cryptographic OS process identities."
            .to_string(),
        "OLLVM, IDA, angr, and Unicorn structural evidence remains Candidate/Related even when materialized and hash-valid."
            .to_string(),
    ];
    let mut content = MinimalEvidenceSliceContent {
        case_id: document.case.case_id.clone(),
        case_title: document.case.title.clone(),
        config,
        selected_claim_ids,
        source_artifacts: sources,
        references,
        records,
        provenance,
        summary: MinimalEvidenceSliceSummary::default(),
        warnings,
        limitations,
    };
    content.summary = recompute_summary(
        &content.selected_claim_ids,
        &content.source_artifacts,
        &content.references,
        &content.records,
        0,
    );
    let payload_bytes = serialized_content_bytes(&content)?;
    content.summary.payload_bytes = payload_bytes;
    if payload_bytes > content.config.max_total_payload_bytes {
        return Err(TraceError::InvalidArgument(format!(
            "minimal evidence slice payload is {payload_bytes} bytes, exceeding maxTotalPayloadBytes {}; reduce selected claims/context or sensitive capture size",
            content.config.max_total_payload_bytes
        )));
    }
    let content_sha256 = sha256_json(&content)?;
    Ok(MinimalEvidenceSliceBundle {
        schema: MINIMAL_EVIDENCE_SLICE_SCHEMA.to_string(),
        slice_id: stable_id("slice", &[&content_sha256]),
        generated_at_ms: now_ms(),
        content_sha256,
        content,
    })
}

pub fn save_minimal_evidence_slice_bundle(
    bundle: &MinimalEvidenceSliceBundle,
    output_path: &str,
) -> Result<()> {
    let path = Path::new(output_path);
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .ok_or_else(|| {
            TraceError::InvalidArgument(
                "minimal evidence slice output path must include a parent directory".to_string(),
            )
        })?;
    if !parent.is_dir() {
        return Err(TraceError::InvalidArgument(format!(
            "minimal evidence slice output directory does not exist: {}",
            parent.display()
        )));
    }
    let mut bytes = serde_json::to_vec_pretty(bundle)
        .map_err(|error| TraceError::Internal(error.to_string()))?;
    bytes.push(b'\n');
    if bytes.len() as u64 > MAX_MINIMAL_EVIDENCE_SLICE_BYTES {
        return Err(TraceError::InvalidArgument(format!(
            "minimal evidence slice exceeds the {} MiB file limit",
            MAX_MINIMAL_EVIDENCE_SLICE_BYTES / (1024 * 1024)
        )));
    }
    let mut file = File::create(path)?;
    file.write_all(&bytes)?;
    file.sync_all()?;
    Ok(())
}

pub fn parse_minimal_evidence_slice_bundle(
    bytes: &[u8],
) -> std::result::Result<MinimalEvidenceSliceBundle, String> {
    if bytes.len() as u64 > MAX_MINIMAL_EVIDENCE_SLICE_BYTES {
        return Err(format!(
            "minimal evidence slice exceeds the {} MiB parse limit",
            MAX_MINIMAL_EVIDENCE_SLICE_BYTES / (1024 * 1024)
        ));
    }
    let bundle: MinimalEvidenceSliceBundle = serde_json::from_slice(bytes)
        .map_err(|error| format!("invalid minimal evidence slice JSON: {error}"))?;
    if bundle.schema != MINIMAL_EVIDENCE_SLICE_SCHEMA {
        return Err(format!(
            "unsupported minimal evidence slice schema: {}",
            bundle.schema
        ));
    }
    if bundle.content.source_artifacts.len() > MAX_SOURCE_ARTIFACTS
        || bundle.content.references.len() > MAX_REFERENCES
        || bundle.content.records.len() > MAX_RECORDS_LIMIT as usize
    {
        return Err("minimal evidence slice exceeds structural limits".to_string());
    }
    Ok(bundle)
}

fn temporary_trace_sessions(
    engine: &TraceEngine,
    case_path: &str,
    case: &TraceAnalysisCase,
    references: &[EvidenceSliceReference],
) -> Result<(HashMap<String, String>, Vec<String>)> {
    let artifact_by_id = case
        .artifacts
        .iter()
        .map(|artifact| (artifact.artifact_id.as_str(), artifact))
        .collect::<HashMap<_, _>>();
    let trace_ids = references
        .iter()
        .filter_map(|reference| {
            artifact_by_id
                .get(reference.artifact_id.as_str())
                .filter(|artifact| artifact.kind == TraceCaseArtifactKind::Trace)
                .map(|_| reference.artifact_id.clone())
        })
        .collect::<BTreeSet<_>>();
    if trace_ids.len() > MAX_TRACE_BINDINGS {
        return Err(TraceError::InvalidArgument(format!(
            "minimal evidence slice references more than {MAX_TRACE_BINDINGS} trace artifacts"
        )));
    }
    let mut sessions = HashMap::new();
    let mut opened = Vec::new();
    for artifact_id in trace_ids {
        let artifact = artifact_by_id[artifact_id.as_str()];
        let path = resolve_trace_case_artifact_path(case_path, &artifact.path)?;
        let session = engine.create_session(&path.to_string_lossy())?;
        let session_id = session.session_id.clone();
        engine.build_index(
            &session_id,
            BuildOptions {
                force_rebuild: false,
                skip_strings: true,
            },
            None,
        )?;
        sessions.insert(artifact_id, session_id.clone());
        opened.push(session_id);
    }
    Ok((sessions, opened))
}

fn validate_graph(graph: &TypedProvenanceGraph) -> std::result::Result<(), String> {
    let mut nodes = HashSet::new();
    for node in &graph.nodes {
        if node.node_id.trim().is_empty() || !nodes.insert(node.node_id.as_str()) {
            return Err(format!(
                "duplicate or empty provenance node ID: {}",
                node.node_id
            ));
        }
    }
    let mut edges = HashSet::new();
    for edge in &graph.edges {
        if !edges.insert(edge.edge_id.as_str()) {
            return Err(format!("duplicate provenance edge ID: {}", edge.edge_id));
        }
        if !nodes.contains(edge.from_node_id.as_str()) || !nodes.contains(edge.to_node_id.as_str())
        {
            return Err(format!(
                "provenance edge {} references an unknown node",
                edge.edge_id
            ));
        }
    }
    Ok(())
}

fn inspect_minimal_evidence_slice_bundle_inner(
    case_path: &str,
    bundle: &MinimalEvidenceSliceBundle,
    revalidate_generated_claims: bool,
) -> Result<MinimalEvidenceSliceInspectionReport> {
    let document = load_trace_analysis_case(case_path)?;
    let mut blockers = Vec::new();
    let mut warnings = Vec::new();
    let mut stale_claim_ids = Vec::new();
    let mut mismatched_record_ids = Vec::new();
    let content_sha256 = sha256_json(&bundle.content)?;
    let content_sha256_matched = content_sha256.eq_ignore_ascii_case(&bundle.content_sha256)
        && bundle.slice_id == stable_id("slice", &[&content_sha256]);
    if !content_sha256_matched {
        blockers.push(
            "Slice content SHA-256 or sliceId does not match the canonical content.".to_string(),
        );
    }
    if bundle.content.case_id != document.case.case_id {
        blockers.push(format!(
            "Slice caseId {} does not match case {}.",
            bundle.content.case_id, document.case.case_id
        ));
    }
    let case_artifacts = document
        .case
        .artifacts
        .iter()
        .map(|artifact| (artifact.artifact_id.as_str(), artifact))
        .collect::<HashMap<_, _>>();
    let mut source_artifacts_matched = true;
    for source in &bundle.content.source_artifacts {
        let Some(artifact) = case_artifacts.get(source.artifact_id.as_str()) else {
            source_artifacts_matched = false;
            blockers.push(format!(
                "Source artifact {} is missing from the case.",
                source.artifact_id
            ));
            continue;
        };
        if artifact.kind != source.kind
            || artifact.file_size != source.file_size
            || !artifact.sha256.eq_ignore_ascii_case(&source.sha256)
            || artifact.path != source.stored_path
            || artifact.parent_artifact_ids != source.parent_artifact_ids
        {
            source_artifacts_matched = false;
            blockers.push(format!(
                "Source artifact metadata changed for {}.",
                source.artifact_id
            ));
            continue;
        }
        let path = resolve_trace_case_artifact_path(case_path, &artifact.path)?;
        match hash_file(&path) {
            Ok((sha256, size))
                if size == source.file_size && sha256.eq_ignore_ascii_case(&source.sha256) => {}
            Ok(_) => {
                source_artifacts_matched = false;
                blockers.push(format!(
                    "Source artifact bytes changed for {}.",
                    source.artifact_id
                ));
            }
            Err(error) => {
                source_artifacts_matched = false;
                blockers.push(format!(
                    "Source artifact {} cannot be read: {error}",
                    source.artifact_id
                ));
            }
        }
    }
    let mut current_claims = if revalidate_generated_claims {
        collect_claims(case_path, bundle.content.config.include_generated_claims)?
    } else {
        persisted_claims(&document.case)
    };
    let mut unrevalidated_generated_claim_ids = Vec::new();
    if !revalidate_generated_claims {
        for claim_id in &bundle.content.selected_claim_ids {
            let generated = bundle.content.references.iter().any(|reference| {
                reference.claim_id == *claim_id && reference.claim_source == "generated"
            }) || bundle.content.provenance.nodes.iter().any(|node| {
                node.kind == ProvenanceNodeKind::Claim
                    && node.node_id == format!("claim:{claim_id}")
                    && node.attributes.get("source").map(String::as_str) == Some("generated")
            });
            if !generated {
                continue;
            }
            unrevalidated_generated_claim_ids.push(claim_id.clone());
            if !current_claims
                .iter()
                .any(|item| item.claim.claim_id == *claim_id)
            {
                if let Some(claim) = generated_claim_from_graph(bundle, claim_id) {
                    current_claims.push(claim);
                }
            }
        }
        unrevalidated_generated_claim_ids.sort();
        unrevalidated_generated_claim_ids.dedup();
        if !unrevalidated_generated_claim_ids.is_empty() {
            warnings.push(
                "Generated Replay Doctor claim fingerprints were not recursively regenerated while Replay Doctor inspected this slice; persisted claims, source bytes, records, hashes, and typed provenance were still checked independently."
                    .to_string(),
            );
        }
    }
    let current_claim_by_id = current_claims
        .iter()
        .map(|item| (item.claim.claim_id.as_str(), item))
        .collect::<HashMap<_, _>>();
    let mut claim_bindings_matched = true;
    for reference in &bundle.content.references {
        if !revalidate_generated_claims && reference.claim_source == "generated" {
            continue;
        }
        let matched = current_claim_by_id
            .get(reference.claim_id.as_str())
            .and_then(|item| claim_fingerprint(&item.claim).ok())
            .is_some_and(|fingerprint| fingerprint == reference.claim_fingerprint);
        if !matched {
            claim_bindings_matched = false;
            stale_claim_ids.push(reference.claim_id.clone());
        }
    }
    stale_claim_ids.sort();
    stale_claim_ids.dedup();
    if !claim_bindings_matched {
        warnings.push(
            "One or more claim statements/scopes/status values changed after the slice was generated. Source records remain independently checked, but claim bindings are stale."
                .to_string(),
        );
    }

    let stored_record_by_id = bundle
        .content
        .records
        .iter()
        .map(|record| (record.record_id.as_str(), record))
        .collect::<HashMap<_, _>>();
    let engine = TraceEngine::new();
    let (temporary_sessions, opened_sessions) = temporary_trace_sessions(
        &engine,
        case_path,
        &document.case,
        &bundle.content.references,
    )?;
    let request = request_from_config(case_path, &bundle.content.config);
    let mut record_content_matched = true;
    for reference in &bundle.content.references {
        let Some(artifact) = case_artifacts.get(reference.artifact_id.as_str()) else {
            continue;
        };
        let result = materialize_reference(
            &engine,
            case_path,
            artifact,
            reference,
            temporary_sessions
                .get(reference.artifact_id.as_str())
                .map(String::as_str),
            &config_from_request(&request),
        )?;
        let regenerated = result
            .records
            .into_iter()
            .map(|record| (record.record_id.clone(), record))
            .collect::<HashMap<_, _>>();
        for record_id in &reference.record_ids {
            let matches = stored_record_by_id
                .get(record_id.as_str())
                .zip(regenerated.get(record_id))
                .is_some_and(|(stored, current)| {
                    *stored == current
                        && sha256_json(&stored.payload)
                            .ok()
                            .is_some_and(|hash| hash == stored.content_sha256)
                });
            if !matches {
                record_content_matched = false;
                mismatched_record_ids.push(record_id.clone());
            }
        }
    }
    for session_id in opened_sessions {
        let _ = engine.close_session(&session_id);
    }
    mismatched_record_ids.sort();
    mismatched_record_ids.dedup();
    if !record_content_matched {
        blockers.push(
            "At least one evidence record does not recompute from the exact bound source artifact."
                .to_string(),
        );
    }

    let selected_claims = current_claims
        .iter()
        .filter(|item| {
            bundle
                .content
                .selected_claim_ids
                .contains(&item.claim.claim_id)
        })
        .cloned()
        .collect::<Vec<_>>();
    let expected_graph = build_provenance_graph(
        &document.case,
        &selected_claims,
        &bundle.content.source_artifacts,
        &bundle.content.references,
        &bundle.content.records,
    );
    let provenance_graph_valid = validate_graph(&bundle.content.provenance).is_ok()
        && bundle.content.provenance == expected_graph;
    if !provenance_graph_valid {
        blockers.push(
            "Typed provenance nodes/edges do not match the canonical graph reconstructed from the slice."
                .to_string(),
        );
    }
    let payload_bytes = serialized_content_bytes(&bundle.content)?;
    let summary_recomputed = recompute_summary(
        &bundle.content.selected_claim_ids,
        &bundle.content.source_artifacts,
        &bundle.content.references,
        &bundle.content.records,
        payload_bytes,
    );
    if summary_recomputed != bundle.content.summary {
        blockers.push(
            "Serialized evidence-slice summary does not match recomputed counts/status."
                .to_string(),
        );
    }
    if payload_bytes > bundle.content.config.max_total_payload_bytes
        || payload_bytes > MAX_MINIMAL_EVIDENCE_SLICE_BYTES
    {
        blockers.push(
            "Evidence-slice payload exceeds its declared or protocol size limit.".to_string(),
        );
    }
    let status = if !blockers.is_empty() {
        "invalid"
    } else if !claim_bindings_matched {
        "valid-stale-claim-bindings"
    } else if !summary_recomputed.materialization_complete {
        "valid-partial"
    } else if !unrevalidated_generated_claim_ids.is_empty() {
        "valid-generated-bindings-not-revalidated"
    } else {
        "valid-complete"
    };
    Ok(MinimalEvidenceSliceInspectionReport {
        schema: MINIMAL_EVIDENCE_SLICE_INSPECTION_SCHEMA.to_string(),
        slice_id: bundle.slice_id.clone(),
        status: status.to_string(),
        content_sha256_matched,
        source_artifacts_matched,
        claim_bindings_matched,
        generated_claim_bindings_revalidated: unrevalidated_generated_claim_ids.is_empty(),
        record_content_matched,
        provenance_graph_valid,
        summary_recomputed,
        source_artifact_ids: bundle
            .content
            .source_artifacts
            .iter()
            .map(|source| source.artifact_id.clone())
            .collect(),
        stale_claim_ids,
        unrevalidated_generated_claim_ids,
        mismatched_record_ids,
        blockers,
        warnings,
        limitations: vec![
            "A valid inspection proves that selected records and graph edges recompute from exact bound source artifact bytes; it does not prove the referenced claim semantics."
                .to_string(),
            "Trace/Frida coverage remains execution-specific, and missing paths or uncaptured state remain unknown."
                .to_string(),
            "Structural OLLVM/IDA/angr/Unicorn records remain Candidate/Related and cannot become Verified from slice validity."
                .to_string(),
        ],
    })
}

pub fn inspect_minimal_evidence_slice_bundle(
    case_path: &str,
    bundle: &MinimalEvidenceSliceBundle,
) -> Result<MinimalEvidenceSliceInspectionReport> {
    inspect_minimal_evidence_slice_bundle_inner(case_path, bundle, true)
}

pub(crate) fn inspect_minimal_evidence_slice_bundle_for_replay(
    case_path: &str,
    bundle: &MinimalEvidenceSliceBundle,
) -> Result<MinimalEvidenceSliceInspectionReport> {
    inspect_minimal_evidence_slice_bundle_inner(case_path, bundle, false)
}

pub fn inspect_minimal_evidence_slice(
    case_path: &str,
    artifact_path: &str,
) -> Result<MinimalEvidenceSliceInspectionReport> {
    let bytes = read_bounded(
        Path::new(artifact_path),
        MAX_MINIMAL_EVIDENCE_SLICE_BYTES,
        "minimal evidence slice",
    )?;
    let bundle =
        parse_minimal_evidence_slice_bundle(&bytes).map_err(TraceError::InvalidArgument)?;
    inspect_minimal_evidence_slice_bundle(case_path, &bundle)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analysis_case::{
        create_trace_analysis_case, save_trace_analysis_case, TraceCaseClaimStatus,
        TraceCaseCoverageRequirement,
    };

    fn temp_path(name: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "trace-ui-evidence-slice-{}-{name}",
            uuid::Uuid::new_v4()
        ))
    }

    fn create_case_with_trace() -> (PathBuf, PathBuf, TraceEngine, String, String) {
        let trace_path = temp_path("sample.log");
        std::fs::write(
            &trace_path,
            b"[libsample.so] 0x1000!0x10 mov x0, #1; x0=0x1\n[libsample.so] 0x1004!0x14 str x0, [x2]; x2=0x2000\n",
        )
        .unwrap();
        let case_path = temp_path("sample.traceui-case");
        let mut document = create_trace_analysis_case(
            case_path.to_str().unwrap(),
            "slice test",
            Some(trace_path.to_str().unwrap()),
            None,
        )
        .unwrap();
        let trace_artifact_id = document.case.primary_trace_artifact_id.clone().unwrap();
        document.case.claims.push(TraceCaseClaim {
            claim_id: "claim-trace".to_string(),
            statement: "The selected instruction was observed.".to_string(),
            scope: "trace:sample".to_string(),
            status: TraceCaseClaimStatus::Observed,
            coverage_requirement: TraceCaseCoverageRequirement::NotRequired,
            supporting_evidence: vec![TraceCaseEvidenceRef {
                artifact_id: trace_artifact_id.clone(),
                locator: "seq:1".to_string(),
                description: "Exact observed trace line".to_string(),
            }],
            counter_evidence: Vec::new(),
            missing_evidence: Vec::new(),
            limitations: Vec::new(),
            created_by: "test".to_string(),
            created_at_ms: 1,
            updated_at_ms: 1,
        });
        save_trace_analysis_case(case_path.to_str().unwrap(), &document.case).unwrap();
        let engine = TraceEngine::new();
        let session = engine.create_session(trace_path.to_str().unwrap()).unwrap();
        engine
            .build_index(
                &session.session_id,
                BuildOptions {
                    force_rebuild: false,
                    skip_strings: true,
                },
                None,
            )
            .unwrap();
        (
            case_path,
            trace_path,
            engine,
            session.session_id,
            trace_artifact_id,
        )
    }

    #[test]
    fn materializes_and_recomputes_exact_trace_line_with_typed_graph() {
        let (case_path, trace_path, engine, session_id, artifact_id) = create_case_with_trace();
        let request = MinimalEvidenceSliceRequest {
            case_path: case_path.to_string_lossy().into_owned(),
            trace_session_bindings: vec![EvidenceSliceTraceSessionBinding {
                artifact_id,
                session_id,
            }],
            claim_ids: vec!["claim-trace".to_string()],
            include_generated_claims: false,
            include_sensitive_values: true,
            context_before: 1,
            context_after: 0,
            module_bytes_before: 16,
            module_bytes_after: 32,
            max_memory_bytes_per_record: 256,
            max_records: 32,
            max_total_payload_bytes: 1024 * 1024,
        };
        let bundle = generate_minimal_evidence_slice(&engine, &request).unwrap();
        assert_eq!(bundle.schema, MINIMAL_EVIDENCE_SLICE_SCHEMA);
        assert_eq!(bundle.content.summary.trace_line_record_count, 1);
        assert!(bundle.content.summary.materialization_complete);
        assert!(bundle
            .content
            .provenance
            .nodes
            .iter()
            .any(|node| node.kind == ProvenanceNodeKind::ProcessRun));
        let output_path = temp_path("slice.json");
        save_minimal_evidence_slice_bundle(&bundle, output_path.to_str().unwrap()).unwrap();
        let inspection = inspect_minimal_evidence_slice(
            case_path.to_str().unwrap(),
            output_path.to_str().unwrap(),
        )
        .unwrap();
        assert_eq!(inspection.status, "valid-complete");
        assert!(inspection.record_content_matched);
        assert!(inspection.provenance_graph_valid);
        let _ = std::fs::remove_file(output_path);
        let _ = std::fs::remove_file(case_path);
        let _ = std::fs::remove_file(trace_path);
    }

    #[test]
    fn forged_record_content_is_rejected_even_when_outer_hash_is_recomputed() {
        let (case_path, trace_path, engine, session_id, artifact_id) = create_case_with_trace();
        let request = MinimalEvidenceSliceRequest {
            case_path: case_path.to_string_lossy().into_owned(),
            trace_session_bindings: vec![EvidenceSliceTraceSessionBinding {
                artifact_id,
                session_id,
            }],
            claim_ids: vec!["claim-trace".to_string()],
            include_generated_claims: false,
            include_sensitive_values: true,
            context_before: 0,
            context_after: 0,
            module_bytes_before: 16,
            module_bytes_after: 32,
            max_memory_bytes_per_record: 256,
            max_records: 32,
            max_total_payload_bytes: 1024 * 1024,
        };
        let mut bundle = generate_minimal_evidence_slice(&engine, &request).unwrap();
        let EvidenceSliceRecordPayload::TraceLines(payload) =
            &mut bundle.content.records[0].payload
        else {
            panic!("expected trace lines");
        };
        payload.lines[0].disasm = "forged instruction".to_string();
        bundle.content.records[0].content_sha256 =
            sha256_json(&bundle.content.records[0].payload).unwrap();
        bundle.content.records[0].record_id = stable_id(
            "record",
            &[
                &bundle.content.records[0].source_artifact_id,
                &bundle.content.records[0].locator.raw,
                &bundle.content.records[0].content_sha256,
            ],
        );
        bundle.content.references[0].record_ids = vec![bundle.content.records[0].record_id.clone()];
        bundle.content.provenance = build_provenance_graph(
            &load_trace_analysis_case(case_path.to_str().unwrap())
                .unwrap()
                .case,
            &collect_claims(case_path.to_str().unwrap(), false).unwrap(),
            &bundle.content.source_artifacts,
            &bundle.content.references,
            &bundle.content.records,
        );
        bundle.content.summary = recompute_summary(
            &bundle.content.selected_claim_ids,
            &bundle.content.source_artifacts,
            &bundle.content.references,
            &bundle.content.records,
            serialized_content_bytes(&bundle.content).unwrap(),
        );
        bundle.content_sha256 = sha256_json(&bundle.content).unwrap();
        bundle.slice_id = stable_id("slice", &[&bundle.content_sha256]);
        let inspection =
            inspect_minimal_evidence_slice_bundle(case_path.to_str().unwrap(), &bundle).unwrap();
        assert_eq!(inspection.status, "invalid");
        assert!(!inspection.record_content_matched);
        let _ = std::fs::remove_file(case_path);
        let _ = std::fs::remove_file(trace_path);
    }
}
