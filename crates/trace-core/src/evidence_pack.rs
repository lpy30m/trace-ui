use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use sha2::Digest;

use crate::analysis_case::{
    diagnose_trace_analysis_case, load_trace_analysis_case, ReplayDoctorNextAction,
    TraceCaseArtifact, TraceCaseArtifactHealth, TraceCaseArtifactKind, TraceCaseClaim,
    TraceCaseClaimAuditEntry, TraceCaseClaimStatus, TraceCaseEvidenceRef,
};
use crate::error::{Result, TraceError};
use crate::query::coverage::CoverageCounts;
use crate::utils::parse_hex_addr;

pub const AI_EVIDENCE_PACK_SCHEMA: &str = "trace-ui/ai-evidence-pack-v1";
const MIN_TOKEN_BUDGET: u32 = 1_024;
const MAX_TOKEN_BUDGET: u32 = 65_536;
const MIN_ITEM_BUDGET: u32 = 16;
const MAX_ITEM_BUDGET: u32 = 2_048;
const MAX_CLAIM_TEXT_CHARS: usize = 1_000;
const MAX_ITEM_TEXT_CHARS: usize = 600;
const MAX_PATH_CHARS: usize = 1_024;

fn default_token_budget() -> u32 {
    8_000
}

fn default_item_budget() -> u32 {
    256
}

fn default_include_generated_claims() -> bool {
    true
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AnalysisCaseEvidencePackRequest {
    pub case_path: String,
    #[serde(default = "default_token_budget")]
    pub max_tokens: u32,
    #[serde(default = "default_item_budget")]
    pub max_items: u32,
    #[serde(default = "default_include_generated_claims")]
    pub include_generated_claims: bool,
}

#[derive(Clone, Debug, Default, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EvidencePackLocator {
    pub raw: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub trace_seq: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub trace_line: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub memory_address: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub memory_size: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub memory_range: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub module_offset: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub event_index: Option<u64>,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EvidencePackClaim {
    pub claim_id: String,
    pub source: String,
    pub statement: String,
    pub scope: String,
    pub current_status: TraceCaseClaimStatus,
    pub recommended_max_status: TraceCaseClaimStatus,
    pub gate_status: String,
    pub verification_gate_passed: bool,
    pub coverage_requirement: String,
    pub coverage_gate_status: String,
    pub coverage_gate_passed: bool,
    pub coverage_max_status: TraceCaseClaimStatus,
    pub coverage_artifact_ids: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub coverage_uncovered_counts: Option<CoverageCounts>,
    pub supporting_evidence_count: u64,
    pub counter_evidence_count: u64,
    pub missing_evidence_count: u64,
    pub blockers: Vec<String>,
    pub limitations: Vec<String>,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EvidencePackEvidenceItem {
    pub claim_id: String,
    pub claim_source: String,
    pub artifact_id: String,
    pub artifact_kind: TraceCaseArtifactKind,
    pub artifact_label: String,
    pub locator: EvidencePackLocator,
    pub description: String,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EvidencePackUnknown {
    pub unknown_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub claim_id: Option<String>,
    pub category: String,
    pub description: String,
    pub artifact_ids: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub suggested_tool: Option<String>,
    pub priority: u8,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EvidencePackInvalidArtifact {
    pub artifact_id: String,
    pub artifact_kind: TraceCaseArtifactKind,
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
pub struct EvidencePackBudget {
    pub max_tokens: u32,
    pub max_items: u32,
    pub estimated_token_count: u32,
    pub included_item_count: u32,
    pub total_claim_count: u32,
    pub omitted_claim_count: u32,
    pub total_supporting_evidence_count: u32,
    pub omitted_supporting_evidence_count: u32,
    pub total_counter_evidence_count: u32,
    pub omitted_counter_evidence_count: u32,
    pub total_unknown_count: u32,
    pub omitted_unknown_count: u32,
    pub total_invalid_artifact_count: u32,
    pub omitted_invalid_artifact_count: u32,
    pub truncated: bool,
    pub token_estimate_method: String,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AnalysisCaseEvidencePack {
    pub schema: String,
    pub case_id: String,
    pub case_path: String,
    pub case_title: String,
    pub replay_doctor_status: String,
    pub generated_at_ms: u64,
    pub budget: EvidencePackBudget,
    pub claims: Vec<EvidencePackClaim>,
    pub supporting_evidence: Vec<EvidencePackEvidenceItem>,
    pub counter_evidence: Vec<EvidencePackEvidenceItem>,
    pub unknowns: Vec<EvidencePackUnknown>,
    pub invalid_artifacts: Vec<EvidencePackInvalidArtifact>,
    pub warnings: Vec<String>,
    pub limitations: Vec<String>,
}

fn validate_request(request: &AnalysisCaseEvidencePackRequest) -> Result<()> {
    if request.case_path.trim().is_empty() {
        return Err(TraceError::InvalidArgument(
            "case_path must not be empty".to_string(),
        ));
    }
    if !(MIN_TOKEN_BUDGET..=MAX_TOKEN_BUDGET).contains(&request.max_tokens) {
        return Err(TraceError::InvalidArgument(format!(
            "max_tokens must be from {MIN_TOKEN_BUDGET} through {MAX_TOKEN_BUDGET}"
        )));
    }
    if !(MIN_ITEM_BUDGET..=MAX_ITEM_BUDGET).contains(&request.max_items) {
        return Err(TraceError::InvalidArgument(format!(
            "max_items must be from {MIN_ITEM_BUDGET} through {MAX_ITEM_BUDGET}"
        )));
    }
    Ok(())
}

fn truncate_text(value: &str, max_chars: usize) -> String {
    if value.chars().count() <= max_chars {
        return value.to_string();
    }
    let mut output = value
        .chars()
        .take(max_chars.saturating_sub(1))
        .collect::<String>();
    output.push('…');
    output
}

fn approximate_tokens(value: &str) -> u32 {
    let mut ascii_run = 0u32;
    let mut tokens = 0u32;
    for character in value.chars() {
        if character.is_ascii() {
            ascii_run = ascii_run.saturating_add(1);
        } else {
            if ascii_run > 0 {
                tokens = tokens.saturating_add(ascii_run.saturating_add(3) / 4);
                ascii_run = 0;
            }
            tokens = tokens.saturating_add(1);
        }
    }
    if ascii_run > 0 {
        tokens = tokens.saturating_add(ascii_run.saturating_add(3) / 4);
    }
    tokens
}

fn estimate_serialized_tokens(value: &impl Serialize) -> u32 {
    serde_json::to_string(value)
        .map(|encoded| approximate_tokens(&encoded))
        .unwrap_or(u32::MAX)
}

fn parse_u64_auto(value: &str) -> Option<u64> {
    let value = value.trim();
    if value.is_empty() {
        return None;
    }
    if value.starts_with("0x") || value.starts_with("0X") {
        parse_hex_addr(value).ok()
    } else {
        value.parse::<u64>().ok()
    }
}

fn parse_locator_number(raw: &str, names: &[&str]) -> Option<u64> {
    let normalized = raw.replace(['@', ',', ';', '/', '\\'], " ");
    for token in normalized.split_whitespace() {
        let lower = token.to_ascii_lowercase();
        for name in names {
            for separator in [":", "="] {
                let prefix = format!("{name}{separator}");
                if let Some(value) = lower.strip_prefix(&prefix) {
                    if let Some(parsed) = parse_u64_auto(value) {
                        return Some(parsed);
                    }
                }
            }
        }
    }
    None
}

pub fn parse_evidence_locator(raw: &str) -> EvidencePackLocator {
    let mut locator = EvidencePackLocator {
        raw: truncate_text(raw.trim(), MAX_ITEM_TEXT_CHARS),
        trace_seq: parse_locator_number(raw, &["seq", "trace-seq", "trace_seq"]),
        trace_line: parse_locator_number(raw, &["line", "trace-line", "trace_line"]),
        event_index: parse_locator_number(raw, &["event", "event-index", "event_index"]),
        ..Default::default()
    };

    if let Some(memory) = raw.trim().strip_prefix("mem:") {
        let range = memory.split('@').next().unwrap_or(memory);
        let mut fields = range.split(':');
        if let (Some(address), Some(size)) = (fields.next(), fields.next()) {
            if fields.next().is_none() {
                if let (Ok(address), Some(size)) = (parse_hex_addr(address), parse_u64_auto(size)) {
                    locator.memory_address = Some(format!("0x{address:x}"));
                    locator.memory_size = Some(size);
                    locator.memory_range = address
                        .checked_add(size)
                        .and_then(|end| end.checked_sub(1))
                        .map(|end| format!("0x{address:x}-0x{end:x}"));
                }
            }
        }
    }

    let normalized = raw.replace(['@', ',', ';', '/', '\\'], " ");
    for token in normalized.split_whitespace() {
        let lower = token.to_ascii_lowercase();
        for prefix in ["offset:", "offset=", "module-offset:", "module_offset="] {
            if let Some(value) = lower.strip_prefix(prefix) {
                if let Ok(offset) = parse_hex_addr(value) {
                    locator.module_offset = Some(format!("0x{offset:x}"));
                    return locator;
                }
            }
        }
    }
    if locator.module_offset.is_none() && raw.trim().starts_with("0x") {
        if let Ok(offset) = parse_hex_addr(raw.trim()) {
            locator.module_offset = Some(format!("0x{offset:x}"));
        }
    }
    locator
}

fn claim_priority<'a>(
    claim: &'a TraceCaseClaim,
    source: &str,
    audit: Option<&TraceCaseClaimAuditEntry>,
) -> (u8, u8, &'a str) {
    let status_priority = if claim.status == TraceCaseClaimStatus::Refuted {
        0
    } else if audit.is_some_and(|audit| audit.gate_status == "blocked") {
        1
    } else {
        match claim.status {
            TraceCaseClaimStatus::Verified => 2,
            TraceCaseClaimStatus::Related => 3,
            TraceCaseClaimStatus::Observed => 4,
            TraceCaseClaimStatus::Unknown => 5,
            TraceCaseClaimStatus::Refuted => 0,
        }
    };
    let source_priority = if source == "persisted" { 0 } else { 1 };
    (status_priority, source_priority, claim.claim_id.as_str())
}

fn evidence_item(
    claim: &TraceCaseClaim,
    source: &str,
    evidence: &TraceCaseEvidenceRef,
    artifact: &TraceCaseArtifact,
) -> EvidencePackEvidenceItem {
    EvidencePackEvidenceItem {
        claim_id: claim.claim_id.clone(),
        claim_source: source.to_string(),
        artifact_id: artifact.artifact_id.clone(),
        artifact_kind: artifact.kind,
        artifact_label: truncate_text(&artifact.label, MAX_ITEM_TEXT_CHARS),
        locator: parse_evidence_locator(&evidence.locator),
        description: truncate_text(&evidence.description, MAX_ITEM_TEXT_CHARS),
    }
}

fn unknown_id(claim_id: Option<&str>, category: &str, description: &str) -> String {
    let mut input = String::new();
    if let Some(claim_id) = claim_id {
        input.push_str(claim_id);
    }
    input.push('\0');
    input.push_str(category);
    input.push('\0');
    input.push_str(description);
    let digest = sha2::Sha256::digest(input.as_bytes());
    let encoded = format!("unknown-{:x}", digest);
    encoded[..32].to_string()
}

fn action_unknown(action: &ReplayDoctorNextAction) -> EvidencePackUnknown {
    let description = format!("{} {}", action.reason, action.instructions);
    EvidencePackUnknown {
        unknown_id: unknown_id(None, &action.action, &description),
        claim_id: None,
        category: format!("next-action/{}", action.action),
        description: truncate_text(&description, MAX_ITEM_TEXT_CHARS),
        artifact_ids: action.artifact_ids.clone(),
        suggested_tool: action.tool_name.clone(),
        priority: action.priority,
    }
}

fn push_with_budget<T: Serialize>(
    output: &mut Vec<T>,
    value: T,
    used_tokens: &mut u32,
    used_items: &mut u32,
    request: &AnalysisCaseEvidencePackRequest,
) -> bool {
    if *used_items >= request.max_items {
        return false;
    }
    let cost = estimate_serialized_tokens(&value).saturating_add(2);
    if used_tokens.saturating_add(cost) > request.max_tokens {
        return false;
    }
    output.push(value);
    *used_tokens = used_tokens.saturating_add(cost);
    *used_items = used_items.saturating_add(1);
    true
}

fn pack_item_count(pack: &AnalysisCaseEvidencePack) -> u32 {
    (pack.claims.len()
        + pack.supporting_evidence.len()
        + pack.counter_evidence.len()
        + pack.unknowns.len()
        + pack.invalid_artifacts.len())
    .min(u32::MAX as usize) as u32
}

fn recalculate_budget(pack: &mut AnalysisCaseEvidencePack) {
    pack.budget.included_item_count = pack_item_count(pack);
    pack.budget.omitted_claim_count = pack
        .budget
        .total_claim_count
        .saturating_sub(pack.claims.len() as u32);
    pack.budget.omitted_supporting_evidence_count = pack
        .budget
        .total_supporting_evidence_count
        .saturating_sub(pack.supporting_evidence.len() as u32);
    pack.budget.omitted_counter_evidence_count = pack
        .budget
        .total_counter_evidence_count
        .saturating_sub(pack.counter_evidence.len() as u32);
    pack.budget.omitted_unknown_count = pack
        .budget
        .total_unknown_count
        .saturating_sub(pack.unknowns.len() as u32);
    pack.budget.omitted_invalid_artifact_count = pack
        .budget
        .total_invalid_artifact_count
        .saturating_sub(pack.invalid_artifacts.len() as u32);
    pack.budget.truncated = pack.budget.omitted_claim_count > 0
        || pack.budget.omitted_supporting_evidence_count > 0
        || pack.budget.omitted_counter_evidence_count > 0
        || pack.budget.omitted_unknown_count > 0
        || pack.budget.omitted_invalid_artifact_count > 0;
    pack.budget.estimated_token_count = estimate_serialized_tokens(pack);
}

fn trim_to_actual_budget(pack: &mut AnalysisCaseEvidencePack) {
    recalculate_budget(pack);
    while pack.budget.estimated_token_count > pack.budget.max_tokens {
        if !remove_low_priority_item(pack) {
            break;
        }
        recalculate_budget(pack);
    }
}

fn remove_low_priority_item(pack: &mut AnalysisCaseEvidencePack) -> bool {
    if pack.unknowns.pop().is_some() || pack.supporting_evidence.pop().is_some() {
        return true;
    }
    if pack.claims.len() > 1 {
        let claim = pack.claims.pop().expect("claim length checked");
        pack.supporting_evidence
            .retain(|evidence| evidence.claim_id != claim.claim_id);
        pack.counter_evidence
            .retain(|evidence| evidence.claim_id != claim.claim_id);
        pack.unknowns
            .retain(|unknown| unknown.claim_id.as_deref() != Some(claim.claim_id.as_str()));
        return true;
    }
    if pack.counter_evidence.pop().is_some() || pack.invalid_artifacts.pop().is_some() {
        return true;
    }
    pack.claims.pop().is_some()
}

pub fn build_analysis_case_evidence_pack(
    request: &AnalysisCaseEvidencePackRequest,
) -> Result<AnalysisCaseEvidencePack> {
    validate_request(request)?;
    let document = load_trace_analysis_case(request.case_path.trim())?;
    let doctor = diagnose_trace_analysis_case(request.case_path.trim())?;
    let artifact_by_id = document
        .case
        .artifacts
        .iter()
        .map(|artifact| (artifact.artifact_id.as_str(), artifact))
        .collect::<BTreeMap<_, _>>();
    let health_by_id = doctor
        .artifact_health
        .iter()
        .map(|health| (health.artifact_id.as_str(), health))
        .collect::<BTreeMap<_, _>>();
    let audit_by_key = doctor
        .claim_ledger_audit
        .claims
        .iter()
        .map(|audit| ((audit.claim_id.as_str(), audit.source.as_str()), audit))
        .collect::<BTreeMap<_, _>>();

    let mut claims = document
        .case
        .claims
        .iter()
        .cloned()
        .map(|claim| (claim, "persisted".to_string()))
        .collect::<Vec<_>>();
    if request.include_generated_claims {
        claims.extend(
            doctor
                .generated_claims
                .iter()
                .cloned()
                .map(|claim| (claim, "generated".to_string())),
        );
    }
    claims.sort_by(|(left, left_source), (right, right_source)| {
        let left_audit = audit_by_key
            .get(&(left.claim_id.as_str(), left_source.as_str()))
            .copied();
        let right_audit = audit_by_key
            .get(&(right.claim_id.as_str(), right_source.as_str()))
            .copied();
        claim_priority(left, left_source, left_audit).cmp(&claim_priority(
            right,
            right_source,
            right_audit,
        ))
    });

    let total_supporting = claims
        .iter()
        .map(|(claim, _)| claim.supporting_evidence.len() as u32)
        .sum::<u32>();
    let total_counter = claims
        .iter()
        .map(|(claim, _)| claim.counter_evidence.len() as u32)
        .sum::<u32>();

    let mut invalid_candidates = doctor
        .artifact_health
        .iter()
        .filter(|health| health.status != "valid")
        .map(|health| invalid_artifact(health))
        .collect::<Vec<_>>();
    invalid_candidates.sort_by(|left, right| left.artifact_id.cmp(&right.artifact_id));

    let mut claim_candidates = Vec::new();
    let mut supporting_candidates = Vec::new();
    let mut counter_candidates = Vec::new();
    let mut unknown_candidates = Vec::new();
    let mut unknown_dedup = BTreeSet::new();

    for (claim, source) in &claims {
        let audit = audit_by_key
            .get(&(claim.claim_id.as_str(), source.as_str()))
            .copied();
        claim_candidates.push(EvidencePackClaim {
            claim_id: claim.claim_id.clone(),
            source: source.clone(),
            statement: truncate_text(&claim.statement, MAX_CLAIM_TEXT_CHARS),
            scope: truncate_text(&claim.scope, MAX_ITEM_TEXT_CHARS),
            current_status: claim.status,
            recommended_max_status: audit
                .map(|audit| audit.recommended_status)
                .unwrap_or(TraceCaseClaimStatus::Unknown),
            gate_status: audit
                .map(|audit| audit.gate_status.clone())
                .unwrap_or_else(|| "not-audited".to_string()),
            verification_gate_passed: audit.is_some_and(|audit| audit.verification_gate_passed),
            coverage_requirement: audit
                .map(|audit| audit.coverage_requirement.clone())
                .unwrap_or_else(|| "not-audited".to_string()),
            coverage_gate_status: audit
                .map(|audit| audit.coverage_gate_status.clone())
                .unwrap_or_else(|| "not-audited".to_string()),
            coverage_gate_passed: audit.is_some_and(|audit| audit.coverage_gate_passed),
            coverage_max_status: audit
                .map(|audit| audit.coverage_max_status)
                .unwrap_or(TraceCaseClaimStatus::Unknown),
            coverage_artifact_ids: audit
                .map(|audit| audit.coverage_artifact_ids.clone())
                .unwrap_or_default(),
            coverage_uncovered_counts: audit
                .and_then(|audit| audit.coverage_uncovered_counts.clone()),
            supporting_evidence_count: claim.supporting_evidence.len() as u64,
            counter_evidence_count: claim.counter_evidence.len() as u64,
            missing_evidence_count: claim.missing_evidence.len() as u64,
            blockers: audit
                .map(|audit| {
                    audit
                        .blockers
                        .iter()
                        .map(|value| truncate_text(value, MAX_ITEM_TEXT_CHARS))
                        .collect()
                })
                .unwrap_or_default(),
            limitations: claim
                .limitations
                .iter()
                .map(|value| truncate_text(value, MAX_ITEM_TEXT_CHARS))
                .collect(),
        });

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
            let valid = health_by_id
                .get(evidence.artifact_id.as_str())
                .is_some_and(|health| health.status == "valid");
            if let Some(artifact) = artifact.filter(|_| valid) {
                let item = evidence_item(claim, source, evidence, artifact);
                if counter {
                    counter_candidates.push(item);
                } else {
                    supporting_candidates.push(item);
                }
            } else {
                let description = format!(
                    "Evidence locator '{}' references a missing, changed, or invalid artifact {}.",
                    evidence.locator, evidence.artifact_id
                );
                let key = (
                    Some(claim.claim_id.clone()),
                    "invalid-evidence-reference".to_string(),
                    description.clone(),
                );
                if unknown_dedup.insert(key) {
                    unknown_candidates.push(EvidencePackUnknown {
                        unknown_id: unknown_id(
                            Some(&claim.claim_id),
                            "invalid-evidence-reference",
                            &description,
                        ),
                        claim_id: Some(claim.claim_id.clone()),
                        category: "invalid-evidence-reference".to_string(),
                        description: truncate_text(&description, MAX_ITEM_TEXT_CHARS),
                        artifact_ids: vec![evidence.artifact_id.clone()],
                        suggested_tool: Some("diagnose_analysis_case".to_string()),
                        priority: 100,
                    });
                }
            }
        }

        for missing in &claim.missing_evidence {
            let description = truncate_text(missing, MAX_ITEM_TEXT_CHARS);
            let key = (
                Some(claim.claim_id.clone()),
                "missing-evidence".to_string(),
                description.clone(),
            );
            if unknown_dedup.insert(key) {
                unknown_candidates.push(EvidencePackUnknown {
                    unknown_id: unknown_id(Some(&claim.claim_id), "missing-evidence", &description),
                    claim_id: Some(claim.claim_id.clone()),
                    category: "missing-evidence".to_string(),
                    description,
                    artifact_ids: Vec::new(),
                    suggested_tool: None,
                    priority: 90,
                });
            }
        }
        if let Some(audit) = audit {
            if !matches!(
                audit.coverage_gate_status.as_str(),
                "not-required" | "passed"
            ) {
                let description = if let Some(counts) = &audit.coverage_uncovered_counts {
                    format!(
                        "Coverage gate {} for {}: uncovered instructions={}, blocks={}, branches={}, functions={}, edges={}; unexecuted paths remain unknown.",
                        audit.coverage_gate_status,
                        audit.coverage_requirement,
                        counts.instructions,
                        counts.blocks,
                        counts.branches,
                        counts.functions,
                        counts.edges,
                    )
                } else {
                    format!(
                        "Coverage gate {} for {}; no exact-scope complete reconciliation is available and unexecuted paths remain unknown.",
                        audit.coverage_gate_status, audit.coverage_requirement
                    )
                };
                let description = truncate_text(&description, MAX_ITEM_TEXT_CHARS);
                let key = (
                    Some(claim.claim_id.clone()),
                    "coverage-gap".to_string(),
                    description.clone(),
                );
                if unknown_dedup.insert(key) {
                    unknown_candidates.push(EvidencePackUnknown {
                        unknown_id: unknown_id(Some(&claim.claim_id), "coverage-gap", &description),
                        claim_id: Some(claim.claim_id.clone()),
                        category: "coverage-gap".to_string(),
                        description,
                        artifact_ids: audit.coverage_artifact_ids.clone(),
                        suggested_tool: Some(
                            if audit.coverage_gate_status == "missing" {
                                "generate_coverage_reconciliation_script"
                            } else {
                                "plan_analysis_case_capture"
                            }
                            .to_string(),
                        ),
                        priority: 97,
                    });
                }
            }
            for blocker in &audit.blockers {
                let description = truncate_text(blocker, MAX_ITEM_TEXT_CHARS);
                let key = (
                    Some(claim.claim_id.clone()),
                    "claim-gate-blocker".to_string(),
                    description.clone(),
                );
                if unknown_dedup.insert(key) {
                    unknown_candidates.push(EvidencePackUnknown {
                        unknown_id: unknown_id(
                            Some(&claim.claim_id),
                            "claim-gate-blocker",
                            &description,
                        ),
                        claim_id: Some(claim.claim_id.clone()),
                        category: "claim-gate-blocker".to_string(),
                        description,
                        artifact_ids: claim
                            .supporting_evidence
                            .iter()
                            .chain(&claim.counter_evidence)
                            .map(|evidence| evidence.artifact_id.clone())
                            .collect::<BTreeSet<_>>()
                            .into_iter()
                            .collect(),
                        suggested_tool: Some("audit_analysis_case_claims".to_string()),
                        priority: 95,
                    });
                }
            }
        }
    }

    unknown_candidates.extend(doctor.next_actions.iter().map(action_unknown));
    for blocker in &doctor.state_readiness.blockers {
        let description = truncate_text(blocker, MAX_ITEM_TEXT_CHARS);
        let key = (None, "state-readiness".to_string(), description.clone());
        if unknown_dedup.insert(key) {
            unknown_candidates.push(EvidencePackUnknown {
                unknown_id: unknown_id(None, "state-readiness", &description),
                claim_id: None,
                category: "state-readiness".to_string(),
                description,
                artifact_ids: Vec::new(),
                suggested_tool: Some("diagnose_analysis_case".to_string()),
                priority: 85,
            });
        }
    }
    for warning in &doctor.warnings {
        let description = truncate_text(warning, MAX_ITEM_TEXT_CHARS);
        let key = (None, "doctor-warning".to_string(), description.clone());
        if unknown_dedup.insert(key) {
            unknown_candidates.push(EvidencePackUnknown {
                unknown_id: unknown_id(None, "doctor-warning", &description),
                claim_id: None,
                category: "doctor-warning".to_string(),
                description,
                artifact_ids: Vec::new(),
                suggested_tool: Some("diagnose_analysis_case".to_string()),
                priority: 80,
            });
        }
    }
    unknown_candidates.sort_by(|left, right| {
        right
            .priority
            .cmp(&left.priority)
            .then_with(|| left.unknown_id.cmp(&right.unknown_id))
    });

    let total_unknown = unknown_candidates.len() as u32;
    let mut pack = AnalysisCaseEvidencePack {
        schema: AI_EVIDENCE_PACK_SCHEMA.to_string(),
        case_id: document.case.case_id,
        case_path: truncate_text(&document.case_path, MAX_PATH_CHARS),
        case_title: truncate_text(&document.case.title, MAX_ITEM_TEXT_CHARS),
        replay_doctor_status: doctor.status,
        generated_at_ms: doctor.generated_at_ms,
        budget: EvidencePackBudget {
            max_tokens: request.max_tokens,
            max_items: request.max_items,
            estimated_token_count: 0,
            included_item_count: 0,
            total_claim_count: claim_candidates.len() as u32,
            omitted_claim_count: 0,
            total_supporting_evidence_count: total_supporting,
            omitted_supporting_evidence_count: 0,
            total_counter_evidence_count: total_counter,
            omitted_counter_evidence_count: 0,
            total_unknown_count: total_unknown,
            omitted_unknown_count: 0,
            total_invalid_artifact_count: invalid_candidates.len() as u32,
            omitted_invalid_artifact_count: 0,
            truncated: false,
            token_estimate_method:
                "ASCII runs ceil(chars/4) plus one token per non-ASCII scalar; deterministic estimate, not a model tokenizer"
                    .to_string(),
        },
        claims: Vec::new(),
        supporting_evidence: Vec::new(),
        counter_evidence: Vec::new(),
        unknowns: Vec::new(),
        invalid_artifacts: Vec::new(),
        warnings: (!doctor.warnings.is_empty()).then(|| {
            format!(
                "Replay Doctor produced {} warning(s); bounded details are listed under unknowns when budget permits.",
                doctor.warnings.len()
            )
        }).into_iter().collect(),
        limitations: vec![
            "This pack is bounded context packaging, not new evidence and not an independent verifier."
                .to_string(),
            "Artifact summaries and evidence descriptions are navigation aids only; follow artifactId + locator and recompute the underlying evidence before asserting a fact."
                .to_string(),
            "Supporting evidence, counter-evidence, unknowns, and invalid artifacts are intentionally separated. Do not silently drop the latter three sections."
                .to_string(),
            "Dynamic traces contain executed behavior only; unobserved paths and uncaptured state remain unknown."
                .to_string(),
        ],
    };

    let mut used_tokens = estimate_serialized_tokens(&pack).min(request.max_tokens);
    let mut used_items = 0u32;
    for artifact in invalid_candidates {
        let _ = push_with_budget(
            &mut pack.invalid_artifacts,
            artifact,
            &mut used_tokens,
            &mut used_items,
            request,
        );
    }
    for claim in claim_candidates {
        let _ = push_with_budget(
            &mut pack.claims,
            claim,
            &mut used_tokens,
            &mut used_items,
            request,
        );
    }
    let included_claim_ids = pack
        .claims
        .iter()
        .map(|claim| (claim.claim_id.as_str(), claim.source.as_str()))
        .collect::<BTreeSet<_>>();

    for evidence in counter_candidates.into_iter().filter(|evidence| {
        included_claim_ids.contains(&(evidence.claim_id.as_str(), evidence.claim_source.as_str()))
    }) {
        let _ = push_with_budget(
            &mut pack.counter_evidence,
            evidence,
            &mut used_tokens,
            &mut used_items,
            request,
        );
    }
    for evidence in supporting_candidates.into_iter().filter(|evidence| {
        included_claim_ids.contains(&(evidence.claim_id.as_str(), evidence.claim_source.as_str()))
    }) {
        let _ = push_with_budget(
            &mut pack.supporting_evidence,
            evidence,
            &mut used_tokens,
            &mut used_items,
            request,
        );
    }
    for unknown in unknown_candidates.into_iter().filter(|unknown| {
        unknown.claim_id.as_deref().map_or(true, |claim_id| {
            pack.claims.iter().any(|claim| claim.claim_id == claim_id)
        })
    }) {
        let _ = push_with_budget(
            &mut pack.unknowns,
            unknown,
            &mut used_tokens,
            &mut used_items,
            request,
        );
    }

    trim_to_actual_budget(&mut pack);
    Ok(pack)
}

fn invalid_artifact(health: &TraceCaseArtifactHealth) -> EvidencePackInvalidArtifact {
    EvidencePackInvalidArtifact {
        artifact_id: health.artifact_id.clone(),
        artifact_kind: health.kind,
        label: truncate_text(&health.label, MAX_ITEM_TEXT_CHARS),
        resolved_path: truncate_text(&health.resolved_path, MAX_PATH_CHARS),
        status: health.status.clone(),
        size_matches: health.size_matches,
        sha256_matches: health.sha256_matches,
        parser_valid: health.parser_valid,
        error: health
            .error
            .as_deref()
            .map(|error| truncate_text(error, MAX_ITEM_TEXT_CHARS)),
    }
}

fn markdown_inline(value: &str) -> String {
    value
        .replace(['\r', '\n'], " ")
        .replace('`', "'")
        .trim()
        .to_string()
}

fn markdown_locator(locator: &EvidencePackLocator) -> String {
    let mut details = vec![format!("locator `{}`", markdown_inline(&locator.raw))];
    if let Some(seq) = locator.trace_seq {
        details.push(format!("trace seq `{seq}`"));
    }
    if let Some(line) = locator.trace_line {
        details.push(format!("trace line `{line}`"));
    }
    if let Some(range) = &locator.memory_range {
        details.push(format!("memory `{range}`"));
    }
    if let Some(offset) = &locator.module_offset {
        details.push(format!("module offset `{offset}`"));
    }
    if let Some(index) = locator.event_index {
        details.push(format!("event index `{index}`"));
    }
    details.join("; ")
}

pub fn render_analysis_case_evidence_pack_markdown(pack: &AnalysisCaseEvidencePack) -> String {
    let mut bounded = pack.clone();
    loop {
        let rendered = render_evidence_pack_markdown_unbounded(&bounded);
        let estimated = approximate_tokens(&rendered);
        bounded.budget.estimated_token_count = estimated;
        let rendered = render_evidence_pack_markdown_unbounded(&bounded);
        let estimated = approximate_tokens(&rendered);
        bounded.budget.estimated_token_count = estimated;
        if estimated <= bounded.budget.max_tokens || !remove_low_priority_item(&mut bounded) {
            return rendered;
        }
        recalculate_budget(&mut bounded);
    }
}

fn render_evidence_pack_markdown_unbounded(pack: &AnalysisCaseEvidencePack) -> String {
    let mut output = String::new();
    output.push_str("# Trace UI AI Evidence Pack\n\n");
    output.push_str(&format!(
        "- Schema: `{}`\n- Case: `{}` — {}\n- Replay Doctor: `{}`\n- Budget: estimated {} / {} tokens; {} / {} items; truncated `{}`\n\n",
        pack.schema,
        markdown_inline(&pack.case_id),
        markdown_inline(&pack.case_title),
        markdown_inline(&pack.replay_doctor_status),
        pack.budget.estimated_token_count,
        pack.budget.max_tokens,
        pack.budget.included_item_count,
        pack.budget.max_items,
        pack.budget.truncated
    ));
    output.push_str(
        "> This is bounded context packaging, not new proof. Follow every artifact ID and locator; do not treat summaries or descriptions as evidence.\n\n",
    );

    output.push_str("## Claims and maximum allowed status\n\n");
    if pack.claims.is_empty() {
        output.push_str("- No claims fit the selected budget.\n\n");
    }
    for claim in &pack.claims {
        output.push_str(&format!(
            "### `{}` ({})\n\n- Scope: `{}`\n- Current: `{:?}`; recommended maximum: `{:?}`; gate: `{}`; verified gate passed: `{}`\n- Coverage: requirement `{}`, gate `{}`, passed `{}`, maximum `{:?}`\n- Statement: {}\n",
            markdown_inline(&claim.claim_id),
            markdown_inline(&claim.source),
            markdown_inline(&claim.scope),
            claim.current_status,
            claim.recommended_max_status,
            markdown_inline(&claim.gate_status),
            claim.verification_gate_passed,
            markdown_inline(&claim.coverage_requirement),
            markdown_inline(&claim.coverage_gate_status),
            claim.coverage_gate_passed,
            claim.coverage_max_status,
            markdown_inline(&claim.statement)
        ));
        for blocker in &claim.blockers {
            output.push_str(&format!("- Blocker: {}\n", markdown_inline(blocker)));
        }
        output.push('\n');
    }

    render_markdown_evidence_section(
        &mut output,
        "Supporting evidence",
        &pack.supporting_evidence,
    );
    render_markdown_evidence_section(&mut output, "Counter-evidence", &pack.counter_evidence);

    output.push_str("## Unknowns and next evidence needs\n\n");
    if pack.unknowns.is_empty() {
        output.push_str("- None included.\n\n");
    }
    for unknown in &pack.unknowns {
        output.push_str(&format!(
            "- `{}`{} (P{}): {}{}\n",
            markdown_inline(&unknown.category),
            unknown
                .claim_id
                .as_deref()
                .map(|claim_id| format!(" for claim `{}`", markdown_inline(claim_id)))
                .unwrap_or_default(),
            unknown.priority,
            markdown_inline(&unknown.description),
            unknown
                .suggested_tool
                .as_deref()
                .map(|tool| format!(" Suggested tool: `{}`.", markdown_inline(tool)))
                .unwrap_or_default()
        ));
    }
    output.push('\n');

    output.push_str("## Invalid artifacts\n\n");
    if pack.invalid_artifacts.is_empty() {
        output.push_str("- None included.\n\n");
    }
    for artifact in &pack.invalid_artifacts {
        output.push_str(&format!(
            "- Artifact `{}` (`{}`), status `{}`: {}{}\n",
            markdown_inline(&artifact.artifact_id),
            artifact.artifact_kind.as_str(),
            markdown_inline(&artifact.status),
            markdown_inline(&artifact.resolved_path),
            artifact
                .error
                .as_deref()
                .map(|error| format!(" — {}", markdown_inline(error)))
                .unwrap_or_default()
        ));
    }
    output.push('\n');

    output.push_str("## Limitations\n\n");
    for limitation in &pack.limitations {
        output.push_str(&format!("- {}\n", markdown_inline(limitation)));
    }
    output
}

fn render_markdown_evidence_section(
    output: &mut String,
    title: &str,
    evidence: &[EvidencePackEvidenceItem],
) {
    output.push_str(&format!("## {title}\n\n"));
    if evidence.is_empty() {
        output.push_str("- None included.\n\n");
        return;
    }
    for item in evidence {
        output.push_str(&format!(
            "- Claim `{}` ({}) → artifact `{}` (`{}`, {}): {}. {}\n",
            markdown_inline(&item.claim_id),
            markdown_inline(&item.claim_source),
            markdown_inline(&item.artifact_id),
            item.artifact_kind.as_str(),
            markdown_inline(&item.artifact_label),
            markdown_locator(&item.locator),
            markdown_inline(&item.description)
        ));
    }
    output.push('\n');
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analysis_case::{
        create_trace_analysis_case, upsert_trace_case_claim, TraceCaseClaim, TraceCaseEvidenceRef,
    };
    use std::path::PathBuf;

    fn temp_path(name: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "trace-ui-evidence-pack-{}-{name}",
            uuid::Uuid::new_v4()
        ))
    }

    fn build_case(name: &str) -> (PathBuf, PathBuf, String) {
        let dir = temp_path(name);
        std::fs::create_dir_all(&dir).unwrap();
        let trace = dir.join("sample.log");
        let case_path = dir.join("sample.traceui-case");
        std::fs::write(&trace, b"trace\n").unwrap();
        let document = create_trace_analysis_case(
            case_path.to_str().unwrap(),
            "Evidence pack case",
            Some(trace.to_str().unwrap()),
            None,
        )
        .unwrap();
        (
            dir,
            case_path,
            document.case.primary_trace_artifact_id.unwrap(),
        )
    }

    #[test]
    fn parses_structured_trace_memory_and_offset_locators() {
        let memory = parse_evidence_locator("mem:0x1000:16@seq:42");
        assert_eq!(memory.trace_seq, Some(42));
        assert_eq!(memory.memory_address.as_deref(), Some("0x1000"));
        assert_eq!(memory.memory_size, Some(16));
        assert_eq!(memory.memory_range.as_deref(), Some("0x1000-0x100f"));

        let line = parse_evidence_locator("line=17 offset:0x2a0 event-index:9");
        assert_eq!(line.trace_line, Some(17));
        assert_eq!(line.module_offset.as_deref(), Some("0x2a0"));
        assert_eq!(line.event_index, Some(9));
    }

    #[test]
    fn separates_support_counter_unknown_and_recommended_status() {
        let (dir, case_path, artifact_id) = build_case("sections");
        let claim = TraceCaseClaim {
            claim_id: "claim-sections".to_string(),
            statement: "The observed value has a disputed origin.".to_string(),
            scope: "trace:sample".to_string(),
            status: TraceCaseClaimStatus::Verified,
            coverage_requirement: Default::default(),
            supporting_evidence: vec![TraceCaseEvidenceRef {
                artifact_id: artifact_id.clone(),
                locator: "mem:0x1000:16@seq:42".to_string(),
                description: "Observed bytes at the selected sequence.".to_string(),
            }],
            counter_evidence: vec![TraceCaseEvidenceRef {
                artifact_id,
                locator: "line:43".to_string(),
                description: "A later write conflicts with the claimed stable value.".to_string(),
            }],
            missing_evidence: vec!["Capture the producing call input.".to_string()],
            limitations: vec!["Only one dynamic run is present.".to_string()],
            created_by: "test".to_string(),
            created_at_ms: 1,
            updated_at_ms: 1,
        };
        upsert_trace_case_claim(case_path.to_str().unwrap(), claim).unwrap();
        let pack = build_analysis_case_evidence_pack(&AnalysisCaseEvidencePackRequest {
            case_path: case_path.to_string_lossy().into_owned(),
            max_tokens: 8_000,
            max_items: 256,
            include_generated_claims: false,
        })
        .unwrap();
        assert_eq!(pack.claims.len(), 1);
        assert_eq!(
            pack.claims[0].recommended_max_status,
            TraceCaseClaimStatus::Refuted
        );
        assert_eq!(pack.supporting_evidence.len(), 1);
        assert_eq!(pack.counter_evidence.len(), 1);
        assert!(pack
            .unknowns
            .iter()
            .any(|unknown| unknown.category == "missing-evidence"));
        assert_eq!(pack.supporting_evidence[0].locator.trace_seq, Some(42));
        assert_eq!(
            pack.supporting_evidence[0].locator.memory_range.as_deref(),
            Some("0x1000-0x100f")
        );
        let markdown = render_analysis_case_evidence_pack_markdown(&pack);
        assert!(markdown.contains("Counter-evidence"));
        assert!(markdown.contains("claim-sections"));
        assert!(markdown.contains("mem:0x1000:16@seq:42"));
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn reports_changed_artifacts_and_truncates_deterministically() {
        let (dir, case_path, artifact_id) = build_case("invalid-budget");
        for index in 0..40 {
            upsert_trace_case_claim(
                case_path.to_str().unwrap(),
                TraceCaseClaim {
                    claim_id: format!("claim-{index:02}"),
                    statement: format!("Claim {index} {}", "x".repeat(200)),
                    scope: "trace:sample".to_string(),
                    status: TraceCaseClaimStatus::Observed,
                    coverage_requirement: Default::default(),
                    supporting_evidence: vec![TraceCaseEvidenceRef {
                        artifact_id: artifact_id.clone(),
                        locator: format!("seq:{index}"),
                        description: "Observed trace evidence.".to_string(),
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
        }
        std::fs::write(dir.join("sample.log"), b"changed\n").unwrap();
        let request = AnalysisCaseEvidencePackRequest {
            case_path: case_path.to_string_lossy().into_owned(),
            max_tokens: 1_200,
            max_items: 16,
            include_generated_claims: false,
        };
        let first = build_analysis_case_evidence_pack(&request).unwrap();
        let second = build_analysis_case_evidence_pack(&request).unwrap();
        assert!(first.budget.truncated);
        assert!(first.budget.included_item_count <= 16);
        assert!(first.budget.estimated_token_count <= 1_200);
        assert!(!first.invalid_artifacts.is_empty());
        assert_eq!(
            first
                .claims
                .iter()
                .map(|claim| &claim.claim_id)
                .collect::<Vec<_>>(),
            second
                .claims
                .iter()
                .map(|claim| &claim.claim_id)
                .collect::<Vec<_>>()
        );
        let markdown = render_analysis_case_evidence_pack_markdown(&first);
        assert!(approximate_tokens(&markdown) <= 1_200);
        assert!(markdown.contains("truncated `true`"));
        let _ = std::fs::remove_dir_all(dir);
    }
}
