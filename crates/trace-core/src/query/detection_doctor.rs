use std::collections::BTreeSet;

use serde::Serialize;

use crate::query::crypto::CryptoScanResult;
use crate::query::crypto_functions::{base_algorithm, CryptoFunctionReport};
use crate::query::whitebox_aes::WhiteBoxReport;

pub const CRYPTO_DETECTION_DOCTOR_SCHEMA: &str = "trace-ui/crypto-detection-doctor-v1";

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CryptoDetectionStage {
    pub code: String,
    pub label: String,
    pub status: String,
    pub observed_count: u64,
    pub details: String,
    pub evidence: Vec<String>,
    pub blockers: Vec<String>,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CryptoDetectionDoctorReport {
    pub schema: String,
    pub session_id: String,
    pub target_algorithm: String,
    pub status: String,
    pub verification_gate_met: bool,
    pub total_lines_scanned: u32,
    pub algorithms_observed: Vec<String>,
    pub target_magic_hit_count: u64,
    pub target_crypto_instruction_count: u64,
    pub target_function_candidate_count: u64,
    pub structural_signal_count: u64,
    pub stages: Vec<CryptoDetectionStage>,
    pub failure_reasons: Vec<String>,
    pub next_actions: Vec<String>,
    pub limitations: Vec<String>,
}

fn normalized_family(value: &str) -> String {
    base_algorithm(value.trim()).to_ascii_uppercase()
}

fn family_matches(value: &str, target: &str) -> bool {
    normalized_family(value) == target
        || value
            .trim()
            .to_ascii_uppercase()
            .starts_with(&format!("{target}-"))
}

fn stage(
    code: &str,
    label: &str,
    status: &str,
    observed_count: u64,
    details: impl Into<String>,
    evidence: Vec<String>,
    blockers: Vec<String>,
) -> CryptoDetectionStage {
    CryptoDetectionStage {
        code: code.to_string(),
        label: label.to_string(),
        status: status.to_string(),
        observed_count,
        details: details.into(),
        evidence,
        blockers,
    }
}

pub fn build_crypto_detection_doctor_report(
    session_id: &str,
    target_algorithm: &str,
    scan: &CryptoScanResult,
    functions: &CryptoFunctionReport,
    implementation: &WhiteBoxReport,
    static_binary_supplied: bool,
) -> CryptoDetectionDoctorReport {
    let target = normalized_family(target_algorithm);
    let target_magic = scan
        .matches
        .iter()
        .filter(|item| family_matches(&item.algorithm, &target))
        .collect::<Vec<_>>();
    let target_candidates = functions
        .candidates
        .iter()
        .filter(|candidate| {
            candidate
                .algorithms
                .iter()
                .any(|algorithm| family_matches(algorithm, &target))
                || (target == "AES"
                    && (candidate.semantic_aes_verified()
                        || candidate.aes_sbox_distinct_indices > 0
                        || candidate
                            .software_signal_counts
                            .keys()
                            .any(|signal| signal.to_ascii_uppercase().contains("AES"))))
        })
        .collect::<Vec<_>>();
    let target_crypto_instruction_count = target_candidates
        .iter()
        .flat_map(|candidate| candidate.crypto_insn_counts.iter())
        .filter(|(family, _)| family_matches(family, &target))
        .map(|(_, count)| u64::from(*count))
        .sum::<u64>();
    let structural_signal_count = if target == "AES" {
        implementation.tables.len() as u64
            + implementation.table_fingerprints.len() as u64
            + implementation.aes_sbox_fingerprints.len() as u64
            + implementation.aes_key_schedules.len() as u64
            + u64::from(implementation.software_crypto.is_some())
    } else {
        implementation.tables.len() as u64 + implementation.table_fingerprints.len() as u64
    };
    let verification_gate_met = implementation.assessment.verification_gate_met
        && family_matches(&implementation.verdict.algorithm, &target);
    let algorithms_observed = scan
        .algorithms_found
        .iter()
        .cloned()
        .chain(
            functions
                .candidates
                .iter()
                .flat_map(|candidate| candidate.algorithms.iter().cloned()),
        )
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect::<Vec<_>>();

    let mut stages = Vec::new();
    stages.push(stage(
        "trace-index",
        "Trace parsing and indexed scan",
        if scan.total_lines_scanned > 0 {
            "passed"
        } else {
            "failed"
        },
        u64::from(scan.total_lines_scanned),
        format!(
            "{} dynamic trace line(s) were scanned in {} ms.",
            scan.total_lines_scanned, scan.scan_duration_ms
        ),
        Vec::new(),
        if scan.total_lines_scanned == 0 {
            vec!["No indexed trace lines were available to the detector.".to_string()]
        } else {
            Vec::new()
        },
    ));
    stages.push(stage(
        "magic-constants",
        "Magic-constant evidence",
        if target_magic.is_empty() {
            "not-observed"
        } else {
            "passed"
        },
        target_magic.len() as u64,
        if target_magic.is_empty() {
            format!("No raw {target} magic-constant hit was observed.")
        } else {
            format!(
                "Observed {} raw {target} magic-constant hit(s).",
                target_magic.len()
            )
        },
        target_magic
            .iter()
            .take(16)
            .map(|item| {
                format!(
                    "seq={} address={} {} {}",
                    item.seq, item.address, item.algorithm, item.magic_hex
                )
            })
            .collect(),
        if target_magic.is_empty() {
            vec![
                "Constants may be split across instructions, transformed, table-fused, bitsliced, or outside the captured execution."
                    .to_string(),
            ]
        } else {
            vec![
                "A constant hit is only a lead and does not prove the algorithm or key.".to_string(),
            ]
        },
    ));
    stages.push(stage(
        "crypto-instructions",
        "Dedicated ARM64 crypto instructions",
        if target_crypto_instruction_count > 0 {
            "passed"
        } else {
            "not-observed"
        },
        target_crypto_instruction_count,
        format!(
            "Observed {target_crypto_instruction_count} dedicated instruction hit(s) attributed to {target} candidate functions."
        ),
        target_candidates
            .iter()
            .filter(|candidate| candidate.crypto_insn_total > 0)
            .take(16)
            .map(|candidate| {
                format!(
                    "{} entrySeq={} instructions={}",
                    candidate
                        .func_name
                        .as_deref()
                        .unwrap_or(&candidate.func_addr),
                    candidate.entry_seq,
                    candidate.crypto_insn_total
                )
            })
            .collect(),
        if target_crypto_instruction_count == 0 {
            vec![
                "Software, table-driven, bitsliced, or obfuscated implementations may not use dedicated crypto instructions."
                    .to_string(),
            ]
        } else {
            Vec::new()
        },
    ));
    stages.push(stage(
        "function-attribution",
        "Function-level attribution",
        if target_candidates.is_empty() {
            "not-observed"
        } else {
            "passed"
        },
        target_candidates.len() as u64,
        format!(
            "{} function candidate(s) carry {target}-related constant, instruction, or software signals.",
            target_candidates.len()
        ),
        target_candidates
            .iter()
            .take(16)
            .map(|candidate| {
                format!(
                    "{} {} score={} gate={}",
                    candidate
                        .func_name
                        .as_deref()
                        .unwrap_or(&candidate.func_addr),
                    candidate.algorithms.join("/"),
                    candidate.assessment.score,
                    candidate.assessment.verification_gate_met
                )
            })
            .collect(),
        if target_candidates.is_empty() && !target_magic.is_empty() {
            vec![
                "Raw hits were observed but could not be coherently attributed to a function-level candidate."
                    .to_string(),
            ]
        } else {
            Vec::new()
        },
    ));
    stages.push(stage(
        "structural-analysis",
        "Software/table/obfuscation structure",
        if structural_signal_count > 0 {
            "passed"
        } else {
            "not-observed"
        },
        structural_signal_count,
        format!(
            "Observed {} table region(s), {} table fingerprint(s), {} AES S-box fingerprint(s), and {} AES key schedule candidate(s).",
            implementation.tables.len(),
            implementation.table_fingerprints.len(),
            implementation.aes_sbox_fingerprints.len(),
            implementation.aes_key_schedules.len()
        ),
        vec![
            format!("implementationKind={:?}", implementation.implementation_kind),
            format!("keyExposure={:?}", implementation.key_exposure),
            format!("verdict={}", implementation.verdict.algorithm),
        ],
        if structural_signal_count > 0 && !verification_gate_met {
            vec![
                "Structural table or OLLVM-like evidence remains Candidate/Related without semantic recomputation."
                    .to_string(),
            ]
        } else {
            Vec::new()
        },
    ));
    stages.push(stage(
        "semantic-verification",
        "Deterministic semantic recomputation",
        if verification_gate_met {
            "verified"
        } else if target_candidates.is_empty() && structural_signal_count == 0 {
            "not-observed"
        } else {
            "blocked"
        },
        u64::from(verification_gate_met),
        if verification_gate_met {
            format!(
                "The imported runtime bytes satisfy the declared verification gate for {}.",
                implementation.verdict.algorithm
            )
        } else {
            format!(
                "No complete key/input/output tuple has deterministically verified {target} for this trace scope."
            )
        },
        implementation
            .assessment
            .factors
            .iter()
            .filter(|factor| factor.observed)
            .map(|factor| {
                format!(
                    "{}={}{}",
                    factor.code,
                    factor.awarded_points,
                    factor
                        .evidence
                        .as_deref()
                        .map(|value| format!(" ({value})"))
                        .unwrap_or_default()
                )
            })
            .collect(),
        if verification_gate_met {
            Vec::new()
        } else {
            vec![
                "Complete observed key material, input bytes, output bytes, mode, direction, and boundary semantics are required."
                    .to_string(),
            ]
        },
    ));
    stages.push(stage(
        "static-binary",
        "Exact ELF reconciliation",
        if static_binary_supplied {
            match implementation.static_binary.as_ref() {
                Some(binary) if !binary.table_matches.is_empty() => "matched",
                Some(_) => "completed-no-match",
                None => "failed",
            }
        } else {
            "not-run"
        },
        implementation
            .static_binary
            .as_ref()
            .map(|binary| binary.table_matches.len() as u64)
            .unwrap_or_default(),
        implementation
            .static_binary
            .as_ref()
            .map(|binary| {
                format!(
                    "AArch64 ELF {} has SHA-256 {} and {} dynamic/static table match(es).",
                    binary.binary_path,
                    binary.binary_sha256,
                    binary.table_matches.len()
                )
            })
            .unwrap_or_else(|| {
                "No exact ELF was reconciled with the dynamic trace in this diagnosis.".to_string()
            }),
        implementation
            .static_binary
            .as_ref()
            .map(|binary| {
                binary
                    .table_matches
                    .iter()
                    .take(16)
                    .map(|item| {
                        format!(
                            "{} fileOffset={} ratio={:.3} {}",
                            item.module_offset, item.file_offset, item.match_ratio, item.match_kind
                        )
                    })
                    .collect()
            })
            .unwrap_or_default(),
        if let Some(binary) = implementation.static_binary.as_ref() {
            let mut blockers = vec![
                "The selected-file SHA-256 identifies that file; it is not runtime-image attestation or cipher semantics."
                    .to_string(),
            ];
            if binary.table_matches.is_empty() {
                blockers.push(
                    "The ELF scan completed, but no dynamic table region was reconciled; confirm the exact build/module mapping before using static provenance."
                        .to_string(),
                );
            }
            blockers
        } else if static_binary_supplied {
            vec!["The supplied ELF could not be inspected or reconciled.".to_string()]
        } else {
            vec![
                "Without the exact ELF, dynamic table provenance and build identity cannot be reconciled."
                    .to_string(),
            ]
        },
    ));

    let mut failure_reasons = Vec::new();
    let mut next_actions = Vec::new();
    if scan.total_lines_scanned == 0 {
        failure_reasons.push("No indexed trace lines were scanned.".to_string());
        next_actions
            .push("Build or rebuild the trace index, then rerun the diagnosis.".to_string());
    }
    if target_magic.is_empty()
        && target_crypto_instruction_count == 0
        && structural_signal_count == 0
    {
        failure_reasons.push(format!(
            "No {target} constant, dedicated-instruction, S-box/schedule, or table-structure signal was observed in the executed trace."
        ));
        next_actions.push(
            "Confirm that the trace begins before the suspected computation and includes the target function return."
                .to_string(),
        );
        next_actions.push(
            "Search the suspected function for split constants, TBL/TBX/permutation-heavy software shapes, and native call boundaries."
                .to_string(),
        );
    }
    if !target_magic.is_empty() && target_candidates.is_empty() {
        failure_reasons.push(
            "Raw target constants were observed, but function-level attribution did not produce a coherent candidate."
                .to_string(),
        );
        next_actions.push(
            "Inspect exact trace lines around the raw hits and verify call-tree scope/function boundaries."
                .to_string(),
        );
    }
    if !verification_gate_met && (!target_candidates.is_empty() || structural_signal_count > 0) {
        failure_reasons.push(
            "Candidate evidence exists, but deterministic semantic verification is missing."
                .to_string(),
        );
        next_actions.push(
            "Capture a complete same-call key/input/output tuple with explicit byte lengths and direction, then rerun semantic verification."
                .to_string(),
        );
    }
    if !static_binary_supplied {
        next_actions.push(
            "Supply the exact AArch64 ELF/shared object to reconcile dynamic table reads and bind later replay artifacts to SHA-256."
                .to_string(),
        );
    } else if implementation
        .static_binary
        .as_ref()
        .is_some_and(|binary| binary.table_matches.is_empty())
    {
        next_actions.push(
            "The selected ELF produced no dynamic/static table match; confirm that it is the exact module build before using it for provenance or replay."
                .to_string(),
        );
    }
    if verification_gate_met {
        next_actions.push(
            "Save the analysis_id/report and preserve the exact trace/ELF hashes so the verified scope remains auditable."
                .to_string(),
        );
    }
    next_actions.sort();
    next_actions.dedup();

    let status = if verification_gate_met {
        "verified"
    } else if !target_candidates.is_empty()
        || structural_signal_count > 0
        || !target_magic.is_empty()
    {
        "related"
    } else if scan.total_lines_scanned == 0 {
        "diagnostic-failure"
    } else {
        "not-observed"
    };

    CryptoDetectionDoctorReport {
        schema: CRYPTO_DETECTION_DOCTOR_SCHEMA.to_string(),
        session_id: session_id.to_string(),
        target_algorithm: target,
        status: status.to_string(),
        verification_gate_met,
        total_lines_scanned: scan.total_lines_scanned,
        algorithms_observed,
        target_magic_hit_count: target_magic.len() as u64,
        target_crypto_instruction_count,
        target_function_candidate_count: target_candidates.len() as u64,
        structural_signal_count,
        stages,
        failure_reasons,
        next_actions,
        limitations: vec![
            "A dynamic trace contains executed instructions only; an unobserved algorithm may be outside the captured path or time range."
                .to_string(),
            "A single magic constant, crypto instruction, table shape, or function score is not semantic proof."
                .to_string(),
            "Only a declared deterministic verification gate may produce Verified status."
                .to_string(),
        ],
    }
}

trait CryptoCandidateExt {
    fn semantic_aes_verified(&self) -> bool;
}

impl CryptoCandidateExt for crate::query::crypto_functions::CryptoFunctionCandidate {
    fn semantic_aes_verified(&self) -> bool {
        self.assessment.verification_gate_met
            || self
                .verification_status
                .as_deref()
                .is_some_and(|status| status.eq_ignore_ascii_case("verified"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::query::evidence_score::score_evidence;
    use crate::query::whitebox_aes::{
        AlgoVerdict, ImplementationKind, KeyExposure, StaticBinaryAnalysis, WhiteBoxStatus,
    };

    fn empty_implementation() -> WhiteBoxReport {
        WhiteBoxReport {
            plaintext: None,
            ciphertext: None,
            input_candidates: Vec::new(),
            output_candidates: Vec::new(),
            implementation_kind: ImplementationKind::Unknown,
            key_exposure: KeyExposure::NotObserved,
            whitebox_status: WhiteBoxStatus::Unknown,
            tables: Vec::new(),
            table_fingerprints: Vec::new(),
            encoding_boundaries: Vec::new(),
            static_binary: None,
            table_read_total: 0,
            rounds: None,
            verdict: AlgoVerdict {
                algorithm: "未定".to_string(),
                block_bits: 0,
                round_count: None,
                rationale: "none".to_string(),
            },
            total_reads: 0,
            total_writes: 0,
            assessment: score_evidence("crypto", false, Vec::new(), Vec::new()),
            next_steps: Vec::new(),
            software_crypto: None,
            aes_sbox_fingerprints: Vec::new(),
            aes_key_schedules: Vec::new(),
            aes_semantic_verification: None,
        }
    }

    #[test]
    fn explains_a_clean_negative_without_claiming_absence() {
        let scan = CryptoScanResult {
            matches: Vec::new(),
            algorithms_found: Vec::new(),
            total_lines_scanned: 123,
            scan_duration_ms: 2,
        };
        let functions = CryptoFunctionReport {
            candidates: Vec::new(),
            total_functions_scanned: 3,
            functions_with_signals: 0,
            magic_hit_count: 0,
            crypto_insn_count: 0,
            software_signal_count: 0,
            candidates_truncated: false,
            limitations: Vec::new(),
            coverage: Vec::new(),
            zero_result_explanation: Some("none".to_string()),
        };
        let report = build_crypto_detection_doctor_report(
            "session",
            "AES",
            &scan,
            &functions,
            &empty_implementation(),
            false,
        );
        assert_eq!(report.status, "not-observed");
        assert!(!report.verification_gate_met);
        assert!(report
            .limitations
            .iter()
            .any(|item| item.contains("unobserved algorithm")));
        assert!(report
            .next_actions
            .iter()
            .any(|item| item.contains("exact AArch64 ELF")));
    }

    #[test]
    fn distinguishes_completed_static_scan_from_dynamic_table_match() {
        let scan = CryptoScanResult {
            matches: Vec::new(),
            algorithms_found: Vec::new(),
            total_lines_scanned: 1,
            scan_duration_ms: 1,
        };
        let functions = CryptoFunctionReport {
            candidates: Vec::new(),
            total_functions_scanned: 0,
            functions_with_signals: 0,
            magic_hit_count: 0,
            crypto_insn_count: 0,
            software_signal_count: 0,
            candidates_truncated: false,
            limitations: Vec::new(),
            coverage: Vec::new(),
            zero_result_explanation: None,
        };
        let mut implementation = empty_implementation();
        implementation.static_binary = Some(StaticBinaryAnalysis {
            binary_path: "libtarget.so".to_string(),
            binary_sha256: "a".repeat(64),
            format: "ELF64 little-endian".to_string(),
            architecture: "AArch64".to_string(),
            elf_machine: 183,
            build_id: None,
            load_segments: 1,
            table_matches: Vec::new(),
        });
        let report = build_crypto_detection_doctor_report(
            "session",
            "AES",
            &scan,
            &functions,
            &implementation,
            true,
        );
        let stage = report
            .stages
            .iter()
            .find(|stage| stage.code == "static-binary")
            .unwrap();
        assert_eq!(stage.status, "completed-no-match");
        assert!(report
            .next_actions
            .iter()
            .any(|action| action.contains("no dynamic/static table match")));
    }
}
