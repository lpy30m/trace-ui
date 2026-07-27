use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

use super::evidence_score::{score_evidence, EvidenceAssessment, EvidenceScoreSignal};
use super::whitebox_aes::{KeyExposure, TableFingerprint, WhiteBoxReport};

const MAX_CASES: usize = 16;

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct WhiteBoxTraceCaseRequest {
    pub session_id: String,
    pub label: String,
    pub key_group: String,
    pub input_group: String,
    pub static_binary_path: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct WhiteBoxMultiTraceRequest {
    pub cases: Vec<WhiteBoxTraceCaseRequest>,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct WhiteBoxTraceCaseSummary {
    pub session_id: String,
    pub label: String,
    pub key_group: String,
    pub input_group: String,
    pub fingerprint_count: u32,
    pub fingerprint_set_sha256: String,
    pub raw_key_observed: bool,
    pub semantic_verification: bool,
    pub binary_sha256: Option<String>,
    pub build_id: Option<String>,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct WhiteBoxKeyGroupSummary {
    pub key_group: String,
    pub case_count: u32,
    pub distinct_input_groups: u32,
    pub input_stable: bool,
    pub fingerprint_set_sha256: Option<String>,
    pub rationale: String,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct WhiteBoxCrossKeyComparison {
    pub left_key_group: String,
    pub right_key_group: String,
    pub same_table_shape: bool,
    pub same_fingerprint_values: bool,
    pub rationale: String,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct WhiteBoxMultiTraceReport {
    pub classification: String,
    pub whitebox_status: String,
    pub verification_gate_met: bool,
    pub rationale: String,
    pub cases: Vec<WhiteBoxTraceCaseSummary>,
    pub key_groups: Vec<WhiteBoxKeyGroupSummary>,
    pub cross_key_comparisons: Vec<WhiteBoxCrossKeyComparison>,
    pub assessment: EvidenceAssessment,
    pub limitations: Vec<String>,
    pub next_steps: Vec<String>,
}

pub struct WhiteBoxCaseAnalysis {
    pub request: WhiteBoxTraceCaseRequest,
    pub report: WhiteBoxReport,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct FingerprintSignature {
    hash: String,
    word_bytes: u8,
    distinct_words: u32,
}

pub fn compare_whitebox_cases(
    analyses: Vec<WhiteBoxCaseAnalysis>,
) -> Result<WhiteBoxMultiTraceReport, String> {
    if analyses.len() < 2 {
        return Err("multi-trace classification requires at least two cases".to_string());
    }
    if analyses.len() > MAX_CASES {
        return Err(format!(
            "multi-trace classification supports at most {MAX_CASES} cases"
        ));
    }
    for case in &analyses {
        if case.request.session_id.is_empty()
            || case.request.label.is_empty()
            || case.request.key_group.is_empty()
            || case.request.input_group.is_empty()
        {
            return Err(
                "every case requires non-empty sessionId, label, keyGroup, and inputGroup"
                    .to_string(),
            );
        }
    }
    let unique_sessions = analyses
        .iter()
        .map(|case| case.request.session_id.as_str())
        .collect::<BTreeSet<_>>();
    if unique_sessions.len() != analyses.len() {
        return Err("each multi-trace case must use a distinct sessionId".to_string());
    }

    let mut case_signatures = BTreeMap::<String, Vec<FingerprintSignature>>::new();
    let mut summaries = Vec::with_capacity(analyses.len());
    let mut any_raw_key = false;
    for case in &analyses {
        let signatures = signatures(&case.report.table_fingerprints);
        let set_hash = fingerprint_set_hash(&signatures);
        let raw_key = matches!(
            case.report.key_exposure,
            KeyExposure::RawKeyObserved | KeyExposure::ExpandedScheduleObserved
        );
        let semantic = case
            .report
            .software_crypto
            .as_ref()
            .is_some_and(|_| case.report.assessment.verification_gate_met);
        any_raw_key |= raw_key;
        summaries.push(WhiteBoxTraceCaseSummary {
            session_id: case.request.session_id.clone(),
            label: case.request.label.clone(),
            key_group: case.request.key_group.clone(),
            input_group: case.request.input_group.clone(),
            fingerprint_count: signatures.len() as u32,
            fingerprint_set_sha256: set_hash,
            raw_key_observed: raw_key,
            semantic_verification: semantic,
            binary_sha256: case
                .report
                .static_binary
                .as_ref()
                .map(|binary| binary.binary_sha256.clone()),
            build_id: case
                .report
                .static_binary
                .as_ref()
                .and_then(|binary| binary.build_id.clone()),
        });
        case_signatures.insert(case.request.session_id.clone(), signatures);
    }

    let mut by_key = BTreeMap::<String, Vec<&WhiteBoxCaseAnalysis>>::new();
    for case in &analyses {
        by_key
            .entry(case.request.key_group.clone())
            .or_default()
            .push(case);
    }

    let mut key_groups = Vec::new();
    for (key_group, cases) in &by_key {
        let input_groups = cases
            .iter()
            .map(|case| case.request.input_group.as_str())
            .collect::<BTreeSet<_>>();
        let first = cases
            .first()
            .and_then(|case| case_signatures.get(&case.request.session_id));
        let non_empty = first.is_some_and(|items| !items.is_empty());
        let stable = input_groups.len() >= 2
            && non_empty
            && cases
                .iter()
                .all(|case| case_signatures.get(&case.request.session_id) == first);
        key_groups.push(WhiteBoxKeyGroupSummary {
            key_group: key_group.clone(),
            case_count: cases.len() as u32,
            distinct_input_groups: input_groups.len() as u32,
            input_stable: stable,
            fingerprint_set_sha256: first.map(|items| fingerprint_set_hash(items)),
            rationale: if stable {
                format!(
                    "The normalized table fingerprint set is unchanged across {} labeled inputs.",
                    input_groups.len()
                )
            } else if input_groups.len() < 2 {
                "At least two differently labeled inputs are required to establish input stability."
                    .to_string()
            } else if !non_empty {
                "No crypto-eligible table fingerprints were observed.".to_string()
            } else {
                "Normalized table fingerprints changed across inputs in this key group.".to_string()
            },
        });
    }

    let key_names = by_key.keys().cloned().collect::<Vec<_>>();
    let mut cross_key_comparisons = Vec::new();
    for left in 0..key_names.len() {
        for right in left + 1..key_names.len() {
            let left_case = by_key[&key_names[left]][0];
            let right_case = by_key[&key_names[right]][0];
            let left_signatures = &case_signatures[&left_case.request.session_id];
            let right_signatures = &case_signatures[&right_case.request.session_id];
            let same_shape = shapes(left_signatures) == shapes(right_signatures);
            let same_values = left_signatures == right_signatures;
            cross_key_comparisons.push(WhiteBoxCrossKeyComparison {
                left_key_group: key_names[left].clone(),
                right_key_group: key_names[right].clone(),
                same_table_shape: same_shape,
                same_fingerprint_values: same_values,
                rationale: if same_values {
                    "The normalized table values are identical across the labeled keys.".to_string()
                } else if same_shape {
                    "Table shapes are stable while normalized table values differ across the labeled keys."
                        .to_string()
                } else {
                    "Both table shape and values differ; version/build drift cannot be separated from key dependence."
                        .to_string()
                },
            });
        }
    }

    let enough_keys = by_key.len() >= 2;
    let all_input_stable = enough_keys && key_groups.iter().all(|group| group.input_stable);
    let key_value_changes = !cross_key_comparisons.is_empty()
        && cross_key_comparisons
            .iter()
            .all(|comparison| comparison.same_table_shape && !comparison.same_fingerprint_values);
    let input_dependent = key_groups
        .iter()
        .any(|group| group.distinct_input_groups >= 2 && !group.input_stable);
    let input_independent = all_input_stable
        && cross_key_comparisons
            .iter()
            .all(|comparison| comparison.same_fingerprint_values);
    let known_binary_hashes = summaries
        .iter()
        .filter_map(|case| case.binary_sha256.as_deref())
        .collect::<BTreeSet<_>>();
    let all_binaries_known = summaries.iter().all(|case| case.binary_sha256.is_some());
    let same_binary = all_binaries_known && known_binary_hashes.len() == 1;

    let (classification, whitebox_status, rationale) = if any_raw_key {
        (
            "RawKeyExposureContradiction",
            "NotWhiteBox",
            "A raw key or expanded standard schedule was observed in at least one case; table differences cannot support a key-fused-only white-box claim.",
        )
    } else if input_dependent {
        (
            "InputDependentTables",
            "Candidate",
            "Table fingerprints changed across inputs within a labeled key group, so key dependence is not isolated.",
        )
    } else if all_input_stable && key_value_changes && same_binary {
        (
            "KeyDependentTableCandidate",
            "Related",
            "Table shapes and per-key input stability are preserved, while normalized values change across labeled key groups. This is multi-trace evidence for key-dependent tables, not semantic proof of the cipher or key.",
        )
    } else if all_input_stable && key_value_changes {
        (
            "BuildIdentityUnconfirmed",
            "Candidate",
            "The table pattern is compatible with key dependence, but identical ELF identity was not established across all cases; build/version drift remains a confounder.",
        )
    } else if input_independent {
        (
            "InputAndKeyIndependentTables",
            "Candidate",
            "The normalized table values remain stable across both input and key labels; the observed tables are not key-dependent under these runs.",
        )
    } else {
        (
            "InsufficientEvidence",
            "Unknown",
            "The case matrix does not yet isolate input stability and cross-key value changes with matching table shapes.",
        )
    };

    let limitations = vec![
        "Key and input groups are caller-provided labels; the engine cannot prove that the external test setup changed only that variable.".to_string(),
        "Normalized table equality/difference is structural evidence. It does not identify the algorithm, recover a key, or semantically verify encryption.".to_string(),
        "Only executed table entries observed in each dynamic trace contribute to fingerprints.".to_string(),
    ];
    let assessment = score_evidence(
        "multi_trace_key_dependent_tables",
        false,
        vec![
            EvidenceScoreSignal::new(
                "multiple_key_groups",
                "At least two labeled key groups were compared",
                20,
                enough_keys,
                Some(format!("{} key groups", by_key.len())),
            ),
            EvidenceScoreSignal::new(
                "input_stability",
                "Every key group has stable fingerprints across at least two inputs",
                30,
                all_input_stable,
                Some(format!(
                    "{}/{} stable groups",
                    key_groups.iter().filter(|group| group.input_stable).count(),
                    key_groups.len()
                )),
            ),
            EvidenceScoreSignal::new(
                "cross_key_value_change",
                "Matching table shapes have different normalized values across key groups",
                30,
                key_value_changes,
                Some(format!("{} cross-key pairs", cross_key_comparisons.len())),
            ),
            EvidenceScoreSignal::new(
                "no_raw_key_contradiction",
                "No raw key or standard expanded schedule was observed",
                20,
                !any_raw_key,
                None,
            ),
            EvidenceScoreSignal::new(
                "same_binary_identity",
                "Every case was reconciled to the same ELF SHA-256",
                20,
                same_binary,
                if all_binaries_known {
                    Some(format!("{} distinct ELF hashes", known_binary_hashes.len()))
                } else {
                    Some("one or more cases omitted static ELF identity".to_string())
                },
            ),
        ],
        limitations.clone(),
    );

    Ok(WhiteBoxMultiTraceReport {
        classification: classification.to_string(),
        whitebox_status: whitebox_status.to_string(),
        verification_gate_met: false,
        rationale: rationale.to_string(),
        cases: summaries,
        key_groups,
        cross_key_comparisons,
        assessment,
        limitations,
        next_steps: vec![
            "Use at least two inputs per key and at least two keys, keeping the SO build and tracing coverage constant.".to_string(),
            "Confirm matching ELF SHA-256/Build ID across cases, or explicitly treat differing binaries as a separate version variable.".to_string(),
            "Use semantic recomputation with independently known key/input/output material before making any Verified crypto claim.".to_string(),
        ],
    })
}

fn signatures(fingerprints: &[TableFingerprint]) -> Vec<FingerprintSignature> {
    let mut result = fingerprints
        .iter()
        .map(|fingerprint| FingerprintSignature {
            hash: fingerprint.normalized_sha256.clone(),
            word_bytes: fingerprint.word_bytes,
            distinct_words: fingerprint.distinct_words,
        })
        .collect::<Vec<_>>();
    result.sort_by(|left, right| {
        (&left.hash, left.word_bytes, left.distinct_words).cmp(&(
            &right.hash,
            right.word_bytes,
            right.distinct_words,
        ))
    });
    result.dedup();
    result
}

fn shapes(signatures: &[FingerprintSignature]) -> Vec<(u8, u32)> {
    let mut result = signatures
        .iter()
        .map(|signature| (signature.word_bytes, signature.distinct_words))
        .collect::<Vec<_>>();
    result.sort_unstable();
    result
}

fn fingerprint_set_hash(signatures: &[FingerprintSignature]) -> String {
    use sha2::{Digest, Sha256};
    let mut digest = Sha256::new();
    for signature in signatures {
        digest.update(signature.hash.as_bytes());
        digest.update([signature.word_bytes]);
        digest.update(signature.distinct_words.to_le_bytes());
    }
    digest
        .finalize()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::query::evidence_score::score_evidence;
    use crate::query::whitebox_aes::{
        AlgoVerdict, ImplementationKind, KeyExposure, StaticBinaryAnalysis, WhiteBoxStatus,
    };

    fn report(hash: &str, raw_key: bool) -> WhiteBoxReport {
        WhiteBoxReport {
            plaintext: None,
            ciphertext: None,
            input_candidates: Vec::new(),
            output_candidates: Vec::new(),
            implementation_kind: ImplementationKind::Unknown,
            key_exposure: if raw_key {
                KeyExposure::RawKeyObserved
            } else {
                KeyExposure::NotObserved
            },
            whitebox_status: WhiteBoxStatus::Candidate,
            tables: Vec::new(),
            table_fingerprints: vec![TableFingerprint {
                scope: "0x1000".to_string(),
                normalized_sha256: hash.to_string(),
                word_bytes: 4,
                distinct_words: 256,
                normalization: "test".to_string(),
                algorithm_hint: None,
            }],
            encoding_boundaries: Vec::new(),
            static_binary: Some(StaticBinaryAnalysis {
                binary_path: "same.so".to_string(),
                binary_sha256: "same-binary".to_string(),
                format: "ELF64".to_string(),
                architecture: "AArch64".to_string(),
                elf_machine: 183,
                build_id: Some("same-build".to_string()),
                load_segments: 1,
                table_matches: Vec::new(),
            }),
            table_read_total: 256,
            rounds: None,
            verdict: AlgoVerdict {
                algorithm: "Unknown".to_string(),
                block_bits: 0,
                round_count: None,
                rationale: "test".to_string(),
            },
            total_reads: 256,
            total_writes: 0,
            assessment: score_evidence("test", false, Vec::new(), Vec::new()),
            next_steps: Vec::new(),
            software_crypto: None,
            aes_sbox_fingerprints: Vec::new(),
            aes_key_schedules: Vec::new(),
            aes_semantic_verification: None,
        }
    }

    fn case(session: &str, key: &str, input: &str, hash: &str) -> WhiteBoxCaseAnalysis {
        WhiteBoxCaseAnalysis {
            request: WhiteBoxTraceCaseRequest {
                session_id: session.to_string(),
                label: session.to_string(),
                key_group: key.to_string(),
                input_group: input.to_string(),
                static_binary_path: None,
            },
            report: report(hash, false),
        }
    }

    #[test]
    fn classifies_input_stable_cross_key_changes_as_related_candidate() {
        let result = compare_whitebox_cases(vec![
            case("a1", "key-a", "input-1", "aa"),
            case("a2", "key-a", "input-2", "aa"),
            case("b1", "key-b", "input-1", "bb"),
            case("b2", "key-b", "input-2", "bb"),
        ])
        .unwrap();
        assert_eq!(result.classification, "KeyDependentTableCandidate");
        assert_eq!(result.whitebox_status, "Related");
        assert!(!result.verification_gate_met);
        assert!(!result.assessment.verification_gate_met);
    }

    #[test]
    fn rejects_input_varying_tables_and_raw_key_claims() {
        let input_dependent = compare_whitebox_cases(vec![
            case("a1", "key-a", "input-1", "aa"),
            case("a2", "key-a", "input-2", "ab"),
            case("b1", "key-b", "input-1", "bb"),
            case("b2", "key-b", "input-2", "bb"),
        ])
        .unwrap();
        assert_eq!(input_dependent.classification, "InputDependentTables");

        let mut raw = case("b2", "key-b", "input-2", "bb");
        raw.report = report("bb", true);
        let contradicted = compare_whitebox_cases(vec![
            case("a1", "key-a", "input-1", "aa"),
            case("a2", "key-a", "input-2", "aa"),
            case("b1", "key-b", "input-1", "bb"),
            raw,
        ])
        .unwrap();
        assert_eq!(contradicted.classification, "RawKeyExposureContradiction");
        assert_eq!(contradicted.whitebox_status, "NotWhiteBox");
    }
}
