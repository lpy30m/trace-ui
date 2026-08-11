use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::analysis_case::{
    diagnose_trace_analysis_case, TraceCaseClaimStatus, INFORMATION_GAIN_CAPTURE_PLAN_SCHEMA,
};

pub const ACCURACY_BENCHMARK_SUITE_SCHEMA: &str = "trace-ui/accuracy-benchmark-suite-v1";
pub const ACCURACY_BENCHMARK_REPORT_SCHEMA: &str = "trace-ui/accuracy-benchmark-report-v1";
const MAX_SUITE_BYTES: u64 = 2 * 1024 * 1024;
const MAX_BENCHMARK_CASES: usize = 128;
const MAX_EXPECTATIONS: usize = 4096;

fn default_require_no_unexpected_verified() -> bool {
    true
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AccuracyBenchmarkClaimExpectation {
    pub claim_id: String,
    pub expected_gate_status: String,
    pub expected_recommended_status: TraceCaseClaimStatus,
    pub expected_verification_gate_passed: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expected_coverage_requirement: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expected_coverage_gate_status: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expected_coverage_gate_passed: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expected_coverage_max_status: Option<TraceCaseClaimStatus>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AccuracyBenchmarkEvidenceSliceExpectation {
    pub artifact_id: String,
    pub expected_status: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expected_record_count: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub maximum_unresolved_reference_count: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub maximum_truncated_record_count: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expected_claim_bindings_matched: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expected_generated_claim_bindings_revalidated: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expected_record_content_matched: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expected_provenance_graph_valid: Option<bool>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AccuracyBenchmarkCase {
    pub case_id: String,
    pub case_path: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expected_replay_status: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expected_capture_plan_status: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expected_top_capture_action: Option<String>,
    #[serde(default)]
    pub claim_expectations: Vec<AccuracyBenchmarkClaimExpectation>,
    #[serde(default)]
    pub evidence_slice_expectations: Vec<AccuracyBenchmarkEvidenceSliceExpectation>,
    #[serde(default = "default_require_no_unexpected_verified")]
    pub require_no_unexpected_verified: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AccuracyBenchmarkSuite {
    pub schema: String,
    pub suite_id: String,
    pub cases: Vec<AccuracyBenchmarkCase>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AccuracyBenchmarkFailure {
    pub kind: String,
    pub subject: String,
    pub expected: String,
    pub actual: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AccuracyBenchmarkCaseResult {
    pub case_id: String,
    pub resolved_case_path: String,
    pub passed: bool,
    pub assertion_count: u64,
    pub passed_assertion_count: u64,
    pub failed_assertion_count: u64,
    pub verified_false_positive_count: u64,
    pub verified_false_negative_count: u64,
    pub fixture_error_count: u64,
    pub coverage_gate_drift_count: u64,
    pub evidence_slice_drift_count: u64,
    pub failures: Vec<AccuracyBenchmarkFailure>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AccuracyBenchmarkReport {
    pub schema: String,
    pub suite_id: String,
    pub gate_met: bool,
    pub case_count: u64,
    pub passed_case_count: u64,
    pub failed_case_count: u64,
    pub assertion_count: u64,
    pub passed_assertion_count: u64,
    pub failed_assertion_count: u64,
    pub verified_false_positive_count: u64,
    pub verified_false_negative_count: u64,
    pub fixture_error_count: u64,
    pub coverage_gate_drift_count: u64,
    pub evidence_slice_drift_count: u64,
    pub cases: Vec<AccuracyBenchmarkCaseResult>,
    pub limitations: Vec<String>,
}

fn validate_suite(suite: &AccuracyBenchmarkSuite) -> Result<(), String> {
    if suite.schema != ACCURACY_BENCHMARK_SUITE_SCHEMA {
        return Err(format!(
            "unsupported accuracy benchmark schema: {}",
            suite.schema
        ));
    }
    if suite.suite_id.trim().is_empty() {
        return Err("accuracy benchmark suiteId must not be empty".to_string());
    }
    if suite.cases.is_empty() || suite.cases.len() > MAX_BENCHMARK_CASES {
        return Err(format!(
            "accuracy benchmark requires 1-{MAX_BENCHMARK_CASES} cases"
        ));
    }
    let expectation_count = suite
        .cases
        .iter()
        .map(|case| case.claim_expectations.len() + case.evidence_slice_expectations.len())
        .sum::<usize>();
    if expectation_count > MAX_EXPECTATIONS {
        return Err(format!(
            "accuracy benchmark exceeds {MAX_EXPECTATIONS} claim expectations"
        ));
    }
    let mut case_ids = std::collections::BTreeSet::new();
    for case in &suite.cases {
        if case.case_id.trim().is_empty()
            || case.case_path.trim().is_empty()
            || !case_ids.insert(case.case_id.as_str())
        {
            return Err(format!(
                "accuracy benchmark contains an invalid or duplicate caseId: {}",
                case.case_id
            ));
        }
        let mut claim_ids = std::collections::BTreeSet::new();
        for expectation in &case.claim_expectations {
            if expectation.claim_id.trim().is_empty()
                || !claim_ids.insert(expectation.claim_id.as_str())
            {
                return Err(format!(
                    "benchmark case {} contains an invalid or duplicate claimId expectation: {}",
                    case.case_id, expectation.claim_id
                ));
            }
            if !matches!(
                expectation.expected_gate_status.as_str(),
                "passed" | "blocked" | "unknown"
            ) {
                return Err(format!(
                    "benchmark claim {} has unsupported expectedGateStatus {}",
                    expectation.claim_id, expectation.expected_gate_status
                ));
            }
            if expectation
                .expected_coverage_requirement
                .as_deref()
                .is_some_and(|value| {
                    !matches!(
                        value,
                        "not-required"
                            | "scope-complete"
                            | "negative-existence"
                            | "global-invariance"
                            | "exhaustive-enumeration"
                            | "complete-control-flow"
                    )
                })
            {
                return Err(format!(
                    "benchmark claim {} has unsupported expectedCoverageRequirement {:?}",
                    expectation.claim_id, expectation.expected_coverage_requirement
                ));
            }
            if expectation
                .expected_coverage_gate_status
                .as_deref()
                .is_some_and(|value| {
                    !matches!(
                        value,
                        "not-required" | "missing" | "scope-mismatch" | "partial" | "passed"
                    )
                })
            {
                return Err(format!(
                    "benchmark claim {} has unsupported expectedCoverageGateStatus {:?}",
                    expectation.claim_id, expectation.expected_coverage_gate_status
                ));
            }
        }
        let mut evidence_slice_artifact_ids = std::collections::BTreeSet::new();
        for expectation in &case.evidence_slice_expectations {
            if expectation.artifact_id.trim().is_empty()
                || expectation.expected_status.trim().is_empty()
                || !evidence_slice_artifact_ids.insert(expectation.artifact_id.as_str())
            {
                return Err(format!(
                    "benchmark case {} contains an invalid or duplicate evidence-slice artifact expectation: {}",
                    case.case_id, expectation.artifact_id
                ));
            }
        }
    }
    Ok(())
}

fn resolved_case_path(base_dir: &Path, case_path: &str) -> PathBuf {
    let path = Path::new(case_path);
    if path.is_absolute() {
        path.to_path_buf()
    } else {
        base_dir.join(path)
    }
}

fn push_assertion(
    result: &mut AccuracyBenchmarkCaseResult,
    passed: bool,
    kind: &str,
    subject: impl Into<String>,
    expected: impl Into<String>,
    actual: impl Into<String>,
) {
    result.assertion_count += 1;
    if passed {
        result.passed_assertion_count += 1;
    } else {
        result.failed_assertion_count += 1;
        result.failures.push(AccuracyBenchmarkFailure {
            kind: kind.to_string(),
            subject: subject.into(),
            expected: expected.into(),
            actual: actual.into(),
        });
    }
}

fn push_evidence_slice_assertion(
    result: &mut AccuracyBenchmarkCaseResult,
    passed: bool,
    kind: &str,
    subject: impl Into<String>,
    expected: impl Into<String>,
    actual: impl Into<String>,
) {
    if !passed {
        result.evidence_slice_drift_count += 1;
    }
    push_assertion(result, passed, kind, subject, expected, actual);
}

pub fn run_accuracy_benchmark_suite(
    suite: &AccuracyBenchmarkSuite,
    base_dir: &Path,
) -> Result<AccuracyBenchmarkReport, String> {
    validate_suite(suite)?;
    let mut case_results = Vec::with_capacity(suite.cases.len());
    for case in &suite.cases {
        let path = resolved_case_path(base_dir, &case.case_path);
        let mut result = AccuracyBenchmarkCaseResult {
            case_id: case.case_id.clone(),
            resolved_case_path: path.to_string_lossy().into_owned(),
            passed: false,
            assertion_count: 0,
            passed_assertion_count: 0,
            failed_assertion_count: 0,
            verified_false_positive_count: 0,
            verified_false_negative_count: 0,
            fixture_error_count: 0,
            coverage_gate_drift_count: 0,
            evidence_slice_drift_count: 0,
            failures: Vec::new(),
        };
        let report = match diagnose_trace_analysis_case(&path.to_string_lossy()) {
            Ok(report) => report,
            Err(error) => {
                result.fixture_error_count = 1;
                result.failures.push(AccuracyBenchmarkFailure {
                    kind: "fixture-error".to_string(),
                    subject: case.case_id.clone(),
                    expected: "diagnosable .traceui-case".to_string(),
                    actual: error.to_string(),
                });
                case_results.push(result);
                continue;
            }
        };
        if let Some(expected) = &case.expected_replay_status {
            push_assertion(
                &mut result,
                report.status == *expected,
                "replay-status-drift",
                "replayDoctor.status",
                expected.clone(),
                report.status.clone(),
            );
        }
        if let Some(expected) = &case.expected_capture_plan_status {
            push_assertion(
                &mut result,
                report.capture_plan.status == *expected,
                "capture-plan-status-drift",
                INFORMATION_GAIN_CAPTURE_PLAN_SCHEMA,
                expected.clone(),
                report.capture_plan.status.clone(),
            );
        }
        if let Some(expected) = &case.expected_top_capture_action {
            let actual = report
                .capture_plan
                .targets
                .first()
                .map(|target| target.action.clone())
                .unwrap_or_else(|| "<none>".to_string());
            push_assertion(
                &mut result,
                actual == *expected,
                "capture-plan-ranking-drift",
                "capturePlan.targets[0].action",
                expected.clone(),
                actual,
            );
        }

        for expectation in &case.evidence_slice_expectations {
            let actual = report
                .evidence_slices
                .iter()
                .find(|slice| slice.artifact_id == expectation.artifact_id);
            let Some(actual) = actual else {
                push_evidence_slice_assertion(
                    &mut result,
                    false,
                    "missing-evidence-slice",
                    expectation.artifact_id.clone(),
                    "strictly inspected evidence slice present".to_string(),
                    "evidence slice absent or invalid".to_string(),
                );
                continue;
            };
            push_evidence_slice_assertion(
                &mut result,
                actual.report.status == expectation.expected_status,
                "evidence-slice-status-drift",
                expectation.artifact_id.clone(),
                expectation.expected_status.clone(),
                actual.report.status.clone(),
            );
            if let Some(expected) = expectation.expected_record_count {
                push_evidence_slice_assertion(
                    &mut result,
                    actual.report.summary_recomputed.record_count == expected,
                    "evidence-slice-record-count-drift",
                    expectation.artifact_id.clone(),
                    expected.to_string(),
                    actual.report.summary_recomputed.record_count.to_string(),
                );
            }
            if let Some(maximum) = expectation.maximum_unresolved_reference_count {
                let actual_count = actual.report.summary_recomputed.unresolved_reference_count;
                push_evidence_slice_assertion(
                    &mut result,
                    actual_count <= maximum,
                    "evidence-slice-unresolved-drift",
                    expectation.artifact_id.clone(),
                    format!("<= {maximum}"),
                    actual_count.to_string(),
                );
            }
            if let Some(maximum) = expectation.maximum_truncated_record_count {
                let actual_count = actual.report.summary_recomputed.truncated_record_count;
                push_evidence_slice_assertion(
                    &mut result,
                    actual_count <= maximum,
                    "evidence-slice-truncation-drift",
                    expectation.artifact_id.clone(),
                    format!("<= {maximum}"),
                    actual_count.to_string(),
                );
            }
            for (expected, actual_value, kind, field) in [
                (
                    expectation.expected_claim_bindings_matched,
                    actual.report.claim_bindings_matched,
                    "evidence-slice-claim-binding-drift",
                    "claimBindingsMatched",
                ),
                (
                    expectation.expected_generated_claim_bindings_revalidated,
                    actual.report.generated_claim_bindings_revalidated,
                    "evidence-slice-generated-binding-drift",
                    "generatedClaimBindingsRevalidated",
                ),
                (
                    expectation.expected_record_content_matched,
                    actual.report.record_content_matched,
                    "evidence-slice-record-content-drift",
                    "recordContentMatched",
                ),
                (
                    expectation.expected_provenance_graph_valid,
                    actual.report.provenance_graph_valid,
                    "evidence-slice-provenance-drift",
                    "provenanceGraphValid",
                ),
            ] {
                if let Some(expected) = expected {
                    push_evidence_slice_assertion(
                        &mut result,
                        actual_value == expected,
                        kind,
                        format!("{}:{field}", expectation.artifact_id),
                        expected.to_string(),
                        actual_value.to_string(),
                    );
                }
            }
        }

        for expectation in &case.claim_expectations {
            let actual = report
                .claim_ledger_audit
                .claims
                .iter()
                .find(|claim| claim.claim_id == expectation.claim_id);
            let Some(actual) = actual else {
                if expectation.expected_verification_gate_passed {
                    result.verified_false_negative_count += 1;
                }
                push_assertion(
                    &mut result,
                    false,
                    "missing-claim",
                    expectation.claim_id.clone(),
                    "claim present".to_string(),
                    "claim absent".to_string(),
                );
                continue;
            };
            push_assertion(
                &mut result,
                actual.gate_status == expectation.expected_gate_status,
                "claim-gate-status-drift",
                expectation.claim_id.clone(),
                expectation.expected_gate_status.clone(),
                actual.gate_status.clone(),
            );
            push_assertion(
                &mut result,
                actual.recommended_status == expectation.expected_recommended_status,
                "claim-recommended-status-drift",
                expectation.claim_id.clone(),
                format!("{:?}", expectation.expected_recommended_status),
                format!("{:?}", actual.recommended_status),
            );
            if actual.verification_gate_passed && !expectation.expected_verification_gate_passed {
                result.verified_false_positive_count += 1;
            } else if !actual.verification_gate_passed
                && expectation.expected_verification_gate_passed
            {
                result.verified_false_negative_count += 1;
            }
            push_assertion(
                &mut result,
                actual.verification_gate_passed == expectation.expected_verification_gate_passed,
                "claim-verified-gate-drift",
                expectation.claim_id.clone(),
                expectation.expected_verification_gate_passed.to_string(),
                actual.verification_gate_passed.to_string(),
            );
            if let Some(expected) = &expectation.expected_coverage_requirement {
                let passed = actual.coverage_requirement == *expected;
                if !passed {
                    result.coverage_gate_drift_count += 1;
                }
                push_assertion(
                    &mut result,
                    passed,
                    "coverage-requirement-drift",
                    expectation.claim_id.clone(),
                    expected.clone(),
                    actual.coverage_requirement.clone(),
                );
            }
            if let Some(expected) = &expectation.expected_coverage_gate_status {
                let passed = actual.coverage_gate_status == *expected;
                if !passed {
                    result.coverage_gate_drift_count += 1;
                }
                push_assertion(
                    &mut result,
                    passed,
                    "coverage-gate-status-drift",
                    expectation.claim_id.clone(),
                    expected.clone(),
                    actual.coverage_gate_status.clone(),
                );
            }
            if let Some(expected) = expectation.expected_coverage_gate_passed {
                let passed = actual.coverage_gate_passed == expected;
                if !passed {
                    result.coverage_gate_drift_count += 1;
                }
                push_assertion(
                    &mut result,
                    passed,
                    "coverage-gate-result-drift",
                    expectation.claim_id.clone(),
                    expected.to_string(),
                    actual.coverage_gate_passed.to_string(),
                );
            }
            if let Some(expected) = expectation.expected_coverage_max_status {
                let passed = actual.coverage_max_status == expected;
                if !passed {
                    result.coverage_gate_drift_count += 1;
                }
                push_assertion(
                    &mut result,
                    passed,
                    "coverage-max-status-drift",
                    expectation.claim_id.clone(),
                    format!("{expected:?}"),
                    format!("{:?}", actual.coverage_max_status),
                );
            }
        }

        if case.require_no_unexpected_verified {
            let expected_verified = case
                .claim_expectations
                .iter()
                .filter(|expectation| expectation.expected_verification_gate_passed)
                .map(|expectation| expectation.claim_id.as_str())
                .collect::<std::collections::BTreeSet<_>>();
            let unexpected = report
                .claim_ledger_audit
                .claims
                .iter()
                .filter(|claim| {
                    claim.verification_gate_passed
                        && !expected_verified.contains(claim.claim_id.as_str())
                })
                .map(|claim| claim.claim_id.clone())
                .collect::<Vec<_>>();
            for claim_id in unexpected {
                result.verified_false_positive_count += 1;
                push_assertion(
                    &mut result,
                    false,
                    "unexpected-verified-claim",
                    claim_id,
                    "not Verified unless explicitly expected".to_string(),
                    "verificationGatePassed=true".to_string(),
                );
            }
        }
        result.passed = result.failed_assertion_count == 0
            && result.fixture_error_count == 0
            && result.verified_false_positive_count == 0
            && result.verified_false_negative_count == 0;
        case_results.push(result);
    }

    let assertion_count = case_results.iter().map(|case| case.assertion_count).sum();
    let passed_assertion_count = case_results
        .iter()
        .map(|case| case.passed_assertion_count)
        .sum();
    let failed_assertion_count = case_results
        .iter()
        .map(|case| case.failed_assertion_count)
        .sum();
    let verified_false_positive_count = case_results
        .iter()
        .map(|case| case.verified_false_positive_count)
        .sum();
    let verified_false_negative_count = case_results
        .iter()
        .map(|case| case.verified_false_negative_count)
        .sum();
    let fixture_error_count = case_results
        .iter()
        .map(|case| case.fixture_error_count)
        .sum();
    let coverage_gate_drift_count = case_results
        .iter()
        .map(|case| case.coverage_gate_drift_count)
        .sum();
    let evidence_slice_drift_count = case_results
        .iter()
        .map(|case| case.evidence_slice_drift_count)
        .sum();
    let passed_case_count = case_results.iter().filter(|case| case.passed).count() as u64;
    let failed_case_count = case_results.len() as u64 - passed_case_count;
    Ok(AccuracyBenchmarkReport {
        schema: ACCURACY_BENCHMARK_REPORT_SCHEMA.to_string(),
        suite_id: suite.suite_id.clone(),
        gate_met: failed_case_count == 0
            && verified_false_positive_count == 0
            && verified_false_negative_count == 0
            && fixture_error_count == 0
            && coverage_gate_drift_count == 0
            && evidence_slice_drift_count == 0,
        case_count: case_results.len() as u64,
        passed_case_count,
        failed_case_count,
        assertion_count,
        passed_assertion_count,
        failed_assertion_count,
        verified_false_positive_count,
        verified_false_negative_count,
        fixture_error_count,
        coverage_gate_drift_count,
        evidence_slice_drift_count,
        cases: case_results,
        limitations: vec![
            "The benchmark detects declared status/gate/ranking drift, coverage-requirement/gate drift, and unexpected Verified claims; it does not establish that fixture labels describe ground truth unless the fixtures themselves are independently reviewed."
                .to_string(),
            "Positive and negative fixtures should include wrong ELF, forged marker/coverage summary, partial coverage, invalid/tampered KAT, sampled attestation, counter-evidence, and OLLVM/simulation non-promotion cases."
                .to_string(),
            "Evidence-slice expectations regression-check strict source/record/provenance handling and unresolved/truncated limits; a passing fixture still does not make the sliced claim semantically true."
                .to_string(),
        ],
    })
}

pub fn run_accuracy_benchmark_file(path: &str) -> Result<AccuracyBenchmarkReport, String> {
    let path = Path::new(path);
    let metadata = path
        .metadata()
        .map_err(|error| format!("failed to inspect accuracy benchmark suite: {error}"))?;
    if !metadata.is_file() {
        return Err("accuracy benchmark suite is not a regular file".to_string());
    }
    if metadata.len() > MAX_SUITE_BYTES {
        return Err(format!(
            "accuracy benchmark suite exceeds {MAX_SUITE_BYTES} bytes"
        ));
    }
    let bytes = std::fs::read(path)
        .map_err(|error| format!("failed to read accuracy benchmark suite: {error}"))?;
    let suite: AccuracyBenchmarkSuite = serde_json::from_slice(&bytes)
        .map_err(|error| format!("invalid accuracy benchmark suite JSON: {error}"))?;
    let base_dir = path.parent().unwrap_or_else(|| Path::new("."));
    run_accuracy_benchmark_suite(&suite, base_dir)
}
