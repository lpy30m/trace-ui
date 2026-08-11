use std::time::{SystemTime, UNIX_EPOCH};

use trace_core::{
    add_trace_case_artifact, create_trace_analysis_case, diagnose_trace_analysis_case,
    generate_minimal_evidence_slice, run_accuracy_benchmark_file, save_crypto_semantic_kat_report,
    save_minimal_evidence_slice_bundle, upsert_trace_case_claim, AccuracyBenchmarkCase,
    AccuracyBenchmarkClaimExpectation, AccuracyBenchmarkEvidenceSliceExpectation,
    AccuracyBenchmarkSuite, CryptoKatAlgorithm, CryptoSemanticKatRequest,
    MinimalEvidenceSliceRequest, TraceCaseClaim, TraceCaseClaimStatus, TraceCaseEvidenceRef,
    TraceEngine, ACCURACY_BENCHMARK_SUITE_SCHEMA, CRYPTO_SEMANTIC_KAT_SCHEMA,
};

fn temp_dir() -> std::path::PathBuf {
    std::env::temp_dir().join(format!(
        "trace-ui-accuracy-benchmark-{}",
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ))
}

fn claim(
    claim_id: &str,
    statement: &str,
    scope: &str,
    artifact_id: &str,
    locator: &str,
) -> TraceCaseClaim {
    TraceCaseClaim {
        claim_id: claim_id.to_string(),
        statement: statement.to_string(),
        scope: scope.to_string(),
        status: TraceCaseClaimStatus::Verified,
        coverage_requirement: Default::default(),
        supporting_evidence: vec![TraceCaseEvidenceRef {
            artifact_id: artifact_id.to_string(),
            locator: locator.to_string(),
            description: "Benchmark evidence reference.".to_string(),
        }],
        counter_evidence: Vec::new(),
        missing_evidence: Vec::new(),
        limitations: Vec::new(),
        created_by: "accuracy-benchmark-test".to_string(),
        created_at_ms: 1,
        updated_at_ms: 1,
    }
}

#[test]
fn accuracy_benchmark_ci_gate_blocks_forged_markers_and_accepts_strict_kat() {
    let dir = temp_dir();
    std::fs::create_dir_all(&dir).unwrap();
    let trace_path = dir.join("sample.log");
    let case_path = dir.join("sample.traceui-case");
    let kat_path = dir.join("sha256-kat.json");
    let suite_path = dir.join("accuracy-suite.json");
    std::fs::write(&trace_path, b"trace\n").unwrap();
    let document = create_trace_analysis_case(
        case_path.to_str().unwrap(),
        "accuracy benchmark fixture",
        Some(trace_path.to_str().unwrap()),
        None,
    )
    .unwrap();
    let trace_artifact_id = document.case.artifacts[0].artifact_id.clone();
    let request = CryptoSemanticKatRequest {
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
    let kat_report = save_crypto_semantic_kat_report(kat_path.to_str().unwrap(), &request).unwrap();
    let imported = add_trace_case_artifact(
        case_path.to_str().unwrap(),
        kat_path.to_str().unwrap(),
        None,
        None,
        Vec::new(),
    )
    .unwrap();
    upsert_trace_case_claim(
        case_path.to_str().unwrap(),
        claim(
            "strict-sha256",
            "The exact SHA-256 vector matches.",
            &kat_report.claim_scope,
            &imported.artifact.artifact_id,
            "crypto-kat/verified-full",
        ),
    )
    .unwrap();
    upsert_trace_case_claim(
        case_path.to_str().unwrap(),
        claim(
            "forged-ollvm",
            "The complete OLLVM CFG was recovered.",
            "ollvm:libtarget.so@0x100",
            &trace_artifact_id,
            "semantic-known-answer verification-gate",
        ),
    )
    .unwrap();

    let slice_path = dir.join("strict-sha256-slice.json");
    let slice_bundle = generate_minimal_evidence_slice(
        &TraceEngine::new(),
        &MinimalEvidenceSliceRequest {
            case_path: case_path.to_string_lossy().into_owned(),
            trace_session_bindings: Vec::new(),
            claim_ids: vec!["strict-sha256".to_string()],
            include_generated_claims: false,
            include_sensitive_values: true,
            context_before: 0,
            context_after: 0,
            module_bytes_before: 16,
            module_bytes_after: 32,
            max_memory_bytes_per_record: 256,
            max_records: 32,
            max_total_payload_bytes: 1024 * 1024,
        },
    )
    .unwrap();
    save_minimal_evidence_slice_bundle(&slice_bundle, slice_path.to_str().unwrap()).unwrap();
    let slice_imported = add_trace_case_artifact(
        case_path.to_str().unwrap(),
        slice_path.to_str().unwrap(),
        None,
        None,
        Vec::new(),
    )
    .unwrap();

    let diagnosed = diagnose_trace_analysis_case(case_path.to_str().unwrap()).unwrap();
    let generated_kat_claim = diagnosed
        .generated_claims
        .iter()
        .find(|claim| claim.scope == kat_report.claim_scope)
        .unwrap();
    let suite = AccuracyBenchmarkSuite {
        schema: ACCURACY_BENCHMARK_SUITE_SCHEMA.to_string(),
        suite_id: "ci-accuracy-gate".to_string(),
        cases: vec![AccuracyBenchmarkCase {
            case_id: "strict-gates".to_string(),
            case_path: case_path.to_string_lossy().into_owned(),
            expected_replay_status: Some("needs-runtime-capture".to_string()),
            expected_capture_plan_status: Some(diagnosed.capture_plan.status.clone()),
            expected_top_capture_action: diagnosed
                .capture_plan
                .targets
                .first()
                .map(|target| target.action.clone()),
            claim_expectations: vec![
                AccuracyBenchmarkClaimExpectation {
                    claim_id: "strict-sha256".to_string(),
                    expected_gate_status: "passed".to_string(),
                    expected_recommended_status: TraceCaseClaimStatus::Verified,
                    expected_verification_gate_passed: true,
                    expected_coverage_requirement: Some("not-required".to_string()),
                    expected_coverage_gate_status: Some("not-required".to_string()),
                    expected_coverage_gate_passed: Some(true),
                    expected_coverage_max_status: Some(TraceCaseClaimStatus::Verified),
                },
                AccuracyBenchmarkClaimExpectation {
                    claim_id: "forged-ollvm".to_string(),
                    expected_gate_status: "blocked".to_string(),
                    expected_recommended_status: TraceCaseClaimStatus::Related,
                    expected_verification_gate_passed: false,
                    expected_coverage_requirement: Some("complete-control-flow".to_string()),
                    expected_coverage_gate_status: Some("missing".to_string()),
                    expected_coverage_gate_passed: Some(false),
                    expected_coverage_max_status: Some(TraceCaseClaimStatus::Related),
                },
                AccuracyBenchmarkClaimExpectation {
                    claim_id: generated_kat_claim.claim_id.clone(),
                    expected_gate_status: "passed".to_string(),
                    expected_recommended_status: TraceCaseClaimStatus::Verified,
                    expected_verification_gate_passed: true,
                    expected_coverage_requirement: Some("not-required".to_string()),
                    expected_coverage_gate_status: Some("not-required".to_string()),
                    expected_coverage_gate_passed: Some(true),
                    expected_coverage_max_status: Some(TraceCaseClaimStatus::Verified),
                },
            ],
            evidence_slice_expectations: vec![AccuracyBenchmarkEvidenceSliceExpectation {
                artifact_id: slice_imported.artifact.artifact_id,
                expected_status: "valid-complete".to_string(),
                expected_record_count: Some(1),
                maximum_unresolved_reference_count: Some(0),
                maximum_truncated_record_count: Some(0),
                expected_claim_bindings_matched: Some(true),
                expected_generated_claim_bindings_revalidated: Some(true),
                expected_record_content_matched: Some(true),
                expected_provenance_graph_valid: Some(true),
            }],
            require_no_unexpected_verified: true,
        }],
    };
    std::fs::write(&suite_path, serde_json::to_vec_pretty(&suite).unwrap()).unwrap();
    let report = run_accuracy_benchmark_file(suite_path.to_str().unwrap()).unwrap();
    assert!(report.gate_met, "{:#?}", report.cases[0].failures);
    assert_eq!(report.verified_false_positive_count, 0);
    assert_eq!(report.verified_false_negative_count, 0);

    let mut wrong_suite = suite;
    wrong_suite.cases[0].claim_expectations[1].expected_gate_status = "passed".to_string();
    wrong_suite.cases[0].claim_expectations[1].expected_recommended_status =
        TraceCaseClaimStatus::Verified;
    wrong_suite.cases[0].claim_expectations[1].expected_verification_gate_passed = true;
    std::fs::write(
        &suite_path,
        serde_json::to_vec_pretty(&wrong_suite).unwrap(),
    )
    .unwrap();
    let failed = run_accuracy_benchmark_file(suite_path.to_str().unwrap()).unwrap();
    assert!(!failed.gate_met);
    assert!(failed.verified_false_negative_count >= 1);
    let _ = std::fs::remove_dir_all(dir);
}
