use trace_core::{BuildOptions, TraceEngine};

#[test]
#[ignore = "requires TRACE_UI_REAL_AES_LOG and optional TRACE_UI_REAL_AES_ELF local fixtures"]
fn detects_sh_security_software_aes_candidate() {
    let trace_path = std::env::var("TRACE_UI_REAL_AES_LOG")
        .expect("TRACE_UI_REAL_AES_LOG must point to the local AES trace fixture");
    let exact_elf = std::env::var("TRACE_UI_REAL_AES_ELF").ok();
    let cache_dir =
        std::env::temp_dir().join(format!("trace-ui-real-aes-cache-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir_all(&cache_dir).unwrap();

    let engine = TraceEngine::new();
    engine
        .set_cache_dir(Some(cache_dir.to_string_lossy().into_owned()))
        .unwrap();
    let session = engine.create_session(&trace_path).unwrap();
    engine
        .build_index(
            &session.session_id,
            BuildOptions {
                force_rebuild: true,
                skip_strings: true,
            },
            None,
        )
        .unwrap();
    let report = engine
        .diagnose_crypto_detection(&session.session_id, "AES", exact_elf.clone())
        .unwrap();
    println!("{}", serde_json::to_string_pretty(&report).unwrap());

    assert_eq!(
        report.total_lines_scanned, 460_975,
        "the checked sh_security fixture changed or was parsed with a different line model"
    );
    assert_eq!(
        report.target_magic_hit_count, 0,
        "this regression must prove software AES without relying on raw magic constants"
    );
    assert_eq!(
        report.target_crypto_instruction_count, 0,
        "this regression must prove software AES without AESE/AESMC/AESD/AESIMC"
    );
    assert_eq!(
        report.status, "verified",
        "the known software-AES trace must not be reported as a clean negative: {:?}",
        report.failure_reasons
    );
    assert!(report.verification_gate_met);
    assert!(report
        .algorithms_observed
        .iter()
        .any(|algorithm| algorithm.eq_ignore_ascii_case("AES")));
    assert!(
        report.target_function_candidate_count > 0 && report.structural_signal_count >= 2,
        "expected function-attributed S-box/key-schedule AES evidence"
    );
    let structural_stage = report
        .stages
        .iter()
        .find(|stage| stage.code == "structural-analysis")
        .expect("software AES structural diagnosis stage");
    assert_eq!(structural_stage.status, "passed");
    for expected in [
        "implementationKind=StandardSoftware",
        "keyExposure=RawKeyObserved",
        "verdict=AES-128",
    ] {
        assert!(
            structural_stage
                .evidence
                .iter()
                .any(|item| item == expected),
            "missing expected sh_security structural evidence: {expected}"
        );
    }
    let semantic_stage = report
        .stages
        .iter()
        .find(|stage| stage.code == "semantic-verification")
        .expect("software AES semantic verification stage");
    assert_eq!(semantic_stage.status, "verified");
    assert!(
        semantic_stage
            .evidence
            .iter()
            .any(|item| item.contains("7 blocks"))
            && semantic_stage
                .evidence
                .iter()
                .any(|item| item.contains("128-bit key; RawKeyObserved")),
        "expected the known seven-block AES-128 semantic recomputation"
    );
    if exact_elf.is_some() {
        let static_stage = report
            .stages
            .iter()
            .find(|stage| stage.code == "static-binary")
            .expect("static binary diagnosis stage");
        assert!(matches!(
            static_stage.status.as_str(),
            "matched" | "completed-no-match"
        ));
    }

    engine.close_session(&session.session_id).unwrap();
    engine.delete_file_cache(&trace_path);
    let _ = std::fs::remove_dir_all(cache_dir);
}
