use crate::error::{Result, TraceError};
use crate::query::evidence_score::{score_evidence, EvidenceScoreSignal};
use crate::query::whitebox_aes::{self, MemAccess, WhiteBoxOptions, WhiteBoxReport};
use crate::query::whitebox_compare::{
    compare_whitebox_cases, WhiteBoxCaseAnalysis, WhiteBoxMultiTraceReport,
    WhiteBoxMultiTraceRequest,
};

/// 把 "0x..." / 裸十六进制解析成 u64。
fn parse_hex(s: &str) -> Option<u64> {
    let t = s.trim().trim_start_matches("0x").trim_start_matches("0X");
    u64::from_str_radix(t, 16).ok()
}

impl super::TraceEngine {
    pub fn compare_whitebox_traces(
        &self,
        request: WhiteBoxMultiTraceRequest,
    ) -> Result<WhiteBoxMultiTraceReport> {
        let mut analyses = Vec::with_capacity(request.cases.len());
        for case in request.cases {
            let report = self.analyze_whitebox(
                &case.session_id,
                WhiteBoxOptions {
                    static_binary_path: case.static_binary_path.clone(),
                    ..WhiteBoxOptions::default()
                },
            )?;
            analyses.push(WhiteBoxCaseAnalysis {
                request: case,
                report,
            });
        }
        compare_whitebox_cases(analyses).map_err(TraceError::InvalidArgument)
    }

    /// 单条 trace 的白盒（软件查表）密码识别。复用 mem_accesses 索引，无需再扫全文本。
    /// 结果缓存在 session state（与 crypto_functions_cache 同规格）。
    pub fn analyze_whitebox(
        &self,
        session_id: &str,
        mut options: WhiteBoxOptions,
    ) -> Result<WhiteBoxReport> {
        let static_binary_path = options.static_binary_path.clone();
        let cacheable = static_binary_path.is_none();
        // 1. 内存缓存命中
        if cacheable {
            let handle = self.get_handle(session_id)?;
            let state = handle
                .state
                .read()
                .map_err(|e| TraceError::Internal(e.to_string()))?;
            if let Some(cached) = &state.whitebox_cache {
                return Ok(cached.clone());
            }
        }

        // 2. 从首行推算模块基址（address - so_offset）；失败则退化为 0（in_module 全 false）。
        let module_base = self
            .get_lines(session_id, &[0])
            .ok()
            .and_then(|v| v.into_iter().next())
            .and_then(|l| Some(parse_hex(&l.address)?.wrapping_sub(parse_hex(&l.so_offset)?)))
            .unwrap_or(0);

        // 3. 从 mem_accesses 索引收集全部读/写（带地址+值+seq+size）。
        let handle = self.get_handle(session_id)?;
        let (reads, mut writes) = {
            let state = handle
                .state
                .read()
                .map_err(|e| TraceError::Internal(e.to_string()))?;
            let view = state.mem_accesses_view().ok_or(TraceError::IndexNotReady)?;
            let mut reads: Vec<MemAccess> = Vec::new();
            let mut writes: Vec<MemAccess> = Vec::new();
            for (addr, rec) in view.iter_all() {
                let a = MemAccess {
                    seq: rec.seq,
                    insn_addr: rec.insn_addr,
                    addr,
                    value: rec.data,
                    size: rec.size,
                };
                if rec.is_read() {
                    reads.push(a);
                } else {
                    writes.push(a);
                }
            }
            (reads, writes)
        };
        // The legacy phase-2 index keeps one MemOp per instruction line. Vector/pair stores may
        // contain multiple mem_w tokens, so crypto analysis supplements writes from the raw line.
        {
            let state = handle
                .state
                .read()
                .map_err(|e| TraceError::Internal(e.to_string()))?;
            writes.extend(crate::query::software_crypto::raw_gumtrace_writes(
                &state.mmap,
            ));
        }

        // 4. 分析
        options.module_base = module_base;
        if options.module_window == 0 {
            options.module_window = 0x0200_0000;
        }
        let annotation_buffers = {
            let state = handle
                .state
                .read()
                .map_err(|e| TraceError::Internal(e.to_string()))?;
            crate::query::software_crypto::annotation_hex_buffers(&state.call_annotations)
        };
        let mut report = whitebox_aes::analyze(&reads, &writes, &options);
        if let Some(path) = static_binary_path.as_deref() {
            let bytes = std::fs::read(path)?;
            report.static_binary = Some(
                whitebox_aes::analyze_static_binary(
                    path,
                    &bytes,
                    &reads,
                    &report.tables,
                    module_base,
                )
                .map_err(TraceError::InvalidArgument)?,
            );
            report.next_steps.push(
                "Static ELF matches prove file-backed table provenance only; semantic recomputation is still required for verified crypto classification."
                    .into(),
            );
        }
        let sbox_scan = crate::query::software_aes::detect_dynamic_aes_sboxes(&reads);
        let schedules = crate::query::software_aes::find_aes128_schedules(&writes);
        let semantic_verification =
            crate::query::software_aes::verify_observed_aes128_ecb(&reads, &writes, &schedules);
        let dynamic_software = semantic_verification.as_ref().and_then(|verification| {
            schedules
                .iter()
                .find(|schedule| schedule.schedule_address == verification.key_schedule_address)
                .and_then(|schedule| {
                    crate::query::software_crypto::report_from_dynamic_aes(
                        verification,
                        schedule,
                        &writes,
                    )
                })
        });
        report.aes_sbox_fingerprints = sbox_scan.fingerprints;
        report.aes_key_schedules = schedules;
        report.aes_semantic_verification = semantic_verification;
        report.software_crypto =
            crate::query::software_crypto::analyze(&annotation_buffers, &writes)
                .or(dynamic_software);
        if let Some(software) = &report.software_crypto {
            report.key_exposure = match software.key_exposure.as_str() {
                "ExpandedScheduleObserved" => whitebox_aes::KeyExposure::ExpandedScheduleObserved,
                "DerivedKeyObserved" => whitebox_aes::KeyExposure::DerivedKeyObserved,
                _ => whitebox_aes::KeyExposure::RawKeyObserved,
            };
            report.implementation_kind = match software.implementation_kind.as_str() {
                "StandardSoftware" => whitebox_aes::ImplementationKind::StandardSoftware,
                "ObfuscatedStandardSoftware" => {
                    whitebox_aes::ImplementationKind::ObfuscatedStandardSoftware
                }
                _ => whitebox_aes::ImplementationKind::TableDrivenSoftware,
            };
            report.whitebox_status = if software.schedule_verified {
                whitebox_aes::WhiteBoxStatus::NotWhiteBox
            } else {
                whitebox_aes::WhiteBoxStatus::Unknown
            };
            report.verdict.algorithm = software.algorithm.clone();
            report.verdict.block_bits = 128;
            report.verdict.round_count = Some(match software.key_hex.len() / 2 {
                16 => 10,
                24 => 12,
                32 => 14,
                _ => 0,
            });
            report.verdict.rationale = format!(
                "{} {} {} was verified across all {} observed blocks by deterministic semantic recomputation.",
                software.algorithm, software.mode, software.direction, software.block_count
            );
            report.assessment = score_evidence(
                "software_crypto_semantic_verification",
                true,
                vec![
                    EvidenceScoreSignal::new(
                        "semantic_recomputation",
                        "Complete observed buffer matches deterministic AES recomputation",
                        60,
                        true,
                        Some(format!("{} blocks", software.block_count)),
                    ),
                    EvidenceScoreSignal::new(
                        "key_material_observed",
                        "Runtime AES key material was recovered from the trace",
                        20,
                        true,
                        Some(format!(
                            "{}-bit key; {}",
                            software.key_hex.len() * 4,
                            software.key_exposure
                        )),
                    ),
                    EvidenceScoreSignal::new(
                        "standard_key_schedule",
                        "Standard AES expanded schedule was observed",
                        20,
                        software.schedule_verified,
                        None,
                    ),
                ],
                if software.schedule_verified {
                    Vec::new()
                } else {
                    vec!["Standard expanded-key schedule was not confirmed in this trace.".into()]
                },
            );
            report.next_steps = if software.schedule_verified {
                vec![
                    "Raw key and standard AES schedule are already observed; skip DCA/BGE/DFA key-recovery workflows.".into(),
                    "Use the generated reproducer to cross-check the complete buffer outside the trace viewer.".into(),
                    "Inspect the linked key/input/output trace lines when auditing call-instance boundaries.".into(),
                ]
            } else {
                vec![
                    "Raw key is observed, so prioritize schedule/call-boundary confirmation over statistical key recovery.".into(),
                    "Use the generated reproducer to cross-check the complete buffer outside the trace viewer.".into(),
                ]
            };
        }

        // 5. 存缓存
        if cacheable {
            let mut state = handle
                .state
                .write()
                .map_err(|e| TraceError::Internal(e.to_string()))?;
            state.whitebox_cache = Some(report.clone());
        }

        Ok(report)
    }
}

#[cfg(test)]
mod integration_tests {
    use crate::{
        BuildOptions, TraceEngine, WhiteBoxMultiTraceRequest, WhiteBoxOptions,
        WhiteBoxTraceCaseRequest,
    };

    #[test]
    #[ignore = "requires both TRACE_AES_* samples and TRACE_AES_SO"]
    fn real_multi_trace_matrix_rejects_raw_key_whitebox_claim() {
        let first_path = std::env::var("TRACE_AES_SAMPLE").expect("TRACE_AES_SAMPLE is required");
        let second_path =
            std::env::var("TRACE_AES_SECOND_SAMPLE").expect("TRACE_AES_SECOND_SAMPLE is required");
        let so_path = std::env::var("TRACE_AES_SO").expect("TRACE_AES_SO is required");
        let engine = TraceEngine::new();
        let first = engine.create_session(&first_path).unwrap();
        let second = engine.create_session(&second_path).unwrap();
        for session_id in [&first.session_id, &second.session_id] {
            engine
                .build_index(
                    session_id,
                    BuildOptions {
                        force_rebuild: false,
                        skip_strings: true,
                    },
                    None,
                )
                .unwrap();
        }

        let report = engine
            .compare_whitebox_traces(WhiteBoxMultiTraceRequest {
                cases: vec![
                    WhiteBoxTraceCaseRequest {
                        session_id: first.session_id,
                        label: "aes-input-1".to_string(),
                        key_group: "observed-key".to_string(),
                        input_group: "input-1".to_string(),
                        static_binary_path: Some(so_path.clone()),
                    },
                    WhiteBoxTraceCaseRequest {
                        session_id: second.session_id,
                        label: "aes-input-2".to_string(),
                        key_group: "observed-key".to_string(),
                        input_group: "input-2".to_string(),
                        static_binary_path: Some(so_path),
                    },
                ],
            })
            .unwrap();

        assert_eq!(report.classification, "RawKeyExposureContradiction");
        assert_eq!(report.whitebox_status, "NotWhiteBox");
        assert!(!report.verification_gate_met);
        assert!(report.cases.iter().all(|case| case.raw_key_observed));
    }

    #[test]
    #[ignore = "requires TRACE_AES_SAMPLE pointing to the private real trace"]
    fn real_trace_reaches_verified_full_without_sample_specific_offsets() {
        let path = std::env::var("TRACE_AES_SAMPLE").expect("TRACE_AES_SAMPLE is required");
        let engine = TraceEngine::new();
        let session = engine.create_session(&path).unwrap();
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
        let report = engine
            .analyze_whitebox(&session.session_id, WhiteBoxOptions::default())
            .unwrap();
        if std::env::var_os("TRACE_AES_DEBUG").is_some() {
            eprintln!(
                "top-level classification: {:?} {:?} {:?}; software={:#?}",
                report.implementation_kind,
                report.key_exposure,
                report.whitebox_status,
                report.software_crypto
            );
        }
        assert!(matches!(
            report.implementation_kind,
            crate::query::whitebox_aes::ImplementationKind::ObfuscatedStandardSoftware
        ));
        assert!(matches!(
            report.key_exposure,
            crate::query::whitebox_aes::KeyExposure::RawKeyObserved
        ));
        assert!(matches!(
            report.whitebox_status,
            crate::query::whitebox_aes::WhiteBoxStatus::NotWhiteBox
        ));
        assert_eq!(report.assessment.grade, "verified");
        assert!(report.assessment.verification_gate_met);
        assert!(report
            .next_steps
            .iter()
            .any(|step| step.contains("skip DCA")));
        let software = report
            .software_crypto
            .expect("software AES should be detected");
        if std::env::var_os("TRACE_AES_DEBUG").is_some() {
            eprintln!("software AES evidence: {software:#?}");
        }
        assert_eq!(software.algorithm, "AES-128");
        assert_eq!(software.direction, "Encrypt");
        assert_eq!(software.mode, "ECB");
        assert_eq!(software.padding, "PKCS#7");
        assert_eq!(software.input_length, 452);
        assert_eq!(software.padded_length, 464);
        assert_eq!(software.block_count, 29);
        assert_eq!(software.output_stride, 16);
        assert_eq!(
            software.first_cipher_block,
            "ae2af887f83430372469ccbf4b3d5916"
        );
        assert_eq!(
            software.last_cipher_block,
            "98e234a6fb29bf721d7201f13f8952bc"
        );
        assert_eq!(software.verification, "VerifiedFull");
    }

    #[test]
    #[ignore = "requires TRACE_AES_MEMORY_SAMPLE pointing to the sh_security trace"]
    fn sh_security_trace_detects_standard_software_aes128() {
        let path =
            std::env::var("TRACE_AES_MEMORY_SAMPLE").expect("TRACE_AES_MEMORY_SAMPLE is required");
        let engine = TraceEngine::new();
        let session = engine.create_session(&path).unwrap();
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

        let report = engine
            .analyze_whitebox(&session.session_id, WhiteBoxOptions::default())
            .unwrap();
        assert!(matches!(
            report.implementation_kind,
            crate::query::whitebox_aes::ImplementationKind::StandardSoftware
        ));
        assert!(matches!(
            report.key_exposure,
            crate::query::whitebox_aes::KeyExposure::ExpandedScheduleObserved
        ));
        assert!(matches!(
            report.whitebox_status,
            crate::query::whitebox_aes::WhiteBoxStatus::NotWhiteBox
        ));
        assert!(report.assessment.verification_gate_met);

        let sbox = report
            .aes_sbox_fingerprints
            .iter()
            .find(|item| item.base_addr == "0x71cd18f3bc")
            .expect("standard AES S-box fingerprint");
        assert_eq!(sbox.matching_reads, 1_400);
        assert_eq!(sbox.distinct_indices, 252);

        let schedule = report
            .aes_key_schedules
            .iter()
            .find(|item| item.schedule_address == "0x71cd1d6280")
            .expect("AES-128 expanded schedule");
        assert_eq!(schedule.verification.words_checked, 44);
        assert_eq!(schedule.verification.words_matched, 44);
        assert!(schedule.verification.standard_key_schedule);

        let software = report
            .software_crypto
            .expect("verified software AES report");
        assert_eq!(software.algorithm, "AES-128");
        assert_eq!(software.direction, "Encrypt");
        assert_eq!(software.mode, "ECB");
        assert_eq!(software.padding, "PKCS#7");
        assert_eq!(software.input_length, 105);
        assert_eq!(software.padded_length, 112);
        assert_eq!(software.block_count, 7);
        assert_eq!(software.verification, "VerifiedFull");
        assert_eq!(software.output_base_addr, "0x730794efc0");

        let functions = engine
            .analyze_crypto_functions(
                &session.session_id,
                crate::query::crypto_functions::CryptoFunctionsOptions::default(),
            )
            .unwrap();
        let cipher = functions
            .candidates
            .iter()
            .find(|candidate| candidate.func_addr == "0x71cd0da63c")
            .expect("AES block function");
        assert_eq!(cipher.verification_status.as_deref(), Some("VerifiedFull"));
        assert!(cipher
            .implementation_hints
            .iter()
            .any(|hint| hint == "StandardSoftware"));
        assert!(functions.candidates.iter().any(|candidate| {
            candidate.func_addr == "0x71cd0da6c0"
                && candidate
                    .software_signal_counts
                    .contains_key("AES128_KEY_SCHEDULE")
        }));
    }

    #[test]
    #[ignore = "requires both TRACE_AES_* samples and TRACE_AES_SO pointing to matching private assets"]
    fn real_trace_joins_dynamic_tables_to_matching_static_elf() {
        let binary_path = std::env::var("TRACE_AES_SO").expect("TRACE_AES_SO is required");
        let traces = [
            (
                std::env::var("TRACE_AES_SAMPLE").expect("TRACE_AES_SAMPLE is required"),
                1_639,
                "0x455e8",
            ),
            (
                std::env::var("TRACE_AES_SECOND_SAMPLE")
                    .expect("TRACE_AES_SECOND_SAMPLE is required"),
                1_351,
                "0x455e9",
            ),
        ];
        for (trace_path, expected_entries, expected_offset) in traces {
            let engine = TraceEngine::new();
            let session = engine.create_session(&trace_path).unwrap();
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
            let report = engine
                .analyze_whitebox(
                    &session.session_id,
                    WhiteBoxOptions {
                        static_binary_path: Some(binary_path.clone()),
                        ..Default::default()
                    },
                )
                .unwrap();
            let static_binary = report
                .static_binary
                .expect("matching ELF should produce a static analysis report");
            eprintln!("real static/dynamic table join: {static_binary:#?}");
            assert_eq!(static_binary.format, "ELF64 little-endian");
            assert_eq!(static_binary.architecture, "AArch64");
            assert_eq!(static_binary.elf_machine, 183);
            assert_eq!(
                static_binary.build_id.as_deref(),
                Some("9f5dd9b43d965da8f77693f3be5a8522bfac32e7")
            );
            assert_eq!(
                static_binary.binary_sha256,
                "ad32516500436e00d709daa9013ecccced69290a022c905499ca664bb694c35c"
            );
            let joined = static_binary
                .table_matches
                .first()
                .expect("real trace should expose a file-backed lookup region");
            assert_eq!(joined.match_kind, "ExactStaticDynamicMatch");
            assert_eq!(joined.compared_entries, expected_entries);
            assert_eq!(joined.matching_entries, expected_entries);
            assert_eq!(joined.mismatched_entries, 0);
            assert_eq!(joined.module_offset, expected_offset);
            assert_eq!(joined.file_offset, expected_offset);
        }
    }

    #[test]
    #[ignore = "requires TRACE_AES_SECOND_SAMPLE pointing to the private wrapper trace"]
    fn real_wrapper_trace_reaches_verified_full_decrypt() {
        let path =
            std::env::var("TRACE_AES_SECOND_SAMPLE").expect("TRACE_AES_SECOND_SAMPLE is required");
        let engine = TraceEngine::new();
        let session = engine.create_session(&path).unwrap();
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
        let report = engine
            .analyze_whitebox(&session.session_id, WhiteBoxOptions::default())
            .unwrap();
        assert!(matches!(
            report.key_exposure,
            crate::query::whitebox_aes::KeyExposure::RawKeyObserved
        ));
        assert_eq!(report.assessment.grade, "verified");
        let software = report
            .software_crypto
            .expect("wrapper AES should be detected");
        if std::env::var_os("TRACE_AES_DEBUG").is_some() {
            eprintln!("wrapper AES evidence: {software:#?}");
        }
        assert_eq!(software.algorithm, "AES-128");
        assert_eq!(software.direction, "Decrypt");
        assert_eq!(software.mode, "ECB");
        assert_eq!(software.padding, "None");
        assert_eq!(software.verification, "VerifiedFull");
    }
}
