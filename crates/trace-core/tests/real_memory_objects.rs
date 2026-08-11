use trace_core::{BuildOptions, MemoryObjectOptions, TraceEngine, MEMORY_OBJECT_GRAPH_SCHEMA};

#[test]
#[ignore = "requires TRACE_UI_REAL_MEMORY_LOG pointing to a user-provided trace"]
fn reconstructs_real_trace_memory_objects_without_promoting_candidates() {
    let path = std::env::var("TRACE_UI_REAL_MEMORY_LOG")
        .expect("set TRACE_UI_REAL_MEMORY_LOG to an absolute GumTrace/unidbg log path");
    let engine = TraceEngine::new();
    let session = engine.create_session(&path).expect("open real trace");
    engine
        .build_index(
            &session.session_id,
            BuildOptions {
                force_rebuild: false,
                skip_strings: true,
            },
            None,
        )
        .expect("build real trace index");

    let report = engine
        .reconstruct_memory_objects(
            &session.session_id,
            MemoryObjectOptions {
                max_objects: 2_000,
                max_aliases_per_object: 64,
                max_field_windows_per_object: 64,
                max_access_samples_per_object: 16,
                max_anomalies: 1_000,
                max_runtime_clusters: 512,
                max_accesses: 5_000_000,
                ..MemoryObjectOptions::default()
            },
        )
        .expect("reconstruct real memory objects");

    eprintln!(
        "memory-object real regression: objects={} heap={} mmap={} stack={} accesses={} attributed={} aliases={} anomalies={} clusters={} truncated={}/{}/{}/{}",
        report.statistics.total_objects,
        report.statistics.heap_objects,
        report.statistics.mmap_objects,
        report.statistics.stack_frame_objects,
        report.statistics.processed_access_count,
        report.statistics.attributed_access_count,
        report.statistics.alias_count,
        report.statistics.anomaly_count,
        report.runtime_clusters.len(),
        report.objects_truncated,
        report.runtime_clusters_truncated,
        report.anomalies_truncated,
        report.accesses_truncated,
    );

    assert_eq!(report.schema_version, MEMORY_OBJECT_GRAPH_SCHEMA);
    assert!(report.statistics.processed_access_count > 0);
    assert!(
        report.statistics.attributed_access_count + report.statistics.unattributed_access_count
            <= report.statistics.processed_access_count
    );
    assert!(!report.verification_gate_met);
    assert!(report
        .anomalies
        .iter()
        .all(|anomaly| anomaly.status == "candidate"));
    assert!(report
        .limitations
        .iter()
        .any(|limitation| limitation.contains("not a proof")));
}
