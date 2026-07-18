use std::collections::HashSet;
use std::time::{SystemTime, UNIX_EPOCH};

use serde_json::Value;

use crate::analysis::{
    AnalysisComparison, AnalysisEvidence, AnalysisRecord, AnalysisRecordSummary,
    AnalysisReportExport, AnalysisUniqueEvidence,
};
use crate::error::{Result, TraceError};

use super::TraceEngine;

const MAX_ANALYSES_PER_SESSION: usize = 100;

fn analysis_key(session_id: &str, analysis_id: &str) -> String {
    format!("{session_id}:{analysis_id}")
}

impl TraceEngine {
    pub fn render_analysis_report(
        &self,
        session_id: &str,
        analysis_id: &str,
        format: &str,
    ) -> Result<String> {
        let record = self.get_analysis(session_id, analysis_id)?;
        match format.to_ascii_lowercase().as_str() {
            "json" => serde_json::to_string_pretty(&record)
                .map_err(|error| TraceError::Internal(error.to_string())),
            "markdown" | "md" => Ok(render_analysis_markdown(&record)),
            other => Err(TraceError::InvalidArgument(format!(
                "Unsupported report format: {other}. Use markdown or json"
            ))),
        }
    }

    pub fn export_analysis_report(
        &self,
        session_id: &str,
        analysis_id: &str,
        format: &str,
        output_path: &str,
    ) -> Result<AnalysisReportExport> {
        let normalized_format = if format.eq_ignore_ascii_case("md") {
            "markdown".to_string()
        } else {
            format.to_ascii_lowercase()
        };
        let content = self.render_analysis_report(session_id, analysis_id, &normalized_format)?;
        std::fs::write(output_path, content.as_bytes()).map_err(TraceError::Io)?;
        Ok(AnalysisReportExport {
            analysis_id: analysis_id.to_string(),
            format: normalized_format,
            output_path: Some(output_path.to_string()),
            bytes_written: content.len() as u64,
            content: None,
        })
    }

    pub fn save_analysis(
        &self,
        session_id: &str,
        kind: &str,
        title: &str,
        request: Value,
        result: Value,
        evidence: AnalysisEvidence,
    ) -> Result<AnalysisRecord> {
        self.get_handle(session_id)?;
        let record = AnalysisRecord {
            analysis_id: uuid::Uuid::new_v4().to_string(),
            session_id: session_id.to_string(),
            kind: kind.to_string(),
            title: title.to_string(),
            created_at_ms: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_millis()
                .min(u64::MAX as u128) as u64,
            request,
            result,
            evidence: normalize_evidence(evidence),
        };
        let mut analyses = self
            .analyses
            .write()
            .map_err(|error| TraceError::Internal(error.to_string()))?;
        analyses.insert(
            analysis_key(session_id, &record.analysis_id),
            record.clone(),
        );

        let mut session_records: Vec<_> = analyses
            .values()
            .filter(|item| item.session_id == session_id)
            .map(|item| (item.created_at_ms, item.analysis_id.clone()))
            .collect();
        if session_records.len() > MAX_ANALYSES_PER_SESSION {
            session_records.sort_unstable();
            let overflow = session_records.len() - MAX_ANALYSES_PER_SESSION;
            for (_, analysis_id) in session_records.into_iter().take(overflow) {
                analyses.remove(&analysis_key(session_id, &analysis_id));
            }
        }
        drop(analyses);
        self.persist_session_analyses(session_id)?;
        Ok(record)
    }

    pub fn get_analysis(&self, session_id: &str, analysis_id: &str) -> Result<AnalysisRecord> {
        self.get_handle(session_id)?;
        let analyses = self
            .analyses
            .read()
            .map_err(|error| TraceError::Internal(error.to_string()))?;
        analyses
            .get(&analysis_key(session_id, analysis_id))
            .cloned()
            .ok_or_else(|| {
                TraceError::InvalidArgument(format!("Analysis not found: {analysis_id}"))
            })
    }

    pub fn list_analyses(
        &self,
        session_id: &str,
        kind: Option<&str>,
        limit: u32,
    ) -> Result<Vec<AnalysisRecordSummary>> {
        self.get_handle(session_id)?;
        let analyses = self
            .analyses
            .read()
            .map_err(|error| TraceError::Internal(error.to_string()))?;
        let mut records: Vec<_> = analyses
            .values()
            .filter(|record| record.session_id == session_id)
            .filter(|record| kind.is_none_or(|expected| record.kind == expected))
            .collect();
        records.sort_by(|left, right| {
            right
                .created_at_ms
                .cmp(&left.created_at_ms)
                .then_with(|| right.analysis_id.cmp(&left.analysis_id))
        });
        Ok(records
            .into_iter()
            .take(limit.clamp(1, MAX_ANALYSES_PER_SESSION as u32) as usize)
            .map(AnalysisRecordSummary::from)
            .collect())
    }

    pub fn delete_analysis(&self, session_id: &str, analysis_id: &str) -> Result<bool> {
        self.get_handle(session_id)?;
        let mut analyses = self
            .analyses
            .write()
            .map_err(|error| TraceError::Internal(error.to_string()))?;
        let deleted = analyses
            .remove(&analysis_key(session_id, analysis_id))
            .is_some();
        drop(analyses);
        if deleted {
            self.persist_session_analyses(session_id)?;
        }
        Ok(deleted)
    }

    pub fn compare_analyses(
        &self,
        session_id: &str,
        analysis_ids: &[String],
    ) -> Result<AnalysisComparison> {
        if analysis_ids.len() < 2 || analysis_ids.len() > 10 {
            return Err(TraceError::InvalidArgument(
                "Compare between 2 and 10 analyses at a time".to_string(),
            ));
        }
        let records: Vec<_> = analysis_ids
            .iter()
            .map(|analysis_id| self.get_analysis(session_id, analysis_id))
            .collect::<Result<Vec<_>>>()?;
        let common_evidence = intersect_evidence(&records);
        let unique_evidence = records
            .iter()
            .map(|record| AnalysisUniqueEvidence {
                analysis_id: record.analysis_id.clone(),
                evidence: subtract_evidence(&record.evidence, &common_evidence),
            })
            .collect();
        Ok(AnalysisComparison {
            analysis_ids: analysis_ids.to_vec(),
            kinds: unique_values(records.iter().map(|record| record.kind.as_str())),
            common_evidence,
            unique_evidence,
        })
    }

    pub(crate) fn remove_session_analyses(&self, session_id: &str) {
        if let Ok(mut analyses) = self.analyses.write() {
            analyses.retain(|_, record| record.session_id != session_id);
        }
    }

    pub(crate) fn load_session_analyses(&self, session_id: &str) -> Result<u32> {
        let handle = self.get_handle(session_id)?;
        let records = {
            let state = handle
                .state
                .read()
                .map_err(|error| TraceError::Internal(error.to_string()))?;
            crate::cache::load_analysis_cache(&handle.file_path, &state.mmap).unwrap_or_default()
        };
        let mut analyses = self
            .analyses
            .write()
            .map_err(|error| TraceError::Internal(error.to_string()))?;
        let mut loaded = 0u32;
        for mut record in records.into_iter().take(MAX_ANALYSES_PER_SESSION) {
            record.session_id = session_id.to_string();
            if let Some(result) = record.result.as_object_mut() {
                if result.contains_key("session_id") {
                    result.insert("session_id".to_string(), serde_json::json!(session_id));
                }
            }
            analyses.insert(analysis_key(session_id, &record.analysis_id), record);
            loaded = loaded.saturating_add(1);
        }
        Ok(loaded)
    }

    fn persist_session_analyses(&self, session_id: &str) -> Result<()> {
        let handle = self.get_handle(session_id)?;
        let mut records: Vec<_> = self
            .analyses
            .read()
            .map_err(|error| TraceError::Internal(error.to_string()))?
            .values()
            .filter(|record| record.session_id == session_id)
            .cloned()
            .collect();
        records.sort_by_key(|record| (record.created_at_ms, record.analysis_id.clone()));
        let state = handle
            .state
            .read()
            .map_err(|error| TraceError::Internal(error.to_string()))?;
        crate::cache::save_analysis_cache(&handle.file_path, &state.mmap, &records);
        Ok(())
    }
}

fn render_analysis_markdown(record: &AnalysisRecord) -> String {
    let evidence = serde_json::to_string_pretty(&record.evidence).unwrap_or_default();
    let request = serde_json::to_string_pretty(&record.request).unwrap_or_default();
    let result = serde_json::to_string_pretty(&record.result).unwrap_or_default();
    let mut markdown = String::new();
    markdown.push_str(&format!("# {}\n\n", record.title));
    markdown.push_str("## Metadata\n\n");
    markdown.push_str(&format!(
        "- Analysis ID: `{}`\n- Session ID: `{}`\n- Kind: `{}`\n- Created At (Unix ms): `{}`\n\n",
        record.analysis_id, record.session_id, record.kind, record.created_at_ms
    ));
    markdown.push_str("## Evidence\n\n```json\n");
    markdown.push_str(&evidence);
    markdown.push_str("\n```\n\n## Request\n\n```json\n");
    markdown.push_str(&request);
    markdown.push_str("\n```\n\n## Result\n\n```json\n");
    markdown.push_str(&result);
    markdown.push_str("\n```\n");
    markdown
}

fn normalize_evidence(mut evidence: AnalysisEvidence) -> AnalysisEvidence {
    evidence.algorithms = unique_values(evidence.algorithms.iter().map(String::as_str));
    evidence.digests = unique_values(evidence.digests.iter().map(String::as_str));
    evidence.functions = unique_values(evidence.functions.iter().map(String::as_str));
    evidence.modules = unique_values(evidence.modules.iter().map(String::as_str));
    evidence.key_strings = unique_values(evidence.key_strings.iter().map(String::as_str));
    evidence.memory_reads = unique_values(evidence.memory_reads.iter().map(String::as_str));
    evidence.memory_writes = unique_values(evidence.memory_writes.iter().map(String::as_str));
    evidence.addresses = unique_values(evidence.addresses.iter().map(String::as_str));
    evidence.operations = unique_values(evidence.operations.iter().map(String::as_str));
    evidence.warnings = unique_values(evidence.warnings.iter().map(String::as_str));
    evidence
}

fn unique_values<'a>(values: impl Iterator<Item = &'a str>) -> Vec<String> {
    let mut values: Vec<_> = values
        .filter(|value| !value.is_empty())
        .map(str::to_string)
        .collect::<HashSet<_>>()
        .into_iter()
        .collect();
    values.sort();
    values
}

fn intersect_evidence(records: &[AnalysisRecord]) -> AnalysisEvidence {
    let intersect = |select: fn(&AnalysisEvidence) -> &Vec<String>| -> Vec<String> {
        let mut common: HashSet<String> = select(&records[0].evidence).iter().cloned().collect();
        for record in &records[1..] {
            let current: HashSet<&str> = select(&record.evidence)
                .iter()
                .map(String::as_str)
                .collect();
            common.retain(|value| current.contains(value.as_str()));
        }
        let mut values: Vec<_> = common.into_iter().collect();
        values.sort();
        values
    };
    AnalysisEvidence {
        algorithms: intersect(|evidence| &evidence.algorithms),
        digests: intersect(|evidence| &evidence.digests),
        functions: intersect(|evidence| &evidence.functions),
        modules: intersect(|evidence| &evidence.modules),
        key_strings: intersect(|evidence| &evidence.key_strings),
        memory_reads: intersect(|evidence| &evidence.memory_reads),
        memory_writes: intersect(|evidence| &evidence.memory_writes),
        addresses: intersect(|evidence| &evidence.addresses),
        operations: intersect(|evidence| &evidence.operations),
        warnings: intersect(|evidence| &evidence.warnings),
    }
}

fn subtract_evidence(evidence: &AnalysisEvidence, common: &AnalysisEvidence) -> AnalysisEvidence {
    let subtract = |values: &[String], common_values: &[String]| -> Vec<String> {
        let common: HashSet<&str> = common_values.iter().map(String::as_str).collect();
        values
            .iter()
            .filter(|value| !common.contains(value.as_str()))
            .cloned()
            .collect()
    };
    AnalysisEvidence {
        algorithms: subtract(&evidence.algorithms, &common.algorithms),
        digests: subtract(&evidence.digests, &common.digests),
        functions: subtract(&evidence.functions, &common.functions),
        modules: subtract(&evidence.modules, &common.modules),
        key_strings: subtract(&evidence.key_strings, &common.key_strings),
        memory_reads: subtract(&evidence.memory_reads, &common.memory_reads),
        memory_writes: subtract(&evidence.memory_writes, &common.memory_writes),
        addresses: subtract(&evidence.addresses, &common.addresses),
        operations: subtract(&evidence.operations, &common.operations),
        warnings: subtract(&evidence.warnings, &common.warnings),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::TraceEngine;

    fn setup() -> (TraceEngine, String, std::path::PathBuf) {
        let path = std::env::temp_dir().join(format!(
            "trace-ui-analysis-store-{}.txt",
            uuid::Uuid::new_v4()
        ));
        std::fs::write(&path, b"trace\n").unwrap();
        let engine = TraceEngine::new();
        let session = engine.create_session(path.to_str().unwrap()).unwrap();
        (engine, session.session_id, path)
    }

    #[test]
    fn stores_lists_compares_and_deletes_analyses() {
        let (engine, session_id, path) = setup();
        let first = engine
            .save_analysis(
                &session_id,
                "known_digest",
                "first",
                Value::Null,
                Value::Null,
                AnalysisEvidence {
                    algorithms: vec!["md5".to_string()],
                    functions: vec!["hash".to_string()],
                    addresses: vec!["0x1000".to_string()],
                    ..AnalysisEvidence::default()
                },
            )
            .unwrap();
        let second = engine
            .save_analysis(
                &session_id,
                "known_digest",
                "second",
                Value::Null,
                Value::Null,
                AnalysisEvidence {
                    algorithms: vec!["md5".to_string()],
                    functions: vec!["hash".to_string(), "caller".to_string()],
                    addresses: vec!["0x2000".to_string()],
                    ..AnalysisEvidence::default()
                },
            )
            .unwrap();

        assert_eq!(
            engine.list_analyses(&session_id, None, 10).unwrap().len(),
            2
        );
        let comparison = engine
            .compare_analyses(
                &session_id,
                &[first.analysis_id.clone(), second.analysis_id.clone()],
            )
            .unwrap();
        assert_eq!(comparison.common_evidence.algorithms, vec!["md5"]);
        assert_eq!(comparison.common_evidence.functions, vec!["hash"]);
        assert!(engine
            .delete_analysis(&session_id, &first.analysis_id)
            .unwrap());
        assert!(engine
            .get_analysis(&session_id, &first.analysis_id)
            .is_err());

        engine.close_session(&session_id).unwrap();
        assert!(engine.analyses.read().unwrap().is_empty());
        engine.delete_file_cache(path.to_str().unwrap());
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn renders_and_exports_analysis_reports() {
        let (engine, session_id, path) = setup();
        let record = engine
            .save_analysis(
                &session_id,
                "forward_taint",
                "Forward report",
                serde_json::json!({"from_specs": ["reg:X0@1"]}),
                serde_json::json!({"affected_count": 3}),
                AnalysisEvidence {
                    operations: vec!["mov".to_string()],
                    ..AnalysisEvidence::default()
                },
            )
            .unwrap();
        let markdown = engine
            .render_analysis_report(&session_id, &record.analysis_id, "markdown")
            .unwrap();
        assert!(markdown.contains("# Forward report"));
        assert!(markdown.contains("affected_count"));
        let json = engine
            .render_analysis_report(&session_id, &record.analysis_id, "json")
            .unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed["analysisId"], record.analysis_id);

        let output = path.with_extension("report.md");
        let exported = engine
            .export_analysis_report(
                &session_id,
                &record.analysis_id,
                "md",
                output.to_str().unwrap(),
            )
            .unwrap();
        assert_eq!(exported.format, "markdown");
        assert!(exported.bytes_written > 0);
        assert!(std::fs::read_to_string(&output).unwrap().contains("Forward report"));
        let _ = std::fs::remove_file(output);
        engine.close_session(&session_id).unwrap();
        engine.delete_file_cache(path.to_str().unwrap());
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn restores_records_and_persists_deletions() {
        let (engine, session_id, path) = setup();
        let record = engine
            .save_analysis(
                &session_id,
                "known_digest",
                "persistent",
                Value::Null,
                Value::Null,
                AnalysisEvidence::default(),
            )
            .unwrap();
        engine.close_session(&session_id).unwrap();
        drop(engine);

        let reopened = TraceEngine::new();
        let session = reopened.create_session(path.to_str().unwrap()).unwrap();
        let records = reopened
            .list_analyses(&session.session_id, None, 10)
            .unwrap();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].analysis_id, record.analysis_id);
        assert!(reopened
            .delete_analysis(&session.session_id, &record.analysis_id)
            .unwrap());
        reopened.close_session(&session.session_id).unwrap();
        drop(reopened);

        let reopened_again = TraceEngine::new();
        let session = reopened_again
            .create_session(path.to_str().unwrap())
            .unwrap();
        assert!(reopened_again
            .list_analyses(&session.session_id, None, 10)
            .unwrap()
            .is_empty());
        reopened_again.delete_file_cache(path.to_str().unwrap());
        reopened_again.close_session(&session.session_id).unwrap();
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn trace_content_change_invalidates_analysis_cache() {
        let (engine, session_id, path) = setup();
        engine
            .save_analysis(
                &session_id,
                "known_digest",
                "stale",
                Value::Null,
                Value::Null,
                AnalysisEvidence::default(),
            )
            .unwrap();
        engine.close_session(&session_id).unwrap();
        drop(engine);
        assert!(crate::cache::load_analysis_cache(path.to_str().unwrap(), b"other\n").is_none());
        crate::cache::delete_cache(path.to_str().unwrap());
        let _ = std::fs::remove_file(path);
    }
}
