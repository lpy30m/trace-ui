use crate::api_types::SearchOptions;
use crate::error::{Result, TraceError};
use crate::query::value_search::{
    max_results, parse_value_search, search_memory_writes, search_string_index, ValueSearchMatch,
    ValueSearchRequest, ValueSearchResponse, ValueSearchSource,
};

use super::TraceEngine;

impl TraceEngine {
    pub fn search_value(
        &self,
        session_id: &str,
        request: &ValueSearchRequest,
    ) -> Result<ValueSearchResponse> {
        let parsed = parse_value_search(request).map_err(TraceError::InvalidArgument)?;
        let limit = max_results(request);
        let mut matches = Vec::new();
        let mut total_matches = 0u32;
        let mut strings_scanned = 0u32;
        let mut writes_scanned = 0u32;

        {
            let handle = self.get_handle(session_id)?;
            let state = handle
                .state
                .read()
                .map_err(|error| TraceError::Internal(error.to_string()))?;
            if request.search_strings {
                if let Some(index) = state.string_index.as_ref() {
                    strings_scanned = index.strings.len().min(u32::MAX as usize) as u32;
                    let (found, total) =
                        search_string_index(index, &parsed, limit.saturating_sub(matches.len()));
                    matches.extend(found);
                    total_matches = total_matches.saturating_add(total);
                }
            }
            if request.search_memory {
                if let Some(view) = state.mem_accesses_view() {
                    let (found, total, scanned) =
                        search_memory_writes(&view, &parsed, limit.saturating_sub(matches.len()));
                    matches.extend(found);
                    total_matches = total_matches.saturating_add(total);
                    writes_scanned = scanned;
                }
            }
        }

        let mut trace_lines_scanned = 0u32;
        if request.search_trace {
            let result = self.search(
                session_id,
                &request.query,
                SearchOptions {
                    case_sensitive: true,
                    use_regex: false,
                    fuzzy: false,
                    max_results: Some(limit.saturating_sub(matches.len()).max(1) as u32),
                },
            )?;
            trace_lines_scanned = result.total_scanned;
            total_matches = total_matches.saturating_add(result.total_matches);
            let lines = self.get_lines(session_id, &result.match_seqs)?;
            for line in lines.into_iter().take(limit.saturating_sub(matches.len())) {
                let preview = if line.disasm.is_empty() {
                    line.raw
                } else {
                    line.disasm
                };
                matches.push(ValueSearchMatch {
                    interpretation_index: 0,
                    source: ValueSearchSource::Trace,
                    addr: (!line.address.is_empty()).then_some(line.address),
                    seq: line.seq,
                    first_seq: line.seq,
                    last_seq: line.seq,
                    write_seqs: Vec::new(),
                    string_index: None,
                    content: None,
                    preview,
                    encoding: Some("trace text (exact case)".to_string()),
                    rw: line.mem_rw,
                });
            }
        }

        matches.sort_by_key(|item| {
            (
                item.seq,
                source_priority(item.source),
                item.interpretation_index,
            )
        });
        Ok(ValueSearchResponse {
            query: request.query.clone(),
            interpretations: parsed.interpretations,
            matches,
            strings_scanned,
            writes_scanned,
            trace_lines_scanned,
            total_matches,
            truncated: total_matches as usize > limit,
            warnings: parsed.warnings,
        })
    }
}

fn source_priority(source: ValueSearchSource) -> u8 {
    match source {
        ValueSearchSource::Memory => 0,
        ValueSearchSource::String => 1,
        ValueSearchSource::Trace => 2,
    }
}
