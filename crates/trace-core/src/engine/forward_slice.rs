use super::TraceEngine;
use crate::api_types::{ForwardSliceOptions, ForwardSliceResult};
use crate::error::{Result, TraceError};
use crate::query::forward_slice::{build_forward_index, traverse_forward_index_with_extra};
use crate::scanner::LINE_MASK;

impl TraceEngine {
    pub fn run_forward_slice(
        &self,
        session_id: &str,
        from_specs: &[String],
        options: ForwardSliceOptions,
    ) -> Result<ForwardSliceResult> {
        self.run_forward_slice_cancellable(session_id, from_specs, options, |_, _| true)
    }

    pub fn run_forward_slice_cancellable<F>(
        &self,
        session_id: &str,
        from_specs: &[String],
        options: ForwardSliceOptions,
        mut checkpoint: F,
    ) -> Result<ForwardSliceResult>
    where
        F: FnMut(u32, u32) -> bool,
    {
        if from_specs.is_empty() {
            return Err(TraceError::InvalidArgument(
                "至少需要一个正向污点源".to_string(),
            ));
        }
        if let (Some(start), Some(end)) = (options.start_seq, options.end_seq) {
            if start > end {
                return Err(TraceError::InvalidArgument(
                    "start_seq 不能大于 end_seq".to_string(),
                ));
            }
        }

        let handle = self.get_handle(session_id)?;
        let (
            mut start_indices,
            normalized_specs,
            warnings,
            forward_index,
            index_reused,
            extra_consumers,
        ) = {
            let _lifecycle = handle
                .lifecycle
                .lock()
                .map_err(|error| TraceError::Internal(error.to_string()))?;
            if handle.closed.load(std::sync::atomic::Ordering::SeqCst) {
                return Err(TraceError::Cancelled);
            }

            let _index_build = handle
                .forward_index_build
                .lock()
                .map_err(|error| TraceError::Internal(error.to_string()))?;
            let state = handle
                .state
                .read()
                .map_err(|error| TraceError::Internal(error.to_string()))?;
            let reg_last_def = state
                .reg_last_def
                .as_ref()
                .ok_or(TraceError::IndexNotReady)?;
            let mem_last_def = state.mem_last_def_view().ok_or(TraceError::IndexNotReady)?;
            let line_index = state.line_index_view().ok_or(TraceError::IndexNotReady)?;

            let mut start_indices = Vec::new();
            let mut normalized_specs = Vec::with_capacity(from_specs.len());
            let mut warnings = Vec::new();
            for spec in from_specs {
                let resolved = super::slice::resolve_start_indices(
                    spec,
                    reg_last_def,
                    &mem_last_def,
                    &state.mmap,
                    &line_index,
                    state.trace_format,
                )
                .map_err(TraceError::InvalidArgument)?;
                start_indices.extend(resolved.start_indices);
                normalized_specs.push(resolved.normalized_spec);
                if let Some(warning) = resolved.warning {
                    warnings.push(warning);
                }
            }

            let min_source = start_indices
                .iter()
                .map(|raw| raw & LINE_MASK)
                .min()
                .unwrap_or(0);
            let max_effect_seq = options
                .end_seq
                .unwrap_or_else(|| line_index.total_lines().saturating_sub(1));
            let call_dependencies = super::slice::call_effect_dependencies_in_range(
                &state,
                &line_index,
                min_source,
                max_effect_seq,
            );
            let mut extra_consumers = std::collections::HashMap::<u32, Vec<u32>>::new();
            for (consumer, dependencies) in call_dependencies {
                for dependency in dependencies {
                    extra_consumers
                        .entry(dependency & LINE_MASK)
                        .or_default()
                        .push(consumer);
                }
            }

            let cached_index = state.forward_dependency_index.clone();
            let (forward_index, index_reused) = if let Some(index) = cached_index {
                let total = index.line_count().saturating_mul(2);
                if !checkpoint(total, total) {
                    return Err(TraceError::Cancelled);
                }
                (index, true)
            } else {
                let scan_view = state.scan_view().ok_or(TraceError::IndexNotReady)?;
                let Some(index) = build_forward_index(&scan_view, &mut checkpoint) else {
                    return Err(TraceError::Cancelled);
                };
                (std::sync::Arc::new(index), false)
            };
            drop(state);

            if !index_reused {
                let mut state = handle
                    .state
                    .write()
                    .map_err(|error| TraceError::Internal(error.to_string()))?;
                state.forward_dependency_index = Some(forward_index.clone());
            }

            (
                start_indices,
                normalized_specs,
                warnings,
                forward_index,
                index_reused,
                extra_consumers,
            )
        };
        start_indices.sort_unstable();
        start_indices.dedup();

        let max_nodes = options.max_nodes.clamp(1, 100_000) as usize;
        let Some(mut traversal) = traverse_forward_index_with_extra(
            &forward_index,
            &start_indices,
            options.data_only,
            max_nodes,
            &extra_consumers,
            &mut checkpoint,
        ) else {
            return Err(TraceError::Cancelled);
        };

        if let Some(start) = options.start_seq {
            let end = (start as usize).min(traversal.affected.len());
            traversal.affected[..end].fill(false);
        }
        if let Some(end) = options.end_seq {
            let start = (end as usize + 1).min(traversal.affected.len());
            traversal.affected[start..].fill(false);
        }
        traversal.terminal_seqs.retain(|seq| {
            traversal
                .affected
                .get(*seq as usize)
                .is_some_and(|bit| *bit)
        });

        let source_seqs = start_indices
            .into_iter()
            .map(|raw| raw & LINE_MASK)
            .filter(|seq| {
                options.start_seq.is_none_or(|start| *seq >= start)
                    && options.end_seq.is_none_or(|end| *seq <= end)
            })
            .collect::<Vec<_>>();
        let affected_seqs = traversal
            .affected
            .iter_ones()
            .map(|seq| seq as u32)
            .collect::<Vec<_>>();

        Ok(ForwardSliceResult {
            source_specs: normalized_specs,
            source_seqs,
            affected_count: affected_seqs.len().min(u32::MAX as usize) as u32,
            total_lines: forward_index.line_count(),
            affected_seqs,
            terminal_seqs: traversal.terminal_seqs,
            traversed_edges: traversal.traversed_edges,
            forward_index_edges: forward_index.edge_count(),
            forward_index_reused: index_reused,
            truncated: traversal.truncated,
            warnings,
        })
    }
}
