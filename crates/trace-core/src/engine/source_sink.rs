use std::collections::HashMap;

use super::TraceEngine;
use crate::error::{Result, TraceError};
use crate::query::source_sink::CallResourceContext;

impl TraceEngine {
    pub fn get_call_resource_contexts(
        &self,
        session_id: &str,
        seqs: &[u32],
    ) -> Result<HashMap<u32, CallResourceContext>> {
        let handle = self.get_handle(session_id)?;
        let state = handle
            .state
            .read()
            .map_err(|error| TraceError::Internal(error.to_string()))?;
        let index = state
            .resource_flow_index
            .as_ref()
            .ok_or(TraceError::IndexNotReady)?;
        Ok(seqs
            .iter()
            .filter_map(|seq| index.get(*seq).cloned().map(|context| (*seq, context)))
            .collect())
    }
}
