use crate::error::{Result, TraceError};
use crate::query::hash_match::{
    match_memory_writes, match_string_index, HashMatchRequest, HashMatchResponse,
    HashMemoryMatchResponse,
};

use super::TraceEngine;

impl TraceEngine {
    pub fn match_known_digests(
        &self,
        session_id: &str,
        request: &HashMatchRequest,
    ) -> Result<HashMatchResponse> {
        let handle = self.get_handle(session_id)?;
        let state = handle
            .state
            .read()
            .map_err(|error| TraceError::Internal(error.to_string()))?;
        let string_index = state
            .string_index
            .as_ref()
            .ok_or(TraceError::IndexNotReady)?;

        match_string_index(string_index, request).map_err(TraceError::InvalidArgument)
    }

    pub fn find_digest_memory(
        &self,
        session_id: &str,
        request: &HashMatchRequest,
    ) -> Result<HashMemoryMatchResponse> {
        let handle = self.get_handle(session_id)?;
        let state = handle
            .state
            .read()
            .map_err(|error| TraceError::Internal(error.to_string()))?;
        let view = state.mem_accesses_view().ok_or(TraceError::IndexNotReady)?;
        match_memory_writes(&view, request).map_err(TraceError::InvalidArgument)
    }
}
