use crate::error::{Result, TraceError};
use crate::query::crypto_material::{
    analyze_crypto_materials as analyze_materials, compare_crypto_material_reports,
    CryptoMaterialMultiTraceReport, CryptoMaterialMultiTraceRequest, CryptoMaterialOptions,
    CryptoMaterialReport,
};
use crate::query::whitebox_aes::WhiteBoxOptions;

impl super::TraceEngine {
    pub fn analyze_crypto_materials(
        &self,
        session_id: &str,
        options: CryptoMaterialOptions,
    ) -> Result<CryptoMaterialReport> {
        let implementation = self.analyze_whitebox(session_id, WhiteBoxOptions::default())?;
        let annotations = {
            let handle = self.get_handle(session_id)?;
            let state = handle
                .state
                .read()
                .map_err(|error| TraceError::Internal(error.to_string()))?;
            state.call_annotations.clone()
        };
        Ok(analyze_materials(
            &annotations,
            implementation.software_crypto.as_ref(),
            &options,
        ))
    }

    pub fn compare_crypto_material_traces(
        &self,
        request: CryptoMaterialMultiTraceRequest,
    ) -> Result<CryptoMaterialMultiTraceReport> {
        if !(2..=16).contains(&request.cases.len()) {
            return Err(TraceError::InvalidArgument(
                "Crypto material comparison requires two to sixteen trace cases".to_string(),
            ));
        }
        let mut cases = Vec::with_capacity(request.cases.len());
        for case in request.cases {
            let report =
                self.analyze_crypto_materials(&case.session_id, CryptoMaterialOptions::default())?;
            cases.push((case, report));
        }
        compare_crypto_material_reports(cases).map_err(TraceError::InvalidArgument)
    }
}
