use crate::error::Result;
use crate::query::crypto_functions::CryptoFunctionsOptions;
use crate::query::detection_doctor::{
    build_crypto_detection_doctor_report, CryptoDetectionDoctorReport,
};
use crate::query::whitebox_aes::WhiteBoxOptions;

impl super::TraceEngine {
    pub fn diagnose_crypto_detection(
        &self,
        session_id: &str,
        target_algorithm: &str,
        static_binary_path: Option<String>,
    ) -> Result<CryptoDetectionDoctorReport> {
        let scan = self.scan_crypto(session_id)?;
        let functions = self.analyze_crypto_functions(
            session_id,
            CryptoFunctionsOptions {
                max_candidates: 500,
            },
        )?;
        let static_binary_supplied = static_binary_path.is_some();
        let implementation = self.analyze_whitebox(
            session_id,
            WhiteBoxOptions {
                algorithm: target_algorithm.trim().to_ascii_lowercase(),
                static_binary_path,
                ..WhiteBoxOptions::default()
            },
        )?;
        Ok(build_crypto_detection_doctor_report(
            session_id,
            target_algorithm,
            &scan,
            &functions,
            &implementation,
            static_binary_supplied,
        ))
    }
}
