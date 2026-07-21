use std::collections::{BTreeMap, HashMap};

use hmac::{Hmac, Mac};
use md5::Md5;
use pbkdf2::pbkdf2_hmac;
use serde::{Deserialize, Serialize};
use sha1::Sha1;
use sha2::{Digest, Sha256, Sha384, Sha512};
use trace_parser::gumtrace::{CallAnnotation, CallHexdumpObservation};

use super::evidence_score::{score_evidence, EvidenceAssessment, EvidenceScoreSignal};
use super::hash_match::HashAlgorithm;
use super::software_crypto::SoftwareCryptoReport;

const DEFAULT_MAX_MATERIALS: u32 = 500;
const MAX_MATERIALS: u32 = 5_000;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum CryptoMaterialKind {
    Key,
    ExpandedKey,
    Password,
    Salt,
    Iv,
    Nonce,
    Counter,
    Aad,
    AuthTag,
    Input,
    Output,
    Plaintext,
    Ciphertext,
    Digest,
    Mac,
    DerivedKey,
    Unknown,
}

#[derive(Clone, Debug)]
pub struct CryptoMaterialOptions {
    pub max_materials: u32,
    pub include_unknown: bool,
}

impl Default for CryptoMaterialOptions {
    fn default() -> Self {
        Self {
            max_materials: DEFAULT_MAX_MATERIALS,
            include_unknown: false,
        }
    }
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CryptoMaterial {
    pub material_id: String,
    pub kind: CryptoMaterialKind,
    pub role: String,
    pub algorithm: Option<String>,
    pub bytes_hex: Option<String>,
    pub ascii_preview: Option<String>,
    pub byte_len: Option<u32>,
    pub address: Option<String>,
    pub observation_seq: Option<u32>,
    pub completion_seq: Option<u32>,
    pub function_name: Option<String>,
    pub register: Option<String>,
    pub source: String,
    pub evidence: Vec<String>,
    pub assessment: EvidenceAssessment,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CryptoFormula {
    pub formula_id: String,
    pub operation: String,
    pub algorithm: String,
    pub expression: String,
    pub input_material_ids: Vec<String>,
    pub output_material_id: Option<String>,
    pub call_seq: Option<u32>,
    pub function_name: Option<String>,
    pub evidence: Vec<String>,
    pub assessment: EvidenceAssessment,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CryptoMaterialReport {
    pub materials: Vec<CryptoMaterial>,
    pub formulas: Vec<CryptoFormula>,
    pub material_counts: BTreeMap<String, u32>,
    pub verified_materials: u32,
    pub verified_formulas: u32,
    pub annotations_scanned: u32,
    pub materials_truncated: bool,
    pub coverage: Vec<String>,
    pub limitations: Vec<String>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CryptoMaterialTraceCase {
    pub session_id: String,
    pub label: String,
    pub input_group: String,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CryptoMaterialMultiTraceRequest {
    pub cases: Vec<CryptoMaterialTraceCase>,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CryptoMaterialCaseSummary {
    pub session_id: String,
    pub label: String,
    pub input_group: String,
    pub material_count: u32,
    pub formula_count: u32,
    pub verified_formula_count: u32,
    pub explicit_salt_count: u32,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DynamicParameterCandidate {
    pub algorithm: String,
    pub function_name: Option<String>,
    pub left_label: String,
    pub right_label: String,
    pub input_group: String,
    pub byte_offset: u32,
    pub common_prefix_hex: String,
    pub common_suffix_hex: String,
    pub left_variable_hex: String,
    pub right_variable_hex: String,
    pub role_hint: String,
    pub rationale: String,
    pub assessment: EvidenceAssessment,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CryptoMaterialMultiTraceReport {
    pub cases: Vec<CryptoMaterialCaseSummary>,
    pub dynamic_parameter_candidates: Vec<DynamicParameterCandidate>,
    pub verification_gate_met: bool,
    pub limitations: Vec<String>,
    pub next_steps: Vec<String>,
}

#[derive(Clone)]
struct BufferObservation {
    address: u64,
    bytes: Vec<u8>,
    observation_seq: Option<u32>,
    completion_seq: Option<u32>,
}

impl From<CallHexdumpObservation> for BufferObservation {
    fn from(value: CallHexdumpObservation) -> Self {
        Self {
            address: value.base_addr,
            bytes: value.bytes,
            observation_seq: value.observation_seq,
            completion_seq: value.completion_seq,
        }
    }
}

struct MaterialBuilder {
    materials: Vec<CryptoMaterial>,
    formulas: Vec<CryptoFormula>,
    next_material: u32,
    next_formula: u32,
}

struct MaterialSpec {
    kind: CryptoMaterialKind,
    role: String,
    algorithm: Option<String>,
    bytes: Option<Vec<u8>>,
    address: Option<u64>,
    observation_seq: Option<u32>,
    completion_seq: Option<u32>,
    function_name: Option<String>,
    register: Option<String>,
    source: String,
    evidence: Vec<String>,
    assessment: EvidenceAssessment,
}

impl MaterialBuilder {
    fn new() -> Self {
        Self {
            materials: Vec::new(),
            formulas: Vec::new(),
            next_material: 1,
            next_formula: 1,
        }
    }

    fn add_material(&mut self, spec: MaterialSpec) -> String {
        let bytes_hex = spec.bytes.as_deref().map(hex);
        if let Some(existing) = self.materials.iter().find(|material| {
            material.kind == spec.kind
                && material.bytes_hex == bytes_hex
                && material.address == spec.address.map(|address| format!("0x{address:x}"))
                && material.observation_seq == spec.observation_seq
                && material.function_name == spec.function_name
        }) {
            return existing.material_id.clone();
        }
        let material_id = format!("material-{}", self.next_material);
        self.next_material += 1;
        let ascii_preview = spec.bytes.as_deref().map(ascii_preview);
        let byte_len = spec.bytes.as_ref().map(|bytes| bytes.len() as u32);
        self.materials.push(CryptoMaterial {
            material_id: material_id.clone(),
            kind: spec.kind,
            role: spec.role,
            algorithm: spec.algorithm,
            bytes_hex,
            ascii_preview,
            byte_len,
            address: spec.address.map(|address| format!("0x{address:x}")),
            observation_seq: spec.observation_seq,
            completion_seq: spec.completion_seq,
            function_name: spec.function_name,
            register: spec.register,
            source: spec.source,
            evidence: spec.evidence,
            assessment: spec.assessment,
        });
        material_id
    }

    fn add_formula(
        &mut self,
        operation: impl Into<String>,
        algorithm: impl Into<String>,
        expression: impl Into<String>,
        inputs: Vec<String>,
        output: Option<String>,
        call_seq: Option<u32>,
        function_name: Option<String>,
        evidence: Vec<String>,
        assessment: EvidenceAssessment,
    ) {
        let formula_id = format!("formula-{}", self.next_formula);
        self.next_formula += 1;
        self.formulas.push(CryptoFormula {
            formula_id,
            operation: operation.into(),
            algorithm: algorithm.into(),
            expression: expression.into(),
            input_material_ids: inputs,
            output_material_id: output,
            call_seq,
            function_name,
            evidence,
            assessment,
        });
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn decode_hex(value: &str) -> Option<Vec<u8>> {
    if value.len() % 2 != 0 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return None;
    }
    value
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            std::str::from_utf8(pair)
                .ok()
                .and_then(|pair| u8::from_str_radix(pair, 16).ok())
        })
        .collect()
}

fn ascii_preview(bytes: &[u8]) -> String {
    bytes
        .iter()
        .take(96)
        .map(|byte| {
            if byte.is_ascii_graphic() || *byte == b' ' {
                *byte as char
            } else {
                '.'
            }
        })
        .collect()
}

fn verified_assessment(scope: &str, evidence: impl Into<String>) -> EvidenceAssessment {
    score_evidence(
        scope,
        true,
        vec![
            EvidenceScoreSignal::new(
                "semantic_recomputation",
                "Observed inputs recompute to the observed output.",
                60,
                true,
                Some(evidence.into()),
            ),
            EvidenceScoreSignal::new(
                "runtime_bytes",
                "Exact material bytes were observed at runtime.",
                25,
                true,
                None,
            ),
            EvidenceScoreSignal::new(
                "api_role",
                "The material role agrees with the called API signature.",
                15,
                true,
                None,
            ),
        ],
        Vec::new(),
    )
}

fn api_role_assessment(scope: &str, role: &str, has_bytes: bool) -> EvidenceAssessment {
    score_evidence(
        scope,
        false,
        vec![
            EvidenceScoreSignal::new(
                "api_role",
                "The called API assigns this argument a cryptographic role.",
                45,
                true,
                Some(role.to_string()),
            ),
            EvidenceScoreSignal::new(
                "runtime_bytes",
                "Exact bytes were captured in a call hexdump.",
                25,
                has_bytes,
                None,
            ),
        ],
        vec![
            "An API argument role identifies how the value was supplied, but semantic recomputation is required for verified status."
                .to_string(),
        ],
    )
}

fn normalize_function_name(name: &str) -> String {
    name.trim()
        .trim_start_matches('_')
        .split('@')
        .next()
        .unwrap_or(name)
        .to_ascii_lowercase()
}

fn parse_number(value: &str) -> Option<u64> {
    let trimmed = value.trim().trim_matches('"');
    if trimmed.starts_with('-') {
        return None;
    }
    if let Some(hex) = trimmed
        .strip_prefix("0x")
        .or_else(|| trimmed.strip_prefix("0X"))
    {
        u64::from_str_radix(hex, 16).ok()
    } else {
        trimmed.parse().ok()
    }
}

fn normalized_arg_index(index: &str) -> Option<usize> {
    index
        .trim()
        .trim_start_matches("args")
        .trim_start_matches(['x', 'X'])
        .parse()
        .ok()
}

fn arg_values(annotation: &CallAnnotation, wanted: usize) -> Vec<&str> {
    annotation
        .args
        .iter()
        .filter_map(|(index, value)| {
            (normalized_arg_index(index) == Some(wanted)).then_some(value.as_str())
        })
        .collect()
}

fn arg_number(annotation: &CallAnnotation, wanted: usize) -> Option<u64> {
    arg_values(annotation, wanted)
        .into_iter()
        .find_map(parse_number)
}

fn observations(annotation: &CallAnnotation) -> Vec<BufferObservation> {
    annotation
        .hexdump_observations()
        .into_iter()
        .map(Into::into)
        .filter(|observation: &BufferObservation| !observation.bytes.is_empty())
        .collect()
}

fn buffer_for_arg(
    annotation: &CallAnnotation,
    observations: &[BufferObservation],
    index: usize,
    requested_len: Option<usize>,
) -> Option<BufferObservation> {
    for pointer in arg_values(annotation, index)
        .into_iter()
        .filter_map(parse_number)
    {
        for observation in observations {
            let end = observation
                .address
                .saturating_add(observation.bytes.len() as u64);
            if pointer < observation.address || pointer >= end {
                continue;
            }
            let offset = (pointer - observation.address) as usize;
            let available = observation.bytes.len().saturating_sub(offset);
            let length = requested_len.unwrap_or(available).min(available);
            if length == 0 {
                continue;
            }
            let mut result = observation.clone();
            result.address = pointer;
            result.bytes = observation.bytes[offset..offset + length].to_vec();
            return Some(result);
        }
    }
    None
}

fn algorithm_label(algorithm: HashAlgorithm) -> &'static str {
    match algorithm {
        HashAlgorithm::Crc32 => "CRC32",
        HashAlgorithm::Md5 => "MD5",
        HashAlgorithm::Sha1 => "SHA-1",
        HashAlgorithm::Sha256 => "SHA-256",
        HashAlgorithm::Sha384 => "SHA-384",
        HashAlgorithm::Sha512 => "SHA-512",
    }
}

fn digest_len(algorithm: HashAlgorithm) -> usize {
    match algorithm {
        HashAlgorithm::Crc32 => 4,
        HashAlgorithm::Md5 => 16,
        HashAlgorithm::Sha1 => 20,
        HashAlgorithm::Sha256 => 32,
        HashAlgorithm::Sha384 => 48,
        HashAlgorithm::Sha512 => 64,
    }
}

fn digest_bytes(algorithm: HashAlgorithm, bytes: &[u8]) -> Vec<u8> {
    match algorithm {
        HashAlgorithm::Crc32 => crc32fast::hash(bytes).to_be_bytes().to_vec(),
        HashAlgorithm::Md5 => Md5::digest(bytes).to_vec(),
        HashAlgorithm::Sha1 => Sha1::digest(bytes).to_vec(),
        HashAlgorithm::Sha256 => Sha256::digest(bytes).to_vec(),
        HashAlgorithm::Sha384 => Sha384::digest(bytes).to_vec(),
        HashAlgorithm::Sha512 => Sha512::digest(bytes).to_vec(),
    }
}

fn hmac_bytes(algorithm: HashAlgorithm, key: &[u8], input: &[u8]) -> Option<Vec<u8>> {
    macro_rules! calculate {
        ($digest:ty) => {{
            let mut mac = Hmac::<$digest>::new_from_slice(key).ok()?;
            mac.update(input);
            Some(mac.finalize().into_bytes().to_vec())
        }};
    }
    match algorithm {
        HashAlgorithm::Md5 => calculate!(Md5),
        HashAlgorithm::Sha1 => calculate!(Sha1),
        HashAlgorithm::Sha256 => calculate!(Sha256),
        HashAlgorithm::Sha384 => calculate!(Sha384),
        HashAlgorithm::Sha512 => calculate!(Sha512),
        HashAlgorithm::Crc32 => None,
    }
}

fn pbkdf2_bytes(
    algorithm: HashAlgorithm,
    password: &[u8],
    salt: &[u8],
    iterations: u32,
    output_len: usize,
) -> Option<Vec<u8>> {
    let mut output = vec![0_u8; output_len];
    match algorithm {
        HashAlgorithm::Sha1 => pbkdf2_hmac::<Sha1>(password, salt, iterations, &mut output),
        HashAlgorithm::Sha256 => pbkdf2_hmac::<Sha256>(password, salt, iterations, &mut output),
        HashAlgorithm::Sha384 => pbkdf2_hmac::<Sha384>(password, salt, iterations, &mut output),
        HashAlgorithm::Sha512 => pbkdf2_hmac::<Sha512>(password, salt, iterations, &mut output),
        HashAlgorithm::Md5 | HashAlgorithm::Crc32 => return None,
    }
    Some(output)
}

fn hash_algorithm_from_name(name: &str) -> Option<HashAlgorithm> {
    let compact: String = name
        .chars()
        .filter(|character| character.is_ascii_alphanumeric())
        .collect();
    if compact.contains("sha512") {
        Some(HashAlgorithm::Sha512)
    } else if compact.contains("sha384") {
        Some(HashAlgorithm::Sha384)
    } else if compact.contains("sha256") {
        Some(HashAlgorithm::Sha256)
    } else if compact.contains("sha1") {
        Some(HashAlgorithm::Sha1)
    } else if compact.contains("md5") {
        Some(HashAlgorithm::Md5)
    } else if compact.contains("crc32") {
        Some(HashAlgorithm::Crc32)
    } else {
        None
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum DigestCallKind {
    Init,
    Update,
    Final,
    OneShot,
}

fn digest_call(name: &str) -> Option<(HashAlgorithm, DigestCallKind)> {
    let algorithm = hash_algorithm_from_name(name)?;
    let compact: String = name
        .chars()
        .filter(|character| character.is_ascii_alphanumeric())
        .collect();
    let kind = if compact.ends_with("update") {
        DigestCallKind::Update
    } else if compact.ends_with("final") {
        DigestCallKind::Final
    } else if compact.ends_with("init") {
        DigestCallKind::Init
    } else {
        let base = match algorithm {
            HashAlgorithm::Crc32 => "crc32",
            HashAlgorithm::Md5 => "md5",
            HashAlgorithm::Sha1 => "sha1",
            HashAlgorithm::Sha256 => "sha256",
            HashAlgorithm::Sha384 => "sha384",
            HashAlgorithm::Sha512 => "sha512",
        };
        if compact == base {
            DigestCallKind::OneShot
        } else {
            return None;
        }
    };
    Some((algorithm, kind))
}

fn add_observed_material(
    builder: &mut MaterialBuilder,
    kind: CryptoMaterialKind,
    role: &str,
    algorithm: Option<String>,
    observation: Option<&BufferObservation>,
    function_name: &str,
    register: Option<&str>,
    verified: Option<String>,
) -> String {
    let assessment = match verified {
        Some(evidence) => verified_assessment("crypto_material", evidence),
        None => api_role_assessment("crypto_material", role, observation.is_some()),
    };
    builder.add_material(MaterialSpec {
        kind,
        role: role.to_string(),
        algorithm,
        bytes: observation.map(|value| value.bytes.clone()),
        address: observation.and_then(|value| (value.address != 0).then_some(value.address)),
        observation_seq: observation.and_then(|value| value.observation_seq),
        completion_seq: observation.and_then(|value| value.completion_seq),
        function_name: Some(function_name.to_string()),
        register: register.map(str::to_string),
        source: "callHexdump".to_string(),
        evidence: vec![format!("Role derived from {function_name} ABI argument")],
        assessment,
    })
}

fn add_digest_operation(
    builder: &mut MaterialBuilder,
    algorithm: HashAlgorithm,
    input: BufferObservation,
    output: Option<BufferObservation>,
    function_name: &str,
    call_seq: u32,
) {
    let expected = digest_bytes(algorithm, &input.bytes);
    let verified = output
        .as_ref()
        .is_some_and(|output| output.bytes == expected);
    let verification = verified.then(|| {
        format!(
            "{}({} bytes) = {}",
            algorithm_label(algorithm),
            input.bytes.len(),
            hex(&expected)
        )
    });
    let input_id = add_observed_material(
        builder,
        CryptoMaterialKind::Input,
        "digestInput",
        Some(algorithm_label(algorithm).to_string()),
        Some(&input),
        function_name,
        Some("X0/X1"),
        verification.clone(),
    );
    let output_id = output.as_ref().map(|output| {
        add_observed_material(
            builder,
            CryptoMaterialKind::Digest,
            "digestOutput",
            Some(algorithm_label(algorithm).to_string()),
            Some(output),
            function_name,
            Some("X0/X2"),
            verification.clone(),
        )
    });
    let assessment = if verified {
        verified_assessment(
            "crypto_formula",
            format!("Observed digest equals {}", hex(&expected)),
        )
    } else {
        api_role_assessment("crypto_formula", "digest input/output", output.is_some())
    };
    builder.add_formula(
        "digest",
        algorithm_label(algorithm),
        format!("{}({input_id}) -> digest", algorithm_label(algorithm)),
        vec![input_id],
        output_id,
        Some(call_seq),
        Some(function_name.to_string()),
        vec![if verified {
            "Deterministic digest recomputation matched the observed output bytes.".to_string()
        } else {
            "Digest API roles were observed, but complete output bytes were unavailable or did not match."
                .to_string()
        }],
        assessment,
    );
}

fn add_hmac_operation(
    builder: &mut MaterialBuilder,
    algorithm: Option<HashAlgorithm>,
    annotation: &CallAnnotation,
    call_seq: u32,
    observations: &[BufferObservation],
) {
    let key_len = arg_number(annotation, 2).map(|value| value as usize);
    let input_len = arg_number(annotation, 4).map(|value| value as usize);
    let key = buffer_for_arg(annotation, observations, 1, key_len);
    let input = buffer_for_arg(annotation, observations, 3, input_len);
    let output_len = algorithm.map(digest_len);
    let output = buffer_for_arg(annotation, observations, 5, output_len);
    let recomputed = algorithm.and_then(|algorithm| {
        Some(hmac_bytes(
            algorithm,
            &key.as_ref()?.bytes,
            &input.as_ref()?.bytes,
        )?)
    });
    let verified = recomputed
        .as_ref()
        .zip(output.as_ref())
        .is_some_and(|(expected, output)| expected == &output.bytes);
    let label = algorithm.map(algorithm_label).unwrap_or("unknown digest");
    let verification = verified.then(|| format!("HMAC-{label} output recomputed exactly"));
    let key_id = add_observed_material(
        builder,
        CryptoMaterialKind::Key,
        "hmacKey",
        algorithm.map(|value| format!("HMAC-{}", algorithm_label(value))),
        key.as_ref(),
        &annotation.func_name,
        Some("X1"),
        verification.clone(),
    );
    let input_id = add_observed_material(
        builder,
        CryptoMaterialKind::Input,
        "hmacInput",
        algorithm.map(|value| format!("HMAC-{}", algorithm_label(value))),
        input.as_ref(),
        &annotation.func_name,
        Some("X3"),
        verification.clone(),
    );
    let output_id = output.as_ref().map(|output| {
        add_observed_material(
            builder,
            CryptoMaterialKind::Mac,
            "macOutput",
            algorithm.map(|value| format!("HMAC-{}", algorithm_label(value))),
            Some(output),
            &annotation.func_name,
            Some("X5"),
            verification.clone(),
        )
    });
    let assessment = if verified {
        verified_assessment("crypto_formula", format!("HMAC-{label} matched"))
    } else {
        api_role_assessment("crypto_formula", "HMAC API arguments", output.is_some())
    };
    builder.add_formula(
        "hmac",
        format!("HMAC-{label}"),
        format!("HMAC-{label}({key_id}, {input_id}) -> mac"),
        vec![key_id, input_id],
        output_id,
        Some(call_seq),
        Some(annotation.func_name.clone()),
        vec![if verified {
            "Observed key and input recompute to the observed MAC.".to_string()
        } else {
            "HMAC argument roles are known; algorithm or complete bytes are insufficient for verification."
                .to_string()
        }],
        assessment,
    );
}

fn add_pbkdf2_operation(
    builder: &mut MaterialBuilder,
    algorithm: Option<HashAlgorithm>,
    annotation: &CallAnnotation,
    call_seq: u32,
    observations: &[BufferObservation],
) {
    let password_len = arg_number(annotation, 1).map(|value| value as usize);
    let salt_len = arg_number(annotation, 3).map(|value| value as usize);
    let iterations = arg_number(annotation, 4).and_then(|value| u32::try_from(value).ok());
    let output_len = arg_number(annotation, 6).map(|value| value as usize);
    let password = buffer_for_arg(annotation, observations, 0, password_len);
    let salt = buffer_for_arg(annotation, observations, 2, salt_len);
    let output = buffer_for_arg(annotation, observations, 7, output_len);
    let recomputed = algorithm.and_then(|algorithm| {
        pbkdf2_bytes(
            algorithm,
            &password.as_ref()?.bytes,
            &salt.as_ref()?.bytes,
            iterations?,
            output_len?,
        )
    });
    let verified = recomputed
        .as_ref()
        .zip(output.as_ref())
        .is_some_and(|(expected, output)| expected == &output.bytes);
    let label = algorithm.map(algorithm_label).unwrap_or("unknown digest");
    let verification = verified.then(|| {
        format!(
            "PBKDF2-HMAC-{label} recomputed for {} iterations",
            iterations.unwrap_or_default()
        )
    });
    let password_id = add_observed_material(
        builder,
        CryptoMaterialKind::Password,
        "password",
        Some(format!("PBKDF2-HMAC-{label}")),
        password.as_ref(),
        &annotation.func_name,
        Some("X0"),
        verification.clone(),
    );
    let salt_id = add_observed_material(
        builder,
        CryptoMaterialKind::Salt,
        "salt",
        Some(format!("PBKDF2-HMAC-{label}")),
        salt.as_ref(),
        &annotation.func_name,
        Some("X2"),
        verification.clone(),
    );
    let output_id = output.as_ref().map(|output| {
        add_observed_material(
            builder,
            CryptoMaterialKind::DerivedKey,
            "derivedKey",
            Some(format!("PBKDF2-HMAC-{label}")),
            Some(output),
            &annotation.func_name,
            Some("X7"),
            verification.clone(),
        )
    });
    let assessment = if verified {
        verified_assessment("crypto_formula", "PBKDF2 derived key matched")
    } else {
        api_role_assessment("crypto_formula", "PBKDF2 API arguments", output.is_some())
    };
    builder.add_formula(
        "kdf",
        format!("PBKDF2-HMAC-{label}"),
        format!(
            "PBKDF2-HMAC-{label}({password_id}, {salt_id}, iterations={}) -> derivedKey",
            iterations
                .map(|value| value.to_string())
                .unwrap_or_else(|| "unknown".to_string())
        ),
        vec![password_id, salt_id],
        output_id,
        Some(call_seq),
        Some(annotation.func_name.clone()),
        vec![
            "PBKDF2 ABI identifies X2 as salt and X4 as iteration count.".to_string(),
            if verified {
                "The derived key was reproduced exactly.".to_string()
            } else {
                "Complete algorithm/parameter/output evidence is required for semantic verification."
                    .to_string()
            },
        ],
        assessment,
    );
}

fn add_verified_aes(builder: &mut MaterialBuilder, report: &SoftwareCryptoReport) {
    let algorithm = format!("{}-{}", report.algorithm, report.mode);
    let verification = format!(
        "{} {} {} matched across {} blocks",
        report.algorithm, report.mode, report.direction, report.block_count
    );
    let key = decode_hex(&report.key_hex);
    let input = decode_hex(&report.input_hex);
    let output = decode_hex(&report.output_hex);
    let key_id = builder.add_material(MaterialSpec {
        kind: CryptoMaterialKind::Key,
        role: "rawKey".to_string(),
        algorithm: Some(algorithm.clone()),
        bytes: key,
        address: None,
        observation_seq: Some(report.key_observation_seq),
        completion_seq: None,
        function_name: None,
        register: None,
        source: "semanticAesVerification".to_string(),
        evidence: vec![verification.clone()],
        assessment: verified_assessment("crypto_material", verification.clone()),
    });
    let encrypting = report.direction.eq_ignore_ascii_case("encrypt");
    let input_id = builder.add_material(MaterialSpec {
        kind: if encrypting {
            CryptoMaterialKind::Plaintext
        } else {
            CryptoMaterialKind::Ciphertext
        },
        role: "cipherInput".to_string(),
        algorithm: Some(algorithm.clone()),
        bytes: input,
        address: None,
        observation_seq: Some(report.input_observation_seq),
        completion_seq: None,
        function_name: None,
        register: None,
        source: "semanticAesVerification".to_string(),
        evidence: vec![verification.clone()],
        assessment: verified_assessment("crypto_material", verification.clone()),
    });
    let output_address = parse_number(&report.output_base_addr);
    let output_id = builder.add_material(MaterialSpec {
        kind: if encrypting {
            CryptoMaterialKind::Ciphertext
        } else {
            CryptoMaterialKind::Plaintext
        },
        role: "cipherOutput".to_string(),
        algorithm: Some(algorithm.clone()),
        bytes: output,
        address: output_address,
        observation_seq: Some(report.output_first_seq),
        completion_seq: Some(report.output_last_seq),
        function_name: None,
        register: None,
        source: "semanticAesVerification".to_string(),
        evidence: vec![verification.clone()],
        assessment: verified_assessment("crypto_material", verification.clone()),
    });
    let mut inputs = vec![key_id, input_id];
    if let Some(value) = report.iv_hex.as_deref().and_then(decode_hex) {
        let (kind, role) = match report.mode.as_str() {
            "GCM" => (CryptoMaterialKind::Nonce, "nonce"),
            "CTR" => (CryptoMaterialKind::Counter, "initialCounter"),
            _ => (CryptoMaterialKind::Iv, "iv"),
        };
        inputs.push(builder.add_material(MaterialSpec {
            kind,
            role: role.to_string(),
            algorithm: Some(algorithm.clone()),
            bytes: Some(value),
            address: None,
            observation_seq: report.iv_observation_seq,
            completion_seq: None,
            function_name: None,
            register: None,
            source: "semanticAesVerification".to_string(),
            evidence: vec![verification.clone()],
            assessment: verified_assessment("crypto_material", verification.clone()),
        }));
    }
    if let Some(value) = report.aad_hex.as_deref().and_then(decode_hex) {
        inputs.push(builder.add_material(MaterialSpec {
            kind: CryptoMaterialKind::Aad,
            role: "additionalAuthenticatedData".to_string(),
            algorithm: Some(algorithm.clone()),
            bytes: Some(value),
            address: None,
            observation_seq: report.aad_observation_seq,
            completion_seq: None,
            function_name: None,
            register: None,
            source: "semanticAesVerification".to_string(),
            evidence: vec![verification.clone()],
            assessment: verified_assessment("crypto_material", verification.clone()),
        }));
    }
    if let Some(value) = report.auth_tag_hex.as_deref().and_then(decode_hex) {
        let tag_id = builder.add_material(MaterialSpec {
            kind: CryptoMaterialKind::AuthTag,
            role: "authenticationTag".to_string(),
            algorithm: Some(algorithm.clone()),
            bytes: Some(value),
            address: None,
            observation_seq: report.auth_tag_observation_seq,
            completion_seq: None,
            function_name: None,
            register: None,
            source: "semanticAesVerification".to_string(),
            evidence: vec![verification.clone()],
            assessment: verified_assessment("crypto_material", verification.clone()),
        });
        inputs.push(tag_id);
    }
    builder.add_formula(
        "cipher",
        algorithm.clone(),
        format!(
            "{}-{}({}) -> {output_id}",
            report.algorithm,
            report.direction,
            inputs.join(", ")
        ),
        inputs,
        Some(output_id),
        Some(report.input_observation_seq),
        None,
        vec![verification.clone()],
        verified_assessment("crypto_formula", verification),
    );
}

#[derive(Clone)]
struct DigestStream {
    function_name: String,
    chunks: Vec<BufferObservation>,
    first_call_seq: u32,
}

pub fn analyze_crypto_materials(
    annotations: &HashMap<u32, CallAnnotation>,
    software_crypto: Option<&SoftwareCryptoReport>,
    options: &CryptoMaterialOptions,
) -> CryptoMaterialReport {
    let mut builder = MaterialBuilder::new();
    if let Some(report) = software_crypto {
        add_verified_aes(&mut builder, report);
    }

    let mut ordered: Vec<_> = annotations.iter().collect();
    ordered.sort_by_key(|(seq, _)| **seq);
    let mut streams: HashMap<(HashAlgorithm, u64), DigestStream> = HashMap::new();

    for (&call_seq, annotation) in ordered {
        let normalized = normalize_function_name(&annotation.func_name);
        let call_observations = observations(annotation);

        if normalized.contains("pbkdf2") {
            add_pbkdf2_operation(
                &mut builder,
                hash_algorithm_from_name(&normalized),
                annotation,
                call_seq,
                &call_observations,
            );
            continue;
        }
        if normalized.contains("hmac") {
            add_hmac_operation(
                &mut builder,
                hash_algorithm_from_name(&normalized),
                annotation,
                call_seq,
                &call_observations,
            );
            continue;
        }

        let Some((algorithm, kind)) = digest_call(&normalized) else {
            if options.include_unknown {
                for observation in call_observations {
                    builder.add_material(MaterialSpec {
                        kind: CryptoMaterialKind::Unknown,
                        role: "unclassifiedCallBuffer".to_string(),
                        algorithm: None,
                        bytes: Some(observation.bytes),
                        address: Some(observation.address),
                        observation_seq: observation.observation_seq,
                        completion_seq: observation.completion_seq,
                        function_name: Some(annotation.func_name.clone()),
                        register: None,
                        source: "callHexdump".to_string(),
                        evidence: vec!["Observed in an unclassified call annotation.".to_string()],
                        assessment: api_role_assessment(
                            "crypto_material",
                            "unclassified call buffer",
                            true,
                        ),
                    });
                }
            }
            continue;
        };

        match kind {
            DigestCallKind::OneShot => {
                let input_len = arg_number(annotation, 1).map(|value| value as usize);
                if let Some(input) = buffer_for_arg(annotation, &call_observations, 0, input_len) {
                    let output = buffer_for_arg(
                        annotation,
                        &call_observations,
                        2,
                        Some(digest_len(algorithm)),
                    );
                    add_digest_operation(
                        &mut builder,
                        algorithm,
                        input,
                        output,
                        &annotation.func_name,
                        call_seq,
                    );
                }
            }
            DigestCallKind::Init => {
                if let Some(context) = arg_number(annotation, 0) {
                    streams.remove(&(algorithm, context));
                }
            }
            DigestCallKind::Update => {
                let Some(context) = arg_number(annotation, 0) else {
                    continue;
                };
                let input_len = arg_number(annotation, 2).map(|value| value as usize);
                let Some(input) = buffer_for_arg(annotation, &call_observations, 1, input_len)
                else {
                    continue;
                };
                streams
                    .entry((algorithm, context))
                    .or_insert_with(|| DigestStream {
                        function_name: annotation.func_name.clone(),
                        chunks: Vec::new(),
                        first_call_seq: call_seq,
                    })
                    .chunks
                    .push(input);
            }
            DigestCallKind::Final => {
                let Some(context) = arg_number(annotation, 1) else {
                    continue;
                };
                let Some(stream) = streams.remove(&(algorithm, context)) else {
                    continue;
                };
                let output = buffer_for_arg(
                    annotation,
                    &call_observations,
                    0,
                    Some(digest_len(algorithm)),
                );
                let mut combined = Vec::new();
                for chunk in &stream.chunks {
                    combined.extend_from_slice(&chunk.bytes);
                }
                if combined.is_empty() {
                    continue;
                }
                let first = stream.chunks.first().cloned().unwrap();
                let single = stream.chunks.len() == 1;
                add_digest_operation(
                    &mut builder,
                    algorithm,
                    BufferObservation {
                        address: if single { first.address } else { 0 },
                        bytes: combined,
                        observation_seq: first.observation_seq.or(Some(stream.first_call_seq)),
                        completion_seq: annotation.completion_seq,
                    },
                    output,
                    &stream.function_name,
                    stream.first_call_seq,
                );
            }
        }
    }

    let max_materials = options.max_materials.clamp(1, MAX_MATERIALS) as usize;
    let materials_truncated = builder.materials.len() > max_materials;
    if materials_truncated {
        builder.materials.truncate(max_materials);
        let retained: std::collections::HashSet<_> = builder
            .materials
            .iter()
            .map(|material| material.material_id.as_str())
            .collect();
        builder.formulas.retain(|formula| {
            formula
                .input_material_ids
                .iter()
                .all(|material_id| retained.contains(material_id.as_str()))
                && formula
                    .output_material_id
                    .as_ref()
                    .is_none_or(|material_id| retained.contains(material_id.as_str()))
        });
    }
    let mut material_counts = BTreeMap::new();
    for material in &builder.materials {
        *material_counts
            .entry(format!("{:?}", material.kind))
            .or_insert(0) += 1;
    }
    CryptoMaterialReport {
        verified_materials: builder
            .materials
            .iter()
            .filter(|material| material.assessment.verification_gate_met)
            .count() as u32,
        verified_formulas: builder
            .formulas
            .iter()
            .filter(|formula| formula.assessment.verification_gate_met)
            .count() as u32,
        materials: builder.materials,
        formulas: builder.formulas,
        material_counts,
        annotations_scanned: annotations.len() as u32,
        materials_truncated,
        coverage: vec![
            "Semantically verified AES key/input/output/IV/nonce/counter/AAD/tag material".to_string(),
            "MD5/SHA one-shot and Init/Update/Final call annotations".to_string(),
            "HMAC and PBKDF2 ABI material roles with deterministic verification when all parameters are observable".to_string(),
            "Exact GumTrace call hexdumps associated with pointer arguments".to_string(),
        ],
        limitations: vec![
            "Only executed calls and captured hexdumps can expose material bytes; an absent item is not proof that it was unused."
                .to_string(),
            "Generic EVP digest pointers do not identify an algorithm unless the trace annotation names it."
                .to_string(),
            "A salt role is reported directly for a recognized KDF API; concatenated hash fields require controlled multi-trace comparison."
                .to_string(),
        ],
    }
}

fn material_bytes<'a>(report: &'a CryptoMaterialReport, material_id: &str) -> Option<Vec<u8>> {
    report
        .materials
        .iter()
        .find(|material| material.material_id == material_id)
        .and_then(|material| material.bytes_hex.as_deref())
        .and_then(decode_hex)
}

fn digest_inputs(report: &CryptoMaterialReport) -> Vec<(&CryptoFormula, Vec<u8>)> {
    report
        .formulas
        .iter()
        .filter(|formula| formula.operation == "digest")
        .filter_map(|formula| {
            let material_id = formula.input_material_ids.first()?;
            Some((formula, material_bytes(report, material_id)?))
        })
        .collect()
}

fn differing_region(left: &[u8], right: &[u8]) -> (usize, usize, usize) {
    let common = left.len().min(right.len());
    let mut prefix = 0;
    while prefix < common && left[prefix] == right[prefix] {
        prefix += 1;
    }
    let mut suffix = 0;
    while suffix < common.saturating_sub(prefix)
        && left[left.len() - 1 - suffix] == right[right.len() - 1 - suffix]
    {
        suffix += 1;
    }
    (prefix, left.len() - suffix, right.len() - suffix)
}

pub fn compare_crypto_material_reports(
    cases: Vec<(CryptoMaterialTraceCase, CryptoMaterialReport)>,
) -> Result<CryptoMaterialMultiTraceReport, String> {
    if !(2..=16).contains(&cases.len()) {
        return Err("Crypto material comparison requires two to sixteen trace cases".to_string());
    }
    let summaries = cases
        .iter()
        .map(|(case, report)| CryptoMaterialCaseSummary {
            session_id: case.session_id.clone(),
            label: case.label.clone(),
            input_group: case.input_group.clone(),
            material_count: report.materials.len() as u32,
            formula_count: report.formulas.len() as u32,
            verified_formula_count: report.verified_formulas,
            explicit_salt_count: report
                .materials
                .iter()
                .filter(|material| material.kind == CryptoMaterialKind::Salt)
                .count() as u32,
        })
        .collect();
    let mut candidates = Vec::new();
    for left_index in 0..cases.len() {
        for right_index in left_index + 1..cases.len() {
            let (left_case, left_report) = &cases[left_index];
            let (right_case, right_report) = &cases[right_index];
            if left_case.input_group != right_case.input_group {
                continue;
            }
            for (left_formula, left_bytes) in digest_inputs(left_report) {
                for (right_formula, right_bytes) in digest_inputs(right_report) {
                    if left_formula.algorithm != right_formula.algorithm
                        || left_formula.function_name != right_formula.function_name
                        || left_bytes == right_bytes
                    {
                        continue;
                    }
                    let (prefix, left_end, right_end) = differing_region(&left_bytes, &right_bytes);
                    let left_variable = &left_bytes[prefix..left_end];
                    let right_variable = &right_bytes[prefix..right_end];
                    if left_variable.is_empty() && right_variable.is_empty() {
                        continue;
                    }
                    let stable_boundary =
                        prefix > 0 || left_end < left_bytes.len() || right_end < right_bytes.len();
                    let verified_inputs = left_formula.assessment.verification_gate_met
                        && right_formula.assessment.verification_gate_met;
                    let assessment = score_evidence(
                        "dynamic_parameter_candidate",
                        false,
                        vec![
                            EvidenceScoreSignal::new(
                                "controlled_input_group",
                                "Both traces are caller-labeled with the same primary input.",
                                35,
                                true,
                                Some(left_case.input_group.clone()),
                            ),
                            EvidenceScoreSignal::new(
                                "verified_digest_inputs",
                                "Both complete digest inputs were semantically verified against their outputs.",
                                25,
                                verified_inputs,
                                None,
                            ),
                            EvidenceScoreSignal::new(
                                "stable_boundary",
                                "A stable prefix or suffix isolates the changing byte range.",
                                20,
                                stable_boundary,
                                None,
                            ),
                        ],
                        vec![
                            "A changing field may be a salt, nonce, timestamp, counter, or device value; API evidence or additional controlled runs are required to name it."
                                .to_string(),
                        ],
                    );
                    candidates.push(DynamicParameterCandidate {
                        algorithm: left_formula.algorithm.clone(),
                        function_name: left_formula.function_name.clone(),
                        left_label: left_case.label.clone(),
                        right_label: right_case.label.clone(),
                        input_group: left_case.input_group.clone(),
                        byte_offset: prefix as u32,
                        common_prefix_hex: hex(&left_bytes[..prefix]),
                        common_suffix_hex: hex(&left_bytes[left_end..]),
                        left_variable_hex: hex(left_variable),
                        right_variable_hex: hex(right_variable),
                        role_hint: "saltOrNonceCandidate".to_string(),
                        rationale: "The primary input label is unchanged while this digest-input byte range changes between runs."
                            .to_string(),
                        assessment,
                    });
                }
            }
        }
    }
    Ok(CryptoMaterialMultiTraceReport {
        cases: summaries,
        dynamic_parameter_candidates: candidates,
        verification_gate_met: false,
        limitations: vec![
            "Cross-run byte differences identify dynamic parameters but do not by themselves prove a salt role."
                .to_string(),
            "Use at least three controlled runs and vary one external value at a time.".to_string(),
        ],
        next_steps: vec![
            "Confirm a candidate by tracing its bytes backward to an API argument or stable source."
                .to_string(),
            "Capture the same primary input with another salt/nonce and verify that the same field changes."
                .to_string(),
            "Recompute the complete digest formula before promoting any candidate to Verified."
                .to_string(),
        ],
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hexdump(address: u64, bytes: &[u8]) -> Vec<String> {
        vec![
            format!(
                "hexdump at address 0x{address:x} with length 0x{:x}:",
                bytes.len()
            ),
            format!(
                "{address:08x}: {} |{}|",
                bytes
                    .iter()
                    .map(|byte| format!("{byte:02x}"))
                    .collect::<Vec<_>>()
                    .join(" "),
                ascii_preview(bytes)
            ),
        ]
    }

    fn annotation(name: &str, args: &[&str], buffers: &[(u64, Vec<u8>)]) -> CallAnnotation {
        let mut raw_lines = vec![format!("call func: {name}({})", args.join(", "))];
        for (address, bytes) in buffers {
            raw_lines.extend(hexdump(*address, bytes));
        }
        CallAnnotation {
            func_name: name.to_string(),
            is_jni: false,
            args: args
                .iter()
                .enumerate()
                .map(|(index, value)| (format!("x{index}"), (*value).to_string()))
                .collect(),
            ret_value: None,
            raw_lines,
            observation_seq: Some(10),
            completion_seq: Some(11),
        }
    }

    #[test]
    fn verifies_one_shot_md5_and_indexes_input_and_digest() {
        let input = b"hello".to_vec();
        let digest = Md5::digest(&input).to_vec();
        let mut annotations = HashMap::new();
        annotations.insert(
            5,
            annotation(
                "MD5",
                &["0x1000", "5", "0x2000"],
                &[(0x1000, input), (0x2000, digest)],
            ),
        );
        let report =
            analyze_crypto_materials(&annotations, None, &CryptoMaterialOptions::default());
        assert_eq!(report.materials.len(), 2);
        assert_eq!(report.formulas.len(), 1);
        assert_eq!(report.verified_formulas, 1);
        assert!(report
            .materials
            .iter()
            .any(|material| material.kind == CryptoMaterialKind::Digest));
    }

    #[test]
    fn pbkdf2_signature_indexes_salt_without_claiming_verification() {
        let mut annotations = HashMap::new();
        annotations.insert(
            8,
            annotation(
                "PKCS5_PBKDF2_HMAC_SHA1",
                &[
                    "0x1000", "8", "0x2000", "4", "1000", "0x3000", "16", "0x4000",
                ],
                &[(0x1000, b"password".to_vec()), (0x2000, b"salt".to_vec())],
            ),
        );
        let report =
            analyze_crypto_materials(&annotations, None, &CryptoMaterialOptions::default());
        let salt = report
            .materials
            .iter()
            .find(|material| material.kind == CryptoMaterialKind::Salt)
            .unwrap();
        assert_eq!(salt.bytes_hex.as_deref(), Some("73616c74"));
        assert_eq!(salt.assessment.grade, "related");
        assert!(!salt.assessment.verification_gate_met);
    }

    #[test]
    fn verifies_streaming_md5_across_multiple_update_calls() {
        let mut annotations = HashMap::new();
        annotations.insert(1, annotation("MD5_Init", &["0x9000"], &[]));
        annotations.insert(
            2,
            annotation(
                "MD5_Update",
                &["0x9000", "0x1000", "3"],
                &[(0x1000, b"hel".to_vec())],
            ),
        );
        annotations.insert(
            3,
            annotation(
                "MD5_Update",
                &["0x9000", "0x1100", "2"],
                &[(0x1100, b"lo".to_vec())],
            ),
        );
        annotations.insert(
            4,
            annotation(
                "MD5_Final",
                &["0x2000", "0x9000"],
                &[(0x2000, Md5::digest(b"hello").to_vec())],
            ),
        );
        let report =
            analyze_crypto_materials(&annotations, None, &CryptoMaterialOptions::default());
        assert_eq!(report.verified_formulas, 1);
        let input = report
            .materials
            .iter()
            .find(|material| material.kind == CryptoMaterialKind::Input)
            .unwrap();
        assert_eq!(input.bytes_hex.as_deref(), Some("68656c6c6f"));
        assert_eq!(input.address, None);
    }

    #[test]
    fn verifies_hmac_and_pbkdf2_when_outputs_are_captured() {
        let key = b"secret".to_vec();
        let input = b"payload".to_vec();
        let mac = hmac_bytes(HashAlgorithm::Sha256, &key, &input).unwrap();
        let password = b"password".to_vec();
        let salt = b"salt".to_vec();
        let derived = pbkdf2_bytes(HashAlgorithm::Sha1, &password, &salt, 1000, 16).unwrap();
        let mut annotations = HashMap::new();
        annotations.insert(
            10,
            annotation(
                "HMAC_SHA256",
                &["0x0", "0x1000", "6", "0x2000", "7", "0x3000", "0x0"],
                &[(0x1000, key), (0x2000, input), (0x3000, mac)],
            ),
        );
        annotations.insert(
            20,
            annotation(
                "PKCS5_PBKDF2_HMAC_SHA1",
                &["0x4000", "8", "0x5000", "4", "1000", "0x0", "16", "0x6000"],
                &[(0x4000, password), (0x5000, salt), (0x6000, derived)],
            ),
        );
        let report =
            analyze_crypto_materials(&annotations, None, &CryptoMaterialOptions::default());
        assert_eq!(report.verified_formulas, 2);
        assert!(report
            .formulas
            .iter()
            .all(|formula| formula.assessment.verification_gate_met));
        assert!(report
            .materials
            .iter()
            .any(|material| material.kind == CryptoMaterialKind::Salt
                && material.assessment.verification_gate_met));
    }

    fn digest_report(input: &[u8], label: &str) -> CryptoMaterialReport {
        let digest = Md5::digest(input).to_vec();
        let mut annotations = HashMap::new();
        annotations.insert(
            5,
            annotation(
                "MD5",
                &["0x1000", &input.len().to_string(), "0x2000"],
                &[(0x1000, input.to_vec()), (0x2000, digest)],
            ),
        );
        let mut report =
            analyze_crypto_materials(&annotations, None, &CryptoMaterialOptions::default());
        report.formulas[0].function_name = Some(label.to_string());
        report
    }

    #[test]
    fn controlled_runs_isolate_dynamic_digest_parameter_without_overclaiming_salt() {
        let left = digest_report(b"user=same&salt=AAAA&tail=x", "MD5");
        let right = digest_report(b"user=same&salt=BBBB&tail=x", "MD5");
        let compared = compare_crypto_material_reports(vec![
            (
                CryptoMaterialTraceCase {
                    session_id: "left".into(),
                    label: "run-a".into(),
                    input_group: "same-user".into(),
                },
                left,
            ),
            (
                CryptoMaterialTraceCase {
                    session_id: "right".into(),
                    label: "run-b".into(),
                    input_group: "same-user".into(),
                },
                right,
            ),
        ])
        .unwrap();
        assert_eq!(compared.dynamic_parameter_candidates.len(), 1);
        let candidate = &compared.dynamic_parameter_candidates[0];
        assert_eq!(candidate.left_variable_hex, "41414141");
        assert_eq!(candidate.right_variable_hex, "42424242");
        assert_eq!(candidate.role_hint, "saltOrNonceCandidate");
        assert!(!candidate.assessment.verification_gate_met);
    }
}
