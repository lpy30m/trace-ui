//! Strict, deterministic crypto known-answer verification artifacts.
//!
//! A report is accepted only when every serialized field matches a fresh recomputation of the
//! embedded request. This makes the artifact suitable for a structured claim gate while keeping
//! the scope deliberately narrow: one exact vector, not implementation provenance or reachability.

use std::fs::File;
use std::io::{Read, Write};
use std::path::Path;
use std::str::FromStr;

use aes::cipher::{generic_array::GenericArray, BlockDecrypt, BlockEncrypt, KeyInit};
use aes::{Aes128, Aes192, Aes256};
use aes_gcm::aead::consts::U12;
use aes_gcm::aead::AeadInPlace;
use aes_gcm::{Aes128Gcm, Aes256Gcm, Nonce, Tag};
use hmac::{Hmac, Mac};
use md5::Md5;
use pbkdf2::pbkdf2_hmac;
use serde::{Deserialize, Serialize};
use sha1::Sha1;
use sha2::{Digest, Sha256, Sha384, Sha512};

type Aes192Gcm = aes_gcm::AesGcm<Aes192, U12>;

pub const CRYPTO_SEMANTIC_KAT_SCHEMA: &str = "trace-ui/crypto-semantic-kat-v1";
pub const CRYPTO_SEMANTIC_KAT_VERIFICATION_SCHEMA: &str =
    "trace-ui/crypto-semantic-kat-verification-v1";
pub const MAX_CRYPTO_KAT_DATA_BYTES: usize = 4 * 1024 * 1024;
pub const MAX_CRYPTO_KAT_SECRET_BYTES: usize = 64 * 1024;
pub const MAX_CRYPTO_KAT_DERIVED_KEY_BYTES: usize = 4096;
pub const MAX_CRYPTO_KAT_PBKDF2_ITERATIONS: u32 = 1_000_000;
const MAX_CRYPTO_KAT_REPORT_BYTES: u64 = 64 * 1024 * 1024;
const MISMATCH_PREVIEW_BYTES: usize = 32;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum CryptoKatAlgorithm {
    AesEcb,
    AesCbc,
    AesCtr,
    AesGcm,
    Md5,
    Sha1,
    Sha256,
    Sha384,
    Sha512,
    HmacMd5,
    HmacSha1,
    HmacSha256,
    HmacSha384,
    HmacSha512,
    Pbkdf2HmacSha1,
    Pbkdf2HmacSha256,
    Pbkdf2HmacSha384,
    Pbkdf2HmacSha512,
}

impl CryptoKatAlgorithm {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::AesEcb => "aes-ecb",
            Self::AesCbc => "aes-cbc",
            Self::AesCtr => "aes-ctr",
            Self::AesGcm => "aes-gcm",
            Self::Md5 => "md5",
            Self::Sha1 => "sha1",
            Self::Sha256 => "sha256",
            Self::Sha384 => "sha384",
            Self::Sha512 => "sha512",
            Self::HmacMd5 => "hmac-md5",
            Self::HmacSha1 => "hmac-sha1",
            Self::HmacSha256 => "hmac-sha256",
            Self::HmacSha384 => "hmac-sha384",
            Self::HmacSha512 => "hmac-sha512",
            Self::Pbkdf2HmacSha1 => "pbkdf2-hmac-sha1",
            Self::Pbkdf2HmacSha256 => "pbkdf2-hmac-sha256",
            Self::Pbkdf2HmacSha384 => "pbkdf2-hmac-sha384",
            Self::Pbkdf2HmacSha512 => "pbkdf2-hmac-sha512",
        }
    }

    fn is_aes(self) -> bool {
        matches!(
            self,
            Self::AesEcb | Self::AesCbc | Self::AesCtr | Self::AesGcm
        )
    }
}

impl FromStr for CryptoKatAlgorithm {
    type Err = String;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let normalized = value.trim().to_ascii_lowercase().replace(['_', '/'], "-");
        match normalized.as_str() {
            "aes-ecb" | "aesecb" => Ok(Self::AesEcb),
            "aes-cbc" | "aescbc" => Ok(Self::AesCbc),
            "aes-ctr" | "aesctr" => Ok(Self::AesCtr),
            "aes-gcm" | "aesgcm" => Ok(Self::AesGcm),
            "md5" => Ok(Self::Md5),
            "sha1" | "sha-1" => Ok(Self::Sha1),
            "sha256" | "sha-256" => Ok(Self::Sha256),
            "sha384" | "sha-384" => Ok(Self::Sha384),
            "sha512" | "sha-512" => Ok(Self::Sha512),
            "hmac-md5" | "hmacmd5" => Ok(Self::HmacMd5),
            "hmac-sha1" | "hmac-sha-1" | "hmacsha1" => Ok(Self::HmacSha1),
            "hmac-sha256" | "hmac-sha-256" | "hmacsha256" => Ok(Self::HmacSha256),
            "hmac-sha384" | "hmac-sha-384" | "hmacsha384" => Ok(Self::HmacSha384),
            "hmac-sha512" | "hmac-sha-512" | "hmacsha512" => Ok(Self::HmacSha512),
            "pbkdf2-hmac-sha1" | "pbkdf2-sha1" | "pbkdf2hmacsha1" => {
                Ok(Self::Pbkdf2HmacSha1)
            }
            "pbkdf2-hmac-sha256" | "pbkdf2-sha256" | "pbkdf2hmacsha256" => {
                Ok(Self::Pbkdf2HmacSha256)
            }
            "pbkdf2-hmac-sha384" | "pbkdf2-sha384" | "pbkdf2hmacsha384" => {
                Ok(Self::Pbkdf2HmacSha384)
            }
            "pbkdf2-hmac-sha512" | "pbkdf2-sha512" | "pbkdf2hmacsha512" => {
                Ok(Self::Pbkdf2HmacSha512)
            }
            _ => Err(format!(
                "unsupported crypto KAT algorithm: {value}; expected AES ECB/CBC/CTR/GCM, MD5, SHA-1/256/384/512, HMAC, or PBKDF2-HMAC"
            )),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum CryptoKatDirection {
    Encrypt,
    Decrypt,
}

impl FromStr for CryptoKatDirection {
    type Err = String;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value.trim().to_ascii_lowercase().as_str() {
            "encrypt" | "enc" => Ok(Self::Encrypt),
            "decrypt" | "dec" => Ok(Self::Decrypt),
            _ => Err(format!(
                "unsupported crypto KAT direction: {value}; expected encrypt or decrypt"
            )),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum CryptoKatStatus {
    VerifiedFull,
    Refuted,
    Invalid,
}

impl CryptoKatStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::VerifiedFull => "verified-full",
            Self::Refuted => "refuted",
            Self::Invalid => "invalid",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CryptoSemanticKatRequest {
    pub schema: String,
    pub algorithm: CryptoKatAlgorithm,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub direction: Option<CryptoKatDirection>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key_hex: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub input_hex: Option<String>,
    pub observed_output_hex: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub iv_hex: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub aad_hex: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub observed_tag_hex: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub password_hex: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub salt_hex: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub iterations: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub derived_key_length: Option<u32>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CryptoKatMismatch {
    pub component: String,
    pub start_offset: u64,
    pub end_offset_exclusive: u64,
    pub expected_length: u64,
    pub observed_length: u64,
    pub expected_preview_hex: String,
    pub observed_preview_hex: String,
    pub preview_truncated: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CryptoSemanticKatReport {
    pub schema: String,
    pub request: CryptoSemanticKatRequest,
    pub algorithm: CryptoKatAlgorithm,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub direction: Option<CryptoKatDirection>,
    pub status: CryptoKatStatus,
    pub verification_gate_met: bool,
    pub claim_scope: String,
    pub bytes_checked: u64,
    pub tag_bytes_checked: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expected_output_hex: Option<String>,
    pub observed_output_hex: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expected_tag_hex: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub observed_tag_hex: Option<String>,
    pub output_matched: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tag_matched: Option<bool>,
    pub mismatch_byte_count: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub first_mismatch: Option<CryptoKatMismatch>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub invalid_reason: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub refutation_reason: Option<String>,
    pub parameter_summary: Vec<String>,
    pub limitations: Vec<String>,
}

fn hex(bytes: &[u8]) -> String {
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        use std::fmt::Write as _;
        let _ = write!(&mut output, "{byte:02x}");
    }
    output
}

fn request_scope(request: &CryptoSemanticKatRequest) -> String {
    let encoded = serde_json::to_vec(request).unwrap_or_default();
    let fingerprint = hex(&Sha256::digest(encoded));
    format!("crypto:{}:{fingerprint}", request.algorithm.as_str())
}

fn limitations() -> Vec<String> {
    vec![
        "VerifiedFull proves only the exact recorded algorithm parameters and byte vector; it does not prove which function produced the bytes, real-entry reachability, or all inputs handled by an implementation."
            .to_string(),
        "The artifact embeds key/password/input/output material in hexadecimal and must be handled as sensitive evidence."
            .to_string(),
        "This deterministic recomputation does not attest the runtime image and cannot verify OLLVM, angr, Unicorn, or IDA structural conclusions."
            .to_string(),
    ]
}

fn invalid_report(
    request: &CryptoSemanticKatRequest,
    reason: impl Into<String>,
) -> CryptoSemanticKatReport {
    CryptoSemanticKatReport {
        schema: CRYPTO_SEMANTIC_KAT_VERIFICATION_SCHEMA.to_string(),
        request: request.clone(),
        algorithm: request.algorithm,
        direction: request.direction,
        status: CryptoKatStatus::Invalid,
        verification_gate_met: false,
        claim_scope: request_scope(request),
        bytes_checked: 0,
        tag_bytes_checked: 0,
        expected_output_hex: None,
        observed_output_hex: request.observed_output_hex.clone(),
        expected_tag_hex: None,
        observed_tag_hex: request.observed_tag_hex.clone(),
        output_matched: false,
        tag_matched: None,
        mismatch_byte_count: 0,
        first_mismatch: None,
        invalid_reason: Some(reason.into()),
        refutation_reason: None,
        parameter_summary: Vec::new(),
        limitations: limitations(),
    }
}

fn decode_hex(name: &str, value: &str, max_bytes: usize) -> Result<Vec<u8>, String> {
    if value.len() % 2 != 0 {
        return Err(format!(
            "{name} must contain an even number of hexadecimal characters"
        ));
    }
    if value.len() / 2 > max_bytes {
        return Err(format!(
            "{name} exceeds the bounded maximum of {max_bytes} bytes"
        ));
    }
    if !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(format!(
            "{name} must contain hexadecimal characters only; prefixes, whitespace, and separators are not accepted"
        ));
    }
    (0..value.len())
        .step_by(2)
        .map(|index| {
            u8::from_str_radix(&value[index..index + 2], 16)
                .map_err(|_| format!("invalid {name} byte at offset {}", index / 2))
        })
        .collect()
}

fn required_hex(
    request: &CryptoSemanticKatRequest,
    name: &str,
    value: Option<&str>,
    max_bytes: usize,
) -> Result<Vec<u8>, CryptoSemanticKatReport> {
    let Some(value) = value else {
        return Err(invalid_report(request, format!("{name} is required")));
    };
    decode_hex(name, value, max_bytes).map_err(|error| invalid_report(request, error))
}

fn reject_fields(
    request: &CryptoSemanticKatRequest,
    fields: &[(&str, bool)],
) -> Result<(), CryptoSemanticKatReport> {
    let present = fields
        .iter()
        .filter_map(|(name, present)| present.then_some(*name))
        .collect::<Vec<_>>();
    if present.is_empty() {
        Ok(())
    } else {
        Err(invalid_report(
            request,
            format!(
                "{} must be omitted for {}",
                present.join(", "),
                request.algorithm.as_str()
            ),
        ))
    }
}

fn validate_aes_key(key: &[u8]) -> Result<(), String> {
    if matches!(key.len(), 16 | 24 | 32) {
        Ok(())
    } else {
        Err(format!(
            "AES key length must be 16, 24, or 32 bytes, got {}",
            key.len()
        ))
    }
}

fn transform_block(
    key: &[u8],
    encrypt: bool,
    block: &mut GenericArray<u8, aes::cipher::consts::U16>,
) -> Result<(), String> {
    macro_rules! apply {
        ($cipher:ty) => {{
            let cipher =
                <$cipher>::new_from_slice(key).map_err(|_| "invalid AES key".to_string())?;
            if encrypt {
                cipher.encrypt_block(block);
            } else {
                cipher.decrypt_block(block);
            }
        }};
    }
    match key.len() {
        16 => apply!(Aes128),
        24 => apply!(Aes192),
        32 => apply!(Aes256),
        _ => return Err("invalid AES key".to_string()),
    }
    Ok(())
}

fn aes_ecb(key: &[u8], direction: CryptoKatDirection, input: &[u8]) -> Result<Vec<u8>, String> {
    validate_aes_key(key)?;
    if input.is_empty() || input.len() % 16 != 0 {
        return Err("AES-ECB input must contain one or more complete 16-byte blocks".to_string());
    }
    let mut output = Vec::with_capacity(input.len());
    for source in input.chunks_exact(16) {
        let mut block = GenericArray::clone_from_slice(source);
        transform_block(key, direction == CryptoKatDirection::Encrypt, &mut block)?;
        output.extend_from_slice(&block);
    }
    Ok(output)
}

fn aes_cbc(
    key: &[u8],
    direction: CryptoKatDirection,
    iv: &[u8],
    input: &[u8],
) -> Result<Vec<u8>, String> {
    validate_aes_key(key)?;
    if iv.len() != 16 {
        return Err(format!("AES-CBC IV must be 16 bytes, got {}", iv.len()));
    }
    if input.is_empty() || input.len() % 16 != 0 {
        return Err("AES-CBC input must contain one or more complete 16-byte blocks".to_string());
    }
    let mut output = Vec::with_capacity(input.len());
    let mut previous = iv.to_vec();
    for source in input.chunks_exact(16) {
        let mut block = GenericArray::clone_from_slice(source);
        match direction {
            CryptoKatDirection::Encrypt => {
                for (byte, chain) in block.iter_mut().zip(&previous) {
                    *byte ^= *chain;
                }
                transform_block(key, true, &mut block)?;
                previous.copy_from_slice(&block);
                output.extend_from_slice(&block);
            }
            CryptoKatDirection::Decrypt => {
                transform_block(key, false, &mut block)?;
                for (byte, chain) in block.iter_mut().zip(&previous) {
                    *byte ^= *chain;
                }
                output.extend_from_slice(&block);
                previous.copy_from_slice(source);
            }
        }
    }
    Ok(output)
}

fn aes_ctr(key: &[u8], counter: &[u8], input: &[u8]) -> Result<Vec<u8>, String> {
    validate_aes_key(key)?;
    if counter.len() != 16 {
        return Err(format!(
            "AES-CTR initial counter must be 16 bytes, got {}",
            counter.len()
        ));
    }
    if input.is_empty() {
        return Err("AES-CTR input must contain at least one byte".to_string());
    }
    let mut counter = <[u8; 16]>::try_from(counter).unwrap();
    let mut output = Vec::with_capacity(input.len());
    for source in input.chunks(16) {
        let mut stream = GenericArray::clone_from_slice(&counter);
        transform_block(key, true, &mut stream)?;
        output.extend(
            source
                .iter()
                .zip(stream.iter())
                .map(|(byte, mask)| byte ^ mask),
        );
        for byte in counter.iter_mut().rev() {
            let (next, overflow) = byte.overflowing_add(1);
            *byte = next;
            if !overflow {
                break;
            }
        }
    }
    Ok(output)
}

enum GcmComputation {
    Complete { output: Vec<u8>, tag: Vec<u8> },
    AuthenticationFailed,
}

fn aes_gcm(
    key: &[u8],
    direction: CryptoKatDirection,
    nonce: &[u8],
    aad: &[u8],
    input: &[u8],
    observed_tag: &[u8],
) -> Result<GcmComputation, String> {
    validate_aes_key(key)?;
    if nonce.len() != 12 {
        return Err(format!(
            "AES-GCM nonce must be 12 bytes, got {}",
            nonce.len()
        ));
    }
    if observed_tag.len() != 16 {
        return Err(format!(
            "AES-GCM authentication tag must be 16 bytes, got {}",
            observed_tag.len()
        ));
    }
    let nonce = Nonce::from_slice(nonce);
    let mut output = input.to_vec();
    macro_rules! run {
        ($cipher:ty) => {{
            let cipher =
                <$cipher>::new_from_slice(key).map_err(|_| "invalid AES-GCM key".to_string())?;
            match direction {
                CryptoKatDirection::Encrypt => {
                    let tag = cipher
                        .encrypt_in_place_detached(nonce, aad, &mut output)
                        .map_err(|_| "AES-GCM encryption recomputation failed".to_string())?;
                    GcmComputation::Complete {
                        output,
                        tag: tag.to_vec(),
                    }
                }
                CryptoKatDirection::Decrypt => {
                    let tag = Tag::from_slice(observed_tag);
                    if cipher
                        .decrypt_in_place_detached(nonce, aad, &mut output, tag)
                        .is_err()
                    {
                        GcmComputation::AuthenticationFailed
                    } else {
                        GcmComputation::Complete {
                            output,
                            tag: observed_tag.to_vec(),
                        }
                    }
                }
            }
        }};
    }
    Ok(match key.len() {
        16 => run!(Aes128Gcm),
        24 => run!(Aes192Gcm),
        32 => run!(Aes256Gcm),
        _ => return Err("invalid AES-GCM key".to_string()),
    })
}

fn digest(algorithm: CryptoKatAlgorithm, input: &[u8]) -> Vec<u8> {
    match algorithm {
        CryptoKatAlgorithm::Md5 => Md5::digest(input).to_vec(),
        CryptoKatAlgorithm::Sha1 => Sha1::digest(input).to_vec(),
        CryptoKatAlgorithm::Sha256 => Sha256::digest(input).to_vec(),
        CryptoKatAlgorithm::Sha384 => Sha384::digest(input).to_vec(),
        CryptoKatAlgorithm::Sha512 => Sha512::digest(input).to_vec(),
        _ => unreachable!(),
    }
}

fn hmac(algorithm: CryptoKatAlgorithm, key: &[u8], input: &[u8]) -> Result<Vec<u8>, String> {
    macro_rules! calculate {
        ($digest:ty) => {{
            let mut mac = <Hmac<$digest> as Mac>::new_from_slice(key)
                .map_err(|_| "invalid HMAC key".to_string())?;
            mac.update(input);
            Ok(mac.finalize().into_bytes().to_vec())
        }};
    }
    match algorithm {
        CryptoKatAlgorithm::HmacMd5 => calculate!(Md5),
        CryptoKatAlgorithm::HmacSha1 => calculate!(Sha1),
        CryptoKatAlgorithm::HmacSha256 => calculate!(Sha256),
        CryptoKatAlgorithm::HmacSha384 => calculate!(Sha384),
        CryptoKatAlgorithm::HmacSha512 => calculate!(Sha512),
        _ => unreachable!(),
    }
}

fn pbkdf2(
    algorithm: CryptoKatAlgorithm,
    password: &[u8],
    salt: &[u8],
    iterations: u32,
    output_len: usize,
) -> Vec<u8> {
    let mut output = vec![0_u8; output_len];
    match algorithm {
        CryptoKatAlgorithm::Pbkdf2HmacSha1 => {
            pbkdf2_hmac::<Sha1>(password, salt, iterations, &mut output)
        }
        CryptoKatAlgorithm::Pbkdf2HmacSha256 => {
            pbkdf2_hmac::<Sha256>(password, salt, iterations, &mut output)
        }
        CryptoKatAlgorithm::Pbkdf2HmacSha384 => {
            pbkdf2_hmac::<Sha384>(password, salt, iterations, &mut output)
        }
        CryptoKatAlgorithm::Pbkdf2HmacSha512 => {
            pbkdf2_hmac::<Sha512>(password, salt, iterations, &mut output)
        }
        _ => unreachable!(),
    }
    output
}

fn mismatch(component: &str, expected: &[u8], observed: &[u8]) -> (u64, Option<CryptoKatMismatch>) {
    let compared_len = expected.len().max(observed.len());
    let mismatch_count = (0..compared_len)
        .filter(|index| expected.get(*index) != observed.get(*index))
        .count() as u64;
    let Some(start) = (0..compared_len).find(|index| expected.get(*index) != observed.get(*index))
    else {
        return (0, None);
    };
    let end = (start + 1..compared_len)
        .find(|index| expected.get(*index) == observed.get(*index))
        .unwrap_or(compared_len);
    let preview_end = end.min(start + MISMATCH_PREVIEW_BYTES);
    let expected_start = start.min(expected.len());
    let observed_start = start.min(observed.len());
    let expected_preview_end = preview_end.min(expected.len());
    let observed_preview_end = preview_end.min(observed.len());
    (
        mismatch_count,
        Some(CryptoKatMismatch {
            component: component.to_string(),
            start_offset: start as u64,
            end_offset_exclusive: end as u64,
            expected_length: expected.len() as u64,
            observed_length: observed.len() as u64,
            expected_preview_hex: hex(&expected[expected_start..expected_preview_end]),
            observed_preview_hex: hex(&observed[observed_start..observed_preview_end]),
            preview_truncated: preview_end < end,
        }),
    )
}

fn complete_report(
    request: &CryptoSemanticKatRequest,
    expected_output: Vec<u8>,
    observed_output: Vec<u8>,
    expected_tag: Option<Vec<u8>>,
    observed_tag: Option<Vec<u8>>,
    parameter_summary: Vec<String>,
) -> CryptoSemanticKatReport {
    let (output_mismatch_count, output_mismatch) =
        mismatch("output", &expected_output, &observed_output);
    let (tag_mismatch_count, tag_mismatch) = match (&expected_tag, &observed_tag) {
        (Some(expected), Some(observed)) => mismatch("tag", expected, observed),
        (None, None) => (0, None),
        (Some(expected), None) => mismatch("tag", expected, &[]),
        (None, Some(observed)) => mismatch("tag", &[], observed),
    };
    let output_matched = output_mismatch_count == 0;
    let tag_matched = expected_tag
        .as_ref()
        .or(observed_tag.as_ref())
        .map(|_| tag_mismatch_count == 0);
    let verified = output_matched && tag_matched.unwrap_or(true);
    CryptoSemanticKatReport {
        schema: CRYPTO_SEMANTIC_KAT_VERIFICATION_SCHEMA.to_string(),
        request: request.clone(),
        algorithm: request.algorithm,
        direction: request.direction,
        status: if verified {
            CryptoKatStatus::VerifiedFull
        } else {
            CryptoKatStatus::Refuted
        },
        verification_gate_met: verified,
        claim_scope: request_scope(request),
        bytes_checked: expected_output.len() as u64,
        tag_bytes_checked: expected_tag.as_ref().map_or(0, |tag| tag.len() as u64),
        expected_output_hex: Some(hex(&expected_output)),
        observed_output_hex: hex(&observed_output),
        expected_tag_hex: expected_tag.as_deref().map(hex),
        observed_tag_hex: observed_tag.as_deref().map(hex),
        output_matched,
        tag_matched,
        mismatch_byte_count: output_mismatch_count + tag_mismatch_count,
        first_mismatch: output_mismatch.or(tag_mismatch),
        invalid_reason: None,
        refutation_reason: (!verified).then(|| {
            if tag_matched == Some(false) {
                "The observed authentication tag does not match the recomputed tag.".to_string()
            } else {
                "The observed output differs from the deterministic recomputation.".to_string()
            }
        }),
        parameter_summary,
        limitations: limitations(),
    }
}

fn authentication_failed_report(
    request: &CryptoSemanticKatRequest,
    observed_output: Vec<u8>,
    observed_tag: Vec<u8>,
    parameter_summary: Vec<String>,
) -> CryptoSemanticKatReport {
    CryptoSemanticKatReport {
        schema: CRYPTO_SEMANTIC_KAT_VERIFICATION_SCHEMA.to_string(),
        request: request.clone(),
        algorithm: request.algorithm,
        direction: request.direction,
        status: CryptoKatStatus::Refuted,
        verification_gate_met: false,
        claim_scope: request_scope(request),
        bytes_checked: observed_output.len() as u64,
        tag_bytes_checked: observed_tag.len() as u64,
        expected_output_hex: None,
        observed_output_hex: hex(&observed_output),
        expected_tag_hex: None,
        observed_tag_hex: Some(hex(&observed_tag)),
        output_matched: false,
        tag_matched: Some(false),
        mismatch_byte_count: observed_tag.len() as u64,
        first_mismatch: Some(CryptoKatMismatch {
            component: "tag".to_string(),
            start_offset: 0,
            end_offset_exclusive: observed_tag.len() as u64,
            expected_length: 16,
            observed_length: observed_tag.len() as u64,
            expected_preview_hex: String::new(),
            observed_preview_hex: hex(&observed_tag[..observed_tag.len().min(MISMATCH_PREVIEW_BYTES)]),
            preview_truncated: observed_tag.len() > MISMATCH_PREVIEW_BYTES,
        }),
        invalid_reason: None,
        refutation_reason: Some(
            "AES-GCM decryption rejected the observed authentication tag; plaintext/output verification cannot pass."
                .to_string(),
        ),
        parameter_summary,
        limitations: limitations(),
    }
}

/// Deterministically recompute one bounded crypto vector.
///
/// Structurally invalid requests return an `invalid` report rather than opening any claim gate.
pub fn verify_crypto_semantic_kat(request: &CryptoSemanticKatRequest) -> CryptoSemanticKatReport {
    if request.schema != CRYPTO_SEMANTIC_KAT_SCHEMA {
        return invalid_report(
            request,
            format!("unsupported crypto KAT request schema: {}", request.schema),
        );
    }

    let observed_output = match decode_hex(
        "observedOutputHex",
        &request.observed_output_hex,
        MAX_CRYPTO_KAT_DATA_BYTES,
    ) {
        Ok(value) => value,
        Err(error) => return invalid_report(request, error),
    };

    if request.algorithm.is_aes() {
        let Some(direction) = request.direction else {
            return invalid_report(request, "direction is required for AES KATs");
        };
        if let Err(report) = reject_fields(
            request,
            &[
                ("passwordHex", request.password_hex.is_some()),
                ("saltHex", request.salt_hex.is_some()),
                ("iterations", request.iterations.is_some()),
                ("derivedKeyLength", request.derived_key_length.is_some()),
            ],
        ) {
            return report;
        }
        let key = match required_hex(
            request,
            "keyHex",
            request.key_hex.as_deref(),
            MAX_CRYPTO_KAT_SECRET_BYTES,
        ) {
            Ok(value) => value,
            Err(report) => return report,
        };
        let input = match required_hex(
            request,
            "inputHex",
            request.input_hex.as_deref(),
            MAX_CRYPTO_KAT_DATA_BYTES,
        ) {
            Ok(value) => value,
            Err(report) => return report,
        };
        let mut summary = vec![
            format!(
                "direction={}",
                match direction {
                    CryptoKatDirection::Encrypt => "encrypt",
                    CryptoKatDirection::Decrypt => "decrypt",
                }
            ),
            format!("keyBits={}", key.len() * 8),
            format!("inputBytes={}", input.len()),
            format!("observedOutputBytes={}", observed_output.len()),
        ];
        match request.algorithm {
            CryptoKatAlgorithm::AesEcb => {
                if let Err(report) = reject_fields(
                    request,
                    &[
                        ("ivHex", request.iv_hex.is_some()),
                        ("aadHex", request.aad_hex.is_some()),
                        ("observedTagHex", request.observed_tag_hex.is_some()),
                    ],
                ) {
                    return report;
                }
                match aes_ecb(&key, direction, &input) {
                    Ok(expected) => {
                        complete_report(request, expected, observed_output, None, None, summary)
                    }
                    Err(error) => invalid_report(request, error),
                }
            }
            CryptoKatAlgorithm::AesCbc | CryptoKatAlgorithm::AesCtr => {
                if let Err(report) = reject_fields(
                    request,
                    &[
                        ("aadHex", request.aad_hex.is_some()),
                        ("observedTagHex", request.observed_tag_hex.is_some()),
                    ],
                ) {
                    return report;
                }
                let iv = match required_hex(request, "ivHex", request.iv_hex.as_deref(), 16) {
                    Ok(value) => value,
                    Err(report) => return report,
                };
                summary.push(format!("ivBytes={}", iv.len()));
                let expected = if request.algorithm == CryptoKatAlgorithm::AesCbc {
                    aes_cbc(&key, direction, &iv, &input)
                } else {
                    aes_ctr(&key, &iv, &input)
                };
                match expected {
                    Ok(expected) => {
                        complete_report(request, expected, observed_output, None, None, summary)
                    }
                    Err(error) => invalid_report(request, error),
                }
            }
            CryptoKatAlgorithm::AesGcm => {
                let nonce = match required_hex(request, "ivHex", request.iv_hex.as_deref(), 12) {
                    Ok(value) => value,
                    Err(report) => return report,
                };
                let aad = match request.aad_hex.as_deref() {
                    Some(value) => match decode_hex("aadHex", value, MAX_CRYPTO_KAT_DATA_BYTES) {
                        Ok(value) => value,
                        Err(error) => return invalid_report(request, error),
                    },
                    None => Vec::new(),
                };
                let observed_tag = match required_hex(
                    request,
                    "observedTagHex",
                    request.observed_tag_hex.as_deref(),
                    16,
                ) {
                    Ok(value) => value,
                    Err(report) => return report,
                };
                summary.push(format!("nonceBytes={}", nonce.len()));
                summary.push(format!("aadBytes={}", aad.len()));
                match aes_gcm(&key, direction, &nonce, &aad, &input, &observed_tag) {
                    Ok(GcmComputation::Complete { output, tag }) => complete_report(
                        request,
                        output,
                        observed_output,
                        Some(tag),
                        Some(observed_tag),
                        summary,
                    ),
                    Ok(GcmComputation::AuthenticationFailed) => authentication_failed_report(
                        request,
                        observed_output,
                        observed_tag,
                        summary,
                    ),
                    Err(error) => invalid_report(request, error),
                }
            }
            _ => unreachable!(),
        }
    } else {
        if request.direction.is_some() {
            return invalid_report(request, "direction must be omitted for non-AES KATs");
        }
        match request.algorithm {
            CryptoKatAlgorithm::Md5
            | CryptoKatAlgorithm::Sha1
            | CryptoKatAlgorithm::Sha256
            | CryptoKatAlgorithm::Sha384
            | CryptoKatAlgorithm::Sha512 => {
                if let Err(report) = reject_fields(
                    request,
                    &[
                        ("keyHex", request.key_hex.is_some()),
                        ("ivHex", request.iv_hex.is_some()),
                        ("aadHex", request.aad_hex.is_some()),
                        ("observedTagHex", request.observed_tag_hex.is_some()),
                        ("passwordHex", request.password_hex.is_some()),
                        ("saltHex", request.salt_hex.is_some()),
                        ("iterations", request.iterations.is_some()),
                        ("derivedKeyLength", request.derived_key_length.is_some()),
                    ],
                ) {
                    return report;
                }
                let input = match required_hex(
                    request,
                    "inputHex",
                    request.input_hex.as_deref(),
                    MAX_CRYPTO_KAT_DATA_BYTES,
                ) {
                    Ok(value) => value,
                    Err(report) => return report,
                };
                let expected = digest(request.algorithm, &input);
                complete_report(
                    request,
                    expected,
                    observed_output,
                    None,
                    None,
                    vec![format!("inputBytes={}", input.len())],
                )
            }
            CryptoKatAlgorithm::HmacMd5
            | CryptoKatAlgorithm::HmacSha1
            | CryptoKatAlgorithm::HmacSha256
            | CryptoKatAlgorithm::HmacSha384
            | CryptoKatAlgorithm::HmacSha512 => {
                if let Err(report) = reject_fields(
                    request,
                    &[
                        ("ivHex", request.iv_hex.is_some()),
                        ("aadHex", request.aad_hex.is_some()),
                        ("observedTagHex", request.observed_tag_hex.is_some()),
                        ("passwordHex", request.password_hex.is_some()),
                        ("saltHex", request.salt_hex.is_some()),
                        ("iterations", request.iterations.is_some()),
                        ("derivedKeyLength", request.derived_key_length.is_some()),
                    ],
                ) {
                    return report;
                }
                let key = match required_hex(
                    request,
                    "keyHex",
                    request.key_hex.as_deref(),
                    MAX_CRYPTO_KAT_SECRET_BYTES,
                ) {
                    Ok(value) => value,
                    Err(report) => return report,
                };
                let input = match required_hex(
                    request,
                    "inputHex",
                    request.input_hex.as_deref(),
                    MAX_CRYPTO_KAT_DATA_BYTES,
                ) {
                    Ok(value) => value,
                    Err(report) => return report,
                };
                match hmac(request.algorithm, &key, &input) {
                    Ok(expected) => complete_report(
                        request,
                        expected,
                        observed_output,
                        None,
                        None,
                        vec![
                            format!("keyBytes={}", key.len()),
                            format!("inputBytes={}", input.len()),
                        ],
                    ),
                    Err(error) => invalid_report(request, error),
                }
            }
            CryptoKatAlgorithm::Pbkdf2HmacSha1
            | CryptoKatAlgorithm::Pbkdf2HmacSha256
            | CryptoKatAlgorithm::Pbkdf2HmacSha384
            | CryptoKatAlgorithm::Pbkdf2HmacSha512 => {
                if let Err(report) = reject_fields(
                    request,
                    &[
                        ("keyHex", request.key_hex.is_some()),
                        ("inputHex", request.input_hex.is_some()),
                        ("ivHex", request.iv_hex.is_some()),
                        ("aadHex", request.aad_hex.is_some()),
                        ("observedTagHex", request.observed_tag_hex.is_some()),
                    ],
                ) {
                    return report;
                }
                let password = match required_hex(
                    request,
                    "passwordHex",
                    request.password_hex.as_deref(),
                    MAX_CRYPTO_KAT_SECRET_BYTES,
                ) {
                    Ok(value) => value,
                    Err(report) => return report,
                };
                let salt = match required_hex(
                    request,
                    "saltHex",
                    request.salt_hex.as_deref(),
                    MAX_CRYPTO_KAT_SECRET_BYTES,
                ) {
                    Ok(value) => value,
                    Err(report) => return report,
                };
                let Some(iterations) = request.iterations else {
                    return invalid_report(request, "iterations is required for PBKDF2-HMAC");
                };
                if iterations == 0 || iterations > MAX_CRYPTO_KAT_PBKDF2_ITERATIONS {
                    return invalid_report(
                        request,
                        format!(
                            "PBKDF2 iterations must be between 1 and {}",
                            MAX_CRYPTO_KAT_PBKDF2_ITERATIONS
                        ),
                    );
                }
                let Some(output_len) = request.derived_key_length.map(|value| value as usize)
                else {
                    return invalid_report(request, "derivedKeyLength is required for PBKDF2-HMAC");
                };
                if output_len == 0 || output_len > MAX_CRYPTO_KAT_DERIVED_KEY_BYTES {
                    return invalid_report(
                        request,
                        format!(
                            "PBKDF2 derivedKeyLength must be between 1 and {} bytes",
                            MAX_CRYPTO_KAT_DERIVED_KEY_BYTES
                        ),
                    );
                }
                if observed_output.len() != output_len {
                    return invalid_report(
                        request,
                        format!(
                            "observedOutputHex contains {} bytes but derivedKeyLength is {output_len}",
                            observed_output.len()
                        ),
                    );
                }
                let expected = pbkdf2(request.algorithm, &password, &salt, iterations, output_len);
                complete_report(
                    request,
                    expected,
                    observed_output,
                    None,
                    None,
                    vec![
                        format!("passwordBytes={}", password.len()),
                        format!("saltBytes={}", salt.len()),
                        format!("iterations={iterations}"),
                        format!("derivedKeyBytes={output_len}"),
                    ],
                )
            }
            _ => unreachable!(),
        }
    }
}

/// Parse a saved report and reject any field that does not match deterministic recomputation.
pub fn parse_crypto_semantic_kat_report(bytes: &[u8]) -> Result<CryptoSemanticKatReport, String> {
    if bytes.len() as u64 > MAX_CRYPTO_KAT_REPORT_BYTES {
        return Err(format!(
            "crypto KAT report exceeds {} bytes",
            MAX_CRYPTO_KAT_REPORT_BYTES
        ));
    }
    let report: CryptoSemanticKatReport = serde_json::from_slice(bytes)
        .map_err(|error| format!("invalid crypto KAT report JSON: {error}"))?;
    if report.schema != CRYPTO_SEMANTIC_KAT_VERIFICATION_SCHEMA {
        return Err(format!(
            "unsupported crypto KAT report schema: {}",
            report.schema
        ));
    }
    let recomputed = verify_crypto_semantic_kat(&report.request);
    if report != recomputed {
        return Err(
            "crypto KAT report fields do not match deterministic recomputation; the file may be stale, malformed, or modified"
                .to_string(),
        );
    }
    Ok(report)
}

pub fn inspect_crypto_semantic_kat_report(path: &str) -> Result<CryptoSemanticKatReport, String> {
    let path = Path::new(path);
    let metadata = path
        .metadata()
        .map_err(|error| format!("failed to inspect crypto KAT report: {error}"))?;
    if !metadata.is_file() {
        return Err(format!("crypto KAT report is not a regular file: {path:?}"));
    }
    if metadata.len() > MAX_CRYPTO_KAT_REPORT_BYTES {
        return Err(format!(
            "crypto KAT report exceeds {} bytes",
            MAX_CRYPTO_KAT_REPORT_BYTES
        ));
    }
    let mut file =
        File::open(path).map_err(|error| format!("failed to open crypto KAT report: {error}"))?;
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    file.read_to_end(&mut bytes)
        .map_err(|error| format!("failed to read crypto KAT report: {error}"))?;
    parse_crypto_semantic_kat_report(&bytes)
}

pub fn save_crypto_semantic_kat_report(
    path: &str,
    request: &CryptoSemanticKatRequest,
) -> Result<CryptoSemanticKatReport, String> {
    let report = verify_crypto_semantic_kat(request);
    let mut file = File::create(path)
        .map_err(|error| format!("failed to create crypto KAT report: {error}"))?;
    serde_json::to_writer_pretty(&mut file, &report)
        .map_err(|error| format!("failed to serialize crypto KAT report: {error}"))?;
    file.write_all(b"\n")
        .map_err(|error| format!("failed to finish crypto KAT report: {error}"))?;
    Ok(report)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request(
        algorithm: CryptoKatAlgorithm,
        observed_output_hex: &str,
    ) -> CryptoSemanticKatRequest {
        CryptoSemanticKatRequest {
            schema: CRYPTO_SEMANTIC_KAT_SCHEMA.to_string(),
            algorithm,
            direction: None,
            key_hex: None,
            input_hex: None,
            observed_output_hex: observed_output_hex.to_string(),
            iv_hex: None,
            aad_hex: None,
            observed_tag_hex: None,
            password_hex: None,
            salt_hex: None,
            iterations: None,
            derived_key_length: None,
        }
    }

    #[test]
    fn verifies_and_refutes_nist_aes_vectors_with_exact_mismatch() {
        let mut aes = request(
            CryptoKatAlgorithm::AesCbc,
            concat!(
                "7649abac8119b246cee98e9b12e9197d",
                "5086cb9b507219ee95db113a917678b2"
            ),
        );
        aes.direction = Some(CryptoKatDirection::Encrypt);
        aes.key_hex = Some("2b7e151628aed2a6abf7158809cf4f3c".to_string());
        aes.iv_hex = Some("000102030405060708090a0b0c0d0e0f".to_string());
        aes.input_hex = Some(
            concat!(
                "6bc1bee22e409f96e93d7e117393172a",
                "ae2d8a571e03ac9c9eb76fac45af8e51"
            )
            .to_string(),
        );
        let verified = verify_crypto_semantic_kat(&aes);
        assert_eq!(verified.status, CryptoKatStatus::VerifiedFull);
        assert!(verified.verification_gate_met);

        aes.observed_output_hex.replace_range(34..36, "00");
        let refuted = verify_crypto_semantic_kat(&aes);
        assert_eq!(refuted.status, CryptoKatStatus::Refuted);
        assert!(!refuted.verification_gate_met);
        assert_eq!(refuted.first_mismatch.as_ref().unwrap().start_offset, 17);
        assert!(refuted.mismatch_byte_count >= 1);
    }

    #[test]
    fn verifies_digest_hmac_pbkdf2_and_gcm() {
        let mut sha = request(
            CryptoKatAlgorithm::Sha256,
            "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824",
        );
        sha.input_hex = Some("68656c6c6f".to_string());
        assert!(verify_crypto_semantic_kat(&sha).verification_gate_met);

        let mut mac = request(
            CryptoKatAlgorithm::HmacSha256,
            "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7",
        );
        mac.key_hex = Some("0b".repeat(20));
        mac.input_hex = Some(hex(b"Hi There"));
        assert!(verify_crypto_semantic_kat(&mac).verification_gate_met);

        let mut derived = request(
            CryptoKatAlgorithm::Pbkdf2HmacSha1,
            "0c60c80f961f0e71f3a9b524af6012062fe037a6",
        );
        derived.password_hex = Some(hex(b"password"));
        derived.salt_hex = Some(hex(b"salt"));
        derived.iterations = Some(1);
        derived.derived_key_length = Some(20);
        assert!(verify_crypto_semantic_kat(&derived).verification_gate_met);

        let mut gcm = request(
            CryptoKatAlgorithm::AesGcm,
            "0388dace60b6a392f328c2b971b2fe78",
        );
        gcm.direction = Some(CryptoKatDirection::Encrypt);
        gcm.key_hex = Some("00".repeat(16));
        gcm.iv_hex = Some("00".repeat(12));
        gcm.input_hex = Some("00".repeat(16));
        gcm.observed_tag_hex = Some("ab6e47d42cec13bdf53a67b21257bddf".to_string());
        let report = verify_crypto_semantic_kat(&gcm);
        assert_eq!(report.status, CryptoKatStatus::VerifiedFull);
        assert_eq!(report.tag_matched, Some(true));
    }

    #[test]
    fn invalid_parameters_and_iteration_limits_never_open_gate() {
        let mut aes = request(CryptoKatAlgorithm::AesEcb, &"00".repeat(16));
        aes.direction = Some(CryptoKatDirection::Encrypt);
        aes.key_hex = Some("00".repeat(15));
        aes.input_hex = Some("00".repeat(16));
        let invalid = verify_crypto_semantic_kat(&aes);
        assert_eq!(invalid.status, CryptoKatStatus::Invalid);
        assert!(!invalid.verification_gate_met);

        let mut derived = request(CryptoKatAlgorithm::Pbkdf2HmacSha256, &"00".repeat(32));
        derived.password_hex = Some(String::new());
        derived.salt_hex = Some(String::new());
        derived.iterations = Some(MAX_CRYPTO_KAT_PBKDF2_ITERATIONS + 1);
        derived.derived_key_length = Some(32);
        assert_eq!(
            verify_crypto_semantic_kat(&derived).status,
            CryptoKatStatus::Invalid
        );
    }

    #[test]
    fn strict_report_parser_recomputes_and_rejects_forgery() {
        let mut sha = request(
            CryptoKatAlgorithm::Sha256,
            "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824",
        );
        sha.input_hex = Some("68656c6c6f".to_string());
        let report = verify_crypto_semantic_kat(&sha);
        let encoded = serde_json::to_vec(&report).unwrap();
        assert_eq!(parse_crypto_semantic_kat_report(&encoded).unwrap(), report);

        let mut forged: serde_json::Value = serde_json::from_slice(&encoded).unwrap();
        forged["request"]["observedOutputHex"] = serde_json::Value::String("00".repeat(32));
        let forged = serde_json::to_vec(&forged).unwrap();
        assert!(parse_crypto_semantic_kat_report(&forged).is_err());
    }
}
