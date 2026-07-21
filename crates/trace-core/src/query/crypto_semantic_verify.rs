//! Deterministic AES ECB/CBC/CTR semantic verification. Padding is deliberately separate.

use aes::cipher::{generic_array::GenericArray, BlockDecrypt, BlockEncrypt, KeyInit};
use aes::{Aes128, Aes192, Aes256};
use aes_gcm::aead::consts::U12;
use aes_gcm::aead::AeadInPlace;
use aes_gcm::{Aes128Gcm, Aes256Gcm, Nonce};
use serde::Serialize;

type Aes192Gcm = aes_gcm::AesGcm<Aes192, U12>;

#[derive(Clone, Copy, Debug, Serialize)]
pub enum AesDirection {
    Encrypt,
    Decrypt,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub enum SemanticVerificationStatus {
    NotVerified,
    Verified,
    VerifiedFull,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AesSemanticVerification {
    pub key_bits: u16,
    pub direction: AesDirection,
    pub mode: String,
    pub blocks_checked: usize,
    pub bytes_checked: usize,
    pub matched_blocks: usize,
    pub status: SemanticVerificationStatus,
    pub all_matched: bool,
    pub first_mismatch_block: Option<usize>,
    pub expected_hex: Option<String>,
    pub observed_hex: Option<String>,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AesGcmSemanticVerification {
    pub key_bits: u16,
    pub direction: AesDirection,
    pub mode: String,
    pub bytes_checked: usize,
    pub payload_matched: bool,
    pub tag_matched: bool,
    pub authenticated: bool,
    pub status: SemanticVerificationStatus,
    pub expected_payload_hex: Option<String>,
    pub observed_payload_hex: Option<String>,
    pub expected_tag_hex: String,
    pub observed_tag_hex: String,
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn transform_block(
    key: &[u8],
    direction: AesDirection,
    block: &mut GenericArray<u8, aes::cipher::consts::U16>,
) -> Result<(), String> {
    macro_rules! apply {
        ($ty:ty) => {{
            let cipher = <$ty>::new_from_slice(key).map_err(|_| "invalid AES key".to_string())?;
            match direction {
                AesDirection::Encrypt => cipher.encrypt_block(block),
                AesDirection::Decrypt => cipher.decrypt_block(block),
            }
        }};
    }
    match key.len() {
        16 => apply!(Aes128),
        24 => apply!(Aes192),
        32 => apply!(Aes256),
        n => return Err(format!("invalid AES key length: {n}")),
    }
    Ok(())
}

fn validate_aes_buffers(key: &[u8], input: &[u8], observed: &[u8]) -> Result<(), String> {
    if input.is_empty() {
        return Err("AES verification requires at least one block".into());
    }
    if input.len() % 16 != 0 {
        return Err(format!(
            "input length {} is not a multiple of 16",
            input.len()
        ));
    }
    if observed.len() != input.len() {
        return Err(format!(
            "input/output length mismatch: {} != {}",
            input.len(),
            observed.len()
        ));
    }
    if !matches!(key.len(), 16 | 24 | 32) {
        return Err(format!("invalid AES key length: {}", key.len()));
    }
    Ok(())
}

fn compare_expected(
    key: &[u8],
    direction: AesDirection,
    mode: &str,
    expected: &[u8],
    observed: &[u8],
) -> AesSemanticVerification {
    let mut matched_blocks = 0;
    let mut mismatch = None;
    for (index, (wanted, actual)) in expected.chunks(16).zip(observed.chunks(16)).enumerate() {
        if wanted == actual {
            matched_blocks += 1;
        } else if mismatch.is_none() {
            mismatch = Some((index, hex(wanted), hex(actual)));
        }
    }
    let status = if mismatch.is_none() {
        SemanticVerificationStatus::VerifiedFull
    } else if matched_blocks > 0 {
        SemanticVerificationStatus::Verified
    } else {
        SemanticVerificationStatus::NotVerified
    };
    AesSemanticVerification {
        key_bits: (key.len() * 8) as u16,
        direction,
        mode: mode.into(),
        blocks_checked: expected.len().div_ceil(16),
        bytes_checked: expected.len(),
        matched_blocks,
        status,
        all_matched: mismatch.is_none(),
        first_mismatch_block: mismatch.as_ref().map(|m| m.0),
        expected_hex: mismatch.as_ref().map(|m| m.1.clone()),
        observed_hex: mismatch.map(|m| m.2),
    }
}

pub fn verify_aes_ecb(
    key: &[u8],
    direction: AesDirection,
    input: &[u8],
    observed: &[u8],
) -> Result<AesSemanticVerification, String> {
    validate_aes_buffers(key, input, observed)?;
    let mut expected = Vec::with_capacity(input.len());
    for source in input.chunks_exact(16) {
        let mut block = GenericArray::clone_from_slice(source);
        transform_block(key, direction, &mut block)?;
        expected.extend_from_slice(block.as_slice());
    }
    Ok(compare_expected(key, direction, "ECB", &expected, observed))
}

pub fn verify_aes_cbc(
    key: &[u8],
    direction: AesDirection,
    iv: &[u8],
    input: &[u8],
    observed: &[u8],
) -> Result<AesSemanticVerification, String> {
    validate_aes_buffers(key, input, observed)?;
    if iv.len() != 16 {
        return Err(format!("AES-CBC IV length must be 16, got {}", iv.len()));
    }
    let mut expected = Vec::with_capacity(input.len());
    let mut previous = iv.to_vec();
    for source in input.chunks_exact(16) {
        let mut block = GenericArray::clone_from_slice(source);
        match direction {
            AesDirection::Encrypt => {
                for (byte, chain) in block.iter_mut().zip(&previous) {
                    *byte ^= *chain;
                }
                transform_block(key, AesDirection::Encrypt, &mut block)?;
                previous.copy_from_slice(block.as_slice());
                expected.extend_from_slice(block.as_slice());
            }
            AesDirection::Decrypt => {
                transform_block(key, AesDirection::Decrypt, &mut block)?;
                for (byte, chain) in block.iter_mut().zip(&previous) {
                    *byte ^= *chain;
                }
                expected.extend_from_slice(block.as_slice());
                previous.copy_from_slice(source);
            }
        }
    }
    Ok(compare_expected(key, direction, "CBC", &expected, observed))
}

pub fn verify_aes_ctr(
    key: &[u8],
    direction: AesDirection,
    initial_counter: &[u8],
    input: &[u8],
    observed: &[u8],
) -> Result<AesSemanticVerification, String> {
    if input.is_empty() {
        return Err("AES verification requires at least one byte".into());
    }
    if input.len() != observed.len() {
        return Err(format!(
            "input/output length mismatch: {} != {}",
            input.len(),
            observed.len()
        ));
    }
    if !matches!(key.len(), 16 | 24 | 32) {
        return Err(format!("invalid AES key length: {}", key.len()));
    }
    if initial_counter.len() != 16 {
        return Err(format!(
            "AES-CTR initial counter length must be 16, got {}",
            initial_counter.len()
        ));
    }
    let mut counter = <[u8; 16]>::try_from(initial_counter).unwrap();
    let mut expected = Vec::with_capacity(input.len());
    for source in input.chunks(16) {
        let mut stream = GenericArray::clone_from_slice(&counter);
        transform_block(key, AesDirection::Encrypt, &mut stream)?;
        expected.extend(
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
    Ok(compare_expected(key, direction, "CTR", &expected, observed))
}

pub fn verify_aes_gcm(
    key: &[u8],
    direction: AesDirection,
    nonce: &[u8],
    aad: &[u8],
    input: &[u8],
    observed: &[u8],
    observed_tag: &[u8],
) -> Result<AesGcmSemanticVerification, String> {
    if input.len() != observed.len() {
        return Err(format!(
            "input/output length mismatch: {} != {}",
            input.len(),
            observed.len()
        ));
    }
    if nonce.len() != 12 {
        return Err(format!(
            "AES-GCM nonce length must be 12, got {}",
            nonce.len()
        ));
    }
    if observed_tag.len() != 16 {
        return Err(format!(
            "AES-GCM authentication tag length must be 16, got {}",
            observed_tag.len()
        ));
    }

    // For decrypt verification, re-encrypt the observed plaintext. This proves the ciphertext
    // and authentication tag together without ever accepting unauthenticated plaintext.
    let plaintext = match direction {
        AesDirection::Encrypt => input,
        AesDirection::Decrypt => observed,
    };
    let expected_ciphertext = match direction {
        AesDirection::Encrypt => observed,
        AesDirection::Decrypt => input,
    };
    let mut generated = plaintext.to_vec();
    let nonce = Nonce::from_slice(nonce);
    let expected_tag = match key.len() {
        16 => Aes128Gcm::new_from_slice(key)
            .map_err(|_| "invalid AES-128-GCM key".to_string())?
            .encrypt_in_place_detached(nonce, aad, &mut generated)
            .map_err(|_| "AES-128-GCM verification failed".to_string())?,
        32 => Aes256Gcm::new_from_slice(key)
            .map_err(|_| "invalid AES-256-GCM key".to_string())?
            .encrypt_in_place_detached(nonce, aad, &mut generated)
            .map_err(|_| "AES-256-GCM verification failed".to_string())?,
        24 => Aes192Gcm::new_from_slice(key)
            .map_err(|_| "invalid AES-192-GCM key".to_string())?
            .encrypt_in_place_detached(nonce, aad, &mut generated)
            .map_err(|_| "AES-192-GCM verification failed".to_string())?,
        n => return Err(format!("invalid AES key length: {n}")),
    };
    let payload_matched = generated == expected_ciphertext;
    let tag_matched = expected_tag.as_slice() == observed_tag;
    let authenticated = payload_matched && tag_matched;
    Ok(AesGcmSemanticVerification {
        key_bits: (key.len() * 8) as u16,
        direction,
        mode: "GCM".into(),
        bytes_checked: input.len(),
        payload_matched,
        tag_matched,
        authenticated,
        status: if authenticated {
            SemanticVerificationStatus::VerifiedFull
        } else {
            SemanticVerificationStatus::NotVerified
        },
        expected_payload_hex: (!payload_matched).then(|| hex(&generated)),
        observed_payload_hex: (!payload_matched).then(|| hex(expected_ciphertext)),
        expected_tag_hex: hex(expected_tag.as_slice()),
        observed_tag_hex: hex(observed_tag),
    })
}

pub fn validate_pkcs7(data: &[u8], block_size: usize) -> Result<usize, String> {
    if block_size == 0 || block_size > 255 || data.is_empty() || data.len() % block_size != 0 {
        return Err("invalid PKCS#7 buffer or block size".into());
    }
    let padding = *data.last().unwrap() as usize;
    if padding == 0
        || padding > block_size
        || padding > data.len()
        || !data[data.len() - padding..]
            .iter()
            .all(|&b| b as usize == padding)
    {
        return Err("invalid PKCS#7 padding".into());
    }
    Ok(data.len() - padding)
}

#[cfg(test)]
mod tests {
    use super::*;
    fn bytes(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    #[test]
    fn nist_single_block_encrypt_decrypt_all_key_sizes() {
        let pt = bytes("00112233445566778899aabbccddeeff");
        for (key, ct) in [
            (
                "000102030405060708090a0b0c0d0e0f",
                "69c4e0d86a7b0430d8cdb78070b4c55a",
            ),
            (
                "000102030405060708090a0b0c0d0e0f1011121314151617",
                "dda97ca4864cdfe06eaf70a0ec0d7191",
            ),
            (
                "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
                "8ea2b7ca516745bfeafc49904b496089",
            ),
        ] {
            let encrypted =
                verify_aes_ecb(&bytes(key), AesDirection::Encrypt, &pt, &bytes(ct)).unwrap();
            assert_eq!(encrypted.status, SemanticVerificationStatus::VerifiedFull);
            assert!(encrypted.all_matched);
            assert!(
                verify_aes_ecb(&bytes(key), AesDirection::Decrypt, &bytes(ct), &pt)
                    .unwrap()
                    .all_matched
            );
        }
    }

    #[test]
    fn trace_sample_first_block_matches() {
        let input = b"{\"mobile\":\"17777";
        assert_eq!(input.len(), 16);
        let result = verify_aes_ecb(
            b"KcIufueoThQliBgs",
            AesDirection::Encrypt,
            input,
            &bytes("ae2af887f83430372469ccbf4b3d5916"),
        )
        .unwrap();
        assert!(result.all_matched);
    }

    #[test]
    fn nist_cbc_encrypt_decrypt_and_iv_validation() {
        let key = bytes("2b7e151628aed2a6abf7158809cf4f3c");
        let iv = bytes("000102030405060708090a0b0c0d0e0f");
        let plaintext = bytes(concat!(
            "6bc1bee22e409f96e93d7e117393172a",
            "ae2d8a571e03ac9c9eb76fac45af8e51",
            "30c81c46a35ce411e5fbc1191a0a52ef",
            "f69f2445df4f9b17ad2b417be66c3710"
        ));
        let ciphertext = bytes(concat!(
            "7649abac8119b246cee98e9b12e9197d",
            "5086cb9b507219ee95db113a917678b2",
            "73bed6b8e3c1743b7116e69e22229516",
            "3ff1caa1681fac09120eca307586e1a7"
        ));
        let encrypted =
            verify_aes_cbc(&key, AesDirection::Encrypt, &iv, &plaintext, &ciphertext).unwrap();
        assert!(encrypted.all_matched);
        assert_eq!(encrypted.mode, "CBC");
        assert_eq!(encrypted.blocks_checked, 4);
        assert!(
            verify_aes_cbc(&key, AesDirection::Decrypt, &iv, &ciphertext, &plaintext)
                .unwrap()
                .all_matched
        );
        assert!(verify_aes_cbc(
            &key,
            AesDirection::Encrypt,
            &[0; 15],
            &plaintext,
            &ciphertext
        )
        .is_err());
    }

    #[test]
    fn nist_ctr_encrypt_decrypt_and_counter_validation() {
        let key = bytes("2b7e151628aed2a6abf7158809cf4f3c");
        let counter = bytes("f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff");
        let plaintext = bytes(concat!(
            "6bc1bee22e409f96e93d7e117393172a",
            "ae2d8a571e03ac9c9eb76fac45af8e51",
            "30c81c46a35ce411e5fbc1191a0a52ef",
            "f69f2445df4f9b17ad2b417be66c3710"
        ));
        let ciphertext = bytes(concat!(
            "874d6191b620e3261bef6864990db6ce",
            "9806f66b7970fdff8617187bb9fffdff",
            "5ae4df3edbd5d35e5b4f09020db03eab",
            "1e031dda2fbe03d1792170a0f3009cee"
        ));
        let encrypted = verify_aes_ctr(
            &key,
            AesDirection::Encrypt,
            &counter,
            &plaintext,
            &ciphertext,
        )
        .unwrap();
        assert!(encrypted.all_matched);
        assert_eq!(encrypted.mode, "CTR");
        assert!(
            verify_aes_ctr(
                &key,
                AesDirection::Decrypt,
                &counter,
                &ciphertext,
                &plaintext
            )
            .unwrap()
            .all_matched
        );
        let partial = verify_aes_ctr(
            &key,
            AesDirection::Encrypt,
            &counter,
            &plaintext[..23],
            &ciphertext[..23],
        )
        .unwrap();
        assert!(partial.all_matched);
        assert_eq!(partial.bytes_checked, 23);
        assert_eq!(partial.blocks_checked, 2);
        assert!(verify_aes_ctr(
            &key,
            AesDirection::Encrypt,
            &[0; 15],
            &plaintext,
            &ciphertext
        )
        .is_err());
    }

    #[test]
    fn nist_gcm_requires_payload_and_authentication_tag() {
        let key = [0_u8; 16];
        let nonce = [0_u8; 12];
        let plaintext = [0_u8; 16];
        let ciphertext = bytes("0388dace60b6a392f328c2b971b2fe78");
        let tag = bytes("ab6e47d42cec13bdf53a67b21257bddf");
        let encrypted = verify_aes_gcm(
            &key,
            AesDirection::Encrypt,
            &nonce,
            &[],
            &plaintext,
            &ciphertext,
            &tag,
        )
        .unwrap();
        assert!(encrypted.authenticated);
        assert_eq!(encrypted.status, SemanticVerificationStatus::VerifiedFull);
        assert!(
            verify_aes_gcm(
                &key,
                AesDirection::Decrypt,
                &nonce,
                &[],
                &ciphertext,
                &plaintext,
                &tag,
            )
            .unwrap()
            .authenticated
        );

        let mut wrong_tag = tag.clone();
        wrong_tag[0] ^= 1;
        let rejected = verify_aes_gcm(
            &key,
            AesDirection::Encrypt,
            &nonce,
            &[],
            &plaintext,
            &ciphertext,
            &wrong_tag,
        )
        .unwrap();
        assert!(rejected.payload_matched);
        assert!(!rejected.tag_matched);
        assert!(!rejected.authenticated);
        assert_eq!(rejected.status, SemanticVerificationStatus::NotVerified);
    }

    #[test]
    fn mismatch_and_invalid_inputs_are_explicit() {
        let key = [0u8; 16];
        let input = [0u8; 32];
        let mut output = bytes("66e94bd4ef8a2c3b884cfa59ca342b2e66e94bd4ef8a2c3b884cfa59ca342b2e");
        output[17] ^= 1;
        let result = verify_aes_ecb(&key, AesDirection::Encrypt, &input, &output).unwrap();
        assert_eq!(result.matched_blocks, 1);
        assert_eq!(result.status, SemanticVerificationStatus::Verified);
        assert_eq!(result.first_mismatch_block, Some(1));
        assert!(!result.all_matched);
        assert!(verify_aes_ecb(&[0; 15], AesDirection::Encrypt, &[0; 16], &[0; 16]).is_err());
        assert!(verify_aes_ecb(&key, AesDirection::Encrypt, &[], &[]).is_err());
        assert!(verify_aes_ecb(&key, AesDirection::Encrypt, &[0; 15], &[0; 15]).is_err());
        assert!(verify_aes_ecb(&key, AesDirection::Encrypt, &[0; 16], &[0; 32]).is_err());
    }

    #[test]
    fn pkcs7_is_checked_separately() {
        assert_eq!(
            validate_pkcs7(b"ICE ICE BABY\x04\x04\x04\x04", 16).unwrap(),
            12
        );
        assert!(validate_pkcs7(b"ICE ICE BABY\x05\x05\x05\x05", 16).is_err());
        assert!(validate_pkcs7(&[], 16).is_err());
    }
}
