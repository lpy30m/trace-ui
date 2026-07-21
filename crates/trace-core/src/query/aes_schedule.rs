//! Standard FIPS-197 AES key expansion and comparison helpers.

use serde::Serialize;

const SBOX: [u8; 256] = [
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16,
];

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AesScheduleVerification {
    pub key_bits: u16,
    pub round_count: u8,
    pub expected_len: usize,
    pub observed_len: usize,
    pub all_matched: bool,
    pub first_mismatch_round: Option<u8>,
    pub first_mismatch_byte: Option<usize>,
}

fn rot_word(word: [u8; 4]) -> [u8; 4] {
    [word[1], word[2], word[3], word[0]]
}
fn sub_word(word: [u8; 4]) -> [u8; 4] {
    word.map(|b| SBOX[b as usize])
}

/// Expands an AES-128/192/256 raw key into the canonical byte-oriented schedule.
pub fn expand_aes_key(key: &[u8]) -> Result<Vec<u8>, String> {
    let (nk, nr) = match key.len() {
        16 => (4usize, 10usize),
        24 => (6, 12),
        32 => (8, 14),
        n => {
            return Err(format!(
                "invalid AES key length: {n}; expected 16, 24, or 32"
            ))
        }
    };
    let total_words = 4 * (nr + 1);
    let mut words = vec![[0u8; 4]; total_words];
    for (i, chunk) in key.chunks_exact(4).enumerate() {
        words[i].copy_from_slice(chunk);
    }
    let mut rcon = 1u8;
    for i in nk..total_words {
        let mut temp = words[i - 1];
        if i % nk == 0 {
            temp = sub_word(rot_word(temp));
            temp[0] ^= rcon;
            rcon = if rcon & 0x80 != 0 {
                (rcon << 1) ^ 0x1b
            } else {
                rcon << 1
            };
        } else if nk > 6 && i % nk == 4 {
            temp = sub_word(temp);
        }
        for j in 0..4 {
            words[i][j] = words[i - nk][j] ^ temp[j];
        }
    }
    Ok(words.into_iter().flatten().collect())
}

pub fn verify_aes_schedule(key: &[u8], observed: &[u8]) -> Result<AesScheduleVerification, String> {
    let expected = expand_aes_key(key)?;
    let first_mismatch_byte = expected
        .iter()
        .zip(observed)
        .position(|(a, b)| a != b)
        .or_else(|| {
            (expected.len() != observed.len()).then_some(expected.len().min(observed.len()))
        });
    Ok(AesScheduleVerification {
        key_bits: (key.len() * 8) as u16,
        round_count: match key.len() {
            16 => 10,
            24 => 12,
            32 => 14,
            _ => unreachable!(),
        },
        expected_len: expected.len(),
        observed_len: observed.len(),
        all_matched: first_mismatch_byte.is_none(),
        first_mismatch_round: first_mismatch_byte.map(|i| (i / 16) as u8),
        first_mismatch_byte,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    #[test]
    fn fips_197_aes128_schedule() {
        let schedule = expand_aes_key(&hex("000102030405060708090a0b0c0d0e0f")).unwrap();
        assert_eq!(schedule.len(), 176);
        assert_eq!(&schedule[16..32], &hex("d6aa74fdd2af72fadaa678f1d6ab76fe"));
        assert_eq!(
            &schedule[160..176],
            &hex("13111d7fe3944a17f307a78b4d2b30c5")
        );
    }

    #[test]
    fn fips_197_aes192_and_aes256_schedule() {
        let s192 =
            expand_aes_key(&hex("000102030405060708090a0b0c0d0e0f1011121314151617")).unwrap();
        assert_eq!(s192.len(), 208);
        assert_eq!(&s192[192..208], &hex("a4970a331a78dc09c418c271e3a41d5d"));
        let s256 = expand_aes_key(&hex(
            "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
        ))
        .unwrap();
        assert_eq!(s256.len(), 240);
        assert_eq!(&s256[224..240], &hex("24fc79ccbf0979e9371ac23c6d68de36"));
    }

    #[test]
    fn comparison_reports_wrong_truncated_and_extra_schedules() {
        let key = hex("000102030405060708090a0b0c0d0e0f");
        let expected = expand_aes_key(&key).unwrap();
        assert!(verify_aes_schedule(&key, &expected).unwrap().all_matched);
        let mut wrong = expected.clone();
        wrong[33] ^= 1;
        let result = verify_aes_schedule(&key, &wrong).unwrap();
        assert_eq!(result.first_mismatch_round, Some(2));
        assert_eq!(result.first_mismatch_byte, Some(33));
        assert!(
            !verify_aes_schedule(&key, &expected[..100])
                .unwrap()
                .all_matched
        );
        let mut extra = expected;
        extra.push(0);
        assert!(!verify_aes_schedule(&key, &extra).unwrap().all_matched);
        assert!(expand_aes_key(&[0; 15]).is_err());
    }
}
