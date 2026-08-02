use aes::cipher::{generic_array::GenericArray, BlockDecrypt, BlockEncrypt, KeyInit};
use aes::Aes128;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};

pub const AES_SBOX: [u8; 256] = [
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

pub const AES_INV_SBOX: [u8; 256] = [
    0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
    0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
    0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
    0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
    0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
    0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
    0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
    0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
    0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
    0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
    0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
    0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
    0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
    0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
    0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
    0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d,
];

const AES128_SCHEDULE_BYTES: usize = 176;
const AES128_SCHEDULE_WORDS: u32 = 44;
const SBOX_MIN_MATCHING_READS: u32 = 32;
const SBOX_MIN_DISTINCT_INDICES: u32 = 16;
const SBOX_MIN_MATCH_RATIO: f64 = 0.95;
const MAX_SBOX_FINGERPRINTS: usize = 8;
const MAX_SCHEDULES: usize = 16;
const MAX_SEMANTIC_BLOCKS: usize = 4096;

#[derive(Clone, Copy, Debug)]
pub struct MemAccess {
    pub seq: u32,
    pub insn_addr: u64,
    pub addr: u64,
    pub value: u64,
    pub size: u8,
}

#[derive(Clone, Copy, Debug)]
pub struct AesCallScope {
    pub call_instance_id: u32,
    pub entry_seq: u32,
    pub exit_seq: u32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum AesDirection {
    Encrypt,
    Decrypt,
}

impl AesDirection {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Encrypt => "Encrypt",
            Self::Decrypt => "Decrypt",
        }
    }
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AesSboxFingerprint {
    pub base_addr: String,
    pub direction_candidate: AesDirection,
    pub matching_reads: u32,
    pub total_reads_in_region: u32,
    pub distinct_indices: u32,
    pub match_ratio: f64,
    pub first_seq: u32,
    pub last_seq: u32,
    pub first_line_number_1_based: u32,
    pub last_line_number_1_based: u32,
    pub instruction_sites: Vec<String>,
}

#[derive(Clone, Copy, Debug)]
pub struct AesSboxMatch {
    pub seq: u32,
    pub insn_addr: u64,
    pub table_base: u64,
    pub index: u8,
    pub direction: AesDirection,
}

#[derive(Clone, Debug, Default)]
pub struct AesSboxScan {
    pub fingerprints: Vec<AesSboxFingerprint>,
    pub matches: Vec<AesSboxMatch>,
}

#[derive(Default)]
struct SboxCandidate {
    matching_reads: u32,
    indices: BTreeSet<u8>,
    first_seq: u32,
    last_seq: u32,
    instruction_sites: BTreeSet<u64>,
}

fn inverse_permutation(table: &[u8; 256]) -> [u8; 256] {
    let mut inverse = [0u8; 256];
    for (index, &value) in table.iter().enumerate() {
        inverse[value as usize] = index as u8;
    }
    inverse
}

fn table_for_direction(direction: AesDirection) -> &'static [u8; 256] {
    match direction {
        AesDirection::Encrypt => &AES_SBOX,
        AesDirection::Decrypt => &AES_INV_SBOX,
    }
}

pub fn detect_dynamic_aes_sboxes(reads: &[MemAccess]) -> AesSboxScan {
    let forward_inverse = inverse_permutation(&AES_SBOX);
    let reverse_inverse = inverse_permutation(&AES_INV_SBOX);
    let mut candidates: BTreeMap<(AesDirection, u64), SboxCandidate> = BTreeMap::new();

    for access in reads.iter().filter(|access| access.size == 1) {
        let value = access.value as u8;
        for (direction, inverse) in [
            (AesDirection::Encrypt, &forward_inverse),
            (AesDirection::Decrypt, &reverse_inverse),
        ] {
            let index = inverse[value as usize];
            let Some(base) = access.addr.checked_sub(index as u64) else {
                continue;
            };
            let candidate = candidates.entry((direction, base)).or_default();
            candidate.matching_reads = candidate.matching_reads.saturating_add(1);
            candidate.indices.insert(index);
            if candidate.matching_reads == 1 {
                candidate.first_seq = access.seq;
                candidate.last_seq = access.seq;
            } else {
                candidate.first_seq = candidate.first_seq.min(access.seq);
                candidate.last_seq = candidate.last_seq.max(access.seq);
            }
            candidate.instruction_sites.insert(access.insn_addr);
        }
    }

    let mut accepted: Vec<(AesDirection, u64, AesSboxFingerprint)> = candidates
        .into_iter()
        .filter_map(|((direction, base), candidate)| {
            if candidate.matching_reads < SBOX_MIN_MATCHING_READS
                || candidate.indices.len() < SBOX_MIN_DISTINCT_INDICES as usize
            {
                return None;
            }
            let table = table_for_direction(direction);
            let mut total_reads = 0u32;
            let mut exact_reads = 0u32;
            for access in reads.iter().filter(|access| {
                access.size == 1 && access.addr >= base && access.addr < base.saturating_add(256)
            }) {
                total_reads = total_reads.saturating_add(1);
                let index = (access.addr - base) as usize;
                if access.value as u8 == table[index] {
                    exact_reads = exact_reads.saturating_add(1);
                }
            }
            let ratio = if total_reads == 0 {
                0.0
            } else {
                exact_reads as f64 / total_reads as f64
            };
            if exact_reads < SBOX_MIN_MATCHING_READS || ratio < SBOX_MIN_MATCH_RATIO {
                return None;
            }
            let instruction_sites = candidate
                .instruction_sites
                .iter()
                .take(32)
                .map(|address| format!("0x{address:x}"))
                .collect();
            Some((
                direction,
                base,
                AesSboxFingerprint {
                    base_addr: format!("0x{base:x}"),
                    direction_candidate: direction,
                    matching_reads: exact_reads,
                    total_reads_in_region: total_reads,
                    distinct_indices: candidate.indices.len() as u32,
                    match_ratio: ratio,
                    first_seq: candidate.first_seq,
                    last_seq: candidate.last_seq,
                    first_line_number_1_based: candidate.first_seq.saturating_add(1),
                    last_line_number_1_based: candidate.last_seq.saturating_add(1),
                    instruction_sites,
                },
            ))
        })
        .collect();

    accepted.sort_by(|a, b| {
        b.2.matching_reads
            .cmp(&a.2.matching_reads)
            .then(b.2.distinct_indices.cmp(&a.2.distinct_indices))
            .then(a.1.cmp(&b.1))
    });
    accepted.truncate(MAX_SBOX_FINGERPRINTS);

    let accepted_keys: HashSet<(AesDirection, u64)> = accepted
        .iter()
        .map(|(direction, base, _)| (*direction, *base))
        .collect();
    let mut matches = Vec::new();
    for access in reads.iter().filter(|access| access.size == 1) {
        for &(direction, base) in &accepted_keys {
            if access.addr < base || access.addr >= base.saturating_add(256) {
                continue;
            }
            let index = (access.addr - base) as usize;
            if access.value as u8 == table_for_direction(direction)[index] {
                matches.push(AesSboxMatch {
                    seq: access.seq,
                    insn_addr: access.insn_addr,
                    table_base: base,
                    index: index as u8,
                    direction,
                });
            }
        }
    }
    matches.sort_by_key(|hit| hit.seq);

    AesSboxScan {
        fingerprints: accepted.into_iter().map(|(_, _, report)| report).collect(),
        matches,
    }
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AesScheduleVerification {
    pub words_checked: u32,
    pub words_matched: u32,
    pub first_mismatch_word: Option<u32>,
    pub key_bits: u32,
    pub schedule_bytes: u32,
    pub standard_key_schedule: bool,
    pub partial_schedule: bool,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AesKeyScheduleEvidence {
    pub schedule_address: String,
    pub raw_key_hex: String,
    pub start_seq: u32,
    pub end_seq: u32,
    pub start_line_number_1_based: u32,
    pub end_line_number_1_based: u32,
    pub instruction_sites: Vec<String>,
    pub verification: AesScheduleVerification,
    #[serde(skip)]
    pub raw_key: [u8; 16],
}

pub fn expand_aes128_key(raw_key: &[u8; 16]) -> [u8; AES128_SCHEDULE_BYTES] {
    const RCON: [u8; 10] = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36];
    let mut expanded = [0u8; AES128_SCHEDULE_BYTES];
    expanded[..16].copy_from_slice(raw_key);
    let mut generated = 16usize;
    let mut rcon_index = 0usize;

    while generated < AES128_SCHEDULE_BYTES {
        let mut temp = [
            expanded[generated - 4],
            expanded[generated - 3],
            expanded[generated - 2],
            expanded[generated - 1],
        ];
        if generated % 16 == 0 {
            temp.rotate_left(1);
            for value in &mut temp {
                *value = AES_SBOX[*value as usize];
            }
            temp[0] ^= RCON[rcon_index];
            rcon_index += 1;
        }
        for value in temp {
            expanded[generated] = expanded[generated - 16] ^ value;
            generated += 1;
        }
    }
    expanded
}

pub fn verify_aes128_schedule(raw_key: &[u8; 16], expanded: &[u8]) -> AesScheduleVerification {
    let expected = expand_aes128_key(raw_key);
    let words_checked = (expanded.len().min(AES128_SCHEDULE_BYTES) / 4) as u32;
    let mut words_matched = 0u32;
    let mut first_mismatch_word = None;
    for word in 0..words_checked as usize {
        let start = word * 4;
        if expanded[start..start + 4] == expected[start..start + 4] {
            words_matched += 1;
        } else if first_mismatch_word.is_none() {
            first_mismatch_word = Some(word as u32);
        }
    }
    let complete = expanded.len() >= AES128_SCHEDULE_BYTES;
    AesScheduleVerification {
        words_checked,
        words_matched,
        first_mismatch_word,
        key_bits: 128,
        schedule_bytes: expanded.len().min(AES128_SCHEDULE_BYTES) as u32,
        standard_key_schedule: complete
            && words_checked == AES128_SCHEDULE_WORDS
            && words_matched == AES128_SCHEDULE_WORDS,
        partial_schedule: !complete,
    }
}

#[derive(Clone, Copy)]
struct SnapshotByte {
    value: u8,
    seq: u32,
    insn_addr: u64,
}

fn snapshot_bytes(
    accesses: &[MemAccess],
    latest: bool,
    byte_only: bool,
) -> BTreeMap<u64, SnapshotByte> {
    let mut bytes: BTreeMap<u64, SnapshotByte> = BTreeMap::new();
    for access in accesses {
        if byte_only && access.size != 1 {
            continue;
        }
        let width = access.size.clamp(1, 8) as usize;
        for offset in 0..width {
            let address = access.addr.saturating_add(offset as u64);
            let value = ((access.value >> (offset * 8)) & 0xff) as u8;
            let replace = match bytes.get(&address) {
                None => true,
                Some(existing) => {
                    if latest {
                        access.seq >= existing.seq
                    } else {
                        access.seq < existing.seq
                    }
                }
            };
            if replace {
                bytes.insert(
                    address,
                    SnapshotByte {
                        value,
                        seq: access.seq,
                        insn_addr: access.insn_addr,
                    },
                );
            }
        }
    }
    bytes
}

fn contiguous_runs(bytes: &BTreeMap<u64, SnapshotByte>) -> Vec<(u64, Vec<SnapshotByte>)> {
    let mut runs = Vec::new();
    let mut current_start = 0u64;
    let mut current = Vec::new();
    let mut previous = None;
    for (&address, &byte) in bytes {
        if previous.map_or(true, |last| address != last + 1) {
            if !current.is_empty() {
                runs.push((current_start, std::mem::take(&mut current)));
            }
            current_start = address;
        }
        current.push(byte);
        previous = Some(address);
    }
    if !current.is_empty() {
        runs.push((current_start, current));
    }
    runs
}

pub fn find_aes128_schedules(writes: &[MemAccess]) -> Vec<AesKeyScheduleEvidence> {
    let snapshot = snapshot_bytes(writes, true, false);
    let mut evidence = Vec::new();
    for (run_start, run) in contiguous_runs(&snapshot) {
        if run.len() < AES128_SCHEDULE_BYTES {
            continue;
        }
        for offset in 0..=run.len() - AES128_SCHEDULE_BYTES {
            let bytes: Vec<u8> = run[offset..offset + AES128_SCHEDULE_BYTES]
                .iter()
                .map(|byte| byte.value)
                .collect();
            let mut raw_key = [0u8; 16];
            raw_key.copy_from_slice(&bytes[..16]);
            let verification = verify_aes128_schedule(&raw_key, &bytes);
            if !verification.standard_key_schedule {
                continue;
            }
            let window = &run[offset..offset + AES128_SCHEDULE_BYTES];
            let start_seq = window.iter().map(|byte| byte.seq).min().unwrap_or(0);
            let end_seq = window.iter().map(|byte| byte.seq).max().unwrap_or(0);
            let instruction_sites: Vec<String> = window
                .iter()
                .map(|byte| byte.insn_addr)
                .collect::<BTreeSet<_>>()
                .into_iter()
                .take(32)
                .map(|address| format!("0x{address:x}"))
                .collect();
            let address = run_start + offset as u64;
            evidence.push(AesKeyScheduleEvidence {
                schedule_address: format!("0x{address:x}"),
                raw_key_hex: hex_bytes(&raw_key),
                start_seq,
                end_seq,
                start_line_number_1_based: start_seq.saturating_add(1),
                end_line_number_1_based: end_seq.saturating_add(1),
                instruction_sites,
                verification,
                raw_key,
            });
            if evidence.len() >= MAX_SCHEDULES {
                break;
            }
        }
        if evidence.len() >= MAX_SCHEDULES {
            break;
        }
    }
    evidence.sort_by_key(|item| item.start_seq);
    evidence
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AesSemanticVerification {
    pub status: String,
    pub algorithm: String,
    pub key_bits: u32,
    pub mode: String,
    pub direction: AesDirection,
    pub padding: Option<String>,
    pub blocks_checked: u32,
    pub matched_blocks: u32,
    pub all_matched: bool,
    pub full_call_coverage: bool,
    pub key_schedule_address: String,
    pub key_hex: String,
    pub input_address: String,
    pub output_address: String,
    pub byte_len: u32,
    pub input_hex: String,
    pub output_hex: String,
    pub first_input_seq: u32,
    pub last_input_seq: u32,
    pub first_output_seq: u32,
    pub last_output_seq: u32,
}

#[derive(Clone)]
struct BlockLocation {
    address: u64,
    run_start: u64,
    run_end: u64,
    last_seq: u32,
}

fn block_at(bytes: &BTreeMap<u64, SnapshotByte>, address: u64) -> Option<([u8; 16], u32, u32)> {
    let mut block = [0u8; 16];
    let mut first_seq = u32::MAX;
    let mut last_seq = 0u32;
    for (offset, slot) in block.iter_mut().enumerate() {
        let byte = bytes.get(&address.checked_add(offset as u64)?)?;
        *slot = byte.value;
        first_seq = first_seq.min(byte.seq);
        last_seq = last_seq.max(byte.seq);
    }
    Some((block, first_seq, last_seq))
}

fn aes128_transform(key: &[u8; 16], input: &[u8; 16], direction: AesDirection) -> [u8; 16] {
    let cipher = Aes128::new(GenericArray::from_slice(key));
    let mut block = GenericArray::clone_from_slice(input);
    match direction {
        AesDirection::Encrypt => cipher.encrypt_block(&mut block),
        AesDirection::Decrypt => cipher.decrypt_block(&mut block),
    }
    let mut output = [0u8; 16];
    output.copy_from_slice(&block);
    output
}

fn collect_range(
    bytes: &BTreeMap<u64, SnapshotByte>,
    address: u64,
    length: usize,
) -> Option<Vec<u8>> {
    (0..length)
        .map(|offset| bytes.get(&(address + offset as u64)).map(|byte| byte.value))
        .collect()
}

fn pkcs7_padding(bytes: &[u8]) -> Option<String> {
    let padding = *bytes.last()? as usize;
    if (1..=16).contains(&padding)
        && padding <= bytes.len()
        && bytes[bytes.len() - padding..]
            .iter()
            .all(|&byte| byte as usize == padding)
    {
        Some("PKCS7".to_string())
    } else {
        None
    }
}

pub fn verify_observed_aes128_ecb(
    reads: &[MemAccess],
    writes: &[MemAccess],
    schedules: &[AesKeyScheduleEvidence],
) -> Option<AesSemanticVerification> {
    verify_observed_aes128_ecb_in_scopes(reads, writes, schedules, &[])
}

pub fn verify_observed_aes128_ecb_in_scopes(
    reads: &[MemAccess],
    writes: &[MemAccess],
    schedules: &[AesKeyScheduleEvidence],
    call_scopes: &[AesCallScope],
) -> Option<AesSemanticVerification> {
    if schedules.is_empty() {
        return None;
    }
    let input_bytes = snapshot_bytes(reads, false, true);
    let output_bytes = snapshot_bytes(writes, true, false);
    let input_runs = contiguous_runs(&input_bytes);
    let output_runs = contiguous_runs(&output_bytes);

    let mut output_blocks: HashMap<[u8; 16], Vec<BlockLocation>> = HashMap::new();
    let mut output_window_count = 0usize;
    for (run_start, run) in &output_runs {
        if run.len() < 16 {
            continue;
        }
        let run_end = run_start + run.len() as u64;
        for offset in 0..=run.len() - 16 {
            if output_window_count >= MAX_SEMANTIC_BLOCKS * 64 {
                break;
            }
            let address = run_start + offset as u64;
            let mut block = [0u8; 16];
            for (index, byte) in run[offset..offset + 16].iter().enumerate() {
                block[index] = byte.value;
            }
            let last_seq = run[offset..offset + 16]
                .iter()
                .map(|byte| byte.seq)
                .max()
                .unwrap_or(0);
            output_blocks.entry(block).or_default().push(BlockLocation {
                address,
                run_start: *run_start,
                run_end,
                last_seq,
            });
            output_window_count += 1;
        }
    }

    let mut seen = HashSet::new();
    let mut candidates = Vec::new();
    for schedule in schedules {
        for direction in [AesDirection::Encrypt, AesDirection::Decrypt] {
            for (input_run_start, run) in &input_runs {
                if run.len() < 16 {
                    continue;
                }
                let input_run_end = input_run_start + run.len() as u64;
                for input_offset in 0..=run.len() - 16 {
                    let input_address = input_run_start + input_offset as u64;
                    let mut input_block = [0u8; 16];
                    for (index, byte) in run[input_offset..input_offset + 16].iter().enumerate() {
                        input_block[index] = byte.value;
                    }
                    let transformed = aes128_transform(&schedule.raw_key, &input_block, direction);
                    let Some(locations) = output_blocks.get(&transformed) else {
                        continue;
                    };
                    let input_last_seq = run[input_offset..input_offset + 16]
                        .iter()
                        .map(|byte| byte.seq)
                        .max()
                        .unwrap_or(0);
                    for output in locations {
                        if input_last_seq > output.last_seq {
                            continue;
                        }
                        let mut start_input = input_address;
                        let mut start_output = output.address;
                        while start_input >= input_run_start.saturating_add(16)
                            && start_output >= output.run_start.saturating_add(16)
                        {
                            let previous_input = start_input - 16;
                            let previous_output = start_output - 16;
                            let Some((plain, _, plain_last)) =
                                block_at(&input_bytes, previous_input)
                            else {
                                break;
                            };
                            let Some((cipher, _, cipher_last)) =
                                block_at(&output_bytes, previous_output)
                            else {
                                break;
                            };
                            if plain_last > cipher_last
                                || aes128_transform(&schedule.raw_key, &plain, direction) != cipher
                            {
                                break;
                            }
                            start_input = previous_input;
                            start_output = previous_output;
                        }

                        let mut block_count = 0usize;
                        while block_count < MAX_SEMANTIC_BLOCKS {
                            let current_input = start_input + (block_count * 16) as u64;
                            let current_output = start_output + (block_count * 16) as u64;
                            let Some((plain, _, plain_last)) =
                                block_at(&input_bytes, current_input)
                            else {
                                break;
                            };
                            let Some((cipher, _, cipher_last)) =
                                block_at(&output_bytes, current_output)
                            else {
                                break;
                            };
                            if plain_last > cipher_last
                                || aes128_transform(&schedule.raw_key, &plain, direction) != cipher
                            {
                                break;
                            }
                            block_count += 1;
                        }
                        if block_count == 0
                            || !seen.insert((
                                schedule.schedule_address.clone(),
                                direction,
                                start_input,
                                start_output,
                                block_count,
                            ))
                        {
                            continue;
                        }

                        let byte_len = block_count * 16;
                        let Some(input) = collect_range(&input_bytes, start_input, byte_len) else {
                            continue;
                        };
                        let Some(output_values) =
                            collect_range(&output_bytes, start_output, byte_len)
                        else {
                            continue;
                        };
                        let (_, first_input_seq, _) = block_at(&input_bytes, start_input).unwrap();
                        let (_, _, last_input_seq) =
                            block_at(&input_bytes, start_input + byte_len as u64 - 16).unwrap();
                        let (_, first_output_seq, _) =
                            block_at(&output_bytes, start_output).unwrap();
                        let (_, _, last_output_seq) =
                            block_at(&output_bytes, start_output + byte_len as u64 - 16).unwrap();
                        let evidence_start_seq = schedule
                            .start_seq
                            .min(first_input_seq)
                            .min(first_output_seq);
                        let evidence_end_seq =
                            schedule.end_seq.max(last_input_seq).max(last_output_seq);
                        let call_instance_covered = call_scopes.is_empty()
                            || call_scopes
                                .iter()
                                .filter(|scope| scope.call_instance_id != 0)
                                .filter(|scope| {
                                    scope.entry_seq <= evidence_start_seq
                                        && scope.exit_seq >= evidence_end_seq
                                })
                                .min_by_key(|scope| scope.exit_seq.saturating_sub(scope.entry_seq))
                                .is_some();
                        let full_call_coverage = call_instance_covered
                            && start_input == *input_run_start
                            && start_output == output.run_start
                            && start_input + byte_len as u64 == input_run_end
                            && start_output + byte_len as u64 == output.run_end;
                        let status = if full_call_coverage {
                            "VerifiedFull"
                        } else if block_count > 1 {
                            "VerifiedPartial"
                        } else {
                            "VerifiedBlock"
                        };
                        candidates.push(AesSemanticVerification {
                            status: status.to_string(),
                            algorithm: "AES".to_string(),
                            key_bits: 128,
                            mode: "ECB".to_string(),
                            direction,
                            padding: pkcs7_padding(&input),
                            blocks_checked: block_count as u32,
                            matched_blocks: block_count as u32,
                            all_matched: true,
                            full_call_coverage,
                            key_schedule_address: schedule.schedule_address.clone(),
                            key_hex: schedule.raw_key_hex.clone(),
                            input_address: format!("0x{start_input:x}"),
                            output_address: format!("0x{start_output:x}"),
                            byte_len: byte_len as u32,
                            input_hex: hex_bytes(&input),
                            output_hex: hex_bytes(&output_values),
                            first_input_seq,
                            last_input_seq,
                            first_output_seq,
                            last_output_seq,
                        });
                    }
                }
            }
        }
    }

    candidates.sort_by(|a, b| {
        b.full_call_coverage
            .cmp(&a.full_call_coverage)
            .then(b.matched_blocks.cmp(&a.matched_blocks))
            .then(a.first_input_seq.cmp(&b.first_input_seq))
    });
    candidates.into_iter().next()
}

pub fn hex_bytes(bytes: &[u8]) -> String {
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        use std::fmt::Write;
        let _ = write!(&mut output, "{byte:02x}");
    }
    output
}

#[cfg(test)]
mod tests {
    use super::*;

    fn access(seq: u32, address: u64, value: u8) -> MemAccess {
        MemAccess {
            seq,
            insn_addr: 0x7100_1000,
            addr: address,
            value: value as u64,
            size: 1,
        }
    }

    #[test]
    fn dynamic_forward_sbox_is_identified_by_address_value_relation() {
        let base = 0x7100_8000;
        let reads: Vec<_> = (0..64u32)
            .map(|index| access(index, base + index as u64, AES_SBOX[index as usize]))
            .collect();
        let report = detect_dynamic_aes_sboxes(&reads);
        assert_eq!(report.fingerprints.len(), 1);
        let fingerprint = &report.fingerprints[0];
        assert_eq!(fingerprint.base_addr, "0x71008000");
        assert_eq!(fingerprint.direction_candidate, AesDirection::Encrypt);
        assert_eq!(fingerprint.matching_reads, 64);
        assert_eq!(fingerprint.distinct_indices, 64);
        assert_eq!(fingerprint.match_ratio, 1.0);
    }

    #[test]
    fn isolated_hits_and_unread_static_tables_are_not_sbox_evidence() {
        let base = 0x7100_8000;
        let too_few: Vec<_> = (0..15u32)
            .map(|index| access(index, base + index as u64, AES_SBOX[index as usize]))
            .collect();
        assert!(detect_dynamic_aes_sboxes(&too_few).fingerprints.is_empty());
        assert!(detect_dynamic_aes_sboxes(&[]).fingerprints.is_empty());
    }

    #[test]
    fn random_table_does_not_match_aes_sbox() {
        let base = 0x7100_8000;
        let reads: Vec<_> = (0..256u32)
            .map(|index| access(index, base + index as u64, index.wrapping_mul(17) as u8))
            .collect();
        assert!(detect_dynamic_aes_sboxes(&reads).fingerprints.is_empty());
    }

    #[test]
    fn fips197_aes128_schedule_is_verified_word_for_word() {
        let key = [
            0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf,
            0x4f, 0x3c,
        ];
        let expanded = expand_aes128_key(&key);
        assert_eq!(
            hex_bytes(&expanded[160..176]),
            "d014f9a8c9ee2589e13f0cc8b6630ca6"
        );
        let verification = verify_aes128_schedule(&key, &expanded);
        assert!(verification.standard_key_schedule);
        assert_eq!(verification.words_checked, 44);
        assert_eq!(verification.words_matched, 44);
        assert_eq!(verification.first_mismatch_word, None);
    }

    #[test]
    fn one_modified_schedule_word_fails_verification() {
        let key = [0x11; 16];
        let mut expanded = expand_aes128_key(&key);
        expanded[100] ^= 0x80;
        let verification = verify_aes128_schedule(&key, &expanded);
        assert!(!verification.standard_key_schedule);
        assert_eq!(verification.first_mismatch_word, Some(25));
    }

    #[test]
    fn observed_fips_block_opens_semantic_gate_only_on_exact_output() {
        let key = [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
            0x0e, 0x0f,
        ];
        let input = [
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd,
            0xee, 0xff,
        ];
        let output = [
            0x69, 0xc4, 0xe0, 0xd8, 0x6a, 0x7b, 0x04, 0x30, 0xd8, 0xcd, 0xb7, 0x80, 0x70, 0xb4,
            0xc5, 0x5a,
        ];
        let schedule = expand_aes128_key(&key);
        let mut writes = Vec::new();
        for (index, &value) in schedule.iter().enumerate() {
            writes.push(access(index as u32, 0x7100_2000 + index as u64, value));
        }
        for (index, &value) in output.iter().enumerate() {
            writes.push(access(
                300 + index as u32,
                0x7300_2000 + index as u64,
                value,
            ));
        }
        let reads: Vec<_> = input
            .iter()
            .enumerate()
            .map(|(index, &value)| access(200 + index as u32, 0x7300_1000 + index as u64, value))
            .collect();
        let schedules = find_aes128_schedules(&writes);
        assert_eq!(schedules.len(), 1);
        let verification = verify_observed_aes128_ecb(&reads, &writes, &schedules).unwrap();
        assert_eq!(verification.status, "VerifiedFull");
        assert_eq!(verification.direction, AesDirection::Encrypt);
        assert_eq!(verification.matched_blocks, 1);

        let last = writes.last_mut().unwrap();
        last.value ^= 1;
        assert!(verify_observed_aes128_ecb(&reads, &writes, &schedules).is_none());
    }

    #[test]
    fn exact_bytes_split_across_call_instances_are_not_verified_full() {
        let key = [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
            0x0e, 0x0f,
        ];
        let input = [
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd,
            0xee, 0xff,
        ];
        let output = aes128_transform(&key, &input, AesDirection::Encrypt);
        let schedule = expand_aes128_key(&key);
        let mut writes = Vec::new();
        for (index, &value) in schedule.iter().enumerate() {
            writes.push(access(index as u32, 0x7100_2000 + index as u64, value));
        }
        for (index, &value) in output.iter().enumerate() {
            writes.push(access(
                300 + index as u32,
                0x7300_2000 + index as u64,
                value,
            ));
        }
        let reads: Vec<_> = input
            .iter()
            .enumerate()
            .map(|(index, &value)| access(200 + index as u32, 0x7300_1000 + index as u64, value))
            .collect();
        let schedules = find_aes128_schedules(&writes);
        let scopes = [
            AesCallScope {
                call_instance_id: 0,
                entry_seq: 0,
                exit_seq: u32::MAX,
            },
            AesCallScope {
                call_instance_id: 1,
                entry_seq: 0,
                exit_seq: 250,
            },
            AesCallScope {
                call_instance_id: 2,
                entry_seq: 251,
                exit_seq: 400,
            },
        ];
        let verification =
            verify_observed_aes128_ecb_in_scopes(&reads, &writes, &schedules, &scopes).unwrap();
        assert_eq!(verification.status, "VerifiedBlock");
        assert!(!verification.full_call_coverage);
    }

    #[test]
    fn mismatching_final_block_cannot_be_reported_as_verified_full() {
        let key = [0x2a; 16];
        let schedule = expand_aes128_key(&key);
        let mut input = [0u8; 48];
        for (index, value) in input[..32].iter_mut().enumerate() {
            *value = index as u8;
        }
        input[32..].fill(16);

        let mut output = Vec::with_capacity(input.len());
        for block in input.chunks_exact(16) {
            let mut plain = [0u8; 16];
            plain.copy_from_slice(block);
            output.extend_from_slice(&aes128_transform(&key, &plain, AesDirection::Encrypt));
        }
        output[47] ^= 1;

        let mut writes = Vec::new();
        for (index, &value) in schedule.iter().enumerate() {
            writes.push(access(index as u32, 0x7100_2000 + index as u64, value));
        }
        for (index, &value) in output.iter().enumerate() {
            writes.push(access(
                400 + index as u32,
                0x7300_2000 + index as u64,
                value,
            ));
        }
        let reads: Vec<_> = input
            .iter()
            .enumerate()
            .map(|(index, &value)| access(300 + index as u32, 0x7300_1000 + index as u64, value))
            .collect();

        let schedules = find_aes128_schedules(&writes);
        let verification = verify_observed_aes128_ecb(&reads, &writes, &schedules).unwrap();
        assert_eq!(verification.status, "VerifiedPartial");
        assert_eq!(verification.matched_blocks, 2);
        assert_eq!(verification.blocks_checked, 2);
        assert_eq!(verification.byte_len, 32);
        assert!(!verification.full_call_coverage);
    }
}
