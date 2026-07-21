//! Data-driven software AES role detection from observed annotation buffers and memory writes.

use serde::Serialize;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet, HashMap};
use trace_parser::gumtrace::CallAnnotation;

use super::aes_schedule::expand_aes_key;
use super::crypto_semantic_verify::{
    verify_aes_cbc, verify_aes_ctr, verify_aes_ecb, verify_aes_gcm, AesDirection,
    SemanticVerificationStatus,
};
use super::whitebox_aes::MemAccess;

#[derive(Clone, Debug)]
pub struct ObservedBuffer {
    pub seq: u32,
    pub bytes: Vec<u8>,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SoftwareCryptoReport {
    pub algorithm: String,
    pub direction: String,
    pub mode: String,
    pub padding: String,
    pub key_hex: String,
    pub key_ascii: String,
    pub key_observation_seq: u32,
    pub input_observation_seq: u32,
    pub input_hex: String,
    pub output_hex: String,
    pub iv_hex: Option<String>,
    pub iv_observation_seq: Option<u32>,
    pub auth_tag_hex: Option<String>,
    pub auth_tag_observation_seq: Option<u32>,
    pub aad_hex: Option<String>,
    pub aad_observation_seq: Option<u32>,
    pub input_length: usize,
    pub padded_length: usize,
    pub block_count: usize,
    pub output_base_addr: String,
    pub output_store_insn: String,
    pub output_first_seq: u32,
    pub output_last_seq: u32,
    pub output_stride: usize,
    pub first_cipher_block: String,
    pub last_cipher_block: String,
    pub schedule_verified: bool,
    pub state_layout: String,
    pub state_layout_evidence: String,
    pub implementation_kind: String,
    pub key_exposure: String,
    pub whitebox_status: String,
    pub verification: String,
    pub ciphertext_sha256: String,
    pub reproducer: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum AesStateLayout {
    CanonicalBytes,
    Transpose4x4,
    ReverseBytesInWords,
    Transpose4x4ThenReverseWords,
}

impl AesStateLayout {
    const INFERENCE_CANDIDATES: [Self; 3] = [
        Self::Transpose4x4,
        Self::ReverseBytesInWords,
        Self::Transpose4x4ThenReverseWords,
    ];

    fn label(self) -> &'static str {
        match self {
            Self::CanonicalBytes => "CanonicalBytes",
            Self::Transpose4x4 => "Transpose4x4",
            Self::ReverseBytesInWords => "ReverseBytesInWords",
            Self::Transpose4x4ThenReverseWords => "Transpose4x4ThenReverseWords",
        }
    }

    fn evidence(self) -> &'static str {
        match self {
            Self::CanonicalBytes => {
                "Observed input/output bytes already match canonical AES block serialization."
            }
            Self::Transpose4x4 => {
                "Transposing each observed 4x4 byte matrix to AES column-major order makes every block recompute exactly."
            }
            Self::ReverseBytesInWords => {
                "Reversing bytes inside each observed 32-bit word makes every block recompute exactly."
            }
            Self::Transpose4x4ThenReverseWords => {
                "Transposing each 4x4 byte matrix and then reversing bytes inside each 32-bit word makes every block recompute exactly."
            }
        }
    }
}

fn blocks_to_canonical(bytes: &[u8], layout: AesStateLayout) -> Option<Vec<u8>> {
    if bytes.len() % 16 != 0 {
        return None;
    }
    let mut result = Vec::with_capacity(bytes.len());
    for block in bytes.chunks_exact(16) {
        let mut canonical = [0_u8; 16];
        match layout {
            AesStateLayout::CanonicalBytes => canonical.copy_from_slice(block),
            AesStateLayout::Transpose4x4 => {
                for row in 0..4 {
                    for column in 0..4 {
                        canonical[column * 4 + row] = block[row * 4 + column];
                    }
                }
            }
            AesStateLayout::ReverseBytesInWords => {
                for word in 0..4 {
                    for byte in 0..4 {
                        canonical[word * 4 + byte] = block[word * 4 + (3 - byte)];
                    }
                }
            }
            AesStateLayout::Transpose4x4ThenReverseWords => {
                let transposed = blocks_to_canonical(block, AesStateLayout::Transpose4x4)?;
                for word in 0..4 {
                    for byte in 0..4 {
                        canonical[word * 4 + byte] = transposed[word * 4 + (3 - byte)];
                    }
                }
            }
        }
        result.extend_from_slice(&canonical);
    }
    Some(result)
}

fn infer_ecb_state_layout(
    key: &[u8],
    direction: AesDirection,
    observed_input: &[u8],
    observed_output: &[u8],
) -> Option<(AesStateLayout, Vec<u8>, Vec<u8>)> {
    for layout in AesStateLayout::INFERENCE_CANDIDATES {
        let canonical_input = blocks_to_canonical(observed_input, layout)?;
        let canonical_output = blocks_to_canonical(observed_output, layout)?;
        if verify_aes_ecb(key, direction, &canonical_input, &canonical_output).is_ok_and(
            |verification| verification.status == SemanticVerificationStatus::VerifiedFull,
        ) {
            return Some((layout, canonical_input, canonical_output));
        }
    }
    None
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
fn ascii(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|&b| {
            if b.is_ascii_graphic() || b == b' ' {
                b as char
            } else {
                '.'
            }
        })
        .collect()
}

fn parse_inline_hex(line: &str) -> Option<Vec<u8>> {
    let start = line.find("hex=")? + 4;
    let value: String = line[start..]
        .chars()
        .take_while(|c| c.is_ascii_hexdigit())
        .collect();
    if value.len() < 2 || value.len() % 2 != 0 {
        return None;
    }
    (0..value.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&value[i..i + 2], 16).ok())
        .collect()
}

pub fn raw_gumtrace_writes(data: &[u8]) -> Vec<MemAccess> {
    let text = String::from_utf8_lossy(data);
    let mut result = Vec::new();
    for (seq, line) in text.lines().enumerate() {
        let Some(close) = line.find("] 0x") else {
            continue;
        };
        let addr_start = close + 2;
        let Some(bang_rel) = line[addr_start..].find('!') else {
            continue;
        };
        let Ok(insn_addr) = u64::from_str_radix(
            line[addr_start..addr_start + bang_rel].trim_start_matches("0x"),
            16,
        ) else {
            continue;
        };
        let mut rest = line;
        while let Some(pos) = rest.find("mem_w=0x") {
            rest = &rest[pos + 8..];
            let address_hex: String = rest.chars().take_while(|c| c.is_ascii_hexdigit()).collect();
            let after_addr = &rest[address_hex.len()..];
            let Some(size_start) = after_addr.strip_prefix('/') else {
                rest = after_addr;
                continue;
            };
            let size_text: String = size_start
                .chars()
                .take_while(|c| c.is_ascii_digit())
                .collect();
            let after_size = &size_start[size_text.len()..];
            let Some(value_start) = after_size.strip_prefix("=0x") else {
                rest = after_size;
                continue;
            };
            let value_hex: String = value_start
                .chars()
                .take_while(|c| c.is_ascii_hexdigit())
                .collect();
            if let (Ok(addr), Ok(size), Ok(value)) = (
                u64::from_str_radix(&address_hex, 16),
                size_text.parse::<u8>(),
                u64::from_str_radix(&value_hex, 16),
            ) {
                result.push(MemAccess {
                    seq: seq as u32,
                    insn_addr,
                    addr,
                    value,
                    size,
                });
            }
            rest = &value_start[value_hex.len()..];
        }
    }
    result
}

pub fn annotation_hex_buffers(annotations: &HashMap<u32, CallAnnotation>) -> Vec<ObservedBuffer> {
    let mut result = Vec::new();
    for (&call_seq, annotation) in annotations {
        let seq = annotation.observation_seq.unwrap_or(call_seq);
        for line in &annotation.raw_lines {
            if let Some(bytes) = parse_inline_hex(line) {
                result.push(ObservedBuffer { seq, bytes });
            }
        }
        let (_, bytes) = annotation.merged_hexdump();
        if !bytes.is_empty() {
            result.push(ObservedBuffer { seq, bytes });
        }
    }
    // HashMap iteration order is deliberately unspecified. Sort before
    // deduplication so repeated observations always retain the earliest real
    // observation rather than an arbitrary call instance.
    result.sort_by(|a, b| a.seq.cmp(&b.seq).then_with(|| a.bytes.cmp(&b.bytes)));
    let mut earliest = Vec::with_capacity(result.len());
    for buffer in result {
        if !earliest
            .iter()
            .any(|existing: &ObservedBuffer| existing.bytes == buffer.bytes)
        {
            earliest.push(buffer);
        }
    }
    earliest
}

#[derive(Clone)]
struct WriteBuffer {
    insn: u64,
    base: u64,
    bytes: Vec<u8>,
    stride: usize,
    first_seq: u32,
    last_seq: u32,
}

fn unique_writes(writes: &[MemAccess]) -> Vec<&MemAccess> {
    let mut seen = BTreeSet::new();
    let mut unique = writes
        .iter()
        .filter(|access| {
            seen.insert((
                access.seq,
                access.insn_addr,
                access.addr,
                access.value,
                access.size,
            ))
        })
        .collect::<Vec<_>>();
    unique.sort_by_key(|access| (access.seq, access.addr));
    unique
}

fn append_contiguous_buffers(
    result: &mut Vec<WriteBuffer>,
    insn: u64,
    map: &BTreeMap<u64, (u8, u32)>,
) {
    let addresses: Vec<u64> = map.keys().copied().collect();
    let mut i = 0;
    while i < addresses.len() {
        let mut j = i + 1;
        while j < addresses.len() && addresses[j] == addresses[j - 1] + 1 {
            j += 1;
        }
        if j - i >= 16 {
            let bytes = addresses[i..j]
                .iter()
                .map(|address| map[address].0)
                .collect::<Vec<_>>();
            let seqs = addresses[i..j]
                .iter()
                .map(|address| map[address].1)
                .collect::<Vec<_>>();
            result.push(WriteBuffer {
                insn,
                base: addresses[i],
                stride: if bytes.len() >= 32 { 16 } else { bytes.len() },
                bytes,
                first_seq: seqs.iter().copied().min().unwrap_or(0),
                last_seq: seqs.iter().copied().max().unwrap_or(0),
            });
        }
        i = j;
    }
}

fn write_site_buffers(writes: &[MemAccess]) -> Vec<WriteBuffer> {
    let mut sites: HashMap<u64, Vec<&MemAccess>> = HashMap::new();
    for access in unique_writes(writes) {
        sites.entry(access.insn_addr).or_default().push(access);
    }
    let mut result = Vec::new();
    for (insn, mut accesses) in sites {
        accesses.sort_by_key(|access| (access.seq, access.addr));
        let mut map = BTreeMap::new();
        for access in accesses {
            let overlaps_previous_generation =
                (0..access.size.clamp(1, 8) as u64).any(|i| map.contains_key(&(access.addr + i)));
            if overlaps_previous_generation {
                append_contiguous_buffers(&mut result, insn, &map);
                map.clear();
            }
            for i in 0..access.size.clamp(1, 8) as u64 {
                let address = access.addr + i;
                let byte = ((access.value >> (8 * i)) & 0xff) as u8;
                map.insert(address, (byte, access.seq));
            }
        }
        append_contiguous_buffers(&mut result, insn, &map);
    }
    result
}

fn global_write_buffers(writes: &[MemAccess]) -> Vec<WriteBuffer> {
    let mut memory: BTreeMap<u64, (u8, u32, u64, u32)> = BTreeMap::new();
    for access in unique_writes(writes) {
        for i in 0..access.size.clamp(1, 8) as u64 {
            let generation = memory
                .get(&(access.addr + i))
                .map_or(1, |previous| previous.3 + 1);
            let entry = (
                ((access.value >> (8 * i)) & 0xff) as u8,
                access.seq,
                access.insn_addr,
                generation,
            );
            if memory
                .get(&(access.addr + i))
                .is_none_or(|old| access.seq >= old.1)
            {
                memory.insert(access.addr + i, entry);
            }
        }
    }
    let addresses: Vec<u64> = memory.keys().copied().collect();
    let mut result = Vec::new();
    let mut i = 0;
    while i < addresses.len() {
        let mut j = i + 1;
        while j < addresses.len() && addresses[j] == addresses[j - 1] + 1 {
            j += 1;
        }
        let len = j - i;
        if (16..=4096).contains(&len) {
            let mut sites: HashMap<u64, usize> = HashMap::new();
            let bytes = addresses[i..j]
                .iter()
                .map(|a| {
                    let (byte, _, insn, _) = memory[a];
                    *sites.entry(insn).or_default() += 1;
                    byte
                })
                .collect();
            let insn = sites
                .into_iter()
                .max_by_key(|(_, count)| *count)
                .map(|(site, _)| site)
                .unwrap_or(0);
            let same_generation = addresses[i..j]
                .iter()
                .map(|address| memory[address].3)
                .all(|generation| generation == memory[&addresses[i]].3);
            if !same_generation {
                i = j;
                continue;
            }
            result.push(WriteBuffer {
                insn,
                base: addresses[i],
                bytes,
                stride: if len >= 32 && len % 16 == 0 { 16 } else { len },
                first_seq: addresses[i..j]
                    .iter()
                    .map(|address| memory[address].1)
                    .min()
                    .unwrap_or(0),
                last_seq: addresses[i..j]
                    .iter()
                    .map(|address| memory[address].1)
                    .max()
                    .unwrap_or(0),
            });
        }
        i = j;
    }
    result
}

fn pkcs7_pad(input: &[u8]) -> Vec<u8> {
    let padding = 16 - input.len() % 16;
    let mut result = input.to_vec();
    result.extend(std::iter::repeat_n(padding as u8, padding));
    result
}

fn schedule_seen(key: &[u8], writes: &[MemAccess]) -> bool {
    fn layout_seen(key_len: usize, expected: &[u8], ordered: &[MemAccess]) -> bool {
        let mut expected_offsets = vec![Vec::new(); 256];
        for (offset, &byte) in expected.iter().enumerate() {
            expected_offsets[byte as usize].push(offset);
        }
        let mut base_hits: HashMap<u64, [u64; 4]> = HashMap::new();
        for access in ordered {
            for i in 0..access.size.clamp(1, 8) as u64 {
                let address = access.addr + i;
                let byte = ((access.value >> (8 * i)) & 0xff) as u8;
                for &offset in &expected_offsets[byte as usize] {
                    if address >= offset as u64 {
                        let bits = base_hits.entry(address - offset as u64).or_default();
                        bits[offset / 64] |= 1_u64 << (offset % 64);
                    }
                }
            }
        }
        let mut candidates = base_hits
            .into_iter()
            .filter(|(_, bits)| bits.iter().map(|word| word.count_ones()).sum::<u32>() >= 32)
            .map(|(base, _)| (base, (vec![None; expected.len()], 0_usize)))
            .collect::<BTreeMap<_, _>>();
        if candidates.is_empty() {
            return false;
        }
        for access in ordered {
            for i in 0..access.size.clamp(1, 8) as u64 {
                let address = access.addr + i;
                let byte = ((access.value >> (8 * i)) & 0xff) as u8;
                let earliest_base = address.saturating_sub(expected.len() as u64 - 1);
                for (&base, (state, defined)) in candidates.range_mut(earliest_base..=address) {
                    let offset = (address - base) as usize;
                    if offset >= state.len() {
                        continue;
                    }
                    if state[offset].is_none() {
                        *defined += 1;
                    }
                    state[offset] = Some(byte);
                    if *defined == expected.len()
                        && state
                            .iter()
                            .zip(expected)
                            .all(|(actual, wanted)| *actual == Some(*wanted))
                    {
                        return true;
                    }
                    if state[key_len..]
                        .iter()
                        .zip(&expected[key_len..])
                        .all(|(actual, wanted)| *actual == Some(*wanted))
                    {
                        return true;
                    }
                }
            }
        }
        false
    }

    let Ok(expected) = expand_aes_key(key) else {
        return false;
    };
    let mut ordered = writes.to_vec();
    ordered.sort_by_key(|access| access.seq);
    if layout_seen(key.len(), &expected, &ordered) {
        return true;
    }
    let mut word_little_endian = expected.clone();
    for word in word_little_endian.chunks_exact_mut(4) {
        word.reverse();
    }
    layout_seen(key.len(), &word_little_endian, &ordered)
}

fn verified_report(
    key: &ObservedBuffer,
    input: &ObservedBuffer,
    iv: Option<&ObservedBuffer>,
    auth_tag: Option<&ObservedBuffer>,
    aad: Option<&ObservedBuffer>,
    output: &WriteBuffer,
    writes: &[MemAccess],
    direction: AesDirection,
    mode: &str,
    padding: &str,
    semantic_input: &[u8],
    semantic_output: &[u8],
    state_layout: AesStateLayout,
) -> SoftwareCryptoReport {
    let scoped_schedule_writes = writes
        .iter()
        .filter(|access| access.seq >= key.seq && access.seq <= output.last_seq)
        .cloned()
        .collect::<Vec<_>>();
    let schedule_verified = schedule_seen(&key.bytes, &scoped_schedule_writes);
    let ciphertext = match direction {
        AesDirection::Encrypt => semantic_output,
        AesDirection::Decrypt => semantic_input,
    };
    let operation = match direction {
        AesDirection::Encrypt => "encrypt",
        AesDirection::Decrypt => "decrypt",
    };
    let mode_setup = match (mode, iv) {
        ("ECB", _) => "cipher=AES.new(key,AES.MODE_ECB)".to_string(),
        ("CBC", Some(iv)) => format!(
            "iv=bytes.fromhex('{}')\ncipher=AES.new(key,AES.MODE_CBC,iv=iv)",
            hex(&iv.bytes)
        ),
        ("CTR", Some(iv)) => format!(
            "from Crypto.Util import Counter\niv=bytes.fromhex('{}')\nctr=Counter.new(128,initial_value=int.from_bytes(iv,'big'))\ncipher=AES.new(key,AES.MODE_CTR,counter=ctr)",
            hex(&iv.bytes)
        ),
        ("GCM", Some(iv)) => format!(
            "nonce=bytes.fromhex('{}')\naad=bytes.fromhex('{}')\ncipher=AES.new(key,AES.MODE_GCM,nonce=nonce)\ncipher.update(aad)",
            hex(&iv.bytes), aad.map(|value| hex(&value.bytes)).unwrap_or_default()
        ),
        _ => unreachable!("verified mode requires its parameters"),
    };
    let reproducer = if mode == "GCM" {
        let tag = auth_tag.expect("verified GCM requires an authentication tag");
        match direction {
            AesDirection::Encrypt => format!(
                "from Crypto.Cipher import AES\nkey=bytes.fromhex('{}')\ndata=bytes.fromhex('{}')\n{}\nresult,tag=cipher.encrypt_and_digest(data)\nassert result.hex()=='{}'\nassert tag.hex()=='{}'\nprint(result.hex(),tag.hex())\n",
                hex(&key.bytes), hex(semantic_input), mode_setup, hex(semantic_output), hex(&tag.bytes)
            ),
            AesDirection::Decrypt => format!(
                "from Crypto.Cipher import AES\nkey=bytes.fromhex('{}')\ndata=bytes.fromhex('{}')\ntag=bytes.fromhex('{}')\n{}\nresult=cipher.decrypt_and_verify(data,tag)\nassert result.hex()=='{}'\nprint(result.hex())\n",
                hex(&key.bytes), hex(semantic_input), hex(&tag.bytes), mode_setup, hex(semantic_output)
            ),
        }
    } else {
        format!(
            "from Crypto.Cipher import AES\nkey=bytes.fromhex('{}')\ndata=bytes.fromhex('{}')\n{}\nresult=cipher.{}(data)\nassert result.hex()=='{}'\nprint(result.hex())\n",
            hex(&key.bytes),
            hex(semantic_input),
            mode_setup,
            operation,
            hex(semantic_output)
        )
    };
    SoftwareCryptoReport {
        algorithm: format!("AES-{}", key.bytes.len() * 8),
        direction: match direction {
            AesDirection::Encrypt => "Encrypt",
            AesDirection::Decrypt => "Decrypt",
        }
        .into(),
        mode: mode.into(),
        padding: padding.into(),
        key_hex: hex(&key.bytes),
        key_ascii: ascii(&key.bytes),
        key_observation_seq: key.seq,
        input_observation_seq: input.seq,
        input_hex: hex(semantic_input),
        output_hex: hex(semantic_output),
        iv_hex: iv.map(|value| hex(&value.bytes)),
        iv_observation_seq: iv.map(|value| value.seq),
        auth_tag_hex: auth_tag.map(|value| hex(&value.bytes)),
        auth_tag_observation_seq: auth_tag.map(|value| value.seq),
        aad_hex: aad.map(|value| hex(&value.bytes)),
        aad_observation_seq: aad.map(|value| value.seq),
        input_length: input.bytes.len(),
        padded_length: semantic_input.len(),
        block_count: semantic_input.len() / 16,
        output_base_addr: format!("0x{:x}", output.base),
        output_store_insn: format!("0x{:x}", output.insn),
        output_first_seq: output.first_seq,
        output_last_seq: output.last_seq,
        output_stride: output.stride,
        first_cipher_block: hex(&ciphertext[..16]),
        last_cipher_block: hex(&ciphertext[ciphertext.len() - 16..]),
        schedule_verified,
        state_layout: state_layout.label().into(),
        state_layout_evidence: state_layout.evidence().into(),
        implementation_kind: if schedule_verified {
            "ObfuscatedStandardSoftware".into()
        } else {
            "TableDrivenSoftware".into()
        },
        key_exposure: "RawKeyObserved".into(),
        whitebox_status: if schedule_verified {
            "NotWhiteBox".into()
        } else {
            "Unknown".into()
        },
        verification: "VerifiedFull".into(),
        ciphertext_sha256: hex(&Sha256::digest(ciphertext)),
        reproducer,
    }
}

pub fn analyze(buffers: &[ObservedBuffer], writes: &[MemAccess]) -> Option<SoftwareCryptoReport> {
    let keys = buffers
        .iter()
        .filter(|b| matches!(b.bytes.len(), 16 | 24 | 32));
    let mut outputs = write_site_buffers(writes);
    outputs.extend(global_write_buffers(writes));
    if std::env::var_os("TRACE_AES_DEBUG").is_some() {
        eprintln!(
            "[software-crypto] annotation buffer lengths: {:?}",
            buffers.iter().map(|b| b.bytes.len()).collect::<Vec<_>>()
        );
        eprintln!(
            "[software-crypto] write buffers: {:?}",
            outputs
                .iter()
                .map(|o| (
                    format!("0x{:x}", o.insn),
                    format!("0x{:x}", o.base),
                    o.bytes.len()
                ))
                .collect::<Vec<_>>()
        );
    }
    for key in keys {
        for input in buffers
            .iter()
            .filter(|b| b.seq <= key.seq || b.bytes.len() >= 16)
        {
            if input.bytes == key.bytes {
                continue;
            }
            for direction in [AesDirection::Encrypt, AesDirection::Decrypt] {
                for output in outputs.iter().filter(|output| {
                    output.bytes.len() == input.bytes.len()
                        && key.seq <= output.first_seq
                        && input.seq <= output.first_seq
                }) {
                    for nonce in buffers.iter().filter(|candidate| {
                        candidate.bytes.len() == 12
                            && candidate.seq <= output.first_seq
                            && candidate.bytes != input.bytes
                    }) {
                        for tag in buffers.iter().filter(|candidate| {
                            candidate.bytes.len() == 16
                                && candidate.bytes != key.bytes
                                && candidate.bytes != input.bytes
                                && candidate.bytes != nonce.bytes
                        }) {
                            let mut aad_candidates = vec![None];
                            aad_candidates.extend(buffers.iter().filter_map(|candidate| {
                                (candidate.seq <= output.first_seq
                                    && candidate.bytes.len() <= 4096
                                    && candidate.bytes != key.bytes
                                    && candidate.bytes != input.bytes
                                    && candidate.bytes != nonce.bytes
                                    && candidate.bytes != tag.bytes)
                                    .then_some(Some(candidate))
                            }));
                            for aad in aad_candidates {
                                if verify_aes_gcm(
                                    &key.bytes,
                                    direction,
                                    &nonce.bytes,
                                    aad.map(|value| value.bytes.as_slice()).unwrap_or(&[]),
                                    &input.bytes,
                                    &output.bytes,
                                    &tag.bytes,
                                )
                                .is_ok_and(|verification| verification.authenticated)
                                {
                                    return Some(verified_report(
                                        key,
                                        input,
                                        Some(nonce),
                                        Some(tag),
                                        aad,
                                        output,
                                        writes,
                                        direction,
                                        "GCM",
                                        "None",
                                        &input.bytes,
                                        &output.bytes,
                                        AesStateLayout::CanonicalBytes,
                                    ));
                                }
                            }
                        }
                    }
                }
                for output in outputs.iter().filter(|output| {
                    output.bytes.len() == input.bytes.len()
                        && key.seq <= output.first_seq
                        && input.seq <= output.first_seq
                }) {
                    for counter in buffers.iter().filter(|candidate| {
                        candidate.bytes.len() == 16
                            && candidate.seq <= output.first_seq
                            && candidate.bytes != key.bytes
                            && candidate.bytes != input.bytes
                    }) {
                        if verify_aes_ctr(
                            &key.bytes,
                            direction,
                            &counter.bytes,
                            &input.bytes,
                            &output.bytes,
                        )
                        .is_ok_and(|verification| {
                            verification.status == SemanticVerificationStatus::VerifiedFull
                        }) {
                            return Some(verified_report(
                                key,
                                input,
                                Some(counter),
                                None,
                                None,
                                output,
                                writes,
                                direction,
                                "CTR",
                                "None",
                                &input.bytes,
                                &output.bytes,
                                AesStateLayout::CanonicalBytes,
                            ));
                        }
                    }
                }
                let (semantic_input, padding) = match direction {
                    AesDirection::Encrypt if input.bytes.len() % 16 == 0 => {
                        (input.bytes.clone(), "None")
                    }
                    AesDirection::Encrypt => (pkcs7_pad(&input.bytes), "PKCS#7"),
                    AesDirection::Decrypt if input.bytes.len() % 16 == 0 => {
                        (input.bytes.clone(), "None")
                    }
                    AesDirection::Decrypt => continue,
                };
                for output in outputs.iter().filter(|o| {
                    o.bytes.len() == semantic_input.len()
                        && key.seq <= o.first_seq
                        && input.seq <= o.first_seq
                }) {
                    if verify_aes_ecb(&key.bytes, direction, &semantic_input, &output.bytes)
                        .is_ok_and(|verification| {
                            verification.status == SemanticVerificationStatus::VerifiedFull
                        })
                    {
                        return Some(verified_report(
                            key,
                            input,
                            None,
                            None,
                            None,
                            output,
                            writes,
                            direction,
                            "ECB",
                            padding,
                            &semantic_input,
                            &output.bytes,
                            AesStateLayout::CanonicalBytes,
                        ));
                    }
                    if padding == "None" {
                        if let Some((layout, canonical_input, canonical_output)) =
                            infer_ecb_state_layout(
                                &key.bytes,
                                direction,
                                &semantic_input,
                                &output.bytes,
                            )
                        {
                            return Some(verified_report(
                                key,
                                input,
                                None,
                                None,
                                None,
                                output,
                                writes,
                                direction,
                                "ECB",
                                padding,
                                &canonical_input,
                                &canonical_output,
                                layout,
                            ));
                        }
                    }
                    for iv in buffers.iter().filter(|candidate| {
                        candidate.bytes.len() == 16
                            && candidate.seq <= output.first_seq
                            && candidate.bytes != key.bytes
                            && candidate.bytes != input.bytes
                    }) {
                        if verify_aes_cbc(
                            &key.bytes,
                            direction,
                            &iv.bytes,
                            &semantic_input,
                            &output.bytes,
                        )
                        .is_ok_and(|verification| {
                            verification.status == SemanticVerificationStatus::VerifiedFull
                        }) {
                            return Some(verified_report(
                                key,
                                input,
                                Some(iv),
                                None,
                                None,
                                output,
                                writes,
                                direction,
                                "CBC",
                                padding,
                                &semantic_input,
                                &output.bytes,
                                AesStateLayout::CanonicalBytes,
                            ));
                        }
                    }
                }
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use aes::cipher::{BlockDecrypt, BlockEncrypt, KeyInit};
    use aes_gcm::aead::AeadInPlace;

    fn annotation(raw_lines: Vec<String>, observation_seq: Option<u32>) -> CallAnnotation {
        CallAnnotation {
            func_name: "fixture".into(),
            is_jni: false,
            args: Vec::new(),
            ret_value: None,
            raw_lines,
            observation_seq,
            completion_seq: None,
        }
    }

    #[test]
    fn annotation_buffers_use_real_observation_seq_and_keep_earliest_duplicate() {
        let mut annotations = HashMap::new();
        annotations.insert(1, annotation(vec!["value hex=00112233".into()], Some(40)));
        annotations.insert(2, annotation(vec!["value hex=00112233".into()], Some(20)));
        annotations.insert(3, annotation(vec!["value hex=aabbccdd".into()], Some(30)));

        let buffers = annotation_hex_buffers(&annotations);
        assert_eq!(buffers.len(), 2);
        assert_eq!(buffers[0].seq, 20);
        assert_eq!(buffers[0].bytes, vec![0x00, 0x11, 0x22, 0x33]);
        assert_eq!(buffers[1].seq, 30);
    }

    fn write(seq: u32, insn_addr: u64, addr: u64, bytes: &[u8]) -> MemAccess {
        MemAccess {
            seq,
            insn_addr,
            addr,
            value: u64::from_le_bytes(bytes.try_into().unwrap()),
            size: bytes.len() as u8,
        }
    }

    #[test]
    fn write_site_buffers_split_address_reuse_into_call_generations() {
        let first = (0_u8..16).collect::<Vec<_>>();
        let second = (0x80_u8..0x90).collect::<Vec<_>>();
        let mut writes = vec![
            write(10, 0x2000, 0xa000, &first[..8]),
            write(11, 0x2000, 0xa008, &first[8..]),
            write(20, 0x2000, 0xa000, &second[..8]),
            write(21, 0x2000, 0xa008, &second[8..]),
        ];
        // Raw gumtrace supplementation may duplicate an indexed write exactly.
        writes.push(writes[0]);

        let buffers = write_site_buffers(&writes);
        assert_eq!(buffers.len(), 2);
        assert_eq!(buffers[0].bytes, first);
        assert_eq!(buffers[0].first_seq, 10);
        assert_eq!(buffers[1].bytes, second);
        assert_eq!(buffers[1].first_seq, 20);
    }

    #[test]
    fn global_buffer_rejects_partial_cross_call_overwrite() {
        let first = (0_u8..16).collect::<Vec<_>>();
        let replacement = (0x80_u8..0x88).collect::<Vec<_>>();
        let writes = vec![
            write(10, 0x2000, 0xa000, &first[..8]),
            write(11, 0x2008, 0xa008, &first[8..]),
            write(20, 0x2000, 0xa000, &replacement),
        ];

        assert!(global_write_buffers(&writes).is_empty());
    }

    #[test]
    fn schedule_detection_accepts_complete_word_little_endian_round_key_suffix() {
        let key = b"sixteen-byte-key";
        let mut schedule = expand_aes_key(key).unwrap();
        for word in schedule.chunks_exact_mut(4) {
            word.reverse();
        }
        let writes = schedule[16..]
            .chunks(8)
            .enumerate()
            .map(|(index, chunk)| MemAccess {
                seq: index as u32,
                insn_addr: 0x1234,
                addr: 0x8000 + 16 + (index * 8) as u64,
                value: u64::from_le_bytes(chunk.try_into().unwrap()),
                size: 8,
            })
            .collect::<Vec<_>>();
        assert!(schedule_seen(key, &writes));

        let padded_key = [key.as_slice(), &[16_u8; 16]].concat();
        let padded_writes = padded_key
            .chunks(8)
            .enumerate()
            .map(|(index, chunk)| MemAccess {
                seq: index as u32,
                insn_addr: 0x5678,
                addr: 0x9000 + (index * 8) as u64,
                value: u64::from_le_bytes(chunk.try_into().unwrap()),
                size: 8,
            })
            .collect::<Vec<_>>();
        assert!(!schedule_seen(key, &padded_writes));
    }

    #[test]
    fn schedule_written_after_output_does_not_classify_current_call() {
        let key = b"sixteen-byte-key".to_vec();
        let input = (0_u8..16).collect::<Vec<_>>();
        let cipher = aes::Aes128::new_from_slice(&key).unwrap();
        let mut output = input.clone();
        cipher.encrypt_block(aes::cipher::generic_array::GenericArray::from_mut_slice(
            &mut output,
        ));
        let mut writes = output
            .chunks(8)
            .enumerate()
            .map(|(index, chunk)| MemAccess {
                seq: 10 + index as u32,
                insn_addr: 0x2000,
                addr: 0xa000 + (index * 8) as u64,
                value: u64::from_le_bytes(chunk.try_into().unwrap()),
                size: 8,
            })
            .collect::<Vec<_>>();
        let schedule = expand_aes_key(&key).unwrap();
        writes.extend(
            schedule
                .chunks(8)
                .enumerate()
                .map(|(index, chunk)| MemAccess {
                    seq: 100 + index as u32,
                    insn_addr: 0x3000,
                    addr: 0xb000 + (index * 8) as u64,
                    value: u64::from_le_bytes(chunk.try_into().unwrap()),
                    size: 8,
                }),
        );

        let report = analyze(
            &[
                ObservedBuffer {
                    seq: 1,
                    bytes: input,
                },
                ObservedBuffer { seq: 2, bytes: key },
            ],
            &writes,
        )
        .unwrap();
        assert!(!report.schedule_verified);
        assert_eq!(report.whitebox_status, "Unknown");
    }

    #[test]
    fn detects_transposed_ecb_state_layout_by_full_recomputation() {
        let key = (0_u8..16).collect::<Vec<_>>();
        let canonical_input = (0x10_u8..0x20).collect::<Vec<_>>();
        let cipher = aes::Aes128::new_from_slice(&key).unwrap();
        let mut canonical_output = canonical_input.clone();
        cipher.encrypt_block(aes::cipher::generic_array::GenericArray::from_mut_slice(
            &mut canonical_output,
        ));
        let observed_input =
            blocks_to_canonical(&canonical_input, AesStateLayout::Transpose4x4).unwrap();
        let observed_output =
            blocks_to_canonical(&canonical_output, AesStateLayout::Transpose4x4).unwrap();
        let writes = vec![
            write(10, 0x2200, 0xa000, &observed_output[..8]),
            write(11, 0x2200, 0xa008, &observed_output[8..]),
        ];

        let report = analyze(
            &[
                ObservedBuffer {
                    seq: 1,
                    bytes: observed_input,
                },
                ObservedBuffer { seq: 2, bytes: key },
            ],
            &writes,
        )
        .unwrap();
        assert_eq!(report.mode, "ECB");
        assert_eq!(report.verification, "VerifiedFull");
        assert_eq!(report.state_layout, "Transpose4x4");
        assert_eq!(report.first_cipher_block, hex(&canonical_output));
        assert!(report.state_layout_evidence.contains("column-major"));
    }

    #[test]
    fn detects_roles_blocks_stride_and_full_verification() {
        let key = b"KcIufueoThQliBgs".to_vec();
        let input = b"stage-c semantic role test".to_vec();
        let padded = pkcs7_pad(&input);
        let cipher = aes::Aes128::new_from_slice(&key).unwrap();
        let mut output = Vec::new();
        for chunk in padded.chunks(16) {
            let mut b = aes::cipher::generic_array::GenericArray::clone_from_slice(chunk);
            cipher.encrypt_block(&mut b);
            output.extend_from_slice(&b);
        }
        let mut writes = Vec::new();
        for (block, chunk) in output.chunks(16).enumerate() {
            for half in 0..2 {
                writes.push(MemAccess {
                    seq: 10 + (block * 2 + half) as u32,
                    insn_addr: 0x18940,
                    addr: 0x9000 + (block * 16 + half * 8) as u64,
                    value: u64::from_le_bytes(chunk[half * 8..half * 8 + 8].try_into().unwrap()),
                    size: 8,
                });
            }
        }
        let report = analyze(
            &[
                ObservedBuffer {
                    seq: 1,
                    bytes: input.clone(),
                },
                ObservedBuffer { seq: 2, bytes: key },
            ],
            &writes,
        )
        .unwrap();
        assert_eq!(report.state_layout, "CanonicalBytes");
        assert_eq!(report.block_count, 2);
        assert_eq!(report.output_stride, 16);
        assert_eq!(report.verification, "VerifiedFull");
        assert_eq!(report.output_first_seq, 10);
        assert_eq!(report.output_last_seq, 13);
    }

    #[test]
    fn detects_full_aes_ecb_decryption() {
        let key = b"sixteen-byte-key".to_vec();
        let input = (0_u8..16).collect::<Vec<_>>();
        let cipher = aes::Aes128::new_from_slice(&key).unwrap();
        let mut output = input.clone();
        for chunk in output.chunks_mut(16) {
            let block = aes::cipher::generic_array::GenericArray::from_mut_slice(chunk);
            cipher.decrypt_block(block);
        }
        let writes = output
            .chunks(8)
            .enumerate()
            .map(|(index, chunk)| MemAccess {
                seq: 10 + index as u32,
                insn_addr: 0x2000,
                addr: 0xa000 + (index * 8) as u64,
                value: u64::from_le_bytes(chunk.try_into().unwrap()),
                size: 8,
            })
            .collect::<Vec<_>>();
        let report = analyze(
            &[
                ObservedBuffer {
                    seq: 1,
                    bytes: input.clone(),
                },
                ObservedBuffer { seq: 2, bytes: key },
            ],
            &writes,
        )
        .unwrap();
        assert_eq!(report.direction, "Decrypt");
        assert_eq!(report.padding, "None");
        assert_eq!(report.block_count, 1);
        assert_eq!(report.verification, "VerifiedFull");
        assert_eq!(report.output_first_seq, 10);
        assert_eq!(report.output_last_seq, 11);
        assert_eq!(report.first_cipher_block, hex(&input));
        assert_eq!(report.last_cipher_block, hex(&input));
        assert_eq!(report.ciphertext_sha256, hex(&Sha256::digest(&input)));
    }

    #[test]
    fn rejects_buffers_observed_after_the_output_window() {
        let key = b"sixteen-byte-key".to_vec();
        let input = (0_u8..16).collect::<Vec<_>>();
        let cipher = aes::Aes128::new_from_slice(&key).unwrap();
        let mut output = input.clone();
        let block = aes::cipher::generic_array::GenericArray::from_mut_slice(&mut output);
        cipher.encrypt_block(block);
        let writes = output
            .chunks(8)
            .enumerate()
            .map(|(index, chunk)| MemAccess {
                seq: 10 + index as u32,
                insn_addr: 0x2000,
                addr: 0xa000 + (index * 8) as u64,
                value: u64::from_le_bytes(chunk.try_into().unwrap()),
                size: 8,
            })
            .collect::<Vec<_>>();
        assert!(analyze(
            &[
                ObservedBuffer {
                    seq: 20,
                    bytes: input,
                },
                ObservedBuffer {
                    seq: 21,
                    bytes: key,
                },
            ],
            &writes,
        )
        .is_none());
    }

    #[test]
    fn detects_cbc_with_observed_iv() {
        let key = b"sixteen-byte-key".to_vec();
        let iv = (0x80_u8..0x90).collect::<Vec<_>>();
        let input = (0_u8..32).collect::<Vec<_>>();
        let cipher = aes::Aes128::new_from_slice(&key).unwrap();
        let mut previous = iv.clone();
        let mut output = Vec::new();
        for chunk in input.chunks_exact(16) {
            let mut block = aes::cipher::generic_array::GenericArray::clone_from_slice(chunk);
            for (byte, chain) in block.iter_mut().zip(&previous) {
                *byte ^= *chain;
            }
            cipher.encrypt_block(&mut block);
            previous.copy_from_slice(&block);
            output.extend_from_slice(&block);
        }
        let writes = output
            .chunks(8)
            .enumerate()
            .map(|(index, chunk)| MemAccess {
                seq: 10 + index as u32,
                insn_addr: 0x3000,
                addr: 0xb000 + (index * 8) as u64,
                value: u64::from_le_bytes(chunk.try_into().unwrap()),
                size: 8,
            })
            .collect::<Vec<_>>();
        let report = analyze(
            &[
                ObservedBuffer {
                    seq: 1,
                    bytes: input,
                },
                ObservedBuffer { seq: 2, bytes: key },
                ObservedBuffer {
                    seq: 3,
                    bytes: iv.clone(),
                },
            ],
            &writes,
        )
        .unwrap();
        assert_eq!(report.mode, "CBC");
        assert_eq!(report.iv_hex.as_deref(), Some(hex(&iv).as_str()));
        assert_eq!(report.iv_observation_seq, Some(3));
        assert!(report.reproducer.contains("AES.MODE_CBC"));
    }

    #[test]
    fn detects_ctr_with_observed_initial_counter() {
        let key = b"sixteen-byte-key".to_vec();
        let counter = (0xf0_u8..=0xff).collect::<Vec<_>>();
        let input = (0_u8..23).collect::<Vec<_>>();
        let mut output = Vec::new();
        let mut current = <[u8; 16]>::try_from(counter.as_slice()).unwrap();
        let cipher = aes::Aes128::new_from_slice(&key).unwrap();
        for chunk in input.chunks(16) {
            let mut stream = aes::cipher::generic_array::GenericArray::clone_from_slice(&current);
            cipher.encrypt_block(&mut stream);
            output.extend(
                chunk
                    .iter()
                    .zip(stream.iter())
                    .map(|(byte, mask)| byte ^ mask),
            );
            for byte in current.iter_mut().rev() {
                let (next, overflow) = byte.overflowing_add(1);
                *byte = next;
                if !overflow {
                    break;
                }
            }
        }
        let writes = output
            .chunks(8)
            .enumerate()
            .map(|(index, chunk)| {
                let mut value = [0_u8; 8];
                value[..chunk.len()].copy_from_slice(chunk);
                MemAccess {
                    seq: 10 + index as u32,
                    insn_addr: 0x4000,
                    addr: 0xc000 + (index * 8) as u64,
                    value: u64::from_le_bytes(value),
                    size: chunk.len() as u8,
                }
            })
            .collect::<Vec<_>>();
        let report = analyze(
            &[
                ObservedBuffer {
                    seq: 1,
                    bytes: input,
                },
                ObservedBuffer { seq: 2, bytes: key },
                ObservedBuffer {
                    seq: 3,
                    bytes: counter.clone(),
                },
            ],
            &writes,
        )
        .unwrap();
        assert_eq!(report.mode, "CTR");
        assert_eq!(report.input_length, 23);
        assert_eq!(report.padded_length, 23);
        assert_eq!(report.iv_hex.as_deref(), Some(hex(&counter).as_str()));
        assert!(report.reproducer.contains("Counter.new"));
    }

    #[test]
    fn detects_gcm_only_when_payload_and_tag_match() {
        let key = [1_u8; 16].to_vec();
        let nonce = [0_u8; 12].to_vec();
        let aad = (0xa0_u8..0xa8).collect::<Vec<_>>();
        let input = [0_u8; 16].to_vec();
        let cipher = aes_gcm::Aes128Gcm::new_from_slice(&key).unwrap();
        let mut output = input.clone();
        let tag = cipher
            .encrypt_in_place_detached(aes_gcm::Nonce::from_slice(&nonce), &aad, &mut output)
            .unwrap()
            .to_vec();
        let writes = output
            .chunks(8)
            .enumerate()
            .map(|(index, chunk)| MemAccess {
                seq: 10 + index as u32,
                insn_addr: 0x5000,
                addr: 0xd000 + (index * 8) as u64,
                value: u64::from_le_bytes(chunk.try_into().unwrap()),
                size: 8,
            })
            .collect::<Vec<_>>();
        let buffers = vec![
            ObservedBuffer {
                seq: 1,
                bytes: input.clone(),
            },
            ObservedBuffer {
                seq: 2,
                bytes: key.clone(),
            },
            ObservedBuffer {
                seq: 3,
                bytes: nonce.clone(),
            },
            ObservedBuffer {
                seq: 4,
                bytes: aad.clone(),
            },
            ObservedBuffer {
                seq: 20,
                bytes: tag.clone(),
            },
        ];
        let report = analyze(&buffers, &writes).unwrap();
        assert_eq!(report.mode, "GCM");
        assert_eq!(report.iv_hex.as_deref(), Some(hex(&nonce).as_str()));
        assert_eq!(report.auth_tag_hex.as_deref(), Some(hex(&tag).as_str()));
        assert_eq!(report.auth_tag_observation_seq, Some(20));
        assert_eq!(report.aad_hex.as_deref(), Some(hex(&aad).as_str()));
        assert_eq!(report.aad_observation_seq, Some(4));
        assert!(report.reproducer.contains("encrypt_and_digest"));

        let mut wrong_buffers = buffers;
        wrong_buffers.last_mut().unwrap().bytes[0] ^= 1;
        assert!(analyze(&wrong_buffers, &writes).is_none());

        let decrypt_writes = input
            .chunks(8)
            .enumerate()
            .map(|(index, chunk)| MemAccess {
                seq: 10 + index as u32,
                insn_addr: 0x5004,
                addr: 0xe000 + (index * 8) as u64,
                value: u64::from_le_bytes(chunk.try_into().unwrap()),
                size: 8,
            })
            .collect::<Vec<_>>();
        let decrypt_report = analyze(
            &[
                ObservedBuffer {
                    seq: 1,
                    bytes: output,
                },
                ObservedBuffer { seq: 2, bytes: key },
                ObservedBuffer {
                    seq: 3,
                    bytes: nonce,
                },
                ObservedBuffer { seq: 4, bytes: aad },
                ObservedBuffer {
                    seq: 20,
                    bytes: tag,
                },
            ],
            &decrypt_writes,
        )
        .unwrap();
        assert_eq!(decrypt_report.mode, "GCM");
        assert_eq!(decrypt_report.direction, "Decrypt");
        assert!(decrypt_report.reproducer.contains("decrypt_and_verify"));
    }
}
