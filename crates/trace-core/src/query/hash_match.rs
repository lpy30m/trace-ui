use std::borrow::Cow;
use std::collections::{HashMap, HashSet};

use md5::Md5;
use serde::{Deserialize, Serialize};
use sha1::Sha1;
use sha2::{Digest, Sha256, Sha384, Sha512};

use super::strings::{StringEncoding, StringIndex, StringRecord, StringRw};
use crate::flat::mem_access::MemAccessView;

const DEFAULT_MAX_RESULTS: u32 = 500;
const MAX_RESULTS: u32 = 5000;
const MAX_DIGEST_QUERIES: usize = 256;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum HashAlgorithm {
    Crc32,
    Md5,
    Sha1,
    Sha256,
    Sha384,
    Sha512,
}

impl HashAlgorithm {
    fn hex_len(self) -> usize {
        match self {
            Self::Crc32 => 8,
            Self::Md5 => 32,
            Self::Sha1 => 40,
            Self::Sha256 => 64,
            Self::Sha384 => 96,
            Self::Sha512 => 128,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub enum HashTransform {
    #[serde(rename = "utf8")]
    Utf8,
    #[serde(rename = "utf8Nul")]
    Utf8Nul,
    #[serde(rename = "utf16le")]
    Utf16Le,
    #[serde(rename = "utf16leNul")]
    Utf16LeNul,
}

impl HashTransform {
    fn priority(self) -> u8 {
        match self {
            Self::Utf8 => 0,
            Self::Utf8Nul => 1,
            Self::Utf16Le => 2,
            Self::Utf16LeNul => 3,
        }
    }
}

#[derive(Clone, Debug, Default, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct HashTransformOptions {
    pub utf8_nul: bool,
    pub utf16le: bool,
    pub utf16le_nul: bool,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct HashMatchRequest {
    pub digests: Vec<String>,
    pub algorithm: Option<HashAlgorithm>,
    #[serde(default)]
    pub transforms: HashTransformOptions,
    pub max_results: Option<u32>,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct HashDigestQueryResult {
    pub input: String,
    pub normalized_digest: Option<String>,
    pub algorithm: Option<HashAlgorithm>,
    pub error: Option<String>,
    pub match_count: u32,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct HashMatchResult {
    pub query_index: u32,
    pub input_digest: String,
    pub normalized_digest: String,
    pub algorithm: HashAlgorithm,
    pub string_index: u32,
    pub content: String,
    pub addr: String,
    pub seq: u32,
    pub encoding: String,
    pub byte_len: u32,
    pub hashed_byte_len: u32,
    pub xref_count: u32,
    pub rw: String,
    pub transform: HashTransform,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct HashMatchResponse {
    pub queries: Vec<HashDigestQueryResult>,
    pub matches: Vec<HashMatchResult>,
    pub candidate_count: u32,
    pub total_matches: u32,
    pub truncated: bool,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct HashMemoryMatchResult {
    pub query_index: u32,
    pub input_digest: String,
    pub normalized_digest: String,
    pub algorithm: HashAlgorithm,
    pub addr: String,
    pub byte_len: u32,
    pub first_write_seq: u32,
    pub last_write_seq: u32,
    pub write_seqs: Vec<u32>,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct HashMemoryMatchResponse {
    pub queries: Vec<HashDigestQueryResult>,
    pub matches: Vec<HashMemoryMatchResult>,
    pub writes_scanned: u32,
    pub total_matches: u32,
    pub truncated: bool,
}

struct ValidDigest {
    query_index: usize,
    algorithm: HashAlgorithm,
    bytes: Vec<u8>,
}

pub fn match_string_index(
    index: &StringIndex,
    request: &HashMatchRequest,
) -> Result<HashMatchResponse, String> {
    if request.digests.is_empty() {
        return Err("请至少输入一个摘要".to_string());
    }
    if request.digests.len() > MAX_DIGEST_QUERIES {
        return Err(format!(
            "一次最多查询 {MAX_DIGEST_QUERIES} 个摘要，当前为 {} 个",
            request.digests.len()
        ));
    }

    let mut queries = Vec::with_capacity(request.digests.len());
    let mut valid = Vec::new();
    for (query_index, input) in request.digests.iter().enumerate() {
        match parse_digest(input, request.algorithm) {
            Ok((normalized, algorithm, bytes)) => {
                queries.push(HashDigestQueryResult {
                    input: input.clone(),
                    normalized_digest: Some(normalized),
                    algorithm: Some(algorithm),
                    error: None,
                    match_count: 0,
                });
                valid.push(ValidDigest {
                    query_index,
                    algorithm,
                    bytes,
                });
            }
            Err(error) => queries.push(HashDigestQueryResult {
                input: input.clone(),
                normalized_digest: None,
                algorithm: request.algorithm,
                error: Some(error),
                match_count: 0,
            }),
        }
    }

    let mut lookup: HashMap<(HashAlgorithm, Vec<u8>), Vec<usize>> = HashMap::new();
    let mut algorithms = Vec::new();
    let mut seen_algorithms = HashSet::new();
    for digest in &valid {
        lookup
            .entry((digest.algorithm, digest.bytes.clone()))
            .or_default()
            .push(digest.query_index);
        if seen_algorithms.insert(digest.algorithm) {
            algorithms.push(digest.algorithm);
        }
    }

    let transforms = enabled_transforms(&request.transforms);
    let max_results = request
        .max_results
        .unwrap_or(DEFAULT_MAX_RESULTS)
        .clamp(1, MAX_RESULTS) as usize;
    let mut matches = Vec::new();
    let mut total_matches = 0u32;

    for (string_index, record) in index.strings.iter().enumerate() {
        for &transform in &transforms {
            let candidate = transform_bytes(&record.content, transform);
            for &algorithm in &algorithms {
                let digest = digest_bytes(algorithm, candidate.as_ref());
                let Some(query_indices) = lookup.get(&(algorithm, digest)) else {
                    continue;
                };
                for &query_index in query_indices {
                    total_matches = total_matches.saturating_add(1);
                    queries[query_index].match_count =
                        queries[query_index].match_count.saturating_add(1);
                    if matches.len() < max_results {
                        matches.push(make_match(
                            query_index,
                            algorithm,
                            transform,
                            candidate.len() as u32,
                            string_index,
                            record,
                            &queries[query_index],
                        ));
                    }
                }
            }
        }
    }

    matches.sort_by_key(|item| {
        (
            item.transform.priority(),
            item.query_index,
            item.string_index,
            item.seq,
        )
    });

    Ok(HashMatchResponse {
        queries,
        matches,
        candidate_count: index.strings.len().min(u32::MAX as usize) as u32,
        total_matches,
        truncated: total_matches as usize > max_results,
    })
}

pub fn match_memory_writes(
    view: &MemAccessView<'_>,
    request: &HashMatchRequest,
) -> Result<HashMemoryMatchResponse, String> {
    let (mut queries, valid) = parse_queries(request)?;
    let max_results = request
        .max_results
        .unwrap_or(DEFAULT_MAX_RESULTS)
        .clamp(1, MAX_RESULTS) as usize;
    let mut writes: Vec<_> = view
        .iter_all()
        .filter(|(_, record)| record.is_write())
        .map(|(addr, record)| (record.seq, addr, record.data, record.size))
        .collect();
    writes.sort_unstable_by_key(|(seq, addr, _, _)| (*seq, *addr));

    let mut memory: HashMap<u64, u8> = HashMap::new();
    let mut definitions: HashMap<u64, u32> = HashMap::new();
    let mut matches = Vec::new();
    let mut total_matches = 0u32;

    for &(seq, addr, data, size) in &writes {
        let write_len = usize::from(size).min(std::mem::size_of::<u64>());
        let bytes = data.to_le_bytes();
        let mut changed = Vec::new();
        for (offset, &byte) in bytes.iter().take(write_len).enumerate() {
            let byte_addr = addr.saturating_add(offset as u64);
            if memory.insert(byte_addr, byte) != Some(byte) {
                changed.push(byte_addr);
            }
            definitions.insert(byte_addr, seq);
        }
        if changed.is_empty() {
            continue;
        }

        let mut checked = HashSet::new();
        for digest in &valid {
            let digest_len = digest.bytes.len() as u64;
            for &changed_addr in &changed {
                for offset in 0..digest_len {
                    let Some(start_addr) = changed_addr.checked_sub(offset) else {
                        continue;
                    };
                    if !checked.insert((digest.query_index, start_addr)) {
                        continue;
                    }
                    let is_match = digest.bytes.iter().enumerate().all(|(index, expected)| {
                        memory.get(&start_addr.saturating_add(index as u64)) == Some(expected)
                    });
                    if !is_match {
                        continue;
                    }

                    let mut write_seqs: Vec<u32> = (0..digest.bytes.len())
                        .filter_map(|index| {
                            definitions
                                .get(&start_addr.saturating_add(index as u64))
                                .copied()
                        })
                        .collect();
                    write_seqs.sort_unstable();
                    write_seqs.dedup();
                    total_matches = total_matches.saturating_add(1);
                    queries[digest.query_index].match_count =
                        queries[digest.query_index].match_count.saturating_add(1);
                    if matches.len() < max_results {
                        matches.push(HashMemoryMatchResult {
                            query_index: digest.query_index as u32,
                            input_digest: queries[digest.query_index].input.clone(),
                            normalized_digest: queries[digest.query_index]
                                .normalized_digest
                                .clone()
                                .unwrap_or_default(),
                            algorithm: digest.algorithm,
                            addr: format!("0x{start_addr:x}"),
                            byte_len: digest.bytes.len() as u32,
                            first_write_seq: write_seqs.first().copied().unwrap_or(seq),
                            last_write_seq: seq,
                            write_seqs,
                        });
                    }
                }
            }
        }
    }

    Ok(HashMemoryMatchResponse {
        queries,
        matches,
        writes_scanned: writes.len().min(u32::MAX as usize) as u32,
        total_matches,
        truncated: total_matches as usize > max_results,
    })
}

fn parse_queries(
    request: &HashMatchRequest,
) -> Result<(Vec<HashDigestQueryResult>, Vec<ValidDigest>), String> {
    if request.digests.is_empty() {
        return Err("请至少输入一个摘要".to_string());
    }
    if request.digests.len() > MAX_DIGEST_QUERIES {
        return Err(format!(
            "一次最多查询 {MAX_DIGEST_QUERIES} 个摘要，当前为 {} 个",
            request.digests.len()
        ));
    }
    let mut queries = Vec::with_capacity(request.digests.len());
    let mut valid = Vec::new();
    for (query_index, input) in request.digests.iter().enumerate() {
        match parse_digest(input, request.algorithm) {
            Ok((normalized, algorithm, bytes)) => {
                queries.push(HashDigestQueryResult {
                    input: input.clone(),
                    normalized_digest: Some(normalized),
                    algorithm: Some(algorithm),
                    error: None,
                    match_count: 0,
                });
                valid.push(ValidDigest {
                    query_index,
                    algorithm,
                    bytes,
                });
            }
            Err(error) => queries.push(HashDigestQueryResult {
                input: input.clone(),
                normalized_digest: None,
                algorithm: request.algorithm,
                error: Some(error),
                match_count: 0,
            }),
        }
    }
    Ok((queries, valid))
}

fn parse_digest(
    input: &str,
    algorithm_override: Option<HashAlgorithm>,
) -> Result<(String, HashAlgorithm, Vec<u8>), String> {
    let trimmed = input.trim();
    let without_prefix = trimmed
        .strip_prefix("0x")
        .or_else(|| trimmed.strip_prefix("0X"))
        .unwrap_or(trimmed);
    let normalized: String = without_prefix
        .chars()
        .filter(|ch| !ch.is_whitespace() && *ch != ':' && *ch != '-')
        .collect::<String>()
        .to_ascii_lowercase();

    if normalized.is_empty() {
        return Err("摘要不能为空".to_string());
    }
    if let Some(ch) = normalized.chars().find(|ch| !ch.is_ascii_hexdigit()) {
        return Err(format!("摘要包含非十六进制字符: {ch}"));
    }

    let algorithm = match algorithm_override {
        Some(algorithm) => algorithm,
        None => match normalized.len() {
            8 => HashAlgorithm::Crc32,
            32 => HashAlgorithm::Md5,
            40 => HashAlgorithm::Sha1,
            64 => HashAlgorithm::Sha256,
            96 => HashAlgorithm::Sha384,
            128 => HashAlgorithm::Sha512,
            length => {
                return Err(format!(
                "无法根据 {length} 个十六进制字符识别算法；CRC32/MD5/SHA-1/SHA-256/SHA-384/SHA-512 分别需要 8/32/40/64/96/128 个"
            ))
            }
        },
    };

    if normalized.len() != algorithm.hex_len() {
        return Err(format!(
            "所选算法需要 {} 个十六进制字符，当前为 {} 个",
            algorithm.hex_len(),
            normalized.len()
        ));
    }

    let mut bytes = Vec::with_capacity(normalized.len() / 2);
    for pair in normalized.as_bytes().chunks_exact(2) {
        let pair = std::str::from_utf8(pair).expect("normalized digest is ASCII");
        bytes.push(u8::from_str_radix(pair, 16).expect("validated hexadecimal pair"));
    }
    Ok((normalized, algorithm, bytes))
}

fn enabled_transforms(options: &HashTransformOptions) -> Vec<HashTransform> {
    let mut transforms = vec![HashTransform::Utf8];
    if options.utf8_nul {
        transforms.push(HashTransform::Utf8Nul);
    }
    if options.utf16le {
        transforms.push(HashTransform::Utf16Le);
    }
    if options.utf16le_nul {
        transforms.push(HashTransform::Utf16LeNul);
    }
    transforms
}

fn transform_bytes(content: &str, transform: HashTransform) -> Cow<'_, [u8]> {
    match transform {
        HashTransform::Utf8 => Cow::Borrowed(content.as_bytes()),
        HashTransform::Utf8Nul => {
            let mut bytes = Vec::with_capacity(content.len() + 1);
            bytes.extend_from_slice(content.as_bytes());
            bytes.push(0);
            Cow::Owned(bytes)
        }
        HashTransform::Utf16Le | HashTransform::Utf16LeNul => {
            let nul = usize::from(transform == HashTransform::Utf16LeNul) * 2;
            let mut bytes = Vec::with_capacity(content.len() * 2 + nul);
            for unit in content.encode_utf16() {
                bytes.extend_from_slice(&unit.to_le_bytes());
            }
            if transform == HashTransform::Utf16LeNul {
                bytes.extend_from_slice(&[0, 0]);
            }
            Cow::Owned(bytes)
        }
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

fn make_match(
    query_index: usize,
    algorithm: HashAlgorithm,
    transform: HashTransform,
    hashed_byte_len: u32,
    string_index: usize,
    record: &StringRecord,
    query: &HashDigestQueryResult,
) -> HashMatchResult {
    HashMatchResult {
        query_index: query_index as u32,
        input_digest: query.input.clone(),
        normalized_digest: query
            .normalized_digest
            .clone()
            .expect("matches only reference valid queries"),
        algorithm,
        string_index: string_index as u32,
        content: record.content.clone(),
        addr: format!("0x{:x}", record.addr),
        seq: record.seq,
        encoding: match record.encoding {
            StringEncoding::Ascii => "ASCII".to_string(),
            StringEncoding::Utf8 => "UTF-8".to_string(),
        },
        byte_len: record.byte_len,
        hashed_byte_len,
        xref_count: record.xref_count,
        rw: match record.rw {
            StringRw::Read => "R".to_string(),
            StringRw::Write => "W".to_string(),
        },
        transform,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::flat::mem_access::{FlatMemAccess, FlatMemAccessRecord, MEM_RW_WRITE};

    fn sample_index() -> StringIndex {
        StringIndex {
            strings: vec![StringRecord {
                addr: 0x1000,
                content: "hello".to_string(),
                encoding: StringEncoding::Ascii,
                byte_len: 5,
                seq: 42,
                xref_count: 3,
                rw: StringRw::Write,
            }],
        }
    }

    fn request(digests: &[&str]) -> HashMatchRequest {
        HashMatchRequest {
            digests: digests.iter().map(|value| (*value).to_string()).collect(),
            algorithm: None,
            transforms: HashTransformOptions::default(),
            max_results: None,
        }
    }

    fn digest_hex(algorithm: HashAlgorithm, bytes: &[u8]) -> String {
        digest_bytes(algorithm, bytes)
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect()
    }

    #[test]
    fn matches_md5_sha1_and_sha256() {
        let response = match_string_index(
            &sample_index(),
            &request(&[
                "5d41402abc4b2a76b9719d911017c592",
                "aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d",
                "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824",
            ]),
        )
        .unwrap();
        assert_eq!(response.matches.len(), 3);
        assert!(response
            .matches
            .iter()
            .all(|item| item.transform == HashTransform::Utf8));
        assert_eq!(response.matches[0].content, "hello");
    }

    #[test]
    fn matches_crc32_sha384_and_sha512() {
        let response = match_string_index(
            &sample_index(),
            &request(&[
                "3610a686",
                "59e1748777448c69de6b800d7a33bbfb9ff1b463e44354c3553bcdb9c666fa90125a3c79f90397bdf5f6a13de828684f",
                "9b71d224bd62f3785d96d46ad3ea3d73319bfbc2890caadae2dff72519673ca72323c3d99ba5c11d7c7acc6e14b8c5da0c4663475c2e5c3adef46f73bcdec043",
            ]),
        )
        .unwrap();

        assert_eq!(response.matches.len(), 3);
        assert_eq!(response.matches[0].algorithm, HashAlgorithm::Crc32);
        assert!(response
            .matches
            .iter()
            .any(|item| item.algorithm == HashAlgorithm::Sha384));
        assert!(response
            .matches
            .iter()
            .any(|item| item.algorithm == HashAlgorithm::Sha512));
    }

    #[test]
    fn normalizes_case_prefix_and_separators() {
        let response = match_string_index(
            &sample_index(),
            &request(&["0x5D:41-40 2A BC 4B 2A 76 B9 71 9D 91 10 17 C5 92"]),
        )
        .unwrap();
        assert_eq!(response.matches.len(), 1);
        assert_eq!(
            response.queries[0].normalized_digest.as_deref(),
            Some("5d41402abc4b2a76b9719d911017c592")
        );
    }

    #[test]
    fn nul_transform_is_explicit_only() {
        let digest = digest_hex(HashAlgorithm::Md5, b"hello\0");
        assert!(match_string_index(&sample_index(), &request(&[&digest]))
            .unwrap()
            .matches
            .is_empty());

        let mut with_nul = request(&[&digest]);
        with_nul.transforms.utf8_nul = true;
        let response = match_string_index(&sample_index(), &with_nul).unwrap();
        assert_eq!(response.matches.len(), 1);
        assert_eq!(response.matches[0].transform, HashTransform::Utf8Nul);
    }

    #[test]
    fn utf16le_transform_is_explicit_only() {
        let bytes = transform_bytes("hello", HashTransform::Utf16Le);
        let digest = digest_hex(HashAlgorithm::Sha256, bytes.as_ref());
        assert!(match_string_index(&sample_index(), &request(&[&digest]))
            .unwrap()
            .matches
            .is_empty());

        let mut with_utf16 = request(&[&digest]);
        with_utf16.transforms.utf16le = true;
        let response = match_string_index(&sample_index(), &with_utf16).unwrap();
        assert_eq!(response.matches.len(), 1);
        assert_eq!(response.matches[0].transform, HashTransform::Utf16Le);
    }

    #[test]
    fn invalid_digest_does_not_block_valid_queries() {
        let response = match_string_index(
            &sample_index(),
            &request(&["not-a-digest", "5d41402abc4b2a76b9719d911017c592"]),
        )
        .unwrap();
        assert!(response.queries[0].error.is_some());
        assert_eq!(response.queries[0].match_count, 0);
        assert!(response.queries[1].error.is_none());
        assert_eq!(response.queries[1].match_count, 1);
        assert_eq!(response.matches.len(), 1);
    }

    #[test]
    fn finds_digest_bytes_split_across_multiple_writes() {
        let digest = [
            0x5d, 0x41, 0x40, 0x2a, 0xbc, 0x4b, 0x2a, 0x76, 0xb9, 0x71, 0x9d, 0x91, 0x10, 0x17,
            0xc5, 0x92,
        ];
        let flat = FlatMemAccess {
            addrs: vec![0x1000, 0x1008],
            offsets: vec![0, 1, 2],
            records: vec![
                FlatMemAccessRecord {
                    insn_addr: 0x4000,
                    data: u64::from_le_bytes(digest[0..8].try_into().unwrap()),
                    seq: 10,
                    size: 8,
                    rw: MEM_RW_WRITE,
                    _pad: [0; 2],
                },
                FlatMemAccessRecord {
                    insn_addr: 0x4004,
                    data: u64::from_le_bytes(digest[8..16].try_into().unwrap()),
                    seq: 11,
                    size: 8,
                    rw: MEM_RW_WRITE,
                    _pad: [0; 2],
                },
            ],
        };

        let response = match_memory_writes(
            &flat.view(),
            &request(&["5d41402abc4b2a76b9719d911017c592"]),
        )
        .unwrap();

        assert_eq!(response.matches.len(), 1);
        assert_eq!(response.matches[0].addr, "0x1000");
        assert_eq!(response.matches[0].write_seqs, vec![10, 11]);
        assert_eq!(response.matches[0].first_write_seq, 10);
        assert_eq!(response.matches[0].last_write_seq, 11);
    }
}
