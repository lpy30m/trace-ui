use std::collections::{HashMap, HashSet};

use serde::{Deserialize, Serialize};

use super::strings::{StringEncoding, StringIndex, StringRw};
use crate::flat::mem_access::MemAccessView;

const DEFAULT_MAX_RESULTS: u32 = 500;
const MAX_RESULTS: u32 = 5000;
const MAX_QUERY_CHARS: usize = 4096;
const MAX_PATTERN_BYTES: usize = 1024;
const MAX_INTERPRETATIONS: usize = 32;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ValueSearchKind {
    #[default]
    Auto,
    Text,
    Hex,
    Integer,
    Address,
    Digest,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ValueEndian {
    Little,
    Big,
    #[default]
    Both,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum ValueSearchSource {
    String,
    Memory,
    Trace,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct ValueSearchRequest {
    pub query: String,
    pub kind: ValueSearchKind,
    pub endian: ValueEndian,
    pub integer_width: Option<u8>,
    pub include_utf8: bool,
    pub include_utf16le: bool,
    pub include_nul: bool,
    pub search_strings: bool,
    pub search_memory: bool,
    pub search_trace: bool,
    pub max_results: Option<u32>,
}

impl Default for ValueSearchRequest {
    fn default() -> Self {
        Self {
            query: String::new(),
            kind: ValueSearchKind::Auto,
            endian: ValueEndian::Both,
            integer_width: None,
            include_utf8: true,
            include_utf16le: true,
            include_nul: false,
            search_strings: true,
            search_memory: true,
            search_trace: true,
            max_results: None,
        }
    }
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ValueInterpretation {
    pub kind: ValueSearchKind,
    pub label: String,
    pub bytes_hex: String,
    pub byte_len: u32,
    pub encoding: Option<String>,
    pub endian: Option<ValueEndian>,
    pub numeric_value: Option<String>,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ValueSearchMatch {
    pub interpretation_index: u32,
    pub source: ValueSearchSource,
    pub addr: Option<String>,
    pub seq: u32,
    pub first_seq: u32,
    pub last_seq: u32,
    pub write_seqs: Vec<u32>,
    pub string_index: Option<u32>,
    pub content: Option<String>,
    pub preview: String,
    pub encoding: Option<String>,
    pub rw: Option<String>,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ValueSearchResponse {
    pub query: String,
    pub interpretations: Vec<ValueInterpretation>,
    pub matches: Vec<ValueSearchMatch>,
    pub strings_scanned: u32,
    pub writes_scanned: u32,
    pub trace_lines_scanned: u32,
    pub total_matches: u32,
    pub truncated: bool,
    pub warnings: Vec<String>,
}

#[derive(Clone, Debug)]
pub struct ParsedValueSearch {
    pub interpretations: Vec<ValueInterpretation>,
    pub patterns: Vec<Vec<u8>>,
    pub warnings: Vec<String>,
}

pub fn parse_value_search(request: &ValueSearchRequest) -> Result<ParsedValueSearch, String> {
    if request.query.is_empty() {
        return Err("value search query cannot be empty".to_string());
    }
    if request.query.chars().count() > MAX_QUERY_CHARS {
        return Err(format!(
            "value search query is too long (maximum {MAX_QUERY_CHARS} characters)"
        ));
    }
    if let Some(width) = request.integer_width {
        if !matches!(width, 1 | 2 | 4 | 8) {
            return Err("integerWidth must be one of 1, 2, 4, or 8 bytes".to_string());
        }
    }

    let mut parsed = ParsedValueSearch {
        interpretations: Vec::new(),
        patterns: Vec::new(),
        warnings: Vec::new(),
    };

    let wants_text = matches!(request.kind, ValueSearchKind::Auto | ValueSearchKind::Text);
    if wants_text {
        add_text_interpretations(&mut parsed, request);
    }

    let explicit_hex = request.kind == ValueSearchKind::Hex;
    let auto_hex = request.kind == ValueSearchKind::Auto && looks_like_hex(&request.query);
    if explicit_hex || auto_hex {
        match parse_hex_bytes(&request.query) {
            Ok(bytes) => add_interpretation(
                &mut parsed,
                ValueSearchKind::Hex,
                "Hex bytes (input order)".to_string(),
                bytes,
                Some("hex".to_string()),
                None,
                None,
            )?,
            Err(error) if explicit_hex => return Err(error),
            Err(error) => parsed
                .warnings
                .push(format!("Hex interpretation skipped: {error}")),
        }
    }

    let explicit_number = matches!(
        request.kind,
        ValueSearchKind::Integer | ValueSearchKind::Address
    );
    let auto_number = request.kind == ValueSearchKind::Auto && looks_like_number(&request.query);
    if explicit_number || auto_number {
        let number_kind = if request.kind == ValueSearchKind::Address
            || (request.kind == ValueSearchKind::Auto && has_hex_prefix(&request.query))
        {
            ValueSearchKind::Address
        } else {
            ValueSearchKind::Integer
        };
        match parse_number(&request.query) {
            Ok(value) => add_number_interpretations(&mut parsed, request, number_kind, value)?,
            Err(error) if explicit_number => return Err(error),
            Err(error) => parsed
                .warnings
                .push(format!("Numeric interpretation skipped: {error}")),
        }
    }

    let explicit_digest = request.kind == ValueSearchKind::Digest;
    let auto_digest = request.kind == ValueSearchKind::Auto && looks_like_digest(&request.query);
    if explicit_digest || auto_digest {
        match parse_hex_bytes(&request.query) {
            Ok(bytes) => {
                let algorithm = digest_name(bytes.len())
                    .ok_or_else(|| "digest must be 4, 16, 20, 32, 48, or 64 bytes".to_string());
                match algorithm {
                    Ok(algorithm) => add_interpretation(
                        &mut parsed,
                        ValueSearchKind::Digest,
                        format!("{algorithm} digest bytes (display order)"),
                        bytes,
                        Some("digest".to_string()),
                        None,
                        None,
                    )?,
                    Err(error) if explicit_digest => return Err(error),
                    Err(error) => parsed
                        .warnings
                        .push(format!("Digest interpretation skipped: {error}")),
                }
            }
            Err(error) if explicit_digest => return Err(error),
            Err(error) => parsed
                .warnings
                .push(format!("Digest interpretation skipped: {error}")),
        }
    }

    if parsed.interpretations.is_empty() {
        return Err("query produced no enabled byte interpretations".to_string());
    }
    Ok(parsed)
}

pub fn search_string_index(
    index: &StringIndex,
    parsed: &ParsedValueSearch,
    max_results: usize,
) -> (Vec<ValueSearchMatch>, u32) {
    let mut matches = Vec::new();
    let mut total = 0u32;
    for (string_index, record) in index.strings.iter().enumerate() {
        let candidate = record.content.as_bytes();
        for (interpretation_index, pattern) in parsed.patterns.iter().enumerate() {
            if pattern.is_empty() || pattern.len() > candidate.len() {
                continue;
            }
            for offset in candidate
                .windows(pattern.len())
                .enumerate()
                .filter_map(|(offset, window)| (window == pattern).then_some(offset))
            {
                total = total.saturating_add(1);
                if matches.len() < max_results {
                    matches.push(ValueSearchMatch {
                        interpretation_index: interpretation_index as u32,
                        source: ValueSearchSource::String,
                        addr: Some(format!("0x{:x}", record.addr.saturating_add(offset as u64))),
                        seq: record.seq,
                        first_seq: record.seq,
                        last_seq: record.seq,
                        write_seqs: Vec::new(),
                        string_index: Some(string_index as u32),
                        content: Some(record.content.clone()),
                        preview: record.content.clone(),
                        encoding: Some(match record.encoding {
                            StringEncoding::Ascii => "ASCII".to_string(),
                            StringEncoding::Utf8 => "UTF-8".to_string(),
                        }),
                        rw: Some(match record.rw {
                            StringRw::Read => "R".to_string(),
                            StringRw::Write => "W".to_string(),
                        }),
                    });
                }
            }
        }
    }
    (matches, total)
}

pub fn search_memory_writes(
    view: &MemAccessView<'_>,
    parsed: &ParsedValueSearch,
    max_results: usize,
) -> (Vec<ValueSearchMatch>, u32, u32) {
    let mut writes: Vec<_> = view
        .iter_all()
        .filter(|(_, record)| record.is_write())
        .map(|(addr, record)| (record.seq, addr, record.data, record.size))
        .collect();
    writes.sort_unstable_by_key(|(seq, addr, _, _)| (*seq, *addr));

    let mut memory: HashMap<u64, u8> = HashMap::new();
    let mut definitions: HashMap<u64, u32> = HashMap::new();
    let mut matches = Vec::new();
    let mut total = 0u32;

    for &(seq, addr, data, size) in &writes {
        let write_len = usize::from(size).min(std::mem::size_of::<u64>());
        let bytes = data.to_le_bytes();
        let touched: Vec<u64> = bytes
            .iter()
            .take(write_len)
            .enumerate()
            .map(|(offset, &byte)| {
                let byte_addr = addr.saturating_add(offset as u64);
                memory.insert(byte_addr, byte);
                definitions.insert(byte_addr, seq);
                byte_addr
            })
            .collect();

        let mut checked = HashSet::new();
        for (interpretation_index, pattern) in parsed.patterns.iter().enumerate() {
            for &touched_addr in &touched {
                for offset in 0..pattern.len() {
                    let Some(start_addr) = touched_addr.checked_sub(offset as u64) else {
                        continue;
                    };
                    if !checked.insert((interpretation_index, start_addr)) {
                        continue;
                    }
                    if !pattern.iter().enumerate().all(|(index, expected)| {
                        memory.get(&start_addr.saturating_add(index as u64)) == Some(expected)
                    }) {
                        continue;
                    }

                    let mut write_seqs: Vec<u32> = (0..pattern.len())
                        .filter_map(|index| {
                            definitions
                                .get(&start_addr.saturating_add(index as u64))
                                .copied()
                        })
                        .collect();
                    write_seqs.sort_unstable();
                    write_seqs.dedup();
                    total = total.saturating_add(1);
                    if matches.len() < max_results {
                        matches.push(ValueSearchMatch {
                            interpretation_index: interpretation_index as u32,
                            source: ValueSearchSource::Memory,
                            addr: Some(format!("0x{start_addr:x}")),
                            seq,
                            first_seq: write_seqs.first().copied().unwrap_or(seq),
                            last_seq: seq,
                            write_seqs,
                            string_index: None,
                            content: None,
                            preview: hex_bytes(pattern),
                            encoding: parsed.interpretations[interpretation_index]
                                .encoding
                                .clone(),
                            rw: Some("W".to_string()),
                        });
                    }
                }
            }
        }
    }

    (matches, total, writes.len().min(u32::MAX as usize) as u32)
}

pub fn max_results(request: &ValueSearchRequest) -> usize {
    request
        .max_results
        .unwrap_or(DEFAULT_MAX_RESULTS)
        .clamp(1, MAX_RESULTS) as usize
}

fn add_text_interpretations(parsed: &mut ParsedValueSearch, request: &ValueSearchRequest) {
    if request.include_utf8 {
        let bytes = request.query.as_bytes().to_vec();
        let _ = add_interpretation(
            parsed,
            ValueSearchKind::Text,
            "UTF-8 (exact text)".to_string(),
            bytes.clone(),
            Some("UTF-8".to_string()),
            None,
            None,
        );
        if request.include_nul {
            let mut nul = bytes;
            nul.push(0);
            let _ = add_interpretation(
                parsed,
                ValueSearchKind::Text,
                "UTF-8 + NUL".to_string(),
                nul,
                Some("UTF-8 + NUL".to_string()),
                None,
                None,
            );
        }
    }
    if request.include_utf16le {
        let mut bytes = Vec::with_capacity(request.query.len() * 2);
        for unit in request.query.encode_utf16() {
            bytes.extend_from_slice(&unit.to_le_bytes());
        }
        let _ = add_interpretation(
            parsed,
            ValueSearchKind::Text,
            "UTF-16LE (exact text)".to_string(),
            bytes.clone(),
            Some("UTF-16LE".to_string()),
            Some(ValueEndian::Little),
            None,
        );
        if request.include_nul {
            bytes.extend_from_slice(&[0, 0]);
            let _ = add_interpretation(
                parsed,
                ValueSearchKind::Text,
                "UTF-16LE + NUL".to_string(),
                bytes,
                Some("UTF-16LE + NUL".to_string()),
                Some(ValueEndian::Little),
                None,
            );
        }
    }
}

fn add_number_interpretations(
    parsed: &mut ParsedValueSearch,
    request: &ValueSearchRequest,
    kind: ValueSearchKind,
    value: u64,
) -> Result<(), String> {
    let width = request.integer_width.unwrap_or_else(|| {
        if kind == ValueSearchKind::Address {
            8
        } else if value <= u8::MAX as u64 {
            1
        } else if value <= u16::MAX as u64 {
            2
        } else if value <= u32::MAX as u64 {
            4
        } else {
            8
        }
    });
    let max = match width {
        1 => u8::MAX as u64,
        2 => u16::MAX as u64,
        4 => u32::MAX as u64,
        8 => u64::MAX,
        _ => return Err("integerWidth must be one of 1, 2, 4, or 8 bytes".to_string()),
    };
    if value > max {
        return Err(format!("value does not fit in {width} bytes"));
    }

    let full_le = value.to_le_bytes();
    let little = full_le[..width as usize].to_vec();
    let mut big = little.clone();
    big.reverse();
    let numeric = format!("{value} (0x{value:x})");
    let name = if kind == ValueSearchKind::Address {
        "address"
    } else {
        "integer"
    };
    if matches!(request.endian, ValueEndian::Little | ValueEndian::Both) {
        add_interpretation(
            parsed,
            kind,
            format!("{width}-byte little-endian {name}"),
            little,
            Some("integer".to_string()),
            Some(ValueEndian::Little),
            Some(numeric.clone()),
        )?;
    }
    if matches!(request.endian, ValueEndian::Big | ValueEndian::Both) {
        add_interpretation(
            parsed,
            kind,
            format!("{width}-byte big-endian {name}"),
            big,
            Some("integer".to_string()),
            Some(ValueEndian::Big),
            Some(numeric),
        )?;
    }
    Ok(())
}

fn add_interpretation(
    parsed: &mut ParsedValueSearch,
    kind: ValueSearchKind,
    label: String,
    bytes: Vec<u8>,
    encoding: Option<String>,
    endian: Option<ValueEndian>,
    numeric_value: Option<String>,
) -> Result<(), String> {
    if bytes.is_empty() {
        return Err("byte interpretation cannot be empty".to_string());
    }
    if bytes.len() > MAX_PATTERN_BYTES {
        return Err(format!(
            "byte interpretation is too long (maximum {MAX_PATTERN_BYTES} bytes)"
        ));
    }
    if parsed.interpretations.len() >= MAX_INTERPRETATIONS {
        return Err(format!(
            "query produced too many interpretations (maximum {MAX_INTERPRETATIONS})"
        ));
    }
    if parsed
        .interpretations
        .iter()
        .zip(&parsed.patterns)
        .any(|(existing, pattern)| existing.kind == kind && pattern == &bytes)
    {
        return Ok(());
    }
    parsed.interpretations.push(ValueInterpretation {
        kind,
        label,
        bytes_hex: hex_bytes(&bytes),
        byte_len: bytes.len() as u32,
        encoding,
        endian,
        numeric_value,
    });
    parsed.patterns.push(bytes);
    Ok(())
}

fn has_hex_prefix(input: &str) -> bool {
    input.starts_with("0x") || input.starts_with("0X")
}

fn looks_like_number(input: &str) -> bool {
    if has_hex_prefix(input) {
        return input.len() > 2 && input[2..].chars().all(|ch| ch.is_ascii_hexdigit());
    }
    !input.is_empty() && input.chars().all(|ch| ch.is_ascii_digit())
}

fn looks_like_hex(input: &str) -> bool {
    if has_hex_prefix(input) {
        return true;
    }
    let has_separator = input
        .chars()
        .any(|ch| ch.is_ascii_whitespace() || matches!(ch, ':' | '-' | '_'));
    let digits = input
        .chars()
        .filter(|ch| !ch.is_ascii_whitespace() && !matches!(ch, ':' | '-' | '_'))
        .collect::<String>();
    !digits.is_empty()
        && digits.len() % 2 == 0
        && digits.chars().all(|ch| ch.is_ascii_hexdigit())
        && (has_separator || digits.len() >= 2)
}

fn looks_like_digest(input: &str) -> bool {
    parse_hex_bytes(input)
        .ok()
        .and_then(|bytes| digest_name(bytes.len()))
        .is_some()
}

fn parse_hex_bytes(input: &str) -> Result<Vec<u8>, String> {
    let without_prefix = input
        .strip_prefix("0x")
        .or_else(|| input.strip_prefix("0X"))
        .unwrap_or(input);
    let normalized: String = without_prefix
        .chars()
        .filter(|ch| !ch.is_ascii_whitespace() && !matches!(ch, ':' | '-' | '_'))
        .collect();
    if normalized.is_empty() {
        return Err("hex input cannot be empty".to_string());
    }
    if normalized.len() % 2 != 0 {
        return Err("hex input must contain an even number of digits".to_string());
    }
    if let Some(ch) = normalized.chars().find(|ch| !ch.is_ascii_hexdigit()) {
        return Err(format!("hex input contains a non-hex character: {ch}"));
    }
    normalized
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            let pair = std::str::from_utf8(pair).expect("validated ASCII hex");
            u8::from_str_radix(pair, 16).map_err(|error| error.to_string())
        })
        .collect()
}

fn parse_number(input: &str) -> Result<u64, String> {
    if has_hex_prefix(input) {
        u64::from_str_radix(&input[2..], 16).map_err(|_| "invalid hexadecimal number".to_string())
    } else {
        input
            .parse::<u64>()
            .map_err(|_| "invalid unsigned decimal number".to_string())
    }
}

fn digest_name(byte_len: usize) -> Option<&'static str> {
    match byte_len {
        4 => Some("CRC32"),
        16 => Some("MD5"),
        20 => Some("SHA-1"),
        32 => Some("SHA-256"),
        48 => Some("SHA-384"),
        64 => Some("SHA-512"),
        _ => None,
    }
}

fn hex_bytes(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::flat::mem_access::{FlatMemAccess, FlatMemAccessRecord, MEM_RW_WRITE};

    fn request(query: &str, kind: ValueSearchKind) -> ValueSearchRequest {
        ValueSearchRequest {
            query: query.to_string(),
            kind,
            search_trace: false,
            ..ValueSearchRequest::default()
        }
    }

    fn flat_writes(entries: &[(u64, u64, u32, u8)]) -> FlatMemAccess {
        let mut entries = entries.to_vec();
        entries.sort_by_key(|(addr, _, seq, _)| (*addr, *seq));
        let mut addrs = Vec::new();
        let mut offsets = vec![0];
        let mut records = Vec::new();
        let mut current = None;
        for (addr, data, seq, size) in entries {
            if current != Some(addr) {
                if current.is_some() {
                    offsets.push(records.len() as u32);
                }
                addrs.push(addr);
                current = Some(addr);
            }
            records.push(FlatMemAccessRecord {
                insn_addr: 0x4000,
                data,
                seq,
                size,
                rw: MEM_RW_WRITE,
                _pad: [0; 2],
            });
        }
        if current.is_some() {
            offsets.push(records.len() as u32);
        }
        FlatMemAccess {
            addrs,
            offsets,
            records,
        }
    }

    #[test]
    fn parses_utf8_and_utf16le_without_changing_text() {
        let parsed = parse_value_search(&request("Hi ", ValueSearchKind::Text)).unwrap();
        assert_eq!(parsed.patterns[0], b"Hi ");
        assert_eq!(parsed.patterns[1], b"H\0i\0 \0");
    }

    #[test]
    fn parses_separator_hex_in_input_order() {
        let parsed = parse_value_search(&request("de:ad-be_ef", ValueSearchKind::Hex)).unwrap();
        assert_eq!(parsed.patterns, vec![vec![0xde, 0xad, 0xbe, 0xef]]);
        assert!(parsed.interpretations[0].label.contains("input order"));
    }

    #[test]
    fn parses_u32_both_endians() {
        let mut req = request("0x12345678", ValueSearchKind::Integer);
        req.integer_width = Some(4);
        let parsed = parse_value_search(&req).unwrap();
        assert_eq!(parsed.patterns[0], vec![0x78, 0x56, 0x34, 0x12]);
        assert_eq!(parsed.patterns[1], vec![0x12, 0x34, 0x56, 0x78]);
    }

    #[test]
    fn address_defaults_to_eight_bytes() {
        let parsed = parse_value_search(&request("0x1234", ValueSearchKind::Address)).unwrap();
        assert_eq!(parsed.patterns[0].len(), 8);
        assert_eq!(parsed.patterns[0][..2], [0x34, 0x12]);
    }

    #[test]
    fn memory_search_joins_stores_and_preserves_historical_match() {
        let flat = flat_writes(&[
            (0x1000, 0x4241, 10, 2),
            (0x1002, 0x4443, 11, 2),
            (0x1000, 0x5a, 20, 1),
        ]);
        let parsed = parse_value_search(&request("41424344", ValueSearchKind::Hex)).unwrap();
        let (matches, total, _) = search_memory_writes(&flat.view(), &parsed, 20);
        assert_eq!(total, 1);
        assert_eq!(matches[0].addr.as_deref(), Some("0x1000"));
        assert_eq!(matches[0].first_seq, 10);
        assert_eq!(matches[0].last_seq, 11);
    }

    #[test]
    fn memory_search_reports_same_value_at_multiple_times() {
        let flat = flat_writes(&[(0x2000, 0x41, 1, 1), (0x2000, 0x41, 2, 1)]);
        let parsed = parse_value_search(&request("41", ValueSearchKind::Hex)).unwrap();
        let (matches, total, _) = search_memory_writes(&flat.view(), &parsed, 20);
        assert_eq!(total, 2);
        assert_eq!(
            matches.iter().map(|item| item.seq).collect::<Vec<_>>(),
            vec![1, 2]
        );
    }

    #[test]
    fn rejects_invalid_width_odd_hex_and_long_input() {
        let mut bad_width = request("1", ValueSearchKind::Integer);
        bad_width.integer_width = Some(3);
        assert!(parse_value_search(&bad_width).is_err());
        assert!(parse_value_search(&request("abc", ValueSearchKind::Hex)).is_err());
        assert!(parse_value_search(&request(&"x".repeat(4097), ValueSearchKind::Text)).is_err());
    }
}
