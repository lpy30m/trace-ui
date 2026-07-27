//! 单条 trace 的软件/查表密码结构候选识别 —— 纯逻辑与 DTO。
//!
//! 设计与真实样本验证见 repo 根 `WHITEBOX_AES_IMPL.md`。正规白盒把 S-box/轮密钥折进随机编码
//! 的查找表，既无标准魔数常量、也不用硬件密码指令，旧 `scan_crypto`/`analyze_crypto_functions`
//! 对它检测为零。这里改用**可复算的结构证据**（全部来自 mem_accesses，指标透明可核）：
//!   A. I/O 候选 —— 模块外连续 ≥16 字节的读/写缓冲（角色保持中性）
//!   B. T-box 表 —— 模块内被大量 load 的连续地址簇（主表读次数最多）
//!   C. 轮数估计 —— 主表「读取次数 ÷ 不同条目数」≈ 每条目每轮命中一次 ≈ 轮数
//!   D. 算法判定 —— 由分组位宽 + 轮数匹配 AES/DES/SM4 的结构不变量
//!
//! 这些结构信号只能产生 candidate/related；只有后续语义复算才能打开 verified gate。

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::sync::OnceLock;

use crate::query::evidence_score::{score_evidence, EvidenceAssessment, EvidenceScoreSignal};
pub use crate::query::software_aes::MemAccess;

// ── 引擎填充的输入信号（纯 struct，便于单测，不依赖 trace）──

// ── 选项 ──

#[derive(Clone, Debug)]
pub struct WhiteBoxOptions {
    /// 目标算法提示，默认 "aes"。预留 "sm4"/"des"（结构分析共用，仅判定表不同）。
    pub algorithm: String,
    /// 模块（.so）映射基址，用于区分「表（模块内）」与「数据缓冲（模块外，栈/堆）」。
    pub module_base: u64,
    /// 认定「在模块内」的地址窗口大小。默认 32MB，覆盖一个 .so 又排除远在高位的栈/堆缓冲。
    pub module_window: u64,
    /// Optional ELF shared-object path. When supplied by the engine, static PT_LOAD bytes are
    /// reconciled with dynamically observed lookup-table reads.
    pub static_binary_path: Option<String>,
}

impl Default for WhiteBoxOptions {
    fn default() -> Self {
        Self {
            algorithm: "aes".to_string(),
            module_base: 0,
            module_window: 0x0200_0000, // 32 MiB
            static_binary_path: None,
        }
    }
}

/// 相邻表地址允许的最大间隙：≤ 视为同一张表，> 则切分。
const TABLE_CLUSTER_GAP: u64 = 0x1000;
/// I/O 块最短连续字节数（AES 分组 16 字节）。
const MIN_BLOCK_LEN: usize = 16;
/// I/O 块上报的最大字节数。
const MAX_BLOCK_LEN: usize = 32;
/// 上报的 I/O 候选缓冲数上限。
const MAX_IO_CANDIDATES: usize = 6;
/// 「主表」判为可信 T-box 的下限（读次数 / 不同条目数）。
const DOMINANT_TABLE_MIN_READS: u32 = 1000;
const DOMINANT_TABLE_MIN_DISTINCT: u32 = 256;
/// Boundary candidates must be local in the dynamic instruction stream. This is deliberately
/// short: it is a structural hint, not a general-purpose taint analysis substitute.
const BOUNDARY_SEQ_WINDOW: u32 = 16;
const MIN_BOUNDARY_MATCHES: u32 = 16;
const MIN_BOUNDARY_EXTERNAL_ADDRS: usize = 16;
const MAX_BOUNDARY_CANDIDATES: usize = 8;

// ── 输出 DTO（serde camelCase）──

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct IoBlock {
    pub base_addr: String,
    pub byte_len: u32,
    pub bytes_hex: String,
    pub ascii: String,
    /// 16 字节是否全可打印（明文常为可读串；用于在多个候选里优先挑明文）。
    pub printable: bool,
    pub first_seq: u32,
    pub last_seq: u32,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum TableRoleHint {
    LookupData,
    ControlFlowDispatcherCandidate,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TableRegion {
    pub base_addr: String,
    pub end_addr: String,
    pub module_offset: String,
    pub span_bytes: u64,
    pub distinct_addrs: u32,
    pub read_count: u32,
    pub dominant_size: u8,
    pub first_seq: u32,
    pub last_seq: u32,
    pub role_hint: TableRoleHint,
    pub crypto_eligible: bool,
    pub pointer_like_entries: u32,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TableFingerprint {
    pub scope: String,
    pub normalized_sha256: String,
    pub word_bytes: u8,
    pub distinct_words: u32,
    pub normalization: String,
    pub algorithm_hint: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EncodingBoundaryEvidence {
    pub direction: String,
    pub table_base: String,
    pub boundary_site: String,
    pub external_base_addr: String,
    pub external_end_addr: String,
    pub matched_events: u32,
    pub distinct_external_addrs: u32,
    pub first_seq: u32,
    pub last_seq: u32,
    pub rationale: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct StaticTableMatch {
    pub table_base: String,
    pub module_offset: String,
    pub file_offset: String,
    pub compared_entries: u32,
    pub matching_entries: u32,
    pub mismatched_entries: u32,
    pub match_ratio: f64,
    pub match_kind: String,
    pub dynamic_normalized_sha256: Option<String>,
    pub static_normalized_sha256: Option<String>,
    pub algorithm_hint: Option<String>,
    pub rationale: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct StaticBinaryAnalysis {
    pub binary_path: String,
    pub binary_sha256: String,
    pub format: String,
    pub architecture: String,
    pub elf_machine: u16,
    pub build_id: Option<String>,
    pub load_segments: u32,
    pub table_matches: Vec<StaticTableMatch>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RoundProfile {
    pub round_count: u32,
    /// 估计依据：主表读取次数。
    pub lookups: u32,
    /// 主表不同条目数。round_count = round(lookups / distinct_entries)。
    pub distinct_entries: u32,
    pub landmark_table: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AlgoVerdict {
    pub algorithm: String,
    pub block_bits: u32,
    pub round_count: Option<u32>,
    pub rationale: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum ImplementationKind {
    StandardSoftware,
    ObfuscatedStandardSoftware,
    TableDrivenSoftware,
    BitslicedSoftware,
    KeyFusedTables,
    Unknown,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum KeyExposure {
    RawKeyObserved,
    ExpandedScheduleObserved,
    DerivedKeyObserved,
    KeyDependentTablesOnly,
    NotObserved,
    Unknown,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum WhiteBoxStatus {
    NotWhiteBox,
    Candidate,
    Related,
    Verified,
    Unknown,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct WhiteBoxReport {
    /// 兼容字段；数据流确认角色前必须为空。
    pub plaintext: Option<IoBlock>,
    /// 兼容字段；数据流确认角色前必须为空。
    pub ciphertext: Option<IoBlock>,
    /// 全部输入缓冲候选（模块外连续 ≥16 字节读），按 seq 早→晚。透明列出供人核验。
    pub input_candidates: Vec<IoBlock>,
    pub output_candidates: Vec<IoBlock>,
    pub implementation_kind: ImplementationKind,
    pub key_exposure: KeyExposure,
    pub whitebox_status: WhiteBoxStatus,
    pub tables: Vec<TableRegion>,
    pub table_fingerprints: Vec<TableFingerprint>,
    pub encoding_boundaries: Vec<EncodingBoundaryEvidence>,
    pub static_binary: Option<StaticBinaryAnalysis>,
    pub table_read_total: u32,
    pub rounds: Option<RoundProfile>,
    pub verdict: AlgoVerdict,
    pub total_reads: u32,
    pub total_writes: u32,
    pub assessment: EvidenceAssessment,
    pub next_steps: Vec<String>,
    pub software_crypto: Option<crate::query::software_crypto::SoftwareCryptoReport>,
    pub aes_sbox_fingerprints: Vec<crate::query::software_aes::AesSboxFingerprint>,
    pub aes_key_schedules: Vec<crate::query::software_aes::AesKeyScheduleEvidence>,
    pub aes_semantic_verification: Option<crate::query::software_aes::AesSemanticVerification>,
}

// ── 小工具 ──

fn hex_bytes(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{:02x}", b));
    }
    s
}

fn ascii_bytes(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|&b| {
            if (0x20..0x7f).contains(&b) {
                b as char
            } else {
                '.'
            }
        })
        .collect()
}

fn is_printable(bytes: &[u8]) -> bool {
    !bytes.is_empty() && bytes.iter().all(|&b| (0x20..0x7f).contains(&b))
}

fn canonical_word(mut word: [u8; 4]) -> [u8; 4] {
    let original = word;
    let mut best = word;
    for reversed in [false, true] {
        word = original;
        if reversed {
            word.reverse();
        }
        for _ in 0..4 {
            best = best.min(word);
            word.rotate_left(1);
        }
    }
    best
}

fn gf_mul(mut a: u8, mut b: u8) -> u8 {
    let mut result = 0;
    for _ in 0..8 {
        if b & 1 != 0 {
            result ^= a;
        }
        let high = a & 0x80;
        a <<= 1;
        if high != 0 {
            a ^= 0x1b;
        }
        b >>= 1;
    }
    result
}

fn aes_sbox(value: u8) -> u8 {
    let inverse = if value == 0 {
        0
    } else {
        (0..=255_u16)
            .map(|candidate| candidate as u8)
            .find(|candidate| gf_mul(value, *candidate) == 1)
            .unwrap_or(0)
    };
    inverse
        ^ inverse.rotate_left(1)
        ^ inverse.rotate_left(2)
        ^ inverse.rotate_left(3)
        ^ inverse.rotate_left(4)
        ^ 0x63
}

fn aes_ttable_words() -> &'static [[u8; 4]] {
    static WORDS: OnceLock<Vec<[u8; 4]>> = OnceLock::new();
    WORDS
        .get_or_init(|| {
            let mut words = (0..=255_u16)
                .map(|value| {
                    let s = aes_sbox(value as u8);
                    canonical_word([gf_mul(s, 2), s, s, gf_mul(s, 3)])
                })
                .collect::<Vec<_>>();
            words.sort_unstable();
            words.dedup();
            words
        })
        .as_slice()
}

fn fingerprint_words(scope: String, mut words: Vec<[u8; 4]>) -> Option<TableFingerprint> {
    words.sort_unstable();
    words.dedup();
    if words.len() < 16 {
        return None;
    }
    let mut digest = Sha256::new();
    for word in &words {
        digest.update(word);
    }
    let normalized_sha256 = hex_bytes(&digest.finalize());
    let algorithm_hint =
        (words.as_slice() == aes_ttable_words()).then(|| "AES T-table candidate".into());
    Some(TableFingerprint {
        scope,
        normalized_sha256,
        word_bytes: 4,
        distinct_words: words.len() as u32,
        normalization: "word-byte-dihedral + entry-order invariant".into(),
        algorithm_hint,
    })
}

fn table_fingerprints(
    reads: &[MemAccess],
    tables: &[TableRegion],
    base: u64,
    window: u64,
) -> Vec<TableFingerprint> {
    let mut by_addr = BTreeMap::new();
    for access in reads
        .iter()
        .filter(|access| access.size == 4 && in_module(access.addr, base, window))
    {
        by_addr.insert(
            access.addr,
            canonical_word((access.value as u32).to_le_bytes()),
        );
    }
    let mut result = Vec::new();
    let mut region_words = Vec::new();
    for table in tables {
        if !table.crypto_eligible {
            continue;
        }
        let Some(start) = u64::from_str_radix(table.base_addr.trim_start_matches("0x"), 16).ok()
        else {
            continue;
        };
        let Some(end) = u64::from_str_radix(table.end_addr.trim_start_matches("0x"), 16).ok()
        else {
            continue;
        };
        let words = by_addr
            .range(start..=end)
            .map(|(_, word)| *word)
            .collect::<Vec<_>>();
        if let Some(fingerprint) = fingerprint_words(table.base_addr.clone(), words.clone()) {
            result.push(fingerprint);
        }
        region_words.push((start, table.base_addr.clone(), words));
    }

    region_words.sort_by_key(|(start, _, _)| *start);

    // A table may be split into separate address regions. Try pairwise unions so unrelated
    // in-module word reads or additional lookup tables do not poison the exact AES value set.
    for left in 0..region_words.len() {
        for right in left + 1..region_words.len() {
            let mut words = region_words[left].2.clone();
            words.extend_from_slice(&region_words[right].2);
            let scope = format!("{} + {}", region_words[left].1, region_words[right].1);
            let Some(fingerprint) = fingerprint_words(scope, words) else {
                continue;
            };
            if fingerprint.algorithm_hint.is_some()
                && !result.iter().any(|existing| {
                    existing.normalized_sha256 == fingerprint.normalized_sha256
                        && existing.algorithm_hint == fingerprint.algorithm_hint
                })
            {
                result.push(fingerprint);
            }
        }
    }

    if region_words.len() > 1 {
        let words = region_words
            .iter()
            .flat_map(|(_, _, words)| words.iter().copied())
            .collect::<Vec<_>>();
        if let Some(fingerprint) = fingerprint_words("all table regions".into(), words) {
            if !result
                .iter()
                .any(|existing| existing.normalized_sha256 == fingerprint.normalized_sha256)
            {
                result.push(fingerprint);
            }
        }
    }
    result
}

#[derive(Default)]
struct BoundaryAggregate {
    matched_events: u32,
    external_addrs: BTreeSet<u64>,
    external_start: u64,
    external_end: u64,
    first_seq: u32,
    last_seq: u32,
}

impl BoundaryAggregate {
    fn observe(&mut self, external: &MemAccess, related: &MemAccess) {
        if self.matched_events == 0 {
            self.external_start = external.addr;
            self.external_end = external
                .addr
                .saturating_add(external.size.clamp(1, 8) as u64 - 1);
            self.first_seq = external.seq.min(related.seq);
            self.last_seq = external.seq.max(related.seq);
        }
        self.matched_events = self.matched_events.saturating_add(1);
        self.external_start = self.external_start.min(external.addr);
        self.external_end = self.external_end.max(
            external
                .addr
                .saturating_add(external.size.clamp(1, 8) as u64 - 1),
        );
        self.first_seq = self.first_seq.min(external.seq.min(related.seq));
        self.last_seq = self.last_seq.max(external.seq.max(related.seq));
        for offset in 0..external.size.clamp(1, 8) as u64 {
            self.external_addrs
                .insert(external.addr.saturating_add(offset));
        }
    }

    fn qualifies(&self) -> bool {
        self.matched_events >= MIN_BOUNDARY_MATCHES
            && self.external_addrs.len() >= MIN_BOUNDARY_EXTERNAL_ADDRS
    }
}

fn parse_table_ranges(tables: &[TableRegion]) -> Vec<(usize, u64, u64)> {
    tables
        .iter()
        .enumerate()
        .filter(|(_, table)| table.crypto_eligible)
        .filter_map(|(index, table)| {
            let start = u64::from_str_radix(table.base_addr.trim_start_matches("0x"), 16).ok()?;
            let end = u64::from_str_radix(table.end_addr.trim_start_matches("0x"), 16).ok()?;
            Some((index, start, end))
        })
        .collect()
}

fn masked_value(access: &MemAccess) -> u64 {
    match access.size.clamp(1, 8) {
        8 => access.value,
        size => access.value & ((1_u64 << (size as u32 * 8)) - 1),
    }
}

#[derive(Clone, Copy)]
enum ElfEndian {
    Little,
    Big,
}

#[derive(Clone, Copy)]
struct ElfLoadSegment {
    file_offset: u64,
    virtual_address: u64,
    file_size: u64,
}

struct ElfLayout {
    class: u8,
    endian: ElfEndian,
    machine: u16,
    build_id: Option<String>,
    load_segments: Vec<ElfLoadSegment>,
}

fn align4(value: usize) -> Option<usize> {
    value.checked_add(3).map(|value| value & !3)
}

fn parse_gnu_build_id(
    bytes: &[u8],
    file_offset: u64,
    file_size: u64,
    endian: ElfEndian,
) -> Option<String> {
    let start = usize::try_from(file_offset).ok()?;
    let size = usize::try_from(file_size).ok()?;
    let end = start.checked_add(size)?.min(bytes.len());
    let mut cursor = start;
    while cursor.checked_add(12)? <= end {
        let name_size = elf_u32(bytes, cursor, endian).ok()? as usize;
        let description_size = elf_u32(bytes, cursor + 4, endian).ok()? as usize;
        let note_type = elf_u32(bytes, cursor + 8, endian).ok()?;
        let name_start = cursor.checked_add(12)?;
        let name_end = name_start.checked_add(name_size)?;
        let description_start = name_start.checked_add(align4(name_size)?)?;
        let description_end = description_start.checked_add(description_size)?;
        if description_end > end || name_end > end {
            return None;
        }
        if note_type == 3 && bytes.get(name_start..name_end)?.starts_with(b"GNU") {
            return Some(hex_bytes(bytes.get(description_start..description_end)?));
        }
        cursor = description_start.checked_add(align4(description_size)?)?;
    }
    None
}

fn elf_machine_name(machine: u16) -> &'static str {
    match machine {
        3 => "x86",
        40 => "ARM",
        62 => "x86-64",
        183 => "AArch64",
        243 => "RISC-V",
        _ => "Unknown",
    }
}

fn elf_u16(bytes: &[u8], offset: usize, endian: ElfEndian) -> Result<u16, String> {
    let raw: [u8; 2] = bytes
        .get(offset..offset + 2)
        .ok_or_else(|| "truncated ELF u16 field".to_string())?
        .try_into()
        .expect("slice length checked");
    Ok(match endian {
        ElfEndian::Little => u16::from_le_bytes(raw),
        ElfEndian::Big => u16::from_be_bytes(raw),
    })
}

fn elf_u32(bytes: &[u8], offset: usize, endian: ElfEndian) -> Result<u32, String> {
    let raw: [u8; 4] = bytes
        .get(offset..offset + 4)
        .ok_or_else(|| "truncated ELF u32 field".to_string())?
        .try_into()
        .expect("slice length checked");
    Ok(match endian {
        ElfEndian::Little => u32::from_le_bytes(raw),
        ElfEndian::Big => u32::from_be_bytes(raw),
    })
}

fn elf_u64(bytes: &[u8], offset: usize, endian: ElfEndian) -> Result<u64, String> {
    let raw: [u8; 8] = bytes
        .get(offset..offset + 8)
        .ok_or_else(|| "truncated ELF u64 field".to_string())?
        .try_into()
        .expect("slice length checked");
    Ok(match endian {
        ElfEndian::Little => u64::from_le_bytes(raw),
        ElfEndian::Big => u64::from_be_bytes(raw),
    })
}

fn parse_elf_layout(bytes: &[u8]) -> Result<ElfLayout, String> {
    if bytes.get(..4) != Some(b"\x7fELF") {
        return Err("static binary is not an ELF image".into());
    }
    let class = *bytes.get(4).ok_or("truncated ELF class")?;
    if !matches!(class, 1 | 2) {
        return Err(format!("unsupported ELF class {class}"));
    }
    let endian = match bytes.get(5) {
        Some(1) => ElfEndian::Little,
        Some(2) => ElfEndian::Big,
        other => return Err(format!("unsupported ELF byte order {other:?}")),
    };
    let machine = elf_u16(bytes, 18, endian)?;
    let (program_offset, entry_size, entry_count) = if class == 2 {
        (
            elf_u64(bytes, 32, endian)?,
            elf_u16(bytes, 54, endian)? as u64,
            elf_u16(bytes, 56, endian)? as u64,
        )
    } else {
        (
            elf_u32(bytes, 28, endian)? as u64,
            elf_u16(bytes, 42, endian)? as u64,
            elf_u16(bytes, 44, endian)? as u64,
        )
    };
    let minimum_entry_size = if class == 2 { 56 } else { 32 };
    if entry_size < minimum_entry_size {
        return Err(format!("invalid ELF program-header size {entry_size}"));
    }

    let mut load_segments = Vec::new();
    let mut build_id = None;
    for index in 0..entry_count {
        let header = program_offset
            .checked_add(index.saturating_mul(entry_size))
            .ok_or("ELF program-header offset overflow")? as usize;
        let program_type = elf_u32(bytes, header, endian)?;
        let (file_offset, virtual_address, file_size) = if class == 2 {
            (
                elf_u64(bytes, header + 8, endian)?,
                elf_u64(bytes, header + 16, endian)?,
                elf_u64(bytes, header + 32, endian)?,
            )
        } else {
            (
                elf_u32(bytes, header + 4, endian)? as u64,
                elf_u32(bytes, header + 8, endian)? as u64,
                elf_u32(bytes, header + 16, endian)? as u64,
            )
        };
        if file_offset.saturating_add(file_size) > bytes.len() as u64 {
            return Err("ELF program segment extends beyond the file".into());
        }
        if program_type == 4 && build_id.is_none() {
            build_id = parse_gnu_build_id(bytes, file_offset, file_size, endian);
        }
        if program_type != 1 {
            continue;
        }
        load_segments.push(ElfLoadSegment {
            file_offset,
            virtual_address,
            file_size,
        });
    }
    if load_segments.is_empty() {
        return Err("ELF contains no file-backed PT_LOAD segment".into());
    }
    Ok(ElfLayout {
        class,
        endian,
        machine,
        build_id,
        load_segments,
    })
}

fn elf_file_offset(layout: &ElfLayout, virtual_offset: u64, size: u8) -> Option<u64> {
    let width = size.clamp(1, 8) as u64;
    layout.load_segments.iter().find_map(|segment| {
        let relative = virtual_offset.checked_sub(segment.virtual_address)?;
        (relative.saturating_add(width) <= segment.file_size)
            .then(|| segment.file_offset.saturating_add(relative))
    })
}

fn static_value(bytes: &[u8], file_offset: u64, size: u8, endian: ElfEndian) -> Option<u64> {
    let width = size.clamp(1, 8) as usize;
    let data = bytes.get(file_offset as usize..file_offset as usize + width)?;
    let mut value = 0_u64;
    match endian {
        ElfEndian::Little => {
            for (shift, byte) in data.iter().enumerate() {
                value |= (*byte as u64) << (shift * 8);
            }
        }
        ElfEndian::Big => {
            for byte in data {
                value = (value << 8) | *byte as u64;
            }
        }
    }
    Some(value)
}

/// Reconcile file-backed ELF table bytes with the values actually read by the dynamic trace.
/// Exact matches prove that the executed table contents originated from the supplied binary, but
/// remain structural evidence: they do not prove a cipher, a key, or white-box status.
pub fn analyze_static_binary(
    binary_path: &str,
    bytes: &[u8],
    reads: &[MemAccess],
    tables: &[TableRegion],
    module_base: u64,
) -> Result<StaticBinaryAnalysis, String> {
    let layout = parse_elf_layout(bytes)?;
    let binary_sha256 = hex_bytes(&Sha256::digest(bytes));
    let mut table_matches = Vec::new();

    for table in tables.iter().filter(|table| table.crypto_eligible) {
        let Some(table_start) =
            u64::from_str_radix(table.base_addr.trim_start_matches("0x"), 16).ok()
        else {
            continue;
        };
        let Some(table_end) = u64::from_str_radix(table.end_addr.trim_start_matches("0x"), 16).ok()
        else {
            continue;
        };
        let module_offset = table_start.saturating_sub(module_base);
        let Some(first_file_offset) = elf_file_offset(&layout, module_offset, 1) else {
            continue;
        };

        let mut dynamic_entries = BTreeMap::new();
        for access in reads
            .iter()
            .filter(|access| access.addr >= table_start && access.addr <= table_end)
            .filter(|access| matches!(access.size, 1 | 2 | 4 | 8))
        {
            dynamic_entries.insert(access.addr, (access.value, access.size));
        }

        let mut compared = 0_u32;
        let mut matching = 0_u32;
        let mut dynamic_words = Vec::new();
        let mut static_words = Vec::new();
        for (address, (dynamic_value, size)) in dynamic_entries {
            let virtual_offset = address.saturating_sub(module_base);
            let Some(file_offset) = elf_file_offset(&layout, virtual_offset, size) else {
                continue;
            };
            let Some(file_value) = static_value(bytes, file_offset, size, layout.endian) else {
                continue;
            };
            compared += 1;
            let dynamic_masked = if size == 8 {
                dynamic_value
            } else {
                dynamic_value & ((1_u64 << (size as u32 * 8)) - 1)
            };
            if dynamic_masked == file_value {
                matching += 1;
            }
            if size == 4 {
                dynamic_words.push(canonical_word((dynamic_masked as u32).to_le_bytes()));
                static_words.push(canonical_word((file_value as u32).to_le_bytes()));
            }
        }
        if compared < MIN_BOUNDARY_MATCHES {
            continue;
        }
        let mismatched = compared - matching;
        let ratio = matching as f64 / compared as f64;
        let dynamic_fingerprint = fingerprint_words(table.base_addr.clone(), dynamic_words);
        let static_fingerprint = fingerprint_words(table.base_addr.clone(), static_words);
        let fingerprints_match = dynamic_fingerprint
            .as_ref()
            .zip(static_fingerprint.as_ref())
            .is_some_and(|(dynamic, static_)| {
                dynamic.normalized_sha256 == static_.normalized_sha256
            });
        let match_kind = if matching == compared {
            "ExactStaticDynamicMatch"
        } else if ratio >= 0.9 {
            "PartialStaticDynamicMatch"
        } else {
            "StaticDynamicMismatch"
        };
        let algorithm_hint = static_fingerprint
            .as_ref()
            .and_then(|fingerprint| fingerprint.algorithm_hint.clone())
            .or_else(|| {
                dynamic_fingerprint
                    .as_ref()
                    .and_then(|fingerprint| fingerprint.algorithm_hint.clone())
            });
        table_matches.push(StaticTableMatch {
            table_base: table.base_addr.clone(),
            module_offset: format!("0x{module_offset:x}"),
            file_offset: format!("0x{first_file_offset:x}"),
            compared_entries: compared,
            matching_entries: matching,
            mismatched_entries: mismatched,
            match_ratio: ratio,
            match_kind: match_kind.into(),
            dynamic_normalized_sha256: dynamic_fingerprint
                .as_ref()
                .map(|fingerprint| fingerprint.normalized_sha256.clone()),
            static_normalized_sha256: static_fingerprint
                .as_ref()
                .map(|fingerprint| fingerprint.normalized_sha256.clone()),
            algorithm_hint,
            rationale: format!(
                "{matching}/{compared} distinct dynamic table entries equal file-backed ELF bytes{}",
                if fingerprints_match {
                    "; normalized static/dynamic fingerprints also match"
                } else {
                    ""
                }
            ),
        });
    }

    table_matches.sort_by(|left, right| {
        right
            .match_ratio
            .total_cmp(&left.match_ratio)
            .then_with(|| right.compared_entries.cmp(&left.compared_entries))
    });
    table_matches.truncate(12);
    Ok(StaticBinaryAnalysis {
        binary_path: binary_path.into(),
        binary_sha256,
        format: format!(
            "ELF{} {}-endian",
            if layout.class == 2 { 64 } else { 32 },
            match layout.endian {
                ElfEndian::Little => "little",
                ElfEndian::Big => "big",
            }
        ),
        architecture: elf_machine_name(layout.machine).into(),
        elf_machine: layout.machine,
        build_id: layout.build_id,
        load_segments: layout.load_segments.len() as u32,
        table_matches,
    })
}

/// Locate conservative dynamic input/output encoding-boundary candidates around crypto-eligible
/// lookup tables. These correlations deliberately remain structural evidence and never open the
/// verification gate.
pub fn encoding_boundaries(
    reads: &[MemAccess],
    writes: &[MemAccess],
    tables: &[TableRegion],
    base: u64,
    window: u64,
) -> Vec<EncodingBoundaryEvidence> {
    let ranges = parse_table_ranges(tables);
    if ranges.is_empty() {
        return Vec::new();
    }

    let mut table_reads = reads
        .iter()
        .filter_map(|access| {
            ranges
                .iter()
                .find(|(_, start, end)| access.addr >= *start && access.addr <= *end)
                .map(|(table_index, _, _)| (access, *table_index))
        })
        .collect::<Vec<_>>();
    table_reads.sort_by_key(|(access, _)| access.seq);

    // Input: an external byte load is followed by an indexed lookup. Aggregate the inferred
    // table origin and stride so coincidental one-off pairs cannot become a report item.
    let mut input_groups: BTreeMap<(usize, u64, u8, u64), BoundaryAggregate> = BTreeMap::new();
    for external in reads
        .iter()
        .filter(|access| access.size == 1 && !in_module(access.addr, base, window))
    {
        let first = table_reads.partition_point(|(access, _)| access.seq <= external.seq);
        let last = table_reads.partition_point(|(access, _)| {
            access.seq <= external.seq.saturating_add(BOUNDARY_SEQ_WINDOW)
        });
        let index = (external.value & 0xff) as u64;
        for (table_read, table_index) in &table_reads[first..last] {
            let (_, region_start, region_end) = ranges
                .iter()
                .find(|(candidate, _, _)| candidate == table_index)
                .expect("table read came from a parsed range");
            for stride in [1_u8, 2, 4, 8] {
                let Some(origin) = table_read.addr.checked_sub(index * stride as u64) else {
                    continue;
                };
                // Permit an unobserved prefix and multiple adjacent lookup banks, while keeping
                // the inferred origin close enough to the clustered region to be meaningful.
                let max_index_span = 255_u64 * stride as u64;
                if origin < region_start.saturating_sub(max_index_span) || origin > *region_end {
                    continue;
                }
                input_groups
                    .entry((*table_index, external.insn_addr, stride, origin))
                    .or_default()
                    .observe(external, table_read);
            }
        }
    }

    let mut result = input_groups
        .into_iter()
        .filter(|(_, aggregate)| aggregate.qualifies())
        .map(
            |((table_index, boundary_site, stride, origin), aggregate)| {
                EncodingBoundaryEvidence {
                    direction: "InputEncodingCandidate".into(),
                    table_base: tables[table_index].base_addr.clone(),
                    boundary_site: format!("0x{boundary_site:x}"),
                    external_base_addr: format!("0x{:x}", aggregate.external_start),
                    external_end_addr: format!("0x{:x}", aggregate.external_end),
                    matched_events: aggregate.matched_events,
                    distinct_external_addrs: aggregate.external_addrs.len() as u32,
                    first_seq: aggregate.first_seq,
                    last_seq: aggregate.last_seq,
                    rationale: format!(
                        "external byte loads drive a stride-{stride} lookup (inferred table origin 0x{origin:x}) within {BOUNDARY_SEQ_WINDOW} seq"
                    ),
                }
            },
        )
        .collect::<Vec<_>>();

    // Output: a lookup value is stored unchanged outside the module shortly afterwards. Group by
    // table and store instruction site; exact width/value equality avoids byte-subset guessing.
    let mut external_writes = writes
        .iter()
        .filter(|access| !in_module(access.addr, base, window))
        .collect::<Vec<_>>();
    external_writes.sort_by_key(|access| access.seq);
    let mut output_groups: BTreeMap<(usize, u64), BoundaryAggregate> = BTreeMap::new();
    for (table_read, table_index) in &table_reads {
        let first = external_writes.partition_point(|access| access.seq <= table_read.seq);
        let last = external_writes.partition_point(|access| {
            access.seq <= table_read.seq.saturating_add(BOUNDARY_SEQ_WINDOW)
        });
        for external in &external_writes[first..last] {
            if external.size != table_read.size
                || masked_value(external) != masked_value(table_read)
            {
                continue;
            }
            output_groups
                .entry((*table_index, external.insn_addr))
                .or_default()
                .observe(external, table_read);
        }
    }
    result.extend(
        output_groups
            .into_iter()
            .filter(|(_, aggregate)| aggregate.qualifies())
            .map(|((table_index, boundary_site), aggregate)| EncodingBoundaryEvidence {
                direction: "OutputEncodingCandidate".into(),
                table_base: tables[table_index].base_addr.clone(),
                boundary_site: format!("0x{boundary_site:x}"),
                external_base_addr: format!("0x{:x}", aggregate.external_start),
                external_end_addr: format!("0x{:x}", aggregate.external_end),
                matched_events: aggregate.matched_events,
                distinct_external_addrs: aggregate.external_addrs.len() as u32,
                first_seq: aggregate.first_seq,
                last_seq: aggregate.last_seq,
                rationale: format!(
                    "lookup values are stored unchanged outside the module within {BOUNDARY_SEQ_WINDOW} seq"
                ),
            }),
    );

    result.sort_by(|left, right| {
        right
            .distinct_external_addrs
            .cmp(&left.distinct_external_addrs)
            .then_with(|| right.matched_events.cmp(&left.matched_events))
            .then_with(|| left.first_seq.cmp(&right.first_seq))
    });
    // Different inferred strides can describe the same observed boundary. Keep the strongest one
    // per direction/table/site/external range so the report stays compact.
    let mut seen = BTreeSet::new();
    result.retain(|candidate| {
        seen.insert((
            candidate.direction.clone(),
            candidate.table_base.clone(),
            candidate.boundary_site.clone(),
            candidate.external_base_addr.clone(),
            candidate.external_end_addr.clone(),
        ))
    });
    result.truncate(MAX_BOUNDARY_CANDIDATES);
    result
}

#[inline]
fn in_module(addr: u64, base: u64, window: u64) -> bool {
    base != 0 && addr >= base && addr < base.saturating_add(window)
}

struct LaidByte {
    seq: u32,
    val: u8,
}

/// 把访问序列铺成 addr→byte，冲突时按 `want_earliest` 取最早/最晚 seq 的字节。
fn lay_bytes(items: &[MemAccess], want_earliest: bool) -> BTreeMap<u64, LaidByte> {
    let mut map: BTreeMap<u64, LaidByte> = BTreeMap::new();
    for a in items {
        let size = a.size.clamp(1, 8) as u64;
        for i in 0..size {
            let byte = ((a.value >> (i * 8)) & 0xff) as u8;
            let addr = a.addr.wrapping_add(i);
            let replace = match map.get(&addr) {
                Some(existing) => {
                    if want_earliest {
                        a.seq < existing.seq
                    } else {
                        a.seq >= existing.seq
                    }
                }
                None => true,
            };
            if replace {
                map.insert(
                    addr,
                    LaidByte {
                        seq: a.seq,
                        val: byte,
                    },
                );
            }
        }
    }
    map
}

/// Stage A：找出所有模块外、长度 ≥16 的连续字节缓冲，作为 I/O 候选。
/// `want_earliest` 决定冲突取值与排序方向（读→最早在前；写→最晚在前）。
/// `byte_only` 仅保留单字节访问：白盒明文按字节逐个查表读入，据此可排除寄存器溢出等字/双字访问。
pub fn io_candidates(
    items: &[MemAccess],
    base: u64,
    window: u64,
    want_earliest: bool,
    byte_only: bool,
) -> Vec<IoBlock> {
    let filtered: Vec<MemAccess> = items
        .iter()
        .copied()
        .filter(|a| !in_module(a.addr, base, window) && (!byte_only || a.size == 1))
        .collect();
    let map = lay_bytes(&filtered, want_earliest);
    let addrs: Vec<u64> = map.keys().copied().collect();

    let mut out: Vec<IoBlock> = Vec::new();
    let mut i = 0usize;
    while i < addrs.len() {
        let mut j = i + 1;
        while j < addrs.len() && addrs[j] == addrs[j - 1] + 1 {
            j += 1;
        }
        let run_len = j - i;
        if run_len >= MIN_BLOCK_LEN {
            let take = run_len.min(MAX_BLOCK_LEN);
            let mut bytes = Vec::with_capacity(take);
            let mut first_seq = u32::MAX;
            let mut last_seq = u32::MIN;
            for k in i..i + take {
                let lb = &map[&addrs[k]];
                bytes.push(lb.val);
                first_seq = first_seq.min(lb.seq);
                last_seq = last_seq.max(lb.seq);
            }
            out.push(IoBlock {
                base_addr: format!("0x{:x}", addrs[i]),
                byte_len: take as u32,
                bytes_hex: hex_bytes(&bytes),
                ascii: ascii_bytes(&bytes),
                printable: is_printable(&bytes),
                first_seq,
                last_seq,
            });
        }
        i = j;
    }

    if want_earliest {
        out.sort_by_key(|b| b.first_seq);
    } else {
        out.sort_by(|a, b| b.last_seq.cmp(&a.last_seq));
    }
    out.truncate(MAX_IO_CANDIDATES);
    out
}

/// Stage B：把模块内的 load 地址聚类成 T-box 表区域，按读取次数降序。
pub fn cluster_tables(
    reads: &[MemAccess],
    base: u64,
    window: u64,
    max_tables: usize,
) -> (Vec<TableRegion>, u32) {
    let mut per_addr: BTreeMap<u64, (u32, BTreeMap<u8, u32>, u32, u32)> = BTreeMap::new();
    for a in reads {
        if !in_module(a.addr, base, window) {
            continue;
        }
        let e = per_addr
            .entry(a.addr)
            .or_insert((0, BTreeMap::new(), a.seq, a.seq));
        e.0 += 1;
        *e.1.entry(a.size).or_insert(0) += 1;
        e.2 = e.2.min(a.seq);
        e.3 = e.3.max(a.seq);
    }
    if per_addr.is_empty() {
        return (Vec::new(), 0);
    }

    let addrs: Vec<u64> = per_addr.keys().copied().collect();
    let mut regions: Vec<TableRegion> = Vec::new();
    let mut i = 0usize;
    while i < addrs.len() {
        let mut j = i + 1;
        while j < addrs.len() && addrs[j] - addrs[j - 1] <= TABLE_CLUSTER_GAP {
            j += 1;
        }
        let mut read_count = 0u32;
        let mut size_hist: BTreeMap<u8, u32> = BTreeMap::new();
        let mut first_seq = u32::MAX;
        let mut last_seq = u32::MIN;
        for k in i..j {
            let (c, sizes, fs, ls) = &per_addr[&addrs[k]];
            read_count += *c;
            for (sz, n) in sizes {
                *size_hist.entry(*sz).or_insert(0) += *n;
            }
            first_seq = first_seq.min(*fs);
            last_seq = last_seq.max(*ls);
        }
        let dominant_size = size_hist
            .iter()
            .max_by_key(|(_, n)| **n)
            .map(|(sz, _)| *sz)
            .unwrap_or(0);
        let base_a = addrs[i];
        let end_a = addrs[j - 1];
        let pointer_like_entries = pointer_like_table_entries(reads, base_a, end_a, base, window);
        let crypto_eligible = (j - i) < 8 || pointer_like_entries * 4 < (j - i) as u32 * 3;
        regions.push(TableRegion {
            base_addr: format!("0x{:x}", base_a),
            end_addr: format!("0x{:x}", end_a),
            module_offset: format!("0x{:x}", base_a.saturating_sub(base)),
            span_bytes: end_a - base_a + 1,
            distinct_addrs: (j - i) as u32,
            read_count,
            dominant_size,
            first_seq,
            last_seq,
            role_hint: if crypto_eligible {
                TableRoleHint::LookupData
            } else {
                TableRoleHint::ControlFlowDispatcherCandidate
            },
            crypto_eligible,
            pointer_like_entries,
        });
        i = j;
    }

    let crypto_total = regions
        .iter()
        .filter(|region| region.crypto_eligible)
        .map(|region| region.read_count)
        .sum();

    regions.sort_by(|a, b| {
        b.read_count
            .cmp(&a.read_count)
            .then(a.base_addr.cmp(&b.base_addr))
    });
    regions.truncate(max_tables);
    (regions, crypto_total)
}

fn pointer_like_table_entries(
    reads: &[MemAccess],
    start: u64,
    end: u64,
    module_base: u64,
    module_window: u64,
) -> u32 {
    let module_end = module_base.saturating_add(module_window);
    let mut entries = BTreeMap::new();
    for access in reads
        .iter()
        .filter(|access| access.addr >= start && access.addr <= end)
        .filter(|access| matches!(access.size, 4 | 8))
    {
        entries.insert(access.addr, (access.value, access.size));
    }
    entries
        .values()
        .filter(|(value, size)| {
            let absolute = *value >= module_base && *value < module_end;
            let relative = if *size == 4 {
                let displacement = (*value as u32 as i32) as i64;
                let target = if displacement >= 0 {
                    start.checked_add(displacement as u64)
                } else {
                    start.checked_sub(displacement.unsigned_abs())
                };
                target.is_some_and(|target| target >= module_base && target < module_end)
            } else {
                false
            };
            absolute || relative
        })
        .count() as u32
}

/// Stage C：由主表「读取次数 ÷ 不同条目数」估计轮数（每条目每轮命中一次的近似）。
/// 仅当主表足够「主导」（大量读 + 足够条目）时才给出，避免对偶发访问乱估。
pub fn estimate_rounds(main: &TableRegion) -> Option<RoundProfile> {
    if !main.crypto_eligible
        || main.read_count < DOMINANT_TABLE_MIN_READS
        || main.distinct_addrs < DOMINANT_TABLE_MIN_DISTINCT
    {
        return None;
    }
    let ratio = main.read_count as f64 / main.distinct_addrs as f64;
    let round_count = ratio.round().clamp(1.0, 64.0) as u32;
    Some(RoundProfile {
        round_count,
        lookups: main.read_count,
        distinct_entries: main.distinct_addrs,
        landmark_table: main.base_addr.clone(),
    })
}

/// Stage D：由分组位宽 + 轮数匹配已知密码的结构不变量。
pub fn classify(block_bytes: u32, round_count: Option<u32>) -> AlgoVerdict {
    let block_bits = block_bytes * 8;
    let (algorithm, rationale) = match (block_bytes, round_count) {
        (16, Some(10)) => (
            "AES-128".into(),
            "128-bit 分组 + ~10 轮，符合 AES-128。".into(),
        ),
        (16, Some(11)) => (
            "AES-128".into(),
            "128-bit 分组 + ~11 轮（含末轮），符合 AES-128。".into(),
        ),
        (16, Some(12)) => (
            "AES-192".into(),
            "128-bit 分组 + ~12 轮，符合 AES-192。".into(),
        ),
        (16, Some(14)) => (
            "AES-256".into(),
            "128-bit 分组 + ~14 轮，符合 AES-256。".into(),
        ),
        (8, Some(16)) => (
            "DES".into(),
            "64-bit 分组 + 16 轮，符合 DES/3DES 单次。".into(),
        ),
        (16, Some(32)) => ("SM4".into(), "128-bit 分组 + 32 轮，符合 SM4。".into()),
        (16, Some(r)) => (
            "AES-family (128-bit)".into(),
            format!("128-bit 分组；轮数估计 {r} 不落在 10/12/14，判为 AES 家族但变体未定。"),
        ),
        (16, None) => (
            "AES-family (128-bit)".into(),
            "128-bit 分组；轮数未能估计。".into(),
        ),
        (bl, r) => (
            "未定".into(),
            format!("分组 {bl} 字节、轮数 {r:?} 未匹配 AES/DES/SM4。"),
        ),
    };
    AlgoVerdict {
        algorithm,
        block_bits,
        round_count,
        rationale,
    }
}

/// 组装完整报告并评分。
pub fn analyze(
    reads: &[MemAccess],
    writes: &[MemAccess],
    opts: &WhiteBoxOptions,
) -> WhiteBoxReport {
    let base = opts.module_base;
    let window = opts.module_window;

    let input_candidates = io_candidates(reads, base, window, true, true);
    let output_candidates = io_candidates(writes, base, window, false, false);
    let (tables, table_read_total) = cluster_tables(reads, base, window, 12);
    let table_fingerprints = table_fingerprints(reads, &tables, base, window);
    let encoding_boundaries = encoding_boundaries(reads, writes, &tables, base, window);
    let rounds = tables
        .iter()
        .find(|table| table.crypto_eligible)
        .and_then(estimate_rounds);

    // Stage A 不再从“存在 16B 候选”推断真实分组位宽。
    let block_bytes = 0;
    let round_count = rounds.as_ref().map(|r| r.round_count);
    let verdict = classify(block_bytes, round_count);

    let assessment = assess(
        &input_candidates,
        &tables,
        &table_fingerprints,
        &encoding_boundaries,
        table_read_total,
        &verdict,
    );

    WhiteBoxReport {
        plaintext: None,
        ciphertext: None,
        input_candidates,
        output_candidates,
        implementation_kind: if tables.iter().any(|table| table.crypto_eligible) {
            ImplementationKind::TableDrivenSoftware
        } else {
            ImplementationKind::Unknown
        },
        key_exposure: KeyExposure::Unknown,
        whitebox_status: WhiteBoxStatus::Unknown,
        tables,
        table_fingerprints,
        encoding_boundaries,
        static_binary: None,
        table_read_total,
        rounds,
        verdict,
        total_reads: reads.len() as u32,
        total_writes: writes.len() as u32,
        assessment,
        next_steps: vec![
            "用数据流确认 key/input/output/IV 角色；可打印性仅作展示属性。".to_string(),
            "验证标准 key schedule，并对至少一个完整 block 做语义复算。".to_string(),
            "只有复算一致后才升级为 verified；white-box 属性需独立证据。".to_string(),
        ],
        software_crypto: None,
        aes_sbox_fingerprints: Vec::new(),
        aes_key_schedules: Vec::new(),
        aes_semantic_verification: None,
    }
}

fn assess(
    input_candidates: &[IoBlock],
    tables: &[TableRegion],
    table_fingerprints: &[TableFingerprint],
    encoding_boundaries: &[EncodingBoundaryEvidence],
    table_read_total: u32,
    verdict: &AlgoVerdict,
) -> EvidenceAssessment {
    let dominant_table = tables.iter().find(|table| {
        table.crypto_eligible
            && table.read_count >= DOMINANT_TABLE_MIN_READS
            && table.distinct_addrs >= DOMINANT_TABLE_MIN_DISTINCT
    });
    let dominant = dominant_table.is_some();
    let has_io = !input_candidates.is_empty();
    let heavy_lookups = table_read_total >= 256;
    let round_matched = matches!(
        (verdict.round_count, verdict.block_bits),
        (Some(10), 128)
            | (Some(11), 128)
            | (Some(12), 128)
            | (Some(14), 128)
            | (Some(16), 64)
            | (Some(32), 128)
    );
    let algo_known = verdict.algorithm.starts_with("AES-")
        || verdict.algorithm == "DES"
        || verdict.algorithm == "SM4";
    let block_known = verdict.block_bits == 64 || verdict.block_bits == 128;
    let aes_ttable_fingerprint = table_fingerprints
        .iter()
        .find(|fingerprint| fingerprint.algorithm_hint.as_deref() == Some("AES T-table candidate"));
    let has_encoding_boundary = !encoding_boundaries.is_empty();

    // 结构证据永远不能打开验证 gate；Stage B/C 的语义复算结果才可以。
    let gate = false;

    let signals = vec![
        EvidenceScoreSignal::new(
            "dominant_lookup_table",
            "存在主导 T-box：单张表被大量 load、覆盖数百不同条目。",
            30,
            dominant,
            dominant_table.map(|t| {
                format!(
                    "{} reads / {} entries @ {}",
                    t.read_count, t.distinct_addrs, t.base_addr
                )
            }),
        ),
        EvidenceScoreSignal::new(
            "aes_ttable_fingerprint",
            "Normalized 32-bit table contents match the standard AES T-table value set.",
            20,
            aes_ttable_fingerprint.is_some(),
            aes_ttable_fingerprint.map(|fingerprint| {
                format!(
                    "{} distinct words, endian/rotation/order invariant",
                    fingerprint.distinct_words
                )
            }),
        ),
        EvidenceScoreSignal::new(
            "encoding_boundary_candidate",
            "External data is dynamically correlated with a crypto-eligible lookup table at a stable boundary site.",
            15,
            has_encoding_boundary,
            encoding_boundaries.first().map(|boundary| {
                format!(
                    "{}: {} matched events / {} external addresses @ {}",
                    boundary.direction,
                    boundary.matched_events,
                    boundary.distinct_external_addrs,
                    boundary.boundary_site
                )
            }),
        ),
        EvidenceScoreSignal::new(
            "lookup_volume",
            "查表读取总量 ≥256（非孤立访问，符合查表型密码）。",
            15,
            heavy_lookups,
            heavy_lookups.then(|| format!("table_reads={}", table_read_total)),
        ),
        EvidenceScoreSignal::new(
            "io_buffer",
            "定位到模块外连续 ≥16 字节的 I/O 缓冲（分组明文/状态）。",
            15,
            has_io,
            input_candidates
                .first()
                .map(|b| format!("{} @seq {}", b.base_addr, b.first_seq)),
        ),
        EvidenceScoreSignal::new(
            "round_count_in_range",
            "由主表命中率估计的轮数落在已知密码上（10/12/14 → AES；16 → DES；32 → SM4）。",
            20,
            round_matched,
            verdict
                .round_count
                .filter(|_| round_matched)
                .map(|r| format!("rounds≈{}", r)),
        ),
        EvidenceScoreSignal::new(
            "block_size_known",
            "分组位宽为 64 或 128 bit。",
            10,
            block_known,
            block_known.then(|| format!("{}-bit", verdict.block_bits)),
        ),
        EvidenceScoreSignal::new(
            "algorithm_matched",
            "分组 + 轮数匹配到某已知密码算法。",
            10,
            algo_known,
            algo_known.then(|| verdict.algorithm.clone()),
        ),
    ];

    score_evidence(
        "software_table_crypto",
        gate,
        signals,
        vec![
            "结构候选不证明具体算法、方向、模式、角色或 white-box 属性。".to_string(),
            "轮数由「主表读取次数 ÷ 不同条目数」估计（≈每条目每轮命中一次），非精确轮数。"
                .to_string(),
            "表区域由地址聚类得出，可能合并相邻表或切碎稀疏表。".to_string(),
            "输入和输出保持中性候选，角色必须由数据流确认。".to_string(),
            "encoding boundary 是短窗口动态相关性，仍可能来自拷贝、序列化或其他查表逻辑。"
                .to_string(),
            "verified 只允许由语义复算打开。".to_string(),
        ],
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    const BASE: u64 = 0x7000_0000;
    const WINDOW: u64 = 0x0200_0000;
    const TBL: u64 = 0x7004_5000; // 模块内
    const STACK: u64 = 0x7fff_0000; // 模块外

    fn acc(seq: u32, addr: u64, value: u64, size: u8) -> MemAccess {
        MemAccess {
            seq,
            insn_addr: 0x7000_1000,
            addr,
            value,
            size,
        }
    }

    #[test]
    fn printable_buffer_remains_a_neutral_input_candidate() {
        let mut reads = Vec::new();
        // 更早的二进制缓冲（seq 100）
        for i in 0..16u32 {
            reads.push(acc(100 + i, STACK + i as u64, 0x00, 1));
        }
        // 稍晚的可打印明文（seq 500）
        let pt = b"Safe_box_1234567";
        for (i, &b) in pt.iter().enumerate() {
            reads.push(acc(500 + i as u32, STACK + 0x100 + i as u64, b as u64, 1));
        }
        let cands = io_candidates(&reads, BASE, WINDOW, true, true);
        assert_eq!(cands.len(), 2);
        assert_eq!(cands[0].first_seq, 100); // 最早在前
        assert_eq!(cands[1].ascii, "Safe_box_1234567");
        assert!(cands[1].printable);
    }

    #[test]
    fn ciphertext_reconstructed_from_word_writes() {
        let mut writes = Vec::new();
        writes.push(acc(9000, STACK + 0x200, 0x1122334455667788, 8));
        writes.push(acc(9001, STACK + 0x208, 0x99aabbccddeeff00, 8));
        let ct = io_candidates(&writes, BASE, WINDOW, false, false)
            .into_iter()
            .next()
            .unwrap();
        assert_eq!(ct.byte_len, 16);
        assert!(ct.bytes_hex.starts_with("8877665544332211"));
    }

    #[test]
    fn tables_clustered_and_ranked() {
        let mut reads = Vec::new();
        for r in 0..300u32 {
            reads.push(acc(1000 + r, TBL + (r as u64 % 256), 0x5a, 1));
        }
        for r in 0..20u32 {
            reads.push(acc(5000 + r, TBL + 0x9000 + (r as u64 % 16), 0x33, 1));
        }
        reads.push(acc(20, STACK, 0x1, 1)); // 模块外噪声
        let (tables, total) = cluster_tables(&reads, BASE, WINDOW, 12);
        assert_eq!(tables.len(), 2);
        assert_eq!(tables[0].base_addr, format!("0x{:x}", TBL));
        assert_eq!(total, 320);
        assert_eq!(tables[0].module_offset, "0x45000");
    }

    #[test]
    fn round_estimate_from_reads_per_entry() {
        // 260 条目各读 10 次 → 2600 读 → 10 轮（满足 dominant 阈值 distinct≥256）
        let mut reads = Vec::new();
        for round in 0..10u32 {
            for k in 0..260u32 {
                reads.push(acc(round * 1000 + k, TBL + k as u64, 0x5a, 1));
            }
        }
        let (tables, _) = cluster_tables(&reads, BASE, WINDOW, 12);
        let rp = estimate_rounds(&tables[0]).unwrap();
        assert_eq!(rp.round_count, 10);
        assert_eq!(rp.distinct_entries, 260);
        assert_eq!(rp.lookups, 2600);
    }

    #[test]
    fn classify_known_ciphers() {
        assert_eq!(classify(16, Some(10)).algorithm, "AES-128");
        assert_eq!(classify(16, Some(14)).algorithm, "AES-256");
        assert_eq!(classify(8, Some(16)).algorithm, "DES");
        assert_eq!(classify(16, Some(32)).algorithm, "SM4");
        assert!(classify(16, None).algorithm.contains("AES-family"));
    }

    #[test]
    fn structural_aes_like_pattern_is_related_not_verified() {
        let mut reads = Vec::new();
        let mut writes = Vec::new();
        let pt = b"Safe_box_1234567";
        for (i, &b) in pt.iter().enumerate() {
            reads.push(acc(10 + i as u32, STACK + i as u64, b as u64, 1));
        }
        // 主表：260 条目各 10 次 = 2600 读（满足 dominant 阈值 reads≥1000 & distinct≥256），10 轮
        for round in 0..10u32 {
            for k in 0..260u32 {
                reads.push(acc(2000 + round * 1000 + k, TBL + k as u64, 0x5a, 1));
            }
        }
        writes.push(acc(90000, STACK + 0x100, 0x1122334455667788, 8));
        writes.push(acc(90001, STACK + 0x108, 0x99aabbccddeeff00, 8));

        let opts = WhiteBoxOptions {
            algorithm: "aes".into(),
            module_base: BASE,
            module_window: WINDOW,
            static_binary_path: None,
        };
        let rep = analyze(&reads, &writes, &opts);
        assert!(rep.plaintext.is_none());
        assert!(rep.ciphertext.is_none());
        assert_eq!(rep.input_candidates[0].ascii, "Safe_box_1234567");
        assert_eq!(rep.output_candidates.len(), 1);
        assert_eq!(rep.verdict.algorithm, "未定");
        assert_eq!(rep.rounds.as_ref().unwrap().round_count, 10);
        assert_eq!(rep.assessment.grade, "related");
        assert!(!rep.assessment.verification_gate_met);
        assert!(matches!(rep.whitebox_status, WhiteBoxStatus::Unknown));
    }

    #[test]
    fn aes_ttable_fingerprint_survives_endian_rotation_order_and_split() {
        let mut reads = Vec::new();
        for slot in 0..256_usize {
            let value = 255 - slot;
            let s = aes_sbox(value as u8);
            let mut bytes = [gf_mul(s, 2), s, s, gf_mul(s, 3)];
            bytes.rotate_left(slot % 4);
            if slot % 2 == 0 {
                bytes.reverse();
            }
            let table_base = if slot < 128 { TBL } else { TBL + 0x4000 };
            let local_slot = slot % 128;
            reads.push(acc(
                slot as u32,
                table_base + (local_slot * 4) as u64,
                u32::from_le_bytes(bytes) as u64,
                4,
            ));
        }
        for index in 0..32_u32 {
            reads.push(acc(
                10_000 + index,
                TBL + 0x9000 + index as u64 * 4,
                index.wrapping_mul(0x0102_0305) as u64,
                4,
            ));
        }
        let (tables, _) = cluster_tables(&reads, BASE, WINDOW, 12);
        assert_eq!(tables.len(), 3);
        let fingerprints = table_fingerprints(&reads, &tables, BASE, WINDOW);
        let split_match = fingerprints
            .iter()
            .find(|fingerprint| {
                fingerprint.scope.contains(" + ") && fingerprint.algorithm_hint.is_some()
            })
            .unwrap();
        assert_eq!(
            split_match.distinct_words as usize,
            aes_ttable_words().len()
        );
        assert_eq!(
            split_match.algorithm_hint.as_deref(),
            Some("AES T-table candidate")
        );

        let assessment = assess(
            &[],
            &tables,
            &fingerprints,
            &[],
            reads.len() as u32,
            &classify(0, None),
        );
        assert!(assessment
            .factors
            .iter()
            .any(|factor| factor.code == "aes_ttable_fingerprint" && factor.observed));
        assert!(!assessment.verification_gate_met);
        assert_ne!(assessment.grade, "verified");
    }

    #[test]
    fn unrelated_word_table_gets_fingerprint_without_aes_hint() {
        let reads = (0..256_u32)
            .map(|index| {
                acc(
                    index,
                    TBL + index as u64 * 4,
                    index.wrapping_mul(0x0102_0305) as u64,
                    4,
                )
            })
            .collect::<Vec<_>>();
        let (tables, _) = cluster_tables(&reads, BASE, WINDOW, 12);
        let fingerprints = table_fingerprints(&reads, &tables, BASE, WINDOW);
        assert_eq!(fingerprints.len(), 1);
        assert!(fingerprints[0].algorithm_hint.is_none());
    }

    #[test]
    fn detects_input_and_output_encoding_boundary_candidates() {
        let mut reads = Vec::new();
        let mut writes = Vec::new();
        for index in 0..16_u32 {
            let input_value = (index * 11) as u8;
            let table_value = 0x8102_0300_u64 + index as u64;
            let input_seq = index * 32;
            reads.push(acc(input_seq, STACK + index as u64, input_value as u64, 1));
            reads.push(acc(
                input_seq + 1,
                TBL + input_value as u64 * 4,
                table_value,
                4,
            ));

            let output_seq = 10_000 + index * 32;
            reads.push(acc(
                output_seq,
                TBL + 0x800 + index as u64 * 4,
                table_value,
                4,
            ));
            writes.push(acc(
                output_seq + 1,
                STACK + 0x100 + index as u64 * 4,
                table_value,
                4,
            ));
        }

        let report = analyze(
            &reads,
            &writes,
            &WhiteBoxOptions {
                algorithm: "aes".into(),
                module_base: BASE,
                module_window: WINDOW,
                static_binary_path: None,
            },
        );
        let input = report
            .encoding_boundaries
            .iter()
            .find(|boundary| boundary.direction == "InputEncodingCandidate")
            .unwrap();
        assert_eq!(input.distinct_external_addrs, 16);
        assert!(input.rationale.contains("stride-4"));
        let output = report
            .encoding_boundaries
            .iter()
            .find(|boundary| boundary.direction == "OutputEncodingCandidate")
            .unwrap();
        assert_eq!(output.matched_events, 16);
        assert_eq!(output.distinct_external_addrs, 64);
        assert!(report
            .assessment
            .factors
            .iter()
            .any(|factor| { factor.code == "encoding_boundary_candidate" && factor.observed }));
        assert!(!report.assessment.verification_gate_met);
        assert_ne!(report.assessment.grade, "verified");
    }

    #[test]
    fn delayed_or_scattered_boundary_correlations_are_rejected() {
        let mut reads = Vec::new();
        let mut writes = Vec::new();
        for index in 0..16_u32 {
            let value = (index * 7) as u8;
            let seq = index * 100;
            reads.push(acc(seq, STACK + index as u64, value as u64, 1));
            reads.push(acc(
                seq + BOUNDARY_SEQ_WINDOW + 1,
                TBL + value as u64 * 4,
                0x5500 + index as u64,
                4,
            ));

            let output_seq = 10_000 + index * 100;
            reads.push(acc(
                output_seq,
                TBL + 0x800 + index as u64 * 4,
                0x6600 + index as u64,
                4,
            ));
            writes.push(acc(output_seq + 1, STACK + 0x400, 0x6600 + index as u64, 4));
        }
        let (tables, _) = cluster_tables(&reads, BASE, WINDOW, 12);
        let boundaries = encoding_boundaries(&reads, &writes, &tables, BASE, WINDOW);
        assert!(boundaries.is_empty());
    }

    fn synthetic_elf64(table_virtual_offset: u64, table_words: &[u32]) -> Vec<u8> {
        let segment_file_offset = 0x1000_usize;
        let segment_size = 0x1000_usize;
        let mut elf = vec![0_u8; segment_file_offset + segment_size];
        elf[0..4].copy_from_slice(b"\x7fELF");
        elf[4] = 2; // ELF64
        elf[5] = 1; // little endian
        elf[6] = 1; // ELF version
        elf[16..18].copy_from_slice(&3_u16.to_le_bytes()); // ET_DYN
        elf[18..20].copy_from_slice(&183_u16.to_le_bytes()); // AArch64
        elf[20..24].copy_from_slice(&1_u32.to_le_bytes());
        elf[32..40].copy_from_slice(&64_u64.to_le_bytes()); // e_phoff
        elf[52..54].copy_from_slice(&64_u16.to_le_bytes()); // e_ehsize
        elf[54..56].copy_from_slice(&56_u16.to_le_bytes()); // e_phentsize
        elf[56..58].copy_from_slice(&1_u16.to_le_bytes()); // e_phnum

        let ph = 64_usize;
        elf[ph..ph + 4].copy_from_slice(&1_u32.to_le_bytes()); // PT_LOAD
        elf[ph + 4..ph + 8].copy_from_slice(&4_u32.to_le_bytes()); // PF_R
        elf[ph + 8..ph + 16].copy_from_slice(&(segment_file_offset as u64).to_le_bytes());
        elf[ph + 16..ph + 24].copy_from_slice(&table_virtual_offset.to_le_bytes());
        elf[ph + 24..ph + 32].copy_from_slice(&table_virtual_offset.to_le_bytes());
        elf[ph + 32..ph + 40].copy_from_slice(&(segment_size as u64).to_le_bytes());
        elf[ph + 40..ph + 48].copy_from_slice(&(segment_size as u64).to_le_bytes());
        elf[ph + 48..ph + 56].copy_from_slice(&0x1000_u64.to_le_bytes());
        for (index, word) in table_words.iter().enumerate() {
            let offset = segment_file_offset + index * 4;
            elf[offset..offset + 4].copy_from_slice(&word.to_le_bytes());
        }
        elf
    }

    #[test]
    fn joins_dynamic_table_reads_to_file_backed_elf_bytes() {
        let words = (0..32_u32)
            .map(|index| index.wrapping_mul(0x0102_0305).wrapping_add(0x1122_3344))
            .collect::<Vec<_>>();
        let reads = words
            .iter()
            .enumerate()
            .map(|(index, word)| acc(index as u32, TBL + index as u64 * 4, *word as u64, 4))
            .collect::<Vec<_>>();
        let (tables, _) = cluster_tables(&reads, BASE, WINDOW, 12);
        let module_offset = TBL - BASE;
        let elf = synthetic_elf64(module_offset, &words);
        let analysis = analyze_static_binary("fixture.so", &elf, &reads, &tables, BASE).unwrap();
        assert_eq!(analysis.format, "ELF64 little-endian");
        assert_eq!(analysis.architecture, "AArch64");
        assert_eq!(analysis.elf_machine, 183);
        assert!(analysis.build_id.is_none());
        assert_eq!(analysis.load_segments, 1);
        assert_eq!(analysis.table_matches.len(), 1);
        let joined = &analysis.table_matches[0];
        assert_eq!(joined.file_offset, "0x1000");
        assert_eq!(joined.compared_entries, 32);
        assert_eq!(joined.matching_entries, 32);
        assert_eq!(joined.match_kind, "ExactStaticDynamicMatch");
        assert_eq!(
            joined.dynamic_normalized_sha256,
            joined.static_normalized_sha256
        );
    }

    #[test]
    fn pointer_dispatch_table_is_visible_but_excluded_from_crypto_scoring() {
        let mut reads = Vec::new();
        for round in 0..100_u32 {
            for entry in 0..16_u32 {
                reads.push(acc(
                    round * 100 + entry,
                    TBL + entry as u64 * 8,
                    BASE + 0x1000 + entry as u64 * 4,
                    8,
                ));
            }
        }
        let (tables, eligible_reads) = cluster_tables(&reads, BASE, WINDOW, 12);
        assert_eq!(tables.len(), 1);
        assert!(matches!(
            tables[0].role_hint,
            TableRoleHint::ControlFlowDispatcherCandidate
        ));
        assert!(!tables[0].crypto_eligible);
        assert_eq!(tables[0].pointer_like_entries, 16);
        assert_eq!(eligible_reads, 0);
        assert!(estimate_rounds(&tables[0]).is_none());

        let report = analyze(
            &reads,
            &[],
            &WhiteBoxOptions {
                algorithm: "aes".into(),
                module_base: BASE,
                module_window: WINDOW,
                static_binary_path: None,
            },
        );
        assert!(report.table_fingerprints.is_empty());
        assert!(matches!(
            report.implementation_kind,
            ImplementationKind::Unknown
        ));
        assert_eq!(report.assessment.grade, "uncertain");
        assert!(!report.assessment.verification_gate_met);
    }
}
