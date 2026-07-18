use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

use crate::query::call_tree::CallTree;
use crate::query::evidence_score::{score_evidence, EvidenceAssessment, EvidenceScoreSignal};

/// ARM64 专用密码指令家族。
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum CryptoFamily {
    Aes,
    Sha1,
    Sha256,
    Sha512,
    Sm3,
    Sm4,
    Crc32,
    GhashPmull,
}

impl CryptoFamily {
    pub fn as_str(self) -> &'static str {
        match self {
            CryptoFamily::Aes => "AES",
            CryptoFamily::Sha1 => "SHA1",
            CryptoFamily::Sha256 => "SHA256",
            CryptoFamily::Sha512 => "SHA512",
            CryptoFamily::Sm3 => "SM3",
            CryptoFamily::Sm4 => "SM4",
            CryptoFamily::Crc32 => "CRC32",
            CryptoFamily::GhashPmull => "GHASH/PMULL",
        }
    }
}

/// 把助记符映射到专用密码指令家族。知识与 `trace-parser/src/insn_class.rs`
/// 的 P0 Crypto 段一致，但这里保留"密码身份"。
pub fn crypto_insn_family(mnemonic: &str) -> Option<CryptoFamily> {
    match mnemonic {
        "aese" | "aesd" | "aesmc" | "aesimc" => Some(CryptoFamily::Aes),
        "sha1c" | "sha1m" | "sha1p" | "sha1h" | "sha1su0" | "sha1su1" => Some(CryptoFamily::Sha1),
        "sha256h" | "sha256h2" | "sha256su0" | "sha256su1" => Some(CryptoFamily::Sha256),
        "sha512h" | "sha512h2" | "sha512su0" | "sha512su1" => Some(CryptoFamily::Sha512),
        "sm3ss1" | "sm3tt1a" | "sm3tt1b" | "sm3tt2a" | "sm3tt2b" | "sm3partw1" | "sm3partw2" => {
            Some(CryptoFamily::Sm3)
        }
        "sm4e" | "sm4ekey" => Some(CryptoFamily::Sm4),
        "crc32b" | "crc32h" | "crc32w" | "crc32x" | "crc32cb" | "crc32ch" | "crc32cw"
        | "crc32cx" => Some(CryptoFamily::Crc32),
        "pmull" | "pmull2" => Some(CryptoFamily::GhashPmull),
        _ => None,
    }
}

/// 便宜的预过滤：解析助记符前先做子串测试，跳过绝大多数行。
/// `ascii_contains` 大小写不敏感，needle 必须小写。
pub fn line_might_contain_crypto_insn(line: &[u8]) -> bool {
    const KEYS: &[&[u8]] = &[
        b"aes", b"sha1", b"sha256", b"sha512", b"sm3", b"sm4", b"crc32", b"pmull",
    ];
    KEYS.iter().any(|k| crate::utils::ascii_contains(line, k))
}

// ── 输入信号 ──

#[derive(Clone, Debug)]
pub struct CryptoMagicHit {
    pub seq: u32,
    pub algorithm: String,
    pub magic_hex: String,
}

#[derive(Clone, Debug)]
pub struct CryptoInsnHit {
    pub seq: u32,
    pub family: CryptoFamily,
}

// ── 选项 ──

#[derive(Clone, Debug)]
pub struct CryptoFunctionsOptions {
    /// 返回的候选函数上限（按分数排序取前 N）。默认 50，clamp 到 1..=500。
    pub max_candidates: u32,
}

impl Default for CryptoFunctionsOptions {
    fn default() -> Self {
        Self { max_candidates: 50 }
    }
}

// ── 聚合中间结果（评分与 I/O 提取前）──

#[derive(Clone, Debug)]
pub struct RawFunctionSignals {
    pub func_id: u32,
    pub func_addr: u64,
    pub func_name: Option<String>,
    pub entry_seq: u32,
    pub exit_seq: u32,
    pub line_count: u32,
    pub algorithms: Vec<String>,
    pub magic_hits: u32,
    pub distinct_magics: u32,
    pub base_family_count: u32,
    pub crypto_insn_counts: BTreeMap<String, u32>,
    pub crypto_insn_total: u32,
}

// ── 输出 DTO（serde camelCase）──

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CryptoRegValue {
    pub reg: String,
    pub value: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CryptoCallAnnotation {
    pub func_name: String,
    pub is_jni: bool,
    pub args: Vec<CryptoRegValue>,
    pub ret_value: Option<String>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CryptoFunctionIo {
    pub entry_args: Vec<CryptoRegValue>,
    pub return_value: Option<String>,
    pub call_annotation: Option<CryptoCallAnnotation>,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CryptoFunctionCandidate {
    pub func_id: u32,
    pub func_addr: String,
    pub func_name: Option<String>,
    pub entry_seq: u32,
    pub exit_seq: u32,
    pub line_count: u32,
    pub algorithms: Vec<String>,
    pub magic_hits: u32,
    pub distinct_magics: u32,
    pub crypto_insn_counts: BTreeMap<String, u32>,
    pub crypto_insn_total: u32,
    pub io: CryptoFunctionIo,
    pub assessment: EvidenceAssessment,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CryptoFunctionReport {
    pub candidates: Vec<CryptoFunctionCandidate>,
    pub total_functions_scanned: u32,
    pub functions_with_signals: u32,
    pub magic_hit_count: u32,
    pub crypto_insn_count: u32,
    pub candidates_truncated: bool,
    pub limitations: Vec<String>,
}

// ── 纯逻辑 ──

/// 把算法标签归一化到基础家族，用于"家族一致性"判断。
/// 例：AES_SBOX→AES，SHA256_K2→SHA256，CRC32C→CRC32，ChaCha20/Salsa20→CHACHA20。
pub fn base_algorithm(label: &str) -> String {
    let up = label.to_ascii_uppercase();
    let first = up.split_whitespace().next().unwrap_or("");
    let first = first.split('/').next().unwrap_or("");
    let base = first
        .trim_end_matches("_SBOX")
        .trim_end_matches("_K2")
        .trim_end_matches("_IV");
    match base {
        "CRC32C" => "CRC32".to_string(),
        "DES1" => "DES".to_string(),
        other => other.to_string(),
    }
}

/// 找包含 `seq` 的最内层函数节点 id。
/// 语义：在所有满足 entry_seq ≤ seq ≤ exit_seq 的节点里取 entry_seq 最大者（最内层）。
/// `sorted` 为按 entry_seq 升序的 (entry_seq, exit_seq, id)。
fn innermost_from_sorted(sorted: &[(u32, u32, u32)], seq: u32) -> Option<u32> {
    // 右边界：最后一个 entry_seq ≤ seq 的位置
    let mut lo = 0usize;
    let mut hi = sorted.len();
    while lo < hi {
        let mid = (lo + hi) / 2;
        if sorted[mid].0 <= seq {
            lo = mid + 1;
        } else {
            hi = mid;
        }
    }
    // 从该位置往左，第一个 exit_seq ≥ seq 的即最内层
    let mut i = lo;
    while i > 0 {
        i -= 1;
        let (entry, exit, id) = sorted[i];
        if entry <= seq && seq <= exit {
            return Some(id);
        }
    }
    None
}

/// 供外部/测试使用的便捷入口（每次自建排序索引，非热路径）。
pub fn innermost_function_for_seq(tree: &CallTree, seq: u32) -> Option<u32> {
    let mut sorted: Vec<(u32, u32, u32)> = tree
        .nodes
        .iter()
        .map(|n| (n.entry_seq, n.exit_seq, n.id))
        .collect();
    sorted.sort_by_key(|&(e, _, _)| e);
    innermost_from_sorted(&sorted, seq)
}

#[derive(Default)]
struct Acc {
    algorithms: Vec<String>,
    base_families: Vec<String>,
    magic_hexes: Vec<String>,
    magic_hits: u32,
    insn_counts: BTreeMap<String, u32>,
    insn_total: u32,
}

fn push_unique(v: &mut Vec<String>, s: String) {
    if !s.is_empty() && !v.contains(&s) {
        v.push(s);
    }
}

/// 把 magic/insn 命中按最内层函数聚合成每函数的原始信号。
pub fn aggregate_signals(
    magic_hits: &[CryptoMagicHit],
    insn_hits: &[CryptoInsnHit],
    tree: &CallTree,
) -> Vec<RawFunctionSignals> {
    let mut sorted: Vec<(u32, u32, u32)> = tree
        .nodes
        .iter()
        .map(|n| (n.entry_seq, n.exit_seq, n.id))
        .collect();
    sorted.sort_by_key(|&(e, _, _)| e);

    let mut by_func: BTreeMap<u32, Acc> = BTreeMap::new();

    for hit in magic_hits {
        if let Some(fid) = innermost_from_sorted(&sorted, hit.seq) {
            let acc = by_func.entry(fid).or_default();
            acc.magic_hits += 1;
            push_unique(&mut acc.algorithms, hit.algorithm.clone());
            push_unique(&mut acc.base_families, base_algorithm(&hit.algorithm));
            push_unique(&mut acc.magic_hexes, hit.magic_hex.clone());
        }
    }
    for hit in insn_hits {
        if let Some(fid) = innermost_from_sorted(&sorted, hit.seq) {
            let acc = by_func.entry(fid).or_default();
            acc.insn_total += 1;
            *acc
                .insn_counts
                .entry(hit.family.as_str().to_string())
                .or_default() += 1;
            push_unique(&mut acc.algorithms, hit.family.as_str().to_string());
            push_unique(&mut acc.base_families, hit.family.as_str().to_string());
        }
    }

    let mut out = Vec::with_capacity(by_func.len());
    for (fid, acc) in by_func {
        let node = match tree.nodes.iter().find(|n| n.id == fid) {
            Some(n) => n,
            None => continue,
        };
        out.push(RawFunctionSignals {
            func_id: node.id,
            func_addr: node.func_addr,
            func_name: node.func_name.clone(),
            entry_seq: node.entry_seq,
            exit_seq: node.exit_seq,
            line_count: node.exit_seq.saturating_sub(node.entry_seq) + 1,
            algorithms: acc.algorithms,
            magic_hits: acc.magic_hits,
            distinct_magics: acc.magic_hexes.len() as u32,
            base_family_count: acc.base_families.len() as u32,
            crypto_insn_counts: acc.insn_counts,
            crypto_insn_total: acc.insn_total,
        });
    }
    out
}

/// 单函数评分 → EvidenceAssessment（confidence high/medium/low）。
///
/// 说明：High(verified) 需 gate 成立且 score≥75，Medium(related) 需 score≥40，
/// 否则 Low(uncertain)。gate = 有专用密码指令，或 ≥3 个不同魔数常量且家族一致。
/// 点值是初始校准，可按真实 trace 微调（阈值在 evidence_score::score_evidence）。
pub fn score_candidate(raw: &RawFunctionSignals) -> EvidenceAssessment {
    let has_insn = raw.crypto_insn_total > 0;
    let coherent = raw.magic_hits > 0 && raw.base_family_count == 1;
    let many_constants = raw.distinct_magics >= 3;
    let strong_constants = raw.distinct_magics >= 5;
    let two_constants = raw.distinct_magics == 2;
    let single_constant = raw.distinct_magics == 1 && !has_insn;
    let gate = has_insn || (many_constants && raw.base_family_count == 1);

    let signals = vec![
        EvidenceScoreSignal::new(
            "dedicated_crypto_instructions",
            "Function executes dedicated ARM64 crypto instructions (AES/SHA/SM3/SM4/CRC32/PMULL).",
            55,
            has_insn,
            has_insn.then(|| format!("crypto_insn_total={}", raw.crypto_insn_total)),
        ),
        EvidenceScoreSignal::new(
            "crypto_instruction_volume",
            "Four or more crypto instructions executed (not an isolated instruction).",
            20,
            raw.crypto_insn_total >= 4,
            (raw.crypto_insn_total >= 4)
                .then(|| format!("crypto_insn_total={}", raw.crypto_insn_total)),
        ),
        EvidenceScoreSignal::new(
            "multiple_distinct_constants",
            "Three or more distinct magic constants observed in this function.",
            30,
            many_constants,
            many_constants.then(|| format!("distinct_magics={}", raw.distinct_magics)),
        ),
        EvidenceScoreSignal::new(
            "strong_constant_set",
            "Five or more distinct magic constants observed.",
            20,
            strong_constants,
            None,
        ),
        EvidenceScoreSignal::new(
            "some_distinct_constants",
            "Two distinct magic constants observed.",
            18,
            two_constants,
            None,
        ),
        EvidenceScoreSignal::new(
            "constant_family_coherence",
            "Observed magic constants map to a single algorithm family.",
            15,
            coherent,
            coherent.then(|| "single algorithm family".to_string()),
        ),
        EvidenceScoreSignal::new(
            "single_constant_only",
            "Only a single isolated magic constant was observed (common false positive).",
            -15,
            single_constant,
            None,
        ),
    ];

    score_evidence(
        "crypto_function",
        gate,
        signals,
        vec![
            "Confidence reflects corroborating evidence inside one function; it is not proof of a specific algorithm or key."
                .to_string(),
            "Magic constants can appear as ordinary data without indicating an active crypto routine."
                .to_string(),
            "Function boundaries come from BL/BLR/RET reconstruction and may merge inlined or tail-called code."
                .to_string(),
        ],
    )
}

/// 组装最终候选。
pub fn finalize_candidate(
    raw: RawFunctionSignals,
    io: CryptoFunctionIo,
    assessment: EvidenceAssessment,
) -> CryptoFunctionCandidate {
    CryptoFunctionCandidate {
        func_id: raw.func_id,
        func_addr: format!("0x{:x}", raw.func_addr),
        func_name: raw.func_name,
        entry_seq: raw.entry_seq,
        exit_seq: raw.exit_seq,
        line_count: raw.line_count,
        algorithms: raw.algorithms,
        magic_hits: raw.magic_hits,
        distinct_magics: raw.distinct_magics,
        crypto_insn_counts: raw.crypto_insn_counts,
        crypto_insn_total: raw.crypto_insn_total,
        io,
        assessment,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::query::call_tree::CallTreeBuilder;

    #[test]
    fn insn_family_mapping() {
        assert_eq!(crypto_insn_family("aese"), Some(CryptoFamily::Aes));
        assert_eq!(crypto_insn_family("sha256h2"), Some(CryptoFamily::Sha256));
        assert_eq!(crypto_insn_family("sm4e"), Some(CryptoFamily::Sm4));
        assert_eq!(crypto_insn_family("crc32cx"), Some(CryptoFamily::Crc32));
        assert_eq!(crypto_insn_family("pmull2"), Some(CryptoFamily::GhashPmull));
        assert_eq!(crypto_insn_family("add"), None);
    }

    #[test]
    fn base_algorithm_normalizes() {
        assert_eq!(base_algorithm("AES_SBOX"), "AES");
        assert_eq!(base_algorithm("SHA256_K2"), "SHA256");
        assert_eq!(base_algorithm("CRC32C"), "CRC32");
        assert_eq!(base_algorithm("ChaCha20/Salsa20"), "CHACHA20");
        assert_eq!(base_algorithm("HMAC (generic)"), "HMAC");
    }

    // 构造: root[0..100], A=[10..50] 内含 B=[20..30], C=[55..90]
    fn sample_tree() -> CallTree {
        let mut b = CallTreeBuilder::new();
        b.on_call(10, 0xA00); // A id1
        b.on_call(20, 0xB00); // B id2
        b.on_ret(30);
        b.on_ret(50);
        b.on_call(55, 0xC00); // C id3
        b.on_ret(90);
        b.finish(100)
    }

    #[test]
    fn innermost_nesting() {
        let t = sample_tree();
        assert_eq!(innermost_function_for_seq(&t, 25), Some(2)); // 在 B
        assert_eq!(innermost_function_for_seq(&t, 40), Some(1)); // 回到 A
        assert_eq!(innermost_function_for_seq(&t, 60), Some(3)); // 在 C
        assert_eq!(innermost_function_for_seq(&t, 95), Some(0)); // 回到 root
    }

    #[test]
    fn single_isolated_constant_is_low() {
        let t = sample_tree();
        let magic = vec![CryptoMagicHit {
            seq: 25,
            algorithm: "SHA256".into(),
            magic_hex: "0x428A2F98".into(),
        }];
        let raws = aggregate_signals(&magic, &[], &t);
        let raw = raws.iter().find(|r| r.func_id == 2).unwrap();
        let a = score_candidate(raw);
        assert_eq!(a.grade, "uncertain");
        assert_eq!(a.confidence, "low");
    }

    #[test]
    fn dedicated_instructions_are_high() {
        let t = sample_tree();
        let insns: Vec<CryptoInsnHit> = (0..6)
            .map(|i| CryptoInsnHit {
                seq: 22 + i,
                family: CryptoFamily::Aes,
            })
            .collect();
        let raws = aggregate_signals(&[], &insns, &t);
        let raw = raws.iter().find(|r| r.func_id == 2).unwrap();
        assert_eq!(raw.crypto_insn_total, 6);
        let a = score_candidate(raw);
        assert_eq!(a.confidence, "high");
    }

    #[test]
    fn coherent_constant_set_is_at_least_medium() {
        let t = sample_tree();
        let magic: Vec<CryptoMagicHit> = ["0x637C777B", "0xF26B6FC5", "0x3001672B", "0xFEFED7AB"]
            .iter()
            .enumerate()
            .map(|(i, h)| CryptoMagicHit {
                seq: 22 + i as u32,
                algorithm: "AES_SBOX".into(),
                magic_hex: (*h).into(),
            })
            .collect();
        let raws = aggregate_signals(&magic, &[], &t);
        let raw = raws.iter().find(|r| r.func_id == 2).unwrap();
        assert_eq!(raw.distinct_magics, 4);
        assert_eq!(raw.base_family_count, 1);
        let a = score_candidate(raw);
        assert!(a.confidence == "medium" || a.confidence == "high");
    }
}
