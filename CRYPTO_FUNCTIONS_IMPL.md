# 函数级密码算法识别 — 实施清单（Windows 编译用）

> 本文件是**可直接执行的实施指南 + 任务清单**。Mac 端无 Rust/Node 环境，按本文件在 Windows 上应用改动并编译验证即可。
> 每个文件给出完整可粘贴代码；标注 `【新增】` 或 `【修改】`。改动完全向后兼容——不动原 `scan_crypto` / Detection / Known Digest。
> 计划来源：`OPTIMIZATION_ROADMAP.md` 阶段五。设计细节见 `/Users/jiangxia/.claude/plans/eager-floating-hopcroft.md`。

## 0. 背景与目标

现状：密码识别只有"逐行魔数子串匹配"（`engine/query.rs::scan_chunk`），单个常量偶然出现在任意寄存器值里就报"发现 AES/SHA"，误报多，且不回答"哪个函数是加密实现、输入输出是什么"。

目标：把离散魔数命中**按所在函数聚合**，结合 **ARM64 专用密码指令**（aese/sha256h/sm4e/crc32* 等）、常量多样性与家族一致性等佐证，用统一评分产出 **High/Med/Low 置信度**，并给出每个疑似算法函数的入口 X0–X7、返回值 X0、调用注解。全链路交付：core + MCP 工具 + 前端 Functions 页签，**包含**硬件密码指令扫描。

---

## 1. Windows 环境准备

```powershell
# Rust（stable）
winget install Rustlang.Rustup
rustup default stable

# Node.js 20+
winget install OpenJS.NodeJS.LTS

# Tauri CLI
cargo install tauri-cli --version "^2" --locked

# 前端依赖
npm ci --prefix src-web
```

Windows 上 `build.sh` 需在 Git Bash 里跑；否则直接用下面 `cargo` 命令（见第 4 节）。

---

## 2. 任务清单

- [ ] **T1** 新增 `crates/trace-core/src/query/crypto_functions.rs`（类型 + 纯逻辑 + 评分 + 单测）
- [ ] **T2** 新增 `crates/trace-core/src/engine/crypto_functions.rs`（引擎方法 + 指令扫描）
- [ ] **T3** `crates/trace-core/src/session.rs` 加缓存字段
- [ ] **T4** `crates/trace-core/src/engine/mod.rs` 注册模块 + 初始化字段
- [ ] **T5** `crates/trace-core/src/query/mod.rs` + `lib.rs` 导出
- [ ] **T6** `crates/trace-mcp/src/types.rs` + `tools.rs` 新增 MCP 工具
- [ ] **T7** `src-tauri/src/commands/mod.rs` + `main.rs` 新增 Tauri 命令
- [ ] **T8** `src-web/src/types/trace.ts` + `components/CryptoFunctionsPanel.tsx` + `CryptoPanel.tsx` 前端
- [ ] **T9** 编译 + 测试 + 手动验证（第 4、5 节）

---

## T1【新增】`crates/trace-core/src/query/crypto_functions.rs`

```rust
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

#[derive(Clone, Debug, Serialize, Deserialize)]
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

#[derive(Clone, Debug, Serialize, Deserialize)]
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
            *acc.insn_counts.entry(hit.family.as_str().to_string()).or_default() += 1;
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
        let magic = vec![CryptoMagicHit { seq: 25, algorithm: "SHA256".into(), magic_hex: "0x428A2F98".into() }];
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
            .map(|i| CryptoInsnHit { seq: 22 + i, family: CryptoFamily::Aes })
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
            .map(|(i, h)| CryptoMagicHit { seq: 22 + i as u32, algorithm: "AES_SBOX".into(), magic_hex: (*h).into() })
            .collect();
        let raws = aggregate_signals(&magic, &[], &t);
        let raw = raws.iter().find(|r| r.func_id == 2).unwrap();
        assert_eq!(raw.distinct_magics, 4);
        assert_eq!(raw.base_family_count, 1);
        let a = score_candidate(raw);
        assert!(a.confidence == "medium" || a.confidence == "high");
    }
}
```

> **NOTE**：若 `crate::utils::ascii_contains` 不是 `pub`，把 `line_might_contain_crypto_insn` 里改用本模块内联实现，或将 utils 中该函数标 `pub`（当前已是 `pub`）。

---

## T2【新增】`crates/trace-core/src/engine/crypto_functions.rs`

```rust
use crate::error::{Result, TraceError};
use crate::query::crypto_functions::{
    aggregate_signals, crypto_insn_family, finalize_candidate, line_might_contain_crypto_insn,
    score_candidate, CryptoCallAnnotation, CryptoFunctionIo, CryptoFunctionReport,
    CryptoFunctionsOptions, CryptoInsnHit, CryptoMagicHit, CryptoRegValue,
};
use trace_parser::types::TraceFormat;
use trace_parser::{gumtrace as gumtrace_parser, parser};

/// 扫描一个 chunk 里的专用密码指令（助记符级）。
fn scan_insn_chunk(
    data: &[u8],
    start_seq: u32,
    end_seq: u32,
    start_offset: usize,
    trace_format: TraceFormat,
) -> Vec<CryptoInsnHit> {
    let mut hits = Vec::new();
    let mut pos = start_offset;
    let mut seq = start_seq;
    while pos < data.len() && seq < end_seq {
        let end = memchr::memchr(b'\n', &data[pos..])
            .map(|i| pos + i)
            .unwrap_or(data.len());
        let line = &data[pos..end];
        if line_might_contain_crypto_insn(line) {
            if let Ok(line_str) = std::str::from_utf8(line) {
                let parsed = match trace_format {
                    TraceFormat::Unidbg => parser::parse_line(line_str),
                    TraceFormat::Gumtrace => gumtrace_parser::parse_line_gumtrace(line_str),
                };
                if let Some(p) = parsed {
                    if let Some(family) = crypto_insn_family(p.mnemonic.as_str()) {
                        hits.push(CryptoInsnHit { seq, family });
                    }
                }
            }
        }
        pos = end + 1;
        seq += 1;
    }
    hits
}

impl super::TraceEngine {
    pub fn analyze_crypto_functions(
        &self,
        session_id: &str,
        options: CryptoFunctionsOptions,
    ) -> Result<CryptoFunctionReport> {
        // 内存缓存命中（忽略 max_candidates —— 缓存全量，按需截断）
        {
            let handle = self.get_handle(session_id)?;
            let state = handle
                .state
                .read()
                .map_err(|e| TraceError::Internal(e.to_string()))?;
            if let Some(cached) = &state.crypto_functions_cache {
                return Ok(truncate_report(cached.clone(), options.max_candidates));
            }
        }

        // 1. 复用 scan_crypto 拿 magic 命中（自带内存+磁盘缓存）
        let crypto = self.scan_crypto(session_id)?;
        let magic_hits: Vec<CryptoMagicHit> = crypto
            .matches
            .iter()
            .map(|m| CryptoMagicHit {
                seq: m.seq,
                algorithm: m.algorithm.clone(),
                magic_hex: m.magic_hex.clone(),
            })
            .collect();

        let handle = self.get_handle(session_id)?;

        // 2. 并行 chunk 扫描专用密码指令 + 快照 call_tree（照抄 scan_crypto 的分块）
        let (mmap_ref, total_lines, trace_format, chunks, call_tree, node_count) = {
            let state = handle
                .state
                .read()
                .map_err(|e| TraceError::Internal(e.to_string()))?;
            let call_tree = state.call_tree.clone().ok_or(TraceError::IndexNotReady)?;
            let node_count = call_tree.nodes.len() as u32;
            let total_lines = state
                .lidx_store
                .as_ref()
                .map(|s| s.total_lines())
                .unwrap_or(0);
            let num_cpus = std::thread::available_parallelism()
                .map(|n| n.get())
                .unwrap_or(4);
            let chunks: Option<Vec<(u32, u32, usize)>> = if num_cpus > 1 && total_lines > 10000 {
                state.line_index_view().map(|li| {
                    let data: &[u8] = &state.mmap;
                    let num_chunks = num_cpus.min(16);
                    let lines_per_chunk = (total_lines as usize + num_chunks - 1) / num_chunks;
                    let mut chunks = Vec::with_capacity(num_chunks);
                    for i in 0..num_chunks {
                        let s = (i * lines_per_chunk) as u32;
                        if s >= total_lines {
                            break;
                        }
                        let e = ((i + 1) * lines_per_chunk).min(total_lines as usize) as u32;
                        let off = li.line_byte_offset(data, s).unwrap_or(0) as usize;
                        chunks.push((s, e, off));
                    }
                    chunks
                })
            } else {
                None
            };
            (
                state.mmap.clone(),
                total_lines,
                state.trace_format,
                chunks,
                call_tree,
                node_count,
            )
        };

        let data: &[u8] = &mmap_ref;
        let insn_hits: Vec<CryptoInsnHit> = if let Some(chunks) = chunks {
            use rayon::prelude::*;
            let per: Vec<Vec<CryptoInsnHit>> = chunks
                .par_iter()
                .map(|&(s, e, off)| scan_insn_chunk(data, s, e, off, trace_format))
                .collect();
            per.into_iter().flatten().collect()
        } else {
            scan_insn_chunk(data, 0, total_lines, 0, trace_format)
        };

        // 3+4. 聚合 + 评分
        let raws = aggregate_signals(&magic_hits, &insn_hits, &call_tree);
        let functions_with_signals = raws.len() as u32;
        let mut scored: Vec<_> = raws
            .into_iter()
            .map(|r| {
                let a = score_candidate(&r);
                (r, a)
            })
            .collect();
        // 按分数降序，次序稳定：分数 → 密码指令数 → entry_seq 升序
        scored.sort_by(|a, b| {
            b.1.score
                .cmp(&a.1.score)
                .then(b.0.crypto_insn_total.cmp(&a.0.crypto_insn_total))
                .then(a.0.entry_seq.cmp(&b.0.entry_seq))
        });

        // 5. 全量候选（不截断）先存缓存；返回时再按 max_candidates 截断
        let mut candidates = Vec::with_capacity(scored.len());
        for (raw, assessment) in scored {
            let io = self.extract_function_io(session_id, raw.entry_seq, raw.exit_seq);
            candidates.push(finalize_candidate(raw, io, assessment));
        }

        let full = CryptoFunctionReport {
            candidates,
            total_functions_scanned: node_count,
            functions_with_signals,
            magic_hit_count: magic_hits.len() as u32,
            crypto_insn_count: insn_hits.len() as u32,
            candidates_truncated: false,
            limitations: vec![
                "Only executed instructions recorded in the trace are analyzed.".to_string(),
                "Magic-constant hits are substring matches over line text and can be coincidental; confidence weighs corroborating signals.".to_string(),
                "Dedicated crypto instructions are strong evidence but absent from software (table-based) implementations.".to_string(),
                "Entry X0-X7 and return X0 are read from register checkpoints at function entry/exit and may not all be live arguments.".to_string(),
            ],
        };

        // 6. 存内存缓存
        {
            let mut state = handle
                .state
                .write()
                .map_err(|e| TraceError::Internal(e.to_string()))?;
            state.crypto_functions_cache = Some(full.clone());
        }

        Ok(truncate_report(full, options.max_candidates))
    }

    /// 提取函数入口 X0-X7、返回 X0、调用注解。
    fn extract_function_io(
        &self,
        session_id: &str,
        entry_seq: u32,
        exit_seq: u32,
    ) -> CryptoFunctionIo {
        let mut entry_args = Vec::new();
        if let Ok(regs) = self.get_registers_at(session_id, entry_seq) {
            for i in 0..8u8 {
                let key = format!("X{i}");
                if let Some(v) = regs.get(&key) {
                    if v != "?" {
                        entry_args.push(CryptoRegValue {
                            reg: key,
                            value: v.clone(),
                        });
                    }
                }
            }
        }
        let return_value = self
            .get_registers_at(session_id, exit_seq)
            .ok()
            .and_then(|m| m.get("X0").filter(|v| *v != "?").cloned());

        // 调用注解挂在 bl/blr 行；entry_seq 可能是 bl 行或被调方首行，两处都试。
        let call_annotation = self.get_handle(session_id).ok().and_then(|h| {
            let state = h.state.read().ok()?;
            let ann = state
                .call_annotations
                .get(&entry_seq)
                .or_else(|| state.call_annotations.get(&entry_seq.saturating_sub(1)))?;
            Some(CryptoCallAnnotation {
                func_name: ann.func_name.clone(),
                is_jni: ann.is_jni,
                args: ann
                    .args
                    .iter()
                    .map(|(idx, val)| CryptoRegValue {
                        reg: idx.clone(),
                        value: val.clone(),
                    })
                    .collect(),
                ret_value: ann.ret_value.clone(),
            })
        });

        CryptoFunctionIo {
            entry_args,
            return_value,
            call_annotation,
        }
    }
}

fn truncate_report(mut report: CryptoFunctionReport, max_candidates: u32) -> CryptoFunctionReport {
    let max = max_candidates.clamp(1, 500) as usize;
    if report.candidates.len() > max {
        report.candidates.truncate(max);
        report.candidates_truncated = true;
    }
    report
}
```

---

## T3【修改】`crates/trace-core/src/session.rs`

在 `SessionState` 结构体末尾（`crypto_cache` 字段之后）加：

```rust
    /// 缓存函数级密码识别报告（全量，按需截断）
    pub crypto_functions_cache: Option<crate::query::crypto_functions::CryptoFunctionReport>,
```

---

## T4【修改】`crates/trace-core/src/engine/mod.rs`

**(a)** 顶部模块声明区（`mod build;` 附近）加：

```rust
mod crypto_functions;
```

**(b)** `create_session` 里构造 `SessionState { ... }` 的字段列表末尾（`crypto_cache: None,` 之后）加：

```rust
            crypto_functions_cache: None,
```

---

## T5【修改】`crates/trace-core/src/query/mod.rs` 与 `lib.rs`

**`query/mod.rs`**：在 `pub mod crypto;` 之后加：

```rust
pub mod crypto_functions;
```

**`lib.rs`**：在现有 `pub use query::...` 区加：

```rust
pub use query::crypto_functions::{
    CryptoFamily, CryptoFunctionCandidate, CryptoFunctionIo, CryptoFunctionReport,
    CryptoFunctionsOptions,
};
```

---

## T6【修改】`crates/trace-mcp/src/types.rs` 与 `tools.rs`

**`types.rs`** 末尾加请求类型：

```rust
#[derive(Debug, Deserialize, JsonSchema)]
pub struct AnalyzeCryptoFunctionsRequest {
    #[schemars(description = "Session ID (optional if only one session is open)")]
    pub session_id: Option<String>,
    #[schemars(description = "Max candidate functions to return, ranked by confidence (default: 50, max: 500)")]
    #[serde(default = "default_crypto_fn_candidates")]
    pub max_candidates: u32,
}

fn default_crypto_fn_candidates() -> u32 {
    50
}
```

**`tools.rs`**：

(a) 顶部 `use trace_core::{...}` 里补充导入 `CryptoFunctionsOptions`（与其它类型并列）。

(b) 在 `#[tool_router] impl TraceToolHandler` 里、`analyze_crypto` 工具附近新增：

```rust
    #[tool(
        name = "analyze_crypto_functions",
        description = "Identify likely cryptographic FUNCTIONS (not just isolated constants). \
            Aggregates magic-constant hits and dedicated ARM64 crypto instructions (AES/SHA/SM3/SM4/CRC32/PMULL) \
            by their enclosing function, scores each with explainable High/Medium/Low confidence, and reports \
            entry X0-X7, return X0, and any call annotation. Saves an analysis_id for get_analysis/compare_analyses."
    )]
    fn analyze_crypto_functions(
        &self,
        Parameters(req): Parameters<AnalyzeCryptoFunctionsRequest>,
    ) -> Result<String, String> {
        let sid = self.resolve_session(req.session_id.clone())?;
        let report = self
            .engine
            .analyze_crypto_functions(
                &sid,
                CryptoFunctionsOptions {
                    max_candidates: req.max_candidates,
                },
            )
            .map_err(|e| e.to_string())?;

        let mut result = serde_json::to_value(&report)
            .map_err(|e| format!("serialize failed: {e}"))?;

        // 汇总证据
        let mut evidence = AnalysisEvidence::default();
        for c in &report.candidates {
            for a in &c.algorithms {
                push_unique(&mut evidence.algorithms, a.clone());
            }
            if let Some(name) = &c.func_name {
                push_unique(&mut evidence.functions, name.clone());
            }
            push_unique(&mut evidence.functions, c.func_addr.clone());
            push_unique(&mut evidence.addresses, c.func_addr.clone());
            for k in c.crypto_insn_counts.keys() {
                push_unique(&mut evidence.operations, k.clone());
            }
        }
        evidence.algorithms.truncate(100);
        evidence.functions.truncate(100);
        evidence.addresses.truncate(200);
        evidence.operations.truncate(50);

        let request_record = serde_json::json!({
            "max_candidates": req.max_candidates,
        });
        match self.engine.save_analysis(
            &sid,
            "crypto_functions",
            "Function-level crypto identification",
            request_record,
            result.clone(),
            evidence,
        ) {
            Ok(record) => {
                result["analysis_id"] = serde_json::json!(record.analysis_id);
                result["saved"] = serde_json::json!(true);
                result["compare_with"] = serde_json::json!("compare_analyses");
            }
            Err(e) => {
                result["saved"] = serde_json::json!(false);
                result["save_error"] = serde_json::json!(e.to_string());
            }
        }
        Ok(json(&result))
    }
```

> `push_unique` / `json` / `AnalysisEvidence` 均已在 tools.rs 内定义或导入，直接用。

---

## T7【修改】`src-tauri/src/commands/mod.rs` 与 `main.rs`

**`commands/mod.rs`** 加命令（照抄 `scan_crypto` 的 `spawn_blocking` 包装）：

```rust
#[tauri::command]
pub async fn analyze_crypto_functions(
    session_id: String,
    max_candidates: Option<u32>,
    engine: State<'_, Arc<TraceEngine>>,
) -> Result<trace_core::CryptoFunctionReport, String> {
    let engine = engine.inner().clone();
    tauri::async_runtime::spawn_blocking(move || {
        engine
            .analyze_crypto_functions(
                &session_id,
                trace_core::CryptoFunctionsOptions {
                    max_candidates: max_candidates.unwrap_or(50),
                },
            )
            .map_err(|e| e.to_string())
    })
    .await
    .map_err(|e| format!("Task execution failed: {}", e))?
}
```

**`main.rs`** 的 `tauri::generate_handler![ ... ]` 里加一行：

```rust
            commands::analyze_crypto_functions,
```

---

## T8 前端

### 【修改】`src-web/src/types/trace.ts` 末尾加

```ts
export interface EvidenceScoreFactor {
  code: string;
  label: string;
  points: number;
  observed: boolean;
  awardedPoints: number;
  evidence: string | null;
}

export interface EvidenceAssessment {
  scope: string;
  score: number;
  grade: string;       // "verified" | "related" | "uncertain"
  confidence: string;  // "high" | "medium" | "low"
  verificationGateMet: boolean;
  factors: EvidenceScoreFactor[];
  limitations: string[];
}

export interface CryptoRegValue { reg: string; value: string; }

export interface CryptoCallAnnotation {
  funcName: string;
  isJni: boolean;
  args: CryptoRegValue[];
  retValue: string | null;
}

export interface CryptoFunctionIo {
  entryArgs: CryptoRegValue[];
  returnValue: string | null;
  callAnnotation: CryptoCallAnnotation | null;
}

export interface CryptoFunctionCandidate {
  funcId: number;
  funcAddr: string;
  funcName: string | null;
  entrySeq: number;
  exitSeq: number;
  lineCount: number;
  algorithms: string[];
  magicHits: number;
  distinctMagics: number;
  cryptoInsnCounts: Record<string, number>;
  cryptoInsnTotal: number;
  io: CryptoFunctionIo;
  assessment: EvidenceAssessment;
}

export interface CryptoFunctionReport {
  candidates: CryptoFunctionCandidate[];
  totalFunctionsScanned: number;
  functionsWithSignals: number;
  magicHitCount: number;
  cryptoInsnCount: number;
  candidatesTruncated: boolean;
  limitations: string[];
}
```

### 【新增】`src-web/src/components/CryptoFunctionsPanel.tsx`

```tsx
import React, { useState, useCallback } from "react";
import { invoke } from "@tauri-apps/api/core";
import type { CryptoFunctionReport, CryptoFunctionCandidate } from "../types/trace";

interface Props {
  sessionId: string | null;
  onJumpToSeq: (seq: number) => void;
}

function confColor(confidence: string): string {
  switch (confidence) {
    case "high": return "#e5484d";
    case "medium": return "#f5a623";
    default: return "#8a8f98";
  }
}

function CandidateRow({ c, onJumpToSeq }: { c: CryptoFunctionCandidate; onJumpToSeq: (s: number) => void }) {
  const [open, setOpen] = useState(false);
  const insn = Object.entries(c.cryptoInsnCounts)
    .map(([k, v]) => `${k}×${v}`)
    .join(" ");
  return (
    <div style={{ borderBottom: "1px solid var(--border-color)" }}>
      <div
        onClick={() => setOpen(o => !o)}
        style={{
          display: "flex", alignItems: "center", gap: 8, padding: "5px 8px",
          cursor: "pointer", fontSize: 12,
        }}
      >
        <span style={{
          minWidth: 54, textAlign: "center", padding: "1px 6px", borderRadius: 3,
          background: confColor(c.assessment.confidence), color: "#fff", fontSize: 10, textTransform: "uppercase",
        }}>{c.assessment.confidence}</span>
        <span style={{ width: 34, color: "var(--text-tertiary)" }}>{c.assessment.score}</span>
        <span style={{ color: "var(--syntax-keyword)", minWidth: 120 }}>
          {c.algorithms.join(", ") || "—"}
        </span>
        <span
          onClick={(e) => { e.stopPropagation(); onJumpToSeq(c.entrySeq); }}
          style={{ color: "var(--syntax-literal)", textDecoration: "underline", cursor: "pointer" }}
          title="Jump to function entry"
        >{c.funcName || c.funcAddr}</span>
        <span style={{ flex: 1 }} />
        <span style={{ color: "var(--text-tertiary)", fontSize: 11 }}>
          {c.magicHits > 0 && `${c.distinctMagics} const`}
          {c.cryptoInsnTotal > 0 && `  ${insn}`}
          {`  ·${c.lineCount} ln`}
        </span>
      </div>
      {open && (
        <div style={{ padding: "6px 12px 10px 68px", fontSize: 11, color: "var(--text-secondary)", background: "var(--bg-secondary)" }}>
          <div style={{ marginBottom: 4 }}>
            entry seq {c.entrySeq + 1} · exit seq {c.exitSeq + 1} · {c.funcAddr}
          </div>
          {c.io.entryArgs.length > 0 && (
            <div style={{ marginBottom: 4 }}>
              args: {c.io.entryArgs.map(a => `${a.reg}=${a.value}`).join("  ")}
            </div>
          )}
          {c.io.returnValue && <div style={{ marginBottom: 4 }}>return X0={c.io.returnValue}</div>}
          {c.io.callAnnotation && (
            <div style={{ marginBottom: 4, color: "var(--syntax-comment)" }}>
              call: {c.io.callAnnotation.funcName}
              {c.io.callAnnotation.retValue ? ` → ${c.io.callAnnotation.retValue}` : ""}
            </div>
          )}
          <div style={{ marginTop: 6, borderTop: "1px solid var(--border-color)", paddingTop: 6 }}>
            {c.assessment.factors.filter(f => f.observed).map(f => (
              <div key={f.code} style={{ display: "flex", gap: 8 }}>
                <span style={{ width: 40, color: f.awardedPoints >= 0 ? "#3fb950" : "#e5484d" }}>
                  {f.awardedPoints >= 0 ? "+" : ""}{f.awardedPoints}
                </span>
                <span>{f.label}</span>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}

export default function CryptoFunctionsPanel({ sessionId, onJumpToSeq }: Props) {
  const [report, setReport] = useState<CryptoFunctionReport | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const analyze = useCallback(async () => {
    if (!sessionId) return;
    setLoading(true);
    setError(null);
    try {
      const r = await invoke<CryptoFunctionReport>("analyze_crypto_functions", { sessionId });
      setReport(r);
    } catch (e) {
      setError(String(e));
      setReport(null);
    } finally {
      setLoading(false);
    }
  }, [sessionId]);

  return (
    <div style={{ flex: 1, display: "flex", flexDirection: "column", overflow: "hidden" }}>
      <div style={{
        display: "flex", alignItems: "center", gap: 8, padding: "4px 8px",
        borderBottom: "1px solid var(--border-color)", flexShrink: 0,
      }}>
        <button
          type="button"
          onClick={analyze}
          disabled={!sessionId || loading}
          style={{
            height: 24, padding: "0 12px", fontSize: 12, cursor: sessionId ? "pointer" : "default",
            background: "var(--btn-primary)", color: "#fff", border: "none", borderRadius: 3,
            opacity: !sessionId || loading ? 0.6 : 1,
          }}
        >{loading ? "Analyzing..." : "Analyze Functions"}</button>
        {report && (
          <span style={{ color: "var(--text-tertiary)", fontSize: 11 }}>
            {report.candidates.length} candidates · {report.magicHitCount} const hits · {report.cryptoInsnCount} crypto insns
            {report.candidatesTruncated && " (truncated)"}
          </span>
        )}
      </div>

      <div style={{ flex: 1, overflow: "auto" }}>
        {error && <div style={{ padding: 16, color: "#e5484d", fontSize: 12 }}>{error}</div>}
        {!error && !report && !loading && (
          <div style={{ padding: 16, color: "var(--text-secondary)", fontSize: 12 }}>
            Click "Analyze Functions" to aggregate crypto evidence by function.
          </div>
        )}
        {report && report.candidates.length === 0 && (
          <div style={{ padding: 16, color: "var(--text-secondary)", fontSize: 12 }}>
            No crypto signals found in any function.
          </div>
        )}
        {report && report.candidates.map(c => (
          <CandidateRow key={c.funcId} c={c} onJumpToSeq={onJumpToSeq} />
        ))}
      </div>
    </div>
  );
}
```

### 【修改】`src-web/src/components/CryptoPanel.tsx`

(a) 顶部 import 加：

```tsx
import CryptoFunctionsPanel from "./CryptoFunctionsPanel";
```

(b) `CryptoPanel` 组件里 `view` 状态联合类型加 `"functions"`：

```tsx
  const [view, setView] = useState<"detection" | "known-digest" | "functions">("detection");
```

(c) 分段按钮区，把 `Known Digest` 按钮的 `borderRight: "none"` 去掉（让它恢复右边框），并在其后新增第三个按钮：

```tsx
          <button
            type="button"
            style={segmentStyle(view === "known-digest")}
            onClick={() => setView("known-digest")}
          >
            Known Digest
          </button>
          <button
            type="button"
            style={{ ...segmentStyle(view === "functions"), borderRight: "none" }}
            onClick={() => setView("functions")}
          >
            Functions
          </button>
```

(d) 内容区新增第三个面板容器（与 detection / known-digest 容器并列）：

```tsx
        <div style={{ flex: 1, minWidth: 0, minHeight: 0, display: view === "functions" ? "flex" : "none" }}>
          <CryptoFunctionsPanel
            sessionId={props.sessionId}
            onJumpToSeq={props.onJumpToSeq}
          />
        </div>
```

---

## 4. 构建与测试（Windows）

```powershell
# 单元测试（含 T1 新增测试）
cargo test --workspace --all-targets

# 后端库编译
cargo build -p trace-core
cargo build -p trace-mcp

# 前端类型检查 + 生产构建
npm run build --prefix src-web

# 桌面应用（开发模式，含内置 MCP :19821）
cargo tauri dev

# 或 release 应用 + MCP CLI
cargo tauri build
cargo build --release --bin trace-cli
```

预期：`cargo test` 全绿（新增 5 个测试 + 原有）；三处构建通过。

---

## 5. 手动验证

**MCP（trace-cli 或应用内 HTTP）**：对一个含密码逻辑的 trace 跑
```json
analyze_crypto_functions { "max_candidates": 50 }
```
核对：
- 只含单个孤立常量的函数 → `confidence: "low"`；
- 含专用密码指令（如 aese）或多常量同族的函数 → `high`/`medium`；
- `io.entryArgs`（X0–X7）、`io.returnValue`（X0）与 `get_registers_at`/`get_trace_lines` 交叉一致；
- 返回带 `analysis_id`，可 `get_analysis` / `compare_analyses`。

**GUI**：`cargo tauri dev` → 打开 trace → 右侧 Crypto 面板 → **Functions** 页签 → **Analyze Functions**。核对置信度徽章分级、点击函数名跳转到入口行、展开看评分因子（+/- 点值）。

**回归**：Detection / Known Digest 两个旧页签与 `scan_crypto` 缓存行为不变。

---

## 6. 已知取舍 / 后续

- 评分点值是初始校准，建议按真实 trace 微调（阈值逻辑在 `query/evidence_score.rs`：gate+score≥75=high，≥40=medium）。
- 报告目前只做**内存缓存**（`SessionState.crypto_functions_cache`）；磁盘缓存（照 `cache.rs::save_crypto_cache`/`load_crypto_cache`）留作后续。
- `call_annotations` 与 `call_tree.entry_seq` 的 seq 对齐：`extract_function_io` 已同时试 `entry_seq` 与 `entry_seq-1`；若你的 trace 里注解对不上，检查 `merge.rs` 里 `on_call` 传入的 seq 语义并相应调整。
- 未做：函数内 bitops/循环密度信号、输入/输出缓冲区重建、与 known-digest 输出的自动关联（阶段五后半，后续迭代）。

---

## 7. 涉及文件汇总

| 类型 | 路径 |
|------|------|
| 新增 | `crates/trace-core/src/query/crypto_functions.rs` |
| 新增 | `crates/trace-core/src/engine/crypto_functions.rs` |
| 新增 | `src-web/src/components/CryptoFunctionsPanel.tsx` |
| 修改 | `crates/trace-core/src/session.rs` |
| 修改 | `crates/trace-core/src/engine/mod.rs` |
| 修改 | `crates/trace-core/src/query/mod.rs` |
| 修改 | `crates/trace-core/src/lib.rs` |
| 修改 | `crates/trace-mcp/src/types.rs` |
| 修改 | `crates/trace-mcp/src/tools.rs` |
| 修改 | `src-tauri/src/commands/mod.rs` |
| 修改 | `src-tauri/src/main.rs` |
| 修改 | `src-web/src/components/CryptoPanel.tsx` |
| 修改 | `src-web/src/types/trace.ts` |
