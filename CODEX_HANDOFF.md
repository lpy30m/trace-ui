# 交接与分工提案（Claude → Codex）

> 作者：Claude（另一个在本仓库工作的 agent）。用途：就 `WHITEBOX_AES_IMPL.md` 和 `TAINT_ANALYSIS_CASE_STUDY.md` 两份路线图，向 Codex 提出**分工方案 + whitebox P0 精确改动清单**，避免两个 agent 撞同一批文件。
>
> 这是**提案**，最终以用户和 Codex 确认为准。截至本文，Claude 尚未动 whitebox/crypto 代码。

> **2026-07-20 最终决定：**用户将把仓库转到 Windows，在具备 Rust/Cargo 和 GitHub Actions 编译回路的 Codex 环境继续。本文件第 0～6 节保留为历史复核材料；真正的执行顺序、所有权和验收要求以第 7 节以后为准。Windows Codex 接管 crypto/whitebox 与 taint/call-effect 两条路线，不再等待 Claude 分工，但必须先完成 crypto P0，再开始 taint P0-1。

## 0. TL;DR 分工

- **Codex 主刀 whitebox / crypto P0**（`WHITEBOX_AES_IMPL.md` §16 P0）。理由：这块的 `verified = 语义复算一致` 离不开真机 29 MiB trace + Python 复算，**这些数据和脚本在 Codex 这边**，v1 whitebox 和两份规格也都是 Codex 写的、上下文最全。
- **Claude 主刀 taint P0-1**（`TAINT_ANALYSIS_CASE_STUDY.md` §5：外部调用 CallEffect + 内存 provenance）。理由：那是另一批文件（parser/scan/merge/get_memory），与 whitebox 不重叠；且**不依赖那份 29 MiB trace**。
- **关键约束（环境）**：**两个 agent 都只在 Mac 写代码，编译和测试统一在用户的 Windows 环境跑。** 没有 agent 能在 Mac 上 `cargo build/test`。所以文档里"先运行现有测试记录 baseline""复算验证"这些步骤，都是**由用户在 Windows 执行、把结果回传**，不是某个 agent 本地跑。写代码时要按"一次写对、盲改"要求——改动尽量自包含、可离线单测（纯逻辑 + 标准向量），减少来回编译。

## 1. Claude 对 whitebox 勘误的复核结论（同意）

我核对了当前代码，`WHITEBOX_AES_IMPL.md` 的勘误**属实**，问题都在 `crates/trace-core/src/query/whitebox_aes.rs`：

- `assess()` 的 gate = `dominant && has_io`（L441）——纯启发式（主导表 + 任一 16B 缓冲）就能把 `score` 顶到 ≥75 → `verified`。这就是"验证白盒 AES"误判的根。
- `pick_plaintext()`（L252）按"最早可打印"挑明文 → `Safe_box_1234567`（实为包装密钥）被标 plaintext。
- `estimate_rounds()`（L335）用 `read_count/distinct_addrs≈10` 当轮数，被当成不变量。
- `analyze()` 里 `block_bytes` 硬编码 16（L390）。
- 两个测试把错误行为写死：`end_to_end_aes128_is_verified`（L593，断言 `grade=="verified"`）、`plaintext_prefers_printable_candidate`（L521，断言 Safe_box 是明文）。

结论：这不是"检测器分析后证明不是白盒"，是**覆盖不足 + 角色/评分误判**。同意按 v2 规格修，保留 v1 的内存索引基础设施。

## 2. 给 Codex 的 whitebox P0 精确改动清单

按 `WHITEBOX_AES_IMPL.md` §19 的顺序（先跑基线测试 → 先写金标准+负样本测试 → 再改分类/角色/gate → 最后接 MCP/GUI）。逐项对应 §16 P0 checklist：

| P0 项 | 落点 | 具体改法 |
|---|---|---|
| 不再称 verified 白盒 | `whitebox_aes.rs::assess` | gate 由 `dominant && has_io` 改为 `semantic_verified`（新参数，当前恒 false）→ 启发式最高只到 `related`，永不 `verified` |
| 修 Safe_box 角色 | `pick_plaintext` / `analyze` | 停止贴 plaintext。**为不破坏 UI**：保留 `plaintext` 字段名但置 `None`，缓冲只在 `input_candidates` 中性列出；真正角色识别（数据流）留 P1 |
| 加三枚举 | `whitebox_aes.rs` DTO | `ImplementationKind`/`KeyExposure`/`WhiteBoxStatus`（§7）；本样本 = `TableDrivenSoftware`（无复算前）/`Unknown`/`NotWhiteBox` |
| 轮数不当不变量 | `estimate_rounds` | 保留为**弱信号**，改名/措辞，不再驱动 block-size 与 verified |
| 16B stride / 29 block | 需真 I/O | 从输入/输出 stride、`len>>4` 测；依赖 trace 字节（你有样本） |
| AES-128 key schedule 验证 | 新 `query/aes_schedule.rs`（+ 最小 AES 参考实现） | 由 raw key/round-key 生成标准 schedule 比对；用 FIPS-197 向量单测（无需 trace） |
| AES-ECB 单块/全 buffer 复算 | 新 `query/crypto_semantic_verify.rs` | RustCrypto `aes`/`cipher` 或最小 AES；至少 1 块一致才 verified；否则输出 firstMismatchBlock |
| verified gate = 复算一致 | `assess` | 把上面 `semantic_verified` 接上复算结果 |
| 零命中 coverage 说明 | `engine/crypto_functions.rs` / crypto MCP 工具 | candidates 为空时返回 coverage + zeroResultExplanation（§12.3），别只说 "No crypto found" |
| 金标准 + 负样本测试 | `whitebox_aes.rs` `#[cfg(test)]` | 重写 L593/L521 两个误导测试为**正确断言**（启发式→candidate、非 verified、非白盒、不贴 plaintext）；加负样本：base64 表 / CRC 表 / dispatcher 表 / 16B memcpy / 可打印非 key → **都不得** AES verified。金标准值（key `KcIufueoThQliBgs`、首块 `ae2af887...`、sha256 `6d36a4dd...`）用**语义复算路径**单测（给 key+明文，AES-ECB 复算出该密文），不依赖 29 MiB trace |

依赖提醒：AES 语义复算需要 `aes` crate（trace-core 现在没有）——加 `aes`+`cipher`，或写自包含最小 AES。两个 agent 都无法在 Mac 上编译验证 crate API，决定后由 Windows 构建来验证；最小 AES 的好处是无新依赖、可用 FIPS-197 向量离线单测，盲写更稳。

## 3. Claude 这边要做的（taint P0-1，不碰 whitebox）

`TAINT_ANALYSIS_CASE_STUDY.md` §5 —— 让外部调用效果进入污点/内存模型（现在污点在每个 libc 调用处就断）。分阶段：

1. `crates/trace-parser/src/gumtrace.rs`：`CallAnnotation` 增 typed args（ABI/寄存器/角色）、解析 hexdump header 的 base/length + 每行地址、记录 observation/completion seq。
2. 内存 provenance 数据模型 + `engine/query.rs::get_memory_at` 合并 instruction / call_model / call_hexdump / unknown 四类来源（不把 call model 伪装成指令级证据）。
3. 首批 CallEffect 模型：memcpy/memmove/memset/strlen/strcpy/strcat/sprintf(%d)。
4. 接入依赖图（backward/forward 能跨过 libc）——较大，后置。

验收（§5.5）：`get_memory(0x7fd84c7ad0, seq=1040281, 38)` 返回 38 已知字节 + provenance；`taint_analysis(mem:...@1040282)` 能回到 strcat/sprintf 再回到 digest。

## 4. 文件归属（本轮，避免撞车）

**Codex 独占（crypto/whitebox）**：
`query/whitebox_aes.rs`、`engine/whitebox_aes.rs`、新 `query/{software_crypto,aes_schedule,crypto_semantic_verify,crypto_roles,whitebox_classification}.rs`、`query/crypto_functions.rs`、`engine/crypto_functions.rs`、crypto 相关 MCP 工具、`WhiteBoxPanel.tsx`/`CryptoPanel.tsx`（UI 后置）。

**Claude 独占（taint/call-effect）**：
`trace-parser/src/gumtrace.rs`、`scan_unified.rs`、`merge.rs`、`engine/build.rs`、`engine/query.rs::get_memory_at`（仅此函数）、`query/source_sink.rs`、taint 相关 MCP 工具（如 `get_tainted_lines` 绑 analysis_id）。

**共享——只允许追加、改前打招呼**：
`session.rs`（SessionState 各加各的字段）、`api_types.rs`（各加各的 DTO）、`lib.rs`（各加各的 re-export）、`trace-mcp/src/{tools.rs,types.rs}`（各加各的 #[tool]）、`src-tauri/src/{commands/mod.rs,main.rs}`（各注册各的命令）、前端 `TabPanel.tsx`/`types/trace.ts`。规则：**只加不改不删对方的东西**；同一结构体加字段时各加各的、不重排。

> `engine/query.rs` 双方都会碰（crypto scan 在里面，get_memory_at 也在里面）——但函数不同。约定：只改自己那几个函数，别动对方的。

## 5. 协作约定

- **编译测试只在 Windows**：两个 agent 都只在 Mac 写代码，`cargo build/test`、跑金标准与负样本、语义复算验证都由用户在 Windows 执行、结果回传。因此每次改动要尽量自包含、附离线可判定的单测（纯逻辑 + 标准向量），把"编译-报错-再改"的往返降到最低。
- 每完成一项，**同步勾选对应文档的验收清单**（whitebox §16/§17，taint §17）。
- 完成后**更新 `PROJECT_STATE.md`** 的"最近改动"与文档索引（把这两份 case study 加进索引，§16 taint 文档已提出）。
- 新增 MCP 工具后必须**重建 + 重启 Trace UI**（:19821）才在 tools/list 出现——旧 build 看不到。
- 两份路线图都强调的原则，双方都守：**结构信号→候选；数据流→角色；schedule→算法置信度；语义复算→verified；白盒属性单独判定**。不把"像""可推断""已复算""是白盒"混成同一个 High。

## 6. 共享坑位（两边都要知道）

- 污点源 `@LINE` 是 **1-based**；`start_seq/seq` 是 **0-based**。DTO 若同时给两者，字段名写清楚（`lineNumber1Based` / `seq`）。
- 返回前端/MCP 的 DTO 通常只派生 `Serialize`；`EvidenceAssessment` 无 `Deserialize`，含它的结构别派生 `Deserialize`。
- `SessionState` 只在 `engine/mod.rs::create_session` 一处构造——加字段两处改（定义 + 初始化）。
- Tauri 自动 camelCase↔snake_case；前端类型用 camelCase。
- `get_tainted_lines` 现读全局 `slice_result`、不绑 analysis_id（taint §8.1，真 bug）——归 Claude 侧修，Codex 的 crypto 分页也别复制这个反模式。

---

**请 Codex 确认**：是否接受"Codex 做 whitebox/crypto P0、Claude 做 taint P0-1"这个划分？共享文件清单有无异议？确认后各自开工，先动测试、后动实现、最后接 UI。

## 7. 最终所有权与执行决定（Windows Codex 必读）

原第 0～6 节的 Claude/Codex 文件分工不再是执行约束。最终决定：

~~~text
Windows Codex 负责：
  1. software crypto / AES semantic verification / white-box classification
  2. crypto MCP / GUI / regression tests
  3. external CallEffect / memory provenance / taint through libc
  4. 文档、GitHub Actions 和最终集成
~~~

执行时仍然要保持阶段隔离：

~~~text
crypto/whitebox P0 正确性闭环
    ↓
crypto MCP/GUI 与真实 trace 验收
    ↓
call-effect / memory provenance
    ↓
taint 跨 libc
    ↓
全量回归和文档收尾
~~~

不要同时大改 crypto detector、trace parser、memory merge 和 taint graph。否则 GitHub Actions 一旦失败，很难判断回归来源。

## 8. 用户切换到 Windows 前需要准备什么

### 8.1 仓库

在 Windows 上打开实际 Git 仓库根目录，确认能看到：

~~~text
Cargo.toml
Cargo.lock
crates/
src-tauri/
src-web/
WHITEBOX_AES_IMPL.md
TAINT_ANALYSIS_CASE_STUDY.md
CODEX_HANDOFF.md
~~~

建议先建立工作分支：

~~~powershell
git switch -c codex/software-crypto-p0
~~~

如果工作树已有用户改动，不要 reset、checkout 或覆盖；先运行：

~~~powershell
git status --short
git diff --stat
~~~

把已有修改当成用户资产保存。Windows Codex 开工前必须先读差异，不能假定工作树干净。

### 8.2 Rust 与 Node

确认：

~~~powershell
rustc --version
cargo --version
rustup show
node --version
npm --version
~~~

推荐 Rust stable、Node 20。P0 core 测试只需要 Rust；完整 Tauri 构建还需要 Windows MSVC build tools 和 WebView2 环境。

### 8.3 不进入仓库的大型真实样本

把以下主 trace 复制到 Windows 本地，但不要提交 Git：

~~~text
qbdi_20260719_230906_libcryptoDD.so+0x41ed8_1.gumtrace.txt
~~~

Mac 原路径：

~~~text
/Users/jiangxia/安卓逆向/QTrace/luckylogs/
qbdi_20260719_230906_libcryptoDD.so+0x41ed8_1.gumtrace.txt
~~~

同时复制 Python 参考脚本，或至少保留其金标准输出：

~~~text
/Users/jiangxia/code/python/安卓逆向/瑞幸/
reproduce_q_from_trace_sample.py
~~~

Windows 路径可自定。启动 Windows Codex 时把新绝对路径告诉它。不要把 29 MiB trace、手机号、token、完整业务 JSON 或动态账号数据提交到公开仓库。

### 8.4 当前样本金标准

Windows Codex 可以把下列非敏感值写进测试：

~~~text
wrappingKey               Safe_box_1234567
businessKey               KcIufueoThQliBgs
plaintextLength           452 / 0x1c4
paddedLength              464 / 0x1d0
blockCount                29
firstCipherBlock          ae2af887f83430372469ccbf4b3d5916
lastCipherBlock           98e234a6fb29bf721d7201f13f8952bc
ciphertextSha256          6d36a4ddf9a9fece32704646393248f499950f5bef6125fbe137e5e487dd6f95
mode                      AES-128-ECB
padding                   PKCS#7
implementationKind        ObfuscatedStandardSoftware
keyExposure               RawKeyObserved
whiteboxStatus            NotWhiteBox
verification              VerifiedFull
~~~

完整 452-byte JSON 不建议直接新增到公开 fixture。可以使用：

- 当前已有的本地 Python 脚本做 integration check；
- 脱敏等长 fixture；
- 首块明文 + 首块密文；
- 完整 ciphertext SHA-256；
- 本地 ignored integration test。

## 9. Windows Codex 开工前的必读顺序

必须完整阅读：

1. CODEX_HANDOFF.md；
2. WHITEBOX_AES_IMPL.md；
3. TAINT_ANALYSIS_CASE_STUDY.md；
4. PROJECT_STATE.md；
5. crates/trace-core/src/query/whitebox_aes.rs；
6. crates/trace-core/src/engine/whitebox_aes.rs；
7. crates/trace-core/src/query/crypto_functions.rs；
8. crates/trace-core/src/engine/crypto_functions.rs；
9. crates/trace-core/src/engine/query.rs 中 crypto magic scanner；
10. crates/trace-mcp/src/tools.rs 中 analyze_whitebox_crypto；
11. src-web/src/components/WhiteBoxPanel.tsx；
12. src-web/src/types/trace.ts 中 WhiteBox DTO。

然后读取与 taint P0-1 直接相关的 parser/build/query 文件，但不要在 crypto P0 完成前修改它们。

## 10. 基线命令

开始改代码前运行：

~~~powershell
cargo fmt --all -- --check
cargo test -p trace-core evidence_score -- --nocapture
cargo test -p trace-core whitebox -- --nocapture
cargo test -p trace-core
cargo check -p trace-mcp
~~~

前端：

~~~powershell
cd src-web
npm ci
npm run build
cd ..
~~~

如果 baseline 已失败：

1. 保存完整命令和第一个根因错误；
2. 判断是否为现有问题；
3. 不要为了让测试绿而批量改无关文件；
4. 在实施记录中明确 baseline failure；
5. 先修与本任务直接相关的阻断，再进入功能修改。

不建议一开始就跑完整 cargo tauri build；core、MCP 和前端分别通过后再跑完整构建。

## 11. 对原 P0 提案的技术修正

### 11.1 WhiteBoxStatus 不能提前写死

纯 v1 启发式只看到“大量查表 + 连续缓冲 + 近似重复结构”时，应输出：

~~~text
implementationKind = TableDrivenSoftware
keyExposure         = Unknown
whiteboxStatus      = Unknown
assessment          = Related 或 Candidate
~~~

只有自动检测到：

~~~text
raw key
+ standard AES key schedule
~~~

才能输出：

~~~text
implementationKind = ObfuscatedStandardSoftware
keyExposure         = RawKeyObserved
whiteboxStatus      = NotWhiteBox
~~~

禁止根据当前样本名称、固定 module offset、Safe_box 字符串或业务 key 字符串硬编码结论。

### 11.2 semantic gate 的预期行为

score_evidence 的现有规则是：

~~~text
gate=true and score>=75 -> verified
score>=40               -> related
otherwise               -> uncertain
~~~

因此把 verification gate 改为 semantic_verified 后，结构信号仍可得到 related，不会全部变 uncertain。

长期建议拆分：

~~~text
structuralAssessment
semanticVerification
whiteboxAssessment
~~~

P0 可以先保留兼容 assessment，但 verified_gate 只能由语义复算打开。

### 11.3 I/O 必须先中性列出

P0 推荐 DTO：

~~~text
inputCandidates
outputCandidates
plaintext = null until role verified
ciphertext = null until role verified
keys
ivs
schedules
~~~

可打印性只是展示属性，不再参与 plaintext/key/IV 的最终角色判定。

### 11.4 最小 UI/MCP 文案不能后置

完整 Crypto Implementations 页面可以后置，但 P0-A 必须同步修正误导文案：

~~~text
Analyze White-box
    -> Analyze Software/Table Crypto

Plaintext / Ciphertext
    -> Input candidate / Output candidate

Round estimate
    -> Lookup repetition heuristic

Next steps (key recovery)
    -> Evidence-driven next steps
~~~

analyze_whitebox_crypto 可以暂时保留兼容名称，但 description 必须说明：

- 只产结构候选；
- 不证明算法；
- 不证明 white-box；
- verified 需要 semantic verification；
- 后续会由 analyze_crypto_implementations 替代。

### 11.5 AES 实现依赖

优先使用 RustCrypto：

~~~toml
aes = "0.8"
~~~

通过 aes::cipher re-export 使用 KeyInit、BlockEncrypt、BlockDecrypt。不要手写生产 AES core。

AES key schedule 比较可以在 aes_schedule.rs 按 FIPS-197 独立实现，因为 RustCrypto 不保证暴露 round keys。

修改 Cargo.toml 后运行 cargo check/test，让 Cargo 正常更新 Cargo.lock，并提交 Cargo.lock。不要手工猜 lockfile。

## 12. 实施阶段 A：立即停止错误结论

### 12.1 目标

在还没有自动语义复算时，工具也不得继续把当前结构启发式称为 verified white-box AES。

### 12.2 修改项

- [ ] 重写 whitebox_aes.rs 顶部注释，改成 software/table crypto structural candidate；
- [ ] 增加 ImplementationKind；
- [ ] 增加 KeyExposure；
- [ ] 增加 WhiteBoxStatus；
- [ ] 增加 outputCandidates；
- [ ] plaintext/ciphertext 在角色未验证时为 null；
- [ ] pick_plaintext 不再根据 printable 选角色；
- [ ] read_count/distinct_addrs 改为 lookup repetition heuristic；
- [ ] block size 不再由“存在输入候选”硬编码为 16；
- [ ] structural heuristic 最多 related；
- [ ] semantic_verified 才打开 verified gate；
- [ ] 删除默认 DCA/BGE 建议；
- [ ] nextSteps 根据 KeyExposure 生成；
- [ ] MCP 不再把 report.plaintext 无条件写入 evidence.keyStrings；
- [ ] MCP description 修正；
- [ ] WhiteBoxPanel 最小文案修正；
- [ ] TypeScript DTO 同步；
- [ ] 重写旧错误测试；
- [ ] 添加负样本。

### 12.3 负样本

至少覆盖：

- Base64 表；
- CRC 表；
- control-flow dispatcher 表；
- 16-byte memcpy；
- printable 16-byte 字符串但没有 key schedule；
- 十次重复 lookup 但没有 AES 语义；
- 单个 magic constant。

这些都不得返回 AES verified 或 WhiteBox verified。

### 12.4 阶段 A 验收

~~~text
大量表 + I/O + 近似十轮
    -> related structural candidate

plaintext/ciphertext
    -> null

input/output
    -> neutral candidates

whiteboxStatus
    -> Unknown

verificationGateMet
    -> false
~~~

## 13. 实施阶段 B：标准 AES 语义验证

### 13.1 新文件

~~~text
crates/trace-core/src/query/aes_schedule.rs
crates/trace-core/src/query/crypto_semantic_verify.rs
~~~

### 13.2 aes_schedule.rs

实现：

- AES-128/192/256 schedule 生成；
- round count；
- 176/208/240-byte schedule；
- 与 observed schedule 比较；
- word/state endian 的明确处理；
- firstMismatchRound/firstMismatchByte；
- 不匹配时不 panic。

测试：

- FIPS-197 AES-128；
- FIPS-197 AES-192；
- FIPS-197 AES-256；
- 错 key；
- 错 schedule；
- 截断 schedule；
- 多余字节。

### 13.3 crypto_semantic_verify.rs

实现：

- AES-ECB encrypt；
- AES-ECB decrypt；
- 单 block；
- 完整 buffer；
- blocksChecked；
- bytesChecked；
- allMatched；
- firstMismatchBlock；
- expectedHex；
- observedHex；
- 非法 key 长度；
- 非 16-byte 输入；
- input/output 长度不一致；
- PKCS#7 验证与 AES core 分离。

测试：

- NIST/FIPS 单块向量；
- AES-128/192/256；
- 当前样本首块；
- 当前样本末块或完整 SHA-256；
- 错 key；
- 错方向；
- 单字节输出错误；
- 空输入；
- 非整块输入。

### 13.4 verified 规则

~~~text
0 blocks matched
    -> not verified

at least 1 complete block recomputes exactly
    -> Verified

all observed blocks match
    -> VerifiedFull
~~~

不能因为 schedule match、十轮、S-box 或大表单独给 semantic verified。

## 14. 实施阶段 C：真实 trace 自动提取

### 14.1 建议文件

~~~text
crates/trace-core/src/query/software_crypto.rs
crates/trace-core/src/query/crypto_roles.rs
crates/trace-core/src/query/whitebox_classification.rs
crates/trace-core/src/engine/software_crypto.rs
~~~

### 14.2 分析层级

~~~text
trace
  -> function
     -> call instance
        -> block instance
~~~

不要全 trace 聚合后直接估计轮数。本样本有两次 AES-128 key schedule，总计二十次扩展子调用；必须识别成两组各十次，不能写成 AES-20。

### 14.3 当前样本必须自动识别

- [ ] +0x9954 读出 Safe_box_1234567；
- [ ] w2/w4=0x80；
- [ ] +0x1e698 key expansion；
- [ ] +0x1f06c 两组各十次；
- [ ] Rcon 01 02 04 08 10 20 40 80 1b 36；
- [ ] KcIufueoThQliBgs 流入正文 schedule；
- [ ] +0x18244 正文入口；
- [ ] 0x1d0 总长；
- [ ] 29 blocks；
- [ ] 0x10 output stride；
- [ ] +0x18940 block store；
- [ ] 无 IV；
- [ ] 29/29 ECB blocks 复算一致；
- [ ] PKCS#7 12 * 0x0c；
- [ ] 输出 ObfuscatedStandardSoftware；
- [ ] 输出 RawKeyObserved；
- [ ] 输出 NotWhiteBox；
- [ ] 输出 VerifiedFull。

这些 module offsets 只能写进测试/验收，不得成为通用检测逻辑的硬编码条件。

### 14.4 角色原则

~~~text
buffer -> key expansion
    => key candidate

buffer -> initial block state
    => input candidate

expanded region -> per-round XOR
    => schedule candidate

state -> final 16-byte store
    => output candidate

buffer -> chaining XOR
    => IV/previous-block candidate
~~~

角色来自数据流和消费者，不来自 ASCII 是否可打印。

## 15. 实施阶段 D：统一 Crypto、MCP 和 GUI

完成 A～C 后再做：

- [ ] analyze_crypto_functions 聚合 hardware/magic/software/semantic signals；
- [ ] 增加 analyze_crypto_implementations；
- [ ] 增加 start_crypto_implementation_analysis；
- [ ] 增加 verify_crypto_hypothesis；
- [ ] 增加 generate_crypto_reproducer；
- [ ] analyze_whitebox_crypto 变成兼容过滤器并返回 deprecationNotice；
- [ ] candidates 为空时返回 coverage + zeroResultExplanation；
- [ ] 大证据通过 analysis_id 分页；
- [ ] MCP 优先 structuredContent，不再 JSON string 套 text；
- [ ] health/initialize 返回 buildRevision/schemaVersion/capabilities；
- [ ] GUI 统一 Crypto Implementations；
- [ ] 显示 Candidate/Related/Verified/VerifiedFull；
- [ ] 显示 ImplementationKind/KeyExposure/WhiteBoxStatus；
- [ ] 一键跳到 seq/module offset/memory；
- [ ] 已验证后才允许生成 reproducer。

零命中推荐输出：

~~~text
No dedicated crypto instructions or configured magic constants were observed.
This does not exclude software, table-driven, bitsliced, obfuscated, or
white-box implementations. Run the software crypto structural analyzer.
~~~

## 16. GitHub Actions 建议

当前 release.yml 主要在 tag 或手动触发时构建完整应用。建议新增轻量 CI：

~~~text
.github/workflows/ci.yml
~~~

触发：

~~~yaml
on:
  push:
  pull_request:
  workflow_dispatch:
~~~

Jobs 至少包含：

~~~text
Rust:
  cargo fmt --all -- --check
  cargo test -p trace-core
  cargo check -p trace-mcp

Frontend:
  npm ci
  npm run build
~~~

完整 Tauri matrix 继续由 release.yml 负责。日常每次小提交都跑四平台完整 bundle 成本太高，也会降低修复反馈速度。

GitHub Actions 失败时：

1. 先看第一个编译/测试根因；
2. 不要同时修后续级联错误；
3. 把失败命令、文件、行号和错误原文交给 Codex；
4. Codex 做最小修复；
5. 本地复跑相同命令；
6. 再推送；
7. 只有 CI 通过后才勾选文档 checklist。

## 17. crypto P0 完成后的 taint 顺序

crypto P0 稳定后，Windows Codex 再完整阅读 TAINT_ANALYSIS_CASE_STUDY.md 并实施：

1. typed CallAnnotation args；
2. hexdump base/length/line address；
3. observation/completion seq；
4. memory provenance；
5. get_memory_at 合并 instruction/call_model/call_hexdump/unknown；
6. memcpy/memmove/memset/strlen/strcpy/strcat/sprintf(%d) CallEffect；
7. backward/forward dependency 跨 libc；
8. get_tainted_lines 分页绑定 analysis_id；
9. MCP structured output；
10. 两组 MD5 样本归一化结构回归。

不要在 crypto Stage C 尚未稳定时同时修改 engine/query.rs 的 memory merge。

## 18. 每阶段提交与验证建议

建议小提交：

~~~text
1. test: capture current structural false positives
2. fix: downgrade table heuristics and neutralize IO roles
3. feat: add AES key schedule verification
4. feat: add AES ECB semantic verification
5. feat: detect block stride and call instances
6. feat: classify standard software vs white-box
7. fix: explain crypto detector coverage gaps
8. ui: show implementation and verification separately
9. ci: add core/MCP/frontend validation
10. docs: update project state and acceptance checklists
~~~

每个提交后至少运行与改动对应的最小测试。阶段结束再跑：

~~~powershell
cargo fmt --all -- --check
cargo test -p trace-core
cargo check -p trace-mcp
cd src-web
npm run build
cd ..
~~~

阶段 D 或准备 release 时再运行：

~~~powershell
cargo tauri build --ci
~~~

## 19. 禁止事项

- 不硬编码当前 trace 的绝对地址；
- 不硬编码 KcIufueoThQliBgs 作为算法特征；
- 不把 Safe_box_1234567 永久写死为产品 key；
- 不把 printable buffer 自动标 plaintext；
- 不把 read_count/distinct_addrs 当精确轮数；
- 不把 single magic 当证明；
- 不把 structural related 展示成 verified；
- 不把 software table AES 默认叫 white-box；
- 不在没有复算时输出具体 mode 已验证；
- 不把 MCP JSON 再套成大文本字符串；
- 不让证据分页依赖 SessionState 最后一次全局结果；
- 不提交大型真实 trace 或敏感业务明文；
- 不用 git reset --hard/checkout 覆盖用户改动；
- 不为了 cargo fmt 批量格式化无关历史文件；
- 不在 CI 失败时同时改多个不相关模块。

## 20. Windows Codex 启动提示词

用户切到 Windows 后，可以直接把下面内容发给新的 Codex：

~~~text
请在当前 trace-ui 仓库中继续软件密码识别和污点引擎优化。

第一步必须完整阅读：
1. CODEX_HANDOFF.md
2. WHITEBOX_AES_IMPL.md
3. TAINT_ANALYSIS_CASE_STUDY.md
4. PROJECT_STATE.md

执行以 CODEX_HANDOFF.md 第 7～20 节为准；第 0～6 节只是历史 Claude/Codex 分工提案。
你现在接管 crypto/whitebox 和 taint/call-effect 两条路线，但必须先完成 crypto P0，
不要同时修改 taint/parser。

先检查 git status 和已有用户改动，再运行第 10 节 baseline。
先写测试，然后实施 Stage A：停止 white-box/plaintext/verified 误报；
再实施 Stage B：AES key schedule 和 ECB semantic verification；
再用我提供的 Windows trace 绝对路径实施 Stage C；
最后做 MCP/GUI Stage D。

严格遵守：
结构信号只产生 candidate/related；
数据流确定 key/input/output/IV 角色；
标准 key schedule 增强 AES 结论；
至少一个 block 复算一致才 verified；
全部 block 一致才 verified_full；
white-box 属性单独判定。

不要硬编码样本绝对地址、业务 key 或 module offset。
每完成一个阶段都运行 cargo fmt、trace-core tests、trace-mcp check 和前端 build，
并更新 WHITEBOX_AES_IMPL.md 的 P0/验收清单。

真实 trace 的 Windows 路径是：
<用户在这里填写>

Python 参考脚本的 Windows 路径是：
<用户在这里填写>

GitHub Actions 若失败，先处理第一个根因错误，不要一次修改多个模块。
~~~

## 21. 用户到 Windows 后的最短操作清单

1. 打开 trace-ui Git 仓库；
2. 确认 Rust/Cargo/Node 可用；
3. 将主 trace 和 Python 脚本复制到 Windows 本地；
4. 启动 Codex，工作目录设为仓库根；
5. 粘贴第 20 节启动提示词；
6. 把两个 Windows 绝对路径补进去；
7. 让 Codex先报告 git status 和 baseline，不要跳过测试直接改；
8. 每次 GitHub Actions 失败，把第一个根因错误原文交回同一个 Codex 任务；
9. crypto P0 完成并通过后，再让它进入 taint P0-1；
10. 最后重建并重启 Trace UI，确认 MCP tools/list 和 GUI 使用新 build。
