# 项目状态与交接（先读这个）

## 2026-08-02 当前增量

- 前端安全与工作流收尾：Crypto Materials 和 Frida 材料索引默认遮罩 key/salt/digest 等完整字节，改为每条材料独立显示/隐藏；Frida 捕获列表支持元数据搜索、事件类型和 payload 筛选，并使用 `useVirtualizerNoSync` 虚拟滚动；Crypto 子页面按首次访问懒加载并保持已访问页签状态；Frida/OLLVM 页面提示所有脚本由用户手动执行；不支持独立窗口的页签已禁用拖出；`npm run check:ui-guards` 与 `npm run test:ui` 防止自动 Frida 行为、空浮动面板、关键旧文案和核心交互回归。

- 新增 **Crypto Material Explorer**：统一索引 raw/derived key、password、salt、IV、nonce、counter、plaintext/ciphertext、digest/MAC、AAD、tag；支持 AES、MD5/SHA、HMAC、PBKDF2 确定性复算和跨 trace salt/nonce 候选隔离。
- 软件 AES 分析补充动态内存证据：标准 S-box 地址/值指纹、AES-128 44-word 展开密钥验证、连续 input/output 重建和逐 block 语义复算；无 API 注释的 GumTrace 也可进入 Verified，现有 CBC/CTR/GCM 与 Crypto Materials/Frida/OLLVM 工作流保持不变。
- 新增 **Frida 16 Hook Generator**：按 module export 或 module-relative offset 生成 X0-X7、SP/LR/PC、buffer/string、return、backtrace、Stalker 脚本，事件协议为 `trace-ui/frida-hook-v1`。产品边界固定为“只生成/保存脚本”，用户自行 attach、spawn、load 和执行 hook。
- 新增 **Frida 16 Crypto API Recipes**：GUI/MCP 可列出并套用 OpenSSL/BoringSSL 与 Apple CommonCrypto 的 17 个常见 MD5/SHA、EVP、HMAC、PBKDF2、CCCrypt 配方；支持固定长度、X0-X7 长度寄存器和返回时 `*Xn` u32 输出长度。ABI 无法证明的算法、PRF、IV/栈参数均保留警告，长度指针读取失败不会降级为最大缓冲区读取。
- 新增 **Frida Capture Import / angr State Seed**：导入用户手动捕获的 JSON/NDJSON/`TRACE_UI_JSON` CLI 日志，规范化 callId/module mapping，查看 registers/buffers/return/backtrace/Stalker batches，并生成 `trace-ui/angr-state-seed-v1` 的 `configure_state(state)`。
- 新增 **AI 分页检索 Frida Capture**：MCP `search_frida_capture_events` 按元数据、事件类型、module/function/callId 与 payload 条件返回有界摘要和精确 event index；`get_frida_capture_event` 再按需读取单个事件。寄存器、buffer、return、backtrace 默认不返回，避免大捕获占满 AI 上下文。
- 增强 **Frida → angr NZCV state handoff**：从 ARM64 Frida capture 读取 packed `NZCV`，写入 standalone angr seed 和 OLLVM bridge；如果 angr 架构没有 packed `nzcv`，生成脚本会尝试 N/Z/C/V 单独寄存器并保留 warning。Flags 与寄存器/内存一样仍需匹配捕获点语义，不能单独证明 opaque branch 可达。
- 新增 **Frida Capture Crypto Materials**：按 callId 索引 key/password/salt/IV/nonce/AAD/tag/input/output/digest/MAC/KDF 候选，并对完整捕获的 MD5/SHA、HMAC、PBKDF2 做受限确定性重算；标签推断保持 Related。
- 增强 **Frida AES 语义验证**：`analyze_frida_crypto_materials` 现在按 `callId` 合并 enter/leave 捕获，支持显式角色和有界的 X0/X1/X2 native block ABI fallback，尝试 AES-128/192/256 ECB Encrypt/Decrypt，聚合连续单块调用，并按实际覆盖输出 `VerifiedFull` / `VerifiedPartial` / `VerifiedBlock`。错误 key 或被修改的 ciphertext 不能打开完整验证 gate。
- 增强 **IDA / OLLVM**：动态 CFG、dispatcher/opaque branch 候选评分、dispatcher state-register snapshots/transitions、branch register observations、IDAPython 注释/颜色/可选 xrefs，以及 `trace-ui/ida-ollvm-v1` annotations 双向 JSON。所有 OLLVM 结论保持动态候选级。
- 增强 **OLLVM 多运行矩阵**：`compare_ollvm_traces` 对齐 2–16 个 trace scope 的 module offsets，比较 dispatcher/state-register 稳定性与所有条件分支结果；每个 case 可绑定 exact ELF，默认 GUI 要求完整身份，SHA-256 不一致会拒绝比较，Build ID/哈希写入报告；alternate outcome 会明确反驳全局 opaque 假设。
- 新增 **OLLVM 跨版本结构映射**：`map_ollvm_versions` 和 GUI Cross-version 页面接受 2–8 个不同 AArch64 ELF 版本，要求独立 version ID/trace scope/exact ELF 且 SHA-256 两两不同；允许模块名和 offset 改变，按 bounded operation LCS、动态 CFG shape、dispatcher role 与 state-register behavior 返回 top-N 候选并标记 ambiguous。所有映射保持 Candidate/Related，禁止跨版本复用 offset、state value、Frida capture 或 angr seed。
- 增强 **angr / OLLVM bridge**：从动态 OLLVM 报告生成用户手动执行的 Python/angr 脚本，对账 CFGFast/CFGEmulated 静态后继与 trace observed edges，并导回 `trace-ui/angr-ollvm-v1` JSON。除 blank-state/trace-register probe 外，首个 trace seed 与 exact-offset Frida seed 可做限深/限状态 symbolic flow continuation，输出路径与 loop/depth/state/dead-end/external 终止原因；所有结果仍不代表真实入口可达性。
- 增强 **Frida → angr OLLVM exact-offset seed**：可从 opaque branch/condition-source 候选预填 Frida 16 offset Hook，导入用户手动捕获的 hook-enter 事件，并把 X0-X28/FP/LR/SP 与 byteArray memory seed 嵌入 angr 脚本。仅当 capture module/offset 精确命中候选位置时生成额外 probe；结果记录 event/offset/provenance 且始终保持 Candidate/Related。
- 新增 **Frida dispatcher-entry → angr bounded flow**：dispatcher 行可预填 `startOffset` 的 Frida 16 Hook；用户手动执行并导入精确 `hook-enter` 后，angr 从该 dispatcher 状态有界探索到下一 dispatcher、循环、外部目标、死路或深度/状态上限，并回导目标 state-register 的 concrete/symbolic/unavailable 候选值。Trace UI 不执行 Frida/angr，也不把该结果表述为自动去平坦化或 Verified CFG。
- 新增 **Frida multi-dispatcher capture atlas**：`generate_frida_ollvm_dispatcher_hook` 一次生成最多 64 个 ranked dispatcher 入口的 Frida 16.x 手动脚本；用户运行后导入 `ollvm-dispatcher-hit`，`analyze_frida_ollvm_dispatcher_capture` 按 exact module-relative offset、capture session、线程、flow 和连续 hit sequence 汇总 nodes/transitions/state-register distributions/state changes/flow paths。专用脚本的 flow ID 与 legacy idle-gap 派生 flow 都只用于候选聚合，结果保持 Candidate/Related。
- 增强 **Dispatcher pointer/stack-memory capture**：multi-dispatcher 脚本允许用户显式选择 X0-X28、每个指针的最大读取字节数，以及从 SP 开始的可选 0-16 KiB 栈窗口；捕获结果复用 `byteArray`/`readError` 协议，可直接生成后续 angr/Unicorn memory seed。默认不读取任何指针或栈，所有读取有界且由用户手动运行脚本。
- 增强 **angr exact ELF guard / multi-seed handoff**：`generate_angr_ollvm_script` 可选绑定 exact AArch64 ELF SHA-256，生成的 Python 在建立 angr Project 前拒绝哈希不一致的文件；同一 Frida 捕获可一次嵌入最多 32 个精确匹配的 branch/condition-source/dispatcher 事件，并在结果中保留全部 provenance。该哈希只验证用户选择的文件，不证明原 trace 的运行时映像。
- 新增 **Unicorn exact-seed concrete replay**：`generate_unicorn_ollvm_script` 强制绑定 exact AArch64 ELF 和 1–32 个精确 Frida 事件，生成独立 Python 进行 bounded concrete replay；`inspect_unicorn_ollvm_results` 严格导回 next-dispatcher/return/call/loop/missing-state 等停止结果、状态寄存器变化、内存写、dispatcher 转移矩阵和 register-relative recapture suggestion。缺失运行时内存、SIMD、TLS/系统状态不会静默补零，所有结果保持 Candidate/Related。
- 增强 **Unicorn missing-memory → Frida 精确重捕获闭环**：每个 Unicorn seed 现在携带经过 runtime register/pointer 校验的 `seedRecapturePlans`；大于 4096 字节的 exact byteArray 自动拆窗。`generate_frida_unicorn_recapture_hook` 与 GUI 可把最多 64 条 X0-X28/SP 正负位移建议聚合到最多 32 个原始 exact seed offset，并重新读取上一轮可安全携带的 key/input/stack 等窗口；旧窗口和新建议按 register/displacement/length 去重，无法验证相对关系或达到窗口上限时明确 warning。新 `hook-enter` 可再次生成 angr/Unicorn seed，实现逐轮补全而不复制绝对地址、陈旧字节或静默补零。Trace UI 仍不 attach/spawn/load/run Frida，嵌入的 ELF SHA-256 仅作为上一轮 provenance。
- 新增 **Unicorn/OLLVM 多轮重放进度比较**：核心协议 `trace-ui/unicorn-ollvm-round-comparison-v1`、MCP/Tauri `compare_unicorn_ollvm_rounds` 和 GUI“对比多轮 JSON”统一读取 2–16 轮严格校验结果。只允许相同 module 与 exact ELF SHA-256，按 `captureOffset` 聚合 seed，报告累计新增 offset/block、新 dispatcher、缺页前移、同点停滞、路径分歧、覆盖回退、seed 增删、配置漂移和截断证据；建议继续重捕获、选择更近人工 checkpoint 或转有界 angr。所有分类保持 Candidate/Related，Trace UI 不自动执行模拟器。
- 新增 **Unicorn 停滞 → 更近 checkpoint → 再模拟闭环**：协议 `trace-ui/frida-unicorn-checkpoint-hook-v1`、MCP `generate_frida_unicorn_checkpoint_hook`、Tauri 生成/保存命令和 GUI“更近 checkpoint 捕获”统一从严格校验的上一轮 Unicorn 结果选择 1–32 个原 seed。`missing-memory` 优先落在实际 missing PC，`missing-register`、`loop-detected`、`instruction-limit`、`timeout` 落在 terminal PC；捕获完整 X0-X28、FP/LR/SP/PC/NZCV，并只读取已有安全 X0-X28/SP-relative 建议。新 capture 只有同时提供同 module、同 exact ELF SHA-256 的上一轮结果，且 offset 属于其支持 checkpoint 集合时，才可再次生成 Unicorn 脚本；absolute/X29/X30 保持 manual，结果保持 Candidate/Related，Trace UI 不执行 Frida/Unicorn。
- 新增 **更近 Unicorn checkpoint → bounded angr 接力**：`generate_angr_ollvm_script`/Tauri 同步接受 `checkpoint_result_path`，Core 新入口 `generate_angr_ollvm_script_with_seeds_flow_identity_and_checkpoint` 复用严格 checkpoint 授权。只有 report module、上一轮 result expected/actual SHA-256、当前 exact ELF SHA-256 和捕获 offset 全部匹配时，才生成 `frida-capture-authorized-checkpoint` seed；Python 从该捕获建立 blank state、应用 GPR/NZCV/byteArray memory，并有界探索到下一 dispatcher、loop、external、dead-end/unconstrained 或 depth/state 上限。结果新增 `checkpointProbes`；“模拟增强”页第 6 步支持生成/保存/复制脚本、导入结果并查看路径。所有结果保持 Candidate/Related，Trace UI 不执行 angr。
- 新增 **call-boundary → post-call return checkpoint**：Unicorn 结果为 BL/BLR 保存调用点、目标和 `PC+4` return offset；checkpoint Hook 在真实返回点捕获完整 GPR/NZCV，并重新读取已有 `seedRecapturePlans` 中经过验证的 X0-X28/SP-relative byteArray 窗口。旧结果缺少 return offset 时保持兼容但不推断续跑点；调用不返回或走其他控制流时明确没有 capture 证据。
- Frida capture parser 已同步保留 X8-X28 pointer snapshot 与 SP 栈窗口，相关 byteArray 会进入 angr/Unicorn state seed；有端到端回归防止退回旧 X0-X7 导入限制。
- 增强 **OLLVM condition-state profile**：条件分支报告聚合已捕获/缺失观察、distinct 条件值、按 outcome 的值分布及 NZCV 的 N/Z/C/V set/clear 计数；profile 不完整时明确标记，仍仅作为 Candidate/Related 证据。
- GUI 入口位于 `Crypto > Materials`、`Crypto > Frida Hook`、`Crypto > IDA / OLLVM`，其中 OLLVM 面板包含 IDA、通用 angr bridge 与“模拟增强”里的 checkpoint → bounded angr 接力；Tauri 和 MCP 已完整接线。
- MCP 覆盖 `analyze_crypto_materials`、`compare_crypto_material_traces`、`list_frida_hook_recipes`、`generate_frida_hook`、`generate_frida_ollvm_dispatcher_hook`、`generate_frida_unicorn_recapture_hook`、`generate_frida_unicorn_checkpoint_hook`、`inspect_frida_capture`、`search_frida_capture_events`、`get_frida_capture_event`、`analyze_frida_crypto_materials`、`analyze_frida_ollvm_dispatcher_capture`、`generate_angr_state_seed`、`analyze_ollvm`、`compare_ollvm_traces`、`map_ollvm_versions`、`generate_ida_ollvm_script`、`inspect_ida_annotations`、`generate_angr_ollvm_script`、`inspect_angr_ollvm_results`、`generate_unicorn_ollvm_script`、`inspect_unicorn_ollvm_results`、`compare_unicorn_ollvm_rounds`。当前 MCP 共 64 个工具，Tauri invoke handler 共 83 个命令。
- Skills：更新 `trace-analysis`、`frida-hook-generation`、`ida-ollvm-analysis`。Frida skill 会优先检查审计配方，并明确禁止自动执行脚本；angr bridge 同样只生成脚本，由用户手动运行。
- `main` push 会触发 `.github/workflows/macos.yml`，构建 macOS arm64 与 x64 DMG artifacts。

> 用途：让 AI（Claude / Codex）快速理解当前项目状态再继续干活，也给作者自己当记忆锚点。
> 最近更新：2026-08-02。当前代码变更与交接先读 `CURRENT_CHANGELOG.md`；历史设计见 `AI_ANALYSIS_ROADMAP.md` / `OPTIMIZATION_ROADMAP.md`，实施细节见 `CRYPTO_FUNCTIONS_IMPL.md`，macOS 构建见 `MACOS_SOURCE_BUILD.md`。

## 1. 这是什么

Trace UI = ARM64 执行 trace 的可视化分析桌面工具（Tauri 2 + React 19 + Rust workspace），面向安卓/iOS native 逆向。支持 **unidbg** 和 **GumTrace**（Frida Stalker）两种 trace 格式，自动检测。核心能力：大规模 trace 浏览、正/反向污点、依赖图、调用树、字符串提取、密码识别、以及**内置 MCP Server** 让 AI 直接分析 trace。

这是**基于原仓库的魔改分支**（base commit `33ed4270`）。主线方向：把工具从"人工看 trace"升级为"**AI 主导调查、人工核验证据**"。

## 2. 最近几轮做了什么（本轮重点，AI 接手先看这里）

三个新功能 + 构建修复 + AI 技能，均**向后兼容**，不动原有 Detection/Search/Taint 等。

### 2.1 函数级密码识别（Function-level Crypto ID）
把"逐行魔数命中"升级为"按函数聚合 + 置信度评分"。结合 ARM64 专用密码指令（aese/sha256h/sm4e/crc32* 等）与常量多样性，产出 **High/Med/Low**，附入口 X0-X7 / 返回 X0 / 调用注解。
- 核心：`crates/trace-core/src/query/crypto_functions.rs`（类型+纯逻辑+评分+单测）、`engine/crypto_functions.rs`（`analyze_crypto_functions`）
- MCP 工具 `analyze_crypto_functions`（可保存 analysis_id）；Tauri 同名命令；前端 CryptoPanel 第 3 页签 **Functions**（`components/CryptoFunctionsPanel.tsx`）

### 2.2 GUI 分析历史面板（Analysis History）
AI/MCP 建的分析（磁盘持久化、按 trace 内容校验）现在能在 app 里看/比/删/导出，补上"人工核验"闭环。后端方法本来就有（`engine/analysis.rs`），只加了 Tauri 接线。
- Tauri 命令：`list_analyses` / `get_analysis` / `compare_analyses` / `delete_analysis` / `render_analysis_report`
- 前端：`components/AnalysisHistoryPanel.tsx` + TabPanel 第 7 页签 **Analyses**

### 2.3 通用函数检查器（Function Inspector）
把 2.1 的 I/O 提取泛化到任意函数：点 trace 任一行 → 右侧显示所在函数的入口 X0-X7 / 返回 / 调用注解 / 父/子函数 / 内存读写。父/子可点跳转。
- 核心：`query/function_inspect.rs`（DTO）、`engine/function_inspect.rs`（`inspect_function` / `inspect_function_at_seq`，复用 `get_call_tree_children`/`get_registers_at`/`get_lines` + `innermost_function_for_seq`）
- Tauri：`inspect_function` / `inspect_function_at_seq`；前端 `components/FunctionInspectorPanel.tsx` + TabPanel 第 8 页签 **Function**（selectedSeq 驱动、250ms 防抖、`active` 门控）

### 2.4 构建修复（既有问题，非新代码引入）
- `example-trace-unidbg.txt` fixture 未随源码发布 → `test_unidbg_format_basic` 改为"文件不存在就跳过"
- tauri Rust crate（2.11.5 等）领先 npm 包（2.10.x）→ `src-web/package.json` 已 pin 到 2.11.5/2.7.1/2.5.4

### 2.5 AI 技能（trace-analysis skill）
教 AI 把常见逆向问题映射成确定的 MCP 工具套路。三处同步安装：`~/.claude/skills/`、`~/.codex/skills/`、本仓库 `.claude/skills/trace-analysis/`（SKILL.md + references/mcp-tools.md + references/playbook-examples.md）。Codex 的 trace-ui MCP 已注册（HTTP :19821）。

## 3. 架构速览

Rust workspace 5 crate：
- `trace-parser` — 行解析、数据模型（`RegId`/`ParsedLine`/`MemOp`）、指令分类 `insn_class.rs`（**ARM64 密码指令已分类**）、格式检测 `gumtrace::detect_format`
- `trace-core` — 分析引擎。`engine/`（build/slice/forward_slice/search/query/source_sink/trace_diff/crypto_functions/function_inspect）、`query/`（纯逻辑+DTO）、`flat/`（bincode 缓存）、`analysis.rs`（分析记录）、`session.rs`（SessionState）
- `trace-mcp` — MCP 协议层，当前 63 个 `#[tool]`，HTTP/SSE + stdio 双传输
- `trace-cli` — 独立 stdio MCP 二进制
- `src-tauri` — Tauri 胶水，invoke handler 当前 83 个命令、`mcp.rs`（内置 MCP :19821）

前端 `src-web/src`：`App.tsx` + `TraceTable.tsx`(Canvas) 为核心；面板系统在 `components/TabPanel.tsx`（8 个页签：Memory/Accesses/Taint State/Search/Strings/Crypto/Analyses/Function）；状态 `hooks/useTraceStore.ts`；类型 `types/trace.ts`。

数据流：mmap 零拷贝 + 一遍扫描建依赖图/调用树/内存索引/寄存器 checkpoint → bincode 缓存（内容校验）→ 污点是预建依赖图上的 BFS。GUI 与 MCP 共享同一 core。

## 4. 构建 / 运行

> **环境事实**：Mac 只用来写代码（无 cargo/rust）；**编译和测试统一在 Windows**。AI 改完代码由作者在 Windows 构建验证——所以改动要尽量自包含、附离线可判定单测，减少"编译-报错-再改"往返。

Windows（作者唯一编译/测试环境）：
```powershell
cd trace-ui
npm install --prefix src-web        # 注意：改过 package.json 版本后首次用 install（重算 lock），别用 npm ci
cargo test --workspace --all-targets
cargo tauri build                   # 产物含内置 MCP :19821
cargo build --release --bin trace-cli   # 可选：stdio MCP CLI
```
macOS：见 `MACOS_SOURCE_BUILD.md`（`npm ci --prefix src-web` + `cargo tauri build --target aarch64-apple-darwin`）。
验证：`cargo test` 能跑到 "N passed" 就说明 trace-core/trace-mcp 编译通过。

## 5. 下一步候选（按性价比，均未做）

- **工程加固（推荐先做）**：永久锁 tauri 版本漂移 + 最小 CI（fmt/clippy/test + 前端构建）
- 密码线收尾：`analyze_crypto_functions` 接进 `auto_investigate` + 做成 Recipe + 关联 known-digest 输出 + 磁盘缓存
- 通用值/内存搜索 `find_memory_pattern`（Hex/整数/地址/ASCII-UTF8）
- 字符串索引保留原始字节/UTF-16/末尾 NUL（提升 known-digest 命中）
- 前端 Vitest 测试
- 详细路线见 `OPTIMIZATION_ROADMAP.md` 阶段五及后续。

## 6. 改代码要知道的约定 / 坑（AI 务必读）

- **污点源 `@LINE` 是 1-based**（对齐 UI 行号）；`start_seq`/`end_seq`/`seq` 是 0-based。别混。
- **返回给前端/MCP 的 DTO 只派生 `Serialize`**：`EvidenceAssessment` 没有 `Deserialize`，含它的结构（如 CryptoFunctionCandidate/Report）不能派生 `Deserialize`（缓存是内存 Rust 值，不反序列化）。
- **`SessionState` 只在 `engine/mod.rs::create_session` 一处构造**——加新字段两处都要改（`session.rs` 定义 + 这里初始化）。
- **Tauri 自动 camelCase↔snake_case**：前端 `invoke("x",{sessionId})` 对应 Rust `session_id`。前端类型用 camelCase（serde `rename_all="camelCase"`）。
- **浮动面板**：`FloatingPanel.tsx` 的 switch 有 default 占位；Crypto/Analyses/Function 只做停靠、未做浮动（拖出会显示 placeholder，与 Crypto 现状一致）。
- `innermost_function_for_seq`（seq→最内层函数）在 `query/crypto_functions.rs`，被 function_inspect 复用。
- `get_registers_at(seq)` 从最近寄存器 checkpoint 重放得精确值（提取入口/出口寄存器就用它）；`call_annotations` 给注解调用的 func_name/args/ret。
- **新加的 MCP 工具要重建 + 重启 Trace UI 才在 :19821 上出现**（当前跑着的可能是旧 build）。
- 每加一个功能：core 纯逻辑放 `query/`、引擎方法放 `engine/`、`lib.rs` re-export、MCP `tools.rs` + `types.rs`、Tauri `commands/mod.rs` + `main.rs` 注册、前端类型 + 组件 + TabPanel 页签。

## 7. 文档索引

| 文档 | 内容 |
|------|------|
| 本文件 | 项目当前状态、最近改动、构建、约定（先读） |
| `CURRENT_CHANGELOG.md` | 当前实现、最近提交、代码位置、工作流、安全边界与界面中文化记录（交接首选） |
| `README.md` | 面向用户的功能总览 |
| `AI_ANALYSIS_ROADMAP.md` | AI 分析能力路线与决策记录 |
| `OPTIMIZATION_ROADMAP.md` | P0-P3 优化任务、阶段五（密码识别）细节 |
| `CRYPTO_FUNCTIONS_IMPL.md` | 函数级密码识别的完整实施说明（含代码） |
| `MACOS_SOURCE_BUILD.md` | macOS 构建步骤 |
| `.claude/skills/trace-analysis/` | AI 使用 trace-ui MCP 的技能（套路 + 工具表 + 实战案例） |
