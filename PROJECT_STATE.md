# 项目状态与交接（先读这个）

> 用途：让 AI（Claude / Codex）快速理解当前项目状态再继续干活，也给作者自己当记忆锚点。
> 最近更新：2026-07-18。历史设计见 `AI_ANALYSIS_ROADMAP.md` / `OPTIMIZATION_ROADMAP.md`，实施细节见 `CRYPTO_FUNCTIONS_IMPL.md`，macOS 构建见 `MACOS_SOURCE_BUILD.md`。

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
- `trace-mcp` — MCP 协议层，`tools.rs` ~33 个 `#[tool]`，HTTP/SSE + stdio 双传输
- `trace-cli` — 独立 stdio MCP 二进制
- `src-tauri` — Tauri 胶水，`commands/mod.rs`（~47 命令）、`mcp.rs`（内置 MCP :19821）

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
| `README.md` | 面向用户的功能总览 |
| `AI_ANALYSIS_ROADMAP.md` | AI 分析能力路线与决策记录 |
| `OPTIMIZATION_ROADMAP.md` | P0-P3 优化任务、阶段五（密码识别）细节 |
| `CRYPTO_FUNCTIONS_IMPL.md` | 函数级密码识别的完整实施说明（含代码） |
| `MACOS_SOURCE_BUILD.md` | macOS 构建步骤 |
| `.claude/skills/trace-analysis/` | AI 使用 trace-ui MCP 的技能（套路 + 工具表 + 实战案例） |
