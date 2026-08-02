# Trace UI 当前开发记录与后续交接

最后更新：2026-08-02
当前分支：`feat/unicorn-ollvm-replay`
功能基线提交：`9211fdc feat: harden OLLVM angr handoff`（其后的提交继续记录界面中文化与文档交接）

这份文档是后续 Codex/开发者进入项目时的快速入口。它记录当前已经实现的 Frida 16、OLLVM、IDA、angr 和密码材料分析能力，以及每项能力对应的代码位置和边界。

## 本轮 Unicorn OLLVM 模拟增强

- 新增 `trace-ui/unicorn-ollvm-v1` 生成器和严格结果解析器，强制 exact AArch64 ELF SHA-256 与 1–32 个精确 Frida seed。
- 生成的独立 Python 使用 Unicorn 2.x、Capstone 和 pyelftools，支持 next-dispatcher、return、call、loop、missing-memory/register、SIMD/system-state、timeout 和 instruction-limit 等显式停止原因。
- 新增 seed 完整度、dispatcher 转移矩阵、寄存器变化、内存写入和 `baseRegister + displacement` Frida 重捕获建议。
- OLLVM GUI 新增“模拟增强”页签；MCP 新增 `generate_unicorn_ollvm_script` 与 `inspect_unicorn_ollvm_results`。Trace UI 仍只生成/保存脚本并导入结果，不自动执行模拟器。
- Dispatcher Frida 捕获扩展为可选 X0-X28 pointer snapshot 与从 SP 开始的 0–16 KiB 栈窗口；默认均关闭，读取失败保持 `readError`。
- Frida 捕获导入同步接受 X8-X28 和合成 SP 栈 capture index，避免新增内存在生成 angr/Unicorn seed 时被旧 X0-X7 过滤器静默丢弃。
- Release Action 从真实 `src-tauri` 应用目录启动 Tauri，和本地 Windows MSI/NSIS 成功构建路径保持一致。

## 本轮 MCP 大捕获检索

2026-07-22 增加了面向 AI 的 Frida capture 两阶段读取能力：

- `search_frida_capture_events` 对 JSON/NDJSON/CLI log 做元数据、事件类型、模块、函数、callId 和 payload 条件筛选，默认每页 50 条、最大 200 条，只返回摘要与精确 `eventIndex`。
- `get_frida_capture_event` 按精确 `eventIndex` 读取单个事件；registers、captures、return value、backtrace 默认关闭，capture value 受 `maxBytes` 限制并标记 `valueTruncated`。
- AI 推荐流程改为“捕获概要 → 分页搜索 → 单事件详情 → crypto material/angr seed”，避免把超大捕获一次塞进模型上下文。
- 保持 `trace-ui/frida-hook-v1` 协议兼容；Trace UI 仍不 attach、spawn、load 或执行 Frida/angr。
- 同步更新仓库和本机 Codex 的 `trace-analysis`、`frida-hook-generation` skill 文档。

## 本轮工作流与敏感材料防护

2026-07-22 完成了一轮轻量前端收尾，未修改后端 DTO、Frida/angr/IDA 脚本协议或执行边界：

- `Crypto > 材料` 与 Frida 捕获材料索引默认遮罩完整十六进制值；改为每条记录独立“显示完整材料/隐藏完整材料”，默认 tooltip 不再携带完整材料。
- 完整材料仍保留在分析结果和导出协议中；“复制完整十六进制”是明确的用户操作，不改变原始数据。
- Frida 与 OLLVM 页面新增手动工作流提示，明确 Trace UI 只生成脚本、导入结果，不自动连接目标、启动进程或执行 Frida/angr。
- Frida 捕获结果支持按事件、函数、模块、callId 等元数据搜索，按 `hook-enter`/`hook-leave`/dispatcher/Stalker 类型筛选，并可只看含寄存器或 buffer 的事件；筛选后的完整结果交给虚拟列表处理。
- Frida 捕获事件列表改为真正的虚拟滚动：保留完整筛选结果，只渲染视口附近的行，不再因为事件数量增加而创建成千上万个 DOM 节点。
- 主页签仅允许 `Memory`、`Search`、`Strings` 拖出为独立窗口；未实现浮动版本的面板不再打开空白 placeholder 窗口。
- Crypto 子页面按首次访问懒加载，已访问页签继续保留状态；本轮构建的入口 chunk 从约 740 KB 降至约 597 KB，OLLVM 等大面板拆为独立 chunk。
- 清理 Crypto、Known Digest、Analysis History、浮动搜索与 OLLVM 入口的剩余英文操作文案。
- 新增 `npm run check:ui-guards`，检查自动 Frida 边界、浮动面板白名单、敏感材料遮罩和关键旧文案回归。
- 新增 `npm run test:ui`（Vitest + Testing Library），覆盖材料默认遮罩/单条展开和 Frida 捕获筛选逻辑；CI 会在前端构建前执行 guard 与交互测试。

验证：`npm run check:ui-guards`、`npm run build`、`git diff --check` 均通过。

## 本轮界面中文化

2026-07-22 对桌面前端进行了面向中文使用者的系统化文案调整，目标是“专业中文为主，必要英文术语保留”，没有修改后端协议字段、事件名、导入导出格式或脚本 API。

覆盖范围：

- 顶部文件、视图、分析、设置菜单，以及搜索、最近文件、确认框和状态提示。
- Trace 表格、函数树/函数列表/函数检查、内存、字符串、交叉引用、搜索结果和浮动窗口。
- 污点分析配置、污点结果摘要、依赖树和错误提示。
- 值搜索、已知摘要、加密常量、Crypto Materials、软件/查表型加密分析。
- Frida 16 Hook 生成、捕获导入、材料索引、angr state seed。
- OLLVM dispatcher/state/opaque 候选、多运行比较、跨版本映射、Frida Dispatcher Atlas、IDA bridge 和 angr bridge。

术语约定：

- 保留 `Trace`、ARM64、Frida、Stalker、OLLVM、dispatcher、opaque、CFG、ELF、IDA、angr、Hook、seed、Atlas、XRefs 等标准名称。
- 面向操作的文案使用中文，例如“导入捕获”“生成脚本”“精确 ELF 身份校验”“向后污点追踪”。
- `Candidate`/`Related`/`Verified` 等证据等级若来自结果协议，仍保留原值，周边说明使用中文，避免改变机器可读语义。

主要前端文件位于 `src-web/src/App.tsx`、`src-web/src/FloatingPanel.tsx`、`src-web/src/FloatingSession.tsx` 与 `src-web/src/components/*.tsx`。本轮已通过 `src-web/npm run build`。

## 1. 当前总原则

- Trace UI 只生成脚本、保存脚本、导入用户捕获结果。
- Trace UI 不执行 `frida.attach`、`spawn`、设备发现、Frida CLI 或 Hook。
- Trace UI 不安装或执行 angr；用户在自己的 Python 环境手动运行生成的脚本。
- IDA 脚本由用户在 IDA 中手动执行。
- OLLVM、dispatcher、opaque predicate、angr symbolic flow 和跨版本映射全部保持 `Candidate`/`Related`，不能仅凭结构证据标记 `Verified`。
- module basename + module-relative offset 不能单独证明精确 ELF；需要用户绑定 ELF SHA-256 才能验证选中的静态文件。

## 2. 最近提交时间线

| 提交 | 内容 |
|---|---|
| `57d600f` | 导入 Frida capture，并生成 angr state seed |
| `ab7b8b4` | 将 exact-offset Frida seed 接入 OLLVM angr bridge |
| `3ca6133` | OLLVM 比较绑定 exact ELF identity |
| `c0fce46` | Frida 16 Crypto API recipes |
| `565eb9f` | angr bounded OLLVM flow exploration |
| `83fee0b` | 跨版本 dispatcher/state 结构候选映射 |
| `19f6439` | exact Frida dispatcher seed → angr next-dispatcher flow |
| `d248602` | Frida multi-dispatcher capture atlas |
| `6e776e4` | 保留 ARM64 NZCV 到 angr seed |
| `88f011c` | bounded dispatcher pointer memory capture |
| `9211fdc` | angr exact ELF guard、多 Frida seed、OLLVM condition-state profile |

## 3. 功能与代码位置

### 3.1 Frida 16 Hook 生成

核心代码：

- `crates/trace-core/src/query/frida_hook.rs`
- `crates/trace-core/src/query/frida_recipe.rs`
- `crates/trace-mcp/src/tools.rs`
- `src-tauri/src/commands/mod.rs`
- `src-web/src/components/FridaHookPanel.tsx`

主要入口：

- `generate_frida_hook`
- `list_frida_hook_recipes`
- `inspect_frida_capture`
- `analyze_frida_crypto_materials`
- `generate_angr_state_seed`

脚本使用 Frida 16.x 经典 API，输出 `trace-ui/frida-hook-v1`。支持 module export 或 module-relative offset、X0-X7 参数、X0-X28 快照、FP/LR/SP/PC、NZCV、返回值、backtrace 和 bounded Stalker。

### 3.2 OLLVM 动态分析

核心代码：

- `crates/trace-core/src/query/ollvm.rs`
- `crates/trace-core/src/engine/ollvm.rs`
- `src-web/src/components/OllvmPanel.tsx`

`analyze_ollvm` 会生成动态 blocks、edges、dispatcher candidates、state snapshots/transitions 和 opaque branch candidates。

条件分支现在还会生成 `BranchConditionStateProfile`：

- 已捕获/缺失观察数量
- distinct 条件寄存器值
- 按 `taken`/`fallthrough`/`other` 的值分布
- 若条件来源是 NZCV，则显示 N/Z/C/V set/clear 统计
- profile 不完整时设置 `incomplete=true`

该 profile 是人工复核线索，不是 opaque predicate 证明。

### 3.3 Frida OLLVM Dispatcher Atlas

核心代码：

- `crates/trace-core/src/query/frida_ollvm.rs`
- `crates/trace-core/src/query/frida_capture.rs`
- `src-web/src/components/OllvmPanel.tsx`

主要入口：

- `generate_frida_ollvm_dispatcher_hook`
- `analyze_frida_ollvm_dispatcher_capture`

生成的脚本一次最多 Hook 64 个 ranked dispatcher，默认最多 12 个目标、50,000 个事件。专用事件包含：

- `dispatcherOffset`
- `captureSessionId`
- `flowId`
- `hitSequence`
- 完整 ARM64 GPR
- candidate state registers

导入后按 session、线程、flow 和连续 hit sequence 构建 nodes、adjacent transitions、state value distributions、state changes 和 flow paths。legacy capture 没有 flow metadata 时只使用 idle-gap 启发式，并给出 warning。

### 3.4 Dispatcher 指针内存捕获

在 Atlas UI 中可以选择 `X0-X7` 指针寄存器，并指定每个指针的最大读取字节数。

约束：

- 默认关闭
- 最多 8 个寄存器
- 每个指针 1-4096 字节
- 读取失败写入 `readError`
- 不做无界读取或自动重试

捕获的 `byteArray` 可以作为后续 angr state seed 的内存输入。

### 3.5 angr OLLVM Bridge

核心代码：

- `crates/trace-core/src/query/angr.rs`
- `crates/trace-mcp/src/tools.rs`
- `crates/trace-mcp/src/types.rs`
- `src-tauri/src/commands/mod.rs`
- `src-web/src/components/OllvmPanel.tsx`

主要入口：

- `generate_angr_ollvm_script`
- `inspect_angr_ollvm_results`
- `generate_angr_ollvm_script_with_seeds_flow_and_identity`

生成的脚本输出 `trace-ui/angr-ollvm-v1`，内容包括 CFGFast/CFGEmulated 对账、blank-state probes、trace-register probes、Frida branch probes、dispatcher probes 和 bounded flows。

#### Exact ELF guard

GUI 的 `angr` 页面可以选择 exact AArch64 ELF。生成脚本时保存 SHA-256；用户运行 Python 脚本时，脚本在建立 angr Project 前重新计算哈希，若不一致则直接停止。

该机制验证的是用户选择的文件，不对原始 trace 的运行时映像做加密证明。

#### 多 Frida seed

同一份 Frida capture 最多可选择 32 个事件：

- `hook-enter`
- `ollvm-dispatcher-hit`

每个事件必须精确匹配 opaque branch、condition-source 或 dispatcher `startOffset`。每个 seed 独立生成 probe，并在结果中保留 source event、offset、寄存器和内存 provenance。

相关 DTO 字段：

- `AngrOllvmScript.fridaSeeds`
- `AngrOllvmScript.expectedBinaryIdentity`
- `AngrOllvmResultBundle.fridaSeeds`
- `AngrOllvmResultBundle.expectedBinarySha256`
- `AngrOllvmResultBundle.binaryIdentityMatched`

## 4. 数据协议

| 协议 | 用途 | 产生方 |
|---|---|---|
| `trace-ui/frida-hook-v1` | Frida 16 Hook 捕获 | 用户手动运行生成的 JS |
| `trace-ui/angr-state-seed-v1` | 单个 Frida 事件的 angr state seed | Trace UI |
| `trace-ui/angr-ollvm-v1` | angr 静动态对账与 bounded probes | 用户手动运行生成的 Python |
| `trace-ui/ida-ollvm-v1` | IDA 注释/颜色/xref 导出 | 用户手动运行生成的 IDAPython |

修改协议字段时，必须同步：

1. `trace-core` DTO 和 parser/validator
2. `trace-core/src/lib.rs` re-export
3. `trace-mcp/src/types.rs`
4. `trace-mcp/src/tools.rs`
5. Tauri command 参数
6. `src-web/src/types/trace.ts`
7. 对应 GUI 组件
8. README、PROJECT_STATE、skills 和测试

## 5. 推荐手动工作流

```text
open trace
  -> OLLVM Analyze
  -> review Dispatcher / State / Opaque
  -> generate Frida 16 script
  -> user runs Frida manually
  -> import JSON/NDJSON
  -> inspect dispatcher atlas or crypto materials
  -> select exact ELF and one/multiple Frida events
  -> generate angr Python
  -> user runs angr manually
  -> import trace-ui/angr-ollvm-v1 JSON
```

跨版本时不能复制旧版本的 source offset、concrete state、Frida capture 或 angr seed；必须为目标 ELF 重新生成 exact-offset Hook 和 seed。

## 6. 验证记录

当前提交已验证：

- `cargo fmt --all -- --check`
- `cargo test -p trace-core`：334 passed，6 ignored
- `cargo test -p trace-mcp`：全部通过
- `cargo check -p trace-ui`
- `src-web/npm run build`
- 生成 Frida JavaScript 的 Node 语法检查
- 生成 angr Python 的 `py_compile` 检查
- 禁止自动执行项搜索：未发现 `frida.attach`、`frida.spawn`、`get_usb_device`、`DeviceManager`、`--no-pause`

GitHub Actions：

- CI：<https://github.com/lpy30m/trace-ui/actions/runs/29889947270>
- macOS Bundles：<https://github.com/lpy30m/trace-ui/actions/runs/29889947202>

产物名称：

- `TraceUI-macOS-arm64-9211fdcd73e4ed8edc1412737094dbf5c0120924`
- `TraceUI-macOS-x64-9211fdcd73e4ed8edc1412737094dbf5c0120924`

## 7. 后续继续开发时先读什么

1. `CURRENT_CHANGELOG.md`
2. `PROJECT_STATE.md`
3. `README.md` 的 Frida/OLLVM/angr 部分
4. `.claude/skills/frida-hook-generation/SKILL.md`
5. `.claude/skills/ida-ollvm-analysis/SKILL.md`
6. `.claude/skills/trace-analysis/SKILL.md`
7. 最近提交：`git log --oneline -12`

下一步如果继续扩展，优先保持小步、可验证、用户手动执行边界，不要直接实现“自动去平坦化”或自动运行 Frida/angr。
