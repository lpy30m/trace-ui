# Trace UI AI 分析能力路线图

更新日期：2026-08-11

## 1. 目标

将 Trace UI 从“人工查看 Trace 的桌面工具”逐步升级为“AI 主导调查、人工核验证据”的分析平台。

设计原则：

- 确定性分析由 Rust 核心完成，AI 负责组合工具、比较假设和解释结果。
- 所有结论必须保留可跳转、可读取、可复算的证据。
- 候选、相关性和已验证结果必须明确区分。
- 长时间分析必须可以观察进度、取消和恢复结果。
- GUI 与 MCP 应消费相同的核心数据模型。

## 2. 已完成能力

- [x] 已知 CRC32、MD5、SHA-1、SHA-256、SHA-384、SHA-512 匹配。
- [x] 字符串候选与二进制摘要内存定位。
- [x] 1-4096 字节多字节、多来源反向污点。
- [x] 污点 Summary、Key Steps、函数、模块、字符串和内存输入输出摘要。
- [x] MCP `analyze_known_digest` 高层工具。
- [x] MCP `investigate_crypto_flow` 调查编排工具。
- [x] MCP `auto_investigate` 自动证据调查，以及可取消的 `start_auto_investigation`。
- [x] `analysis_id`、分析列表、读取、比较和删除。
- [x] 分析证据结构化为算法、摘要、函数、模块、字符串、地址、操作和警告。
- [x] 候选证据 `verified/related/uncertain` 分级、可解释评分因子和验证范围。
- [x] 跨 Session Trace Diff：比较函数、分支、指令和内存访问站点的动态执行差异。
- [x] Crypto Materials：统一索引 key/password/salt/IV/nonce/counter/input/output/digest/MAC/AAD/tag，并语义复算 AES、MD5/SHA、HMAC、PBKDF2。
- [x] 跨 trace salt/nonce 候选隔离：对相同 caller input 的多次运行比较变化字节范围，保持候选级验证边界。
- [x] Frida 16.x Hook Generator：生成 module symbol/offset、X0-X7、buffer/string、return/backtrace/Stalker 脚本；用户手动 attach/spawn/load。
- [x] Frida 16.x Crypto API Recipes：列出并预填 OpenSSL/BoringSSL、Apple CommonCrypto 的常见 MD5/SHA、EVP、HMAC、PBKDF2、CCCrypt 调用形态，支持返回时 `*Xn` 输出长度且不猜 JNI handle 或 X7 之后的栈参数。
- [x] IDA / OLLVM：ASLR 稳定动态 CFG、dispatcher/opaque branch 候选、IDAPython 注释桥和 IDA annotation JSON 回导。
- [x] angr / OLLVM：生成用户手动执行的 Python bridge，以 exact ELF SHA-256 为锚点，对账静态/动态 CFG，并导回候选级 symbolic branch probe 结果。
- [x] Frida Capture → angr State Seed：导入用户手动捕获的 registers/buffers/call metadata，生成 module-aware `configure_state(state)`，保持运行和 Hook 由用户控制。
- [x] Frida Capture → angr NZCV Seed：保留 Frida 16 ARM64 packed NZCV，并在 standalone state seed 与 OLLVM angr bridge 中按 packed flags 或 N/Z/C/V fallback 应用，保留捕获点/架构语义限制。
- [x] Frida Capture → Crypto Materials：按 callId/label/phase 索引密码材料，并确定性验证完整捕获的 MD5/SHA/HMAC/PBKDF2 公式。
- [x] OLLVM State / Multi-run：重建 dispatcher register snapshots/transitions，保存 branch-time register snapshots，angr 同时生成 blank/trace-seeded probe，并比较 2–16 个受控运行的分支结果。
- [x] OLLVM Exact ELF Identity：多运行 case 可绑定 ELF，校验 SHA-256/Build ID，拒绝不同二进制之间的 module-offset 对齐。
- [x] Frida → angr OLLVM Exact-offset Seed：从 branch/condition-source 生成 Frida 16 候选 Hook 配置，导入用户手动捕获的完整 ARM64 GPR/buffer 状态，并仅在 module-relative offset 精确匹配时嵌入 symbolic probe。
- [x] angr OLLVM Bounded Seeded Flow：从首个 trace-register seed 与 exact-offset Frida seed 继续有界 symbolic exploration，限制深度/状态数并回导路径、循环、截断和终点证据。
- [x] Frida Dispatcher-entry → angr Next-dispatcher Flow：从 dispatcher `startOffset` 生成 Frida 16 候选 Hook，由用户手动捕获精确入口状态；angr 有界探索下一 dispatcher/循环/退出并回导 state-register concrete/symbolic/unavailable 候选值，始终保持 Candidate/Related。
- [x] Frida 16 Multi-dispatcher Capture Atlas：一次生成有界多入口脚本；用户手动执行后导入 `ollvm-dispatcher-hit`，按 exact offset、capture session、线程、flow、连续 hit sequence 聚合 dispatcher nodes/transitions/state distributions/state changes/flow paths；legacy capture 仅以 idle-gap 派生 flow，并保留 Candidate/Related 限制。
- [x] Frida Dispatcher Pointer Memory Seed：multi-dispatcher Frida 16 脚本可选 bounded X0-X7 pointer byteArray 捕获，错误以 readError 返回，默认关闭，并可复用于 angr state seed；不做无界内存读取或自动运行 Hook。
- [x] angr Exact ELF Guard / Multi-seed Handoff：生成的手动 Python bridge 可嵌入 exact AArch64 ELF SHA-256 并在 angr 初始化前拒绝错误文件；同一捕获最多选择 32 个精确匹配 Frida 事件，独立生成 branch/dispatcher probes 并保留 provenance。
- [x] OLLVM Condition Flag Profile：聚合条件值与 outcome，展示 NZCV N/Z/C/V set/clear 分布及缺失观察，帮助人工复核 opaque predicate 候选。
- [x] Runtime Image Attestation：从 exact AArch64 ELF 生成 Frida 16.x 手动 hash 计划，严格回导核对 metadata/build-id 与 file-backed executable `PT_LOAD` bytes；完整覆盖仅能验证 `runtime-image:*` scope，抽样保持 Related，冲突保存为 counter-evidence。
- [x] Coverage-aware Claim Gate：从 exact AArch64 ELF + 严格 OLLVM 动态报告生成手动 angr 静态清单，保存并复算 instruction/block/branch/function/edge 集合、source SHA 与截断状态；否定、全局恒定、穷举和完整 CFG claim 在 coverage 不足时自动降级，100% listed-site coverage 也不产生语义 Verified。

### 2.1 下一轮 AI 准确率强化顺序

1. [x] 运行时镜像认证：完成 Core、`.traceui-case`、Claim Ledger、MCP、Tauri、GUI、文档和回归测试。
2. [x] AI Evidence Pack：在 token/条目预算内输出 artifact ID、locator、trace seq/line、memory range、module offset 和 event index，严格分开 supporting evidence、counter-evidence、unknowns 与 invalid artifacts；JSON/Markdown 都携带 Claim Ledger 推荐最高等级和 omitted counts，摘要本身不能成为证明。
3. [x] Crypto 语义 KAT：`trace-ui/crypto-semantic-kat-v1` / verification-v1 支持 AES ECB/CBC/CTR/GCM、MD5、SHA、HMAC、PBKDF2-HMAC；严格 hex/bounds、首个 mismatch range、exact claimScope 和导入时全字段复算替代自由文本 marker。
4. [x] 信息增益捕获规划：`trace-ui/information-gain-capture-plan-v1` 从 claim blocker、反证、state readiness、checkpoint/stall 与实验矩阵排序 exact offset/register/memory/controlled run；返回 competing hypotheses、success criteria 和 redundancy key，分数明确不是概率。
5. [x] ABI/结构推断：`trace-ui/frida-abi-inference-v1` 从重复手动捕获推断 X0-X7 role、pointer+length、context、enter/leave mutation、base+displacement field 与 return shape；保留 exact event index，所有分类为 Candidate/Related。
6. [x] 精度基准与 CI 门禁：`trace-ui/accuracy-benchmark-suite-v1` / report-v1 检查 replay/capture-plan、claim gate/status、Verified FP/FN、unexpected Verified 与 fixture error；CI 和 MCP handler smoke test 阻止工具注册正常但调用失效或置信度漂移。
7. [x] Coverage-aware Claim Gate：`trace-ui/coverage-reconciliation-v1` / inspection-v1 显式绑定 exact ELF、source artifact SHA、claimScope 和静动态集合；Replay Doctor、Evidence Pack、Capture Plan、Benchmark、MCP/Tauri/GUI 全链路接入，伪造 summary 与未覆盖路径保持 blocked/unknown。

### 2.2 下一阶段准确率候选

1. [x] Minimal Evidence Slice + typed provenance graph：`trace-ui/minimal-evidence-slice-v1` 精确绑定 source artifact SHA-256/大小/parent lineage 与 claim/reference fingerprint，物化 Trace 行、known-mask memory/逐字节来源、Frida event、ELF `PT_LOAD` bytes 或有界 JSON fragment，并连接 case/claim/reference/artifact/build/process/event/record。默认隐藏敏感值；独立 inspector 重开源文件并复算所有记录与 graph。Analysis Case、Replay Doctor、Evidence Pack、Accuracy Benchmark、MCP/Tauri/GUI 和端到端 smoke test 已接入，切片有效不产生语义 Verified。
2. [x] Memory object/alias/lifetime reconstruction：`trace-ui/memory-object-graph-v1` 按 malloc/calloc/realloc/free、mmap/munmap、栈帧、base+offset、地址生成和跨调用 pointer 传播重建对象边界、generation、别名、字段窗口、释放/复用与越界/过期访问候选；Core/MCP/Tauri/GUI/真实日志回归已接入，结果始终为 Candidate，不证明所有权、类型或内存安全缺陷。
3. [x] Exact-call record/replay summaries：Frida `captureExactCall` 对同一 `hookId+callId` 做 enter/leave 双阶段完整 GPR/NZCV/byteArray 捕获，并记录 caller、BL/BLR call-site、target 与 `PC+4` return；`trace-ui/exact-call-summary-v1` / replay-authorization-v1 默认拒绝，必须显式接受六项未知副作用假设。Unicorn 仅在 call-site/target/return/X0-X7/SP/输入内存全部精确匹配时应用授权寄存器与内存效果，否则明确停止；Analysis Case 自动绑定 capture + exact ELF、summary + 同一 ELF，Replay Doctor 重新复算父链并输出聚合报告。Core/MCP/Tauri/GUI、案件测试与 Python smoke 已接入，始终为 Candidate/Related 且 `verificationGateMet=false`。
4. [ ] Counterfactual paired replay：同一 checkpoint 仅改变一个明确变量来搜索 opaque/dispatcher 反例，结果始终标为 hypothetical/counterexample candidate。
5. [ ] Cross-engine differential validation：对 Capstone/IDA/angr/Unicorn 的解码、block 边界、successor 和 stop reason 做结构化差异报告；一致只增加置信，冲突必须成为 counter-evidence，不能多数表决为真。
6. [ ] Hypothesis/contradiction search planner：把“AES”“白盒”“opaque”“dispatcher”“完整 CFG”等假设拆成可证伪子命题，优先主动搜索 alternate outcome、wrong-key、wrong-build、alias reuse 和 dynamic-only edge 反例。
7. [ ] Bounded SIMD/FP/TLS state packs 与更大真实 benchmark/fuzz corpus；GUI 增加 KAT 创建、ABI 和 benchmark 详情，减少人工参数错误。

## 3. 当前限制

- [x] 已支持从 Frida 捕获导出 X0-X7、可选 SP/LR 与 memory state seed；capture point 与 symbolic address 是否语义一致仍需人工核验。
- [x] 跨版本 dispatcher/state 结构映射：每个版本提供独立 trace scope、version ID 与 exact ELF；要求 SHA-256 两两不同，允许模块重命名/offset 变化，并按归一化指令形状、动态 CFG 形状与 state-register 行为返回有界候选。结果始终为 Candidate/Related，不复用 offset、concrete state、Frida capture 或 angr seed。

- [x] 分析记录已随 Trace 内容校验持久化，应用重启后可以恢复。
- [x] Crypto、正向污点和自动调查支持统一后台任务、进度与取消。
- [x] 正向污点可以回答“这个输入最终影响了什么”。
- [x] 摘要候选和自动调查使用统一、可解释的证据评分。
- [ ] 字符串索引仍偏向解码文本，不能始终保留 UTF-16、结尾 NUL 和二进制原始字节。
- [ ] 二进制摘要搜索需要重放内存写入，重复查询成本较高。

## 4. 本轮任务：AI Analysis Foundation v2

### 4.1 分析结果磁盘持久化

- [x] 使用 Trace 内容校验的缓存文件保存分析记录。
- [x] 重新打开同一个 Trace 时恢复分析记录，并绑定到新的 Session ID。
- [x] 保存、删除分析后原子更新缓存。
- [x] Trace 内容变化时拒绝读取旧分析缓存。
- [x] `Clear Cache` 同时删除分析记录缓存。
- [x] 每个 Trace 最多保留 100 条记录。

验收标准：

- 创建分析、关闭应用、重新打开 Trace 后仍能通过 MCP 查询该 `analysis_id`。
- 修改 Trace 文件后不会加载旧记录。
- 删除记录并重启后记录不会恢复。

### 4.2 MCP 后台任务、进度和取消

- [x] 新增后台 Crypto Flow 调查启动工具，立即返回 `task_id`。
- [x] 新增任务状态查询，返回 queued/running/completed/failed/cancelled。
- [x] 返回当前阶段、0-100% 进度、开始/结束时间和最终 `analysis_id`。
- [x] 新增任务取消工具。
- [x] 各阶段之间检查取消信号，取消后不保存不完整分析记录。
- [x] Session 关闭时取消关联任务。

验收标准：

- MCP 不需要保持一个长 HTTP 请求等待调查完成。
- AI 可以轮询进度，并在完成后取得 `analysis_id`。
- 取消任务后不会出现伪造的 completed 状态或半成品分析记录。

## 5. 本轮完成：Forward Data Flow

- [x] 新增正向污点核心算法，基于已有依赖边构建紧凑反向邻接索引。
- [x] 支持寄存器和 1-4096 字节内存输入。
- [x] 返回受影响指令、内存写入、函数调用/返回、终端输出和潜在外部出口。
- [x] 增加同步 `forward_taint_analysis` MCP 工具。
- [x] 增加可取消的 `start_forward_taint_analysis` 后台工具。
- [x] 正向和反向污点结果均保存 `analysis_id`，可使用 `compare_analyses` 交叉比较。
- [x] 增加 `max_nodes`、内联结果上限、Sink 上限和分阶段取消检查。
- [x] MCP 增加 `close_trace`，AI 可释放会话并自动取消关联后台任务。

使用示例：

```text
forward_taint_analysis {
  "from_specs": ["reg:X0@1234"],
  "data_only": true,
  "max_nodes": 10000
}

forward_taint_analysis {
  "from_specs": ["mem:0xbffff000:32@5930"],
  "data_only": true
}
```

结果重点字段：

- `potential_sinks`：内存写入、函数调用、系统调用、返回和终端输出候选。
- `evidence`：函数、模块、字符串、内存读写、地址、操作和警告。
- `analysis_id`：用于 `get_analysis` 和 `compare_analyses`。
- `truncated`：命中 `max_nodes` 上限时为 `true`，应缩小范围或提高上限后复算。

## 6. 后续优化

- [ ] 保存原始字符串字节和明确编码。
- [ ] 摘要派生索引与内存搜索锚点。
- [x] Session 级正向依赖派生索引，首次构建后供后续 AI 调查复用，重建 Trace 索引时自动失效。
- [x] Source/Sink 基础自动识别：内存输入输出、栈读写、JNI、文件、Socket、日志、系统调用、函数调用和返回值。
- [x] Source/Sink 返回方向、类别、置信度、外部出口标记和判定原因。
- [x] Source/Sink 跨调用验证：解析函数原始参数和返回值，跟踪 open/fopen/socket/accept/dup/malloc 创建的资源及 close 生命周期。
- [x] 对 read/write/send/recv/fread/fwrite 等调用验证句柄来源，修正文件与 Socket 分类并返回资源创建序号。
- [ ] 系统调用号、pipe/eventfd、跨线程句柄传递和结构体内嵌句柄的深度验证。
- [x] 候选重新计算验证与 verified/related/uncertain 分级，并明确区分候选字节验证、摘要输出验证和生产函数归因。
- [x] 内置 Analysis Recipes：`forward_to_sinks`、`known_digest_flow`、`crypto_investigation`、`auto_investigation`。
- [x] 自定义 Recipe 支持保存默认参数、列出、运行、删除和随 Trace 持久化。
- [x] 任意 `analysis_id` 可导出 JSON 或 Markdown，支持内联返回或写入文件。
- [ ] 可分享证据包：报告、Trace 片段和内存快照的压缩归档。
- [x] GUI 增加 Analysis History，用于查看和比较 MCP 创建的分析。

## 7. 决策记录

- 2026-07-17：优先完成持久化和任务基础设施，再实现正向污点，避免长任务继续绑定同步 MCP 请求。
- 2026-07-17：分析缓存必须与 Trace 内容校验绑定，不能只按文件路径恢复。
- 2026-07-17：取消采用协作式检查；尚未支持中断的底层阶段必须在阶段结束后立即停止后续工作。
- 2026-07-17：后台任务只在完整成功后写入 Analysis Store，失败和取消结果只保留任务状态。
- 2026-07-17：分析记录使用带 Trace 大小和头部哈希校验的 JSON 缓存负载，避免 `serde_json::Value` 与 bincode 反序列化不兼容。
- 2026-07-17：新增 `start_crypto_investigation`、`get_analysis_task`、`list_analysis_tasks` 和 `cancel_analysis_task`。
- 2026-07-17：正向污点从现有“消费者 -> 依赖”图构建紧凑反向邻接索引，成对指令采用保守的指令级精度，优先避免漏报。
- 2026-07-17：新增 `forward_taint_analysis` 和 `start_forward_taint_analysis`；同步与后台结果均只在完整成功后保存。
- 2026-07-17：原 `taint_analysis` 升级为可保存的 `backward_taint` 分析，正反向结果可直接交叉比较。
- 2026-07-17：正向依赖索引缓存在 Session 内存中，使用单飞锁避免并发 AI 请求重复构建；取消或失败的构建不写入缓存。
- 2026-07-17：Source/Sink 使用确定性规则输出 `flow_endpoints`，高置信度来自明确 JNI/函数名称，中低置信度候选保留具体判定原因。
- 2026-07-17：调用资源索引按执行序号跟踪句柄创建、复制、使用和关闭；只有观察到来源时才将资源状态标记为 verified。
- 2026-07-17：Recipe 定义复用 Analysis Store 持久化，自定义 Recipe 的 ID 即其 `analysis_id`，运行结果保存为 `recipe_run`。
- 2026-07-17：报告导出直接读取持久化 Analysis Record，Markdown 保留 Metadata、Evidence、Request 和 Result 四个证据区块。
- 2026-07-18：新增通用证据评分器；只有满足验证门槛且达到分数阈值时才返回 verified，限制和扣分项随结果输出。
- 2026-07-18：新增 `compare_traces`，按模块相对偏移和执行次数比较动态函数、分支、指令与内存访问站点，避免使用绝对地址和序号硬对齐。
- 2026-07-18：新增同步/后台 `auto_investigate`，确定性编排搜索、Crypto、摘要、正向流、Analysis Compare 和 Trace Diff，并保存单一证据包。
