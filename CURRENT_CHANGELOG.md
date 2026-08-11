# Trace UI 当前开发记录与后续交接

最后更新：2026-08-11
当前分支：`feat/aes-unicorn-integration`
Unicorn/OLLVM 基线提交：`f19d850 feat: preserve Unicorn seed memory across recaptures`
AES 集成提交：`887968e fix: detect software AES from memory traces`

这份文档是后续 Codex/开发者进入项目时的快速入口。它记录当前已经实现的 Frida 16、OLLVM、IDA、angr 和密码材料分析能力，以及每项能力对应的代码位置和边界。

## 本轮 AI 分析准确率与案件工作区增强

- 新增 `trace-ui/frida-runtime-attestation-v1` 与 `trace-ui/runtime-attestation-verification-v1`：从 exact AArch64 ELF 的 `PT_LOAD` 布局生成 metadata/build-id/executable SHA-256 窗口和 Frida 16.x 手动脚本；回导 JSON/NDJSON/send/CLI 后重新生成计划并逐窗验证。完整覆盖全部 file-backed executable bytes 才能得到 scoped `verified-full`，抽样保持 `related-sampled`，身份/计划/hash 冲突为 `refuted`，缺失或不可读为 `incomplete`。
- 运行时认证默认 4096-byte 窗口、最多 1024 个，硬上限 4096 窗口/64 MiB；超过上限使用确定性抽样。脚本内嵌纯 JavaScript SHA-256，只调用 Frida 16.x runtime API，不包含 attach/spawn/load/CLI 控制。认证是用户可复算证据，不是硬件或远程可信认证；writable/BSS/heap/JIT、crypto 语义、OLLVM、angr/Unicorn 可达性均不在 Verified 范围。
- 新增严格的 `trace-ui/case-v1` `.traceui-case` 工作区：保存 artifact 流式 SHA-256、大小、mtime、相对/绝对路径、父 artifact provenance 和严格 parser 摘要；支持 Trace、exact AArch64 ELF、runtime attestation、Frida、Exact-call summary/authorization、Unicorn、angr、IDA、OLLVM、coverage reconciliation、analysis、crypto KAT 与 crypto 报告。runtime attestation 必须绑定唯一 static-binary parent；Exact-call summary 必须绑定同 SHA 的唯一 Frida capture + exact ELF，authorization 必须绑定原 summary + 同一 exact ELF；coverage report 必须绑定唯一 exact ELF parent 和至少一个动态/source parent。任一父文件漂移会连带使 Exact-call 后续 artifact 失效；验证冲突仍允许作为反证保留。非 AArch64 ELF 会在导入时拒绝。
- GUI 在“分析历史”内新增“案件 / Replay Doctor”二级页签，可新建/打开案件、批量导入 artifact、保存生成结论、运行 AES 未识别诊断，并显示时间线、完整性、下一步、Claim 账本、模拟状态和实验矩阵。
- 案件 GUI 新增“运行时镜像认证（手动 Frida）”：选择案件中的 exact ELF parent 与本地 ELF 路径，设置 window/max-windows，生成/保存 `.js`，选择用户捕获文件严格检查覆盖和冲突，并一键导入；`refuted` 结果不会被丢弃。
- 新增 `trace-ui/coverage-reconciliation-v1`、inspection-v1 与 `trace-ui/coverage-claim-gate-v1`：`generate_coverage_reconciliation_script` 从 exact AArch64 ELF + 严格 OLLVM report 生成用户手动执行的 angr Python，按 function closure / module / range 输出显式 instruction/block/branch/function/edge 集合；`inspect_coverage_reconciliation` 重新计算全部 count/basis points，验证 canonical offsets、file-backed executable `PT_LOAD` 范围、exact ELF SHA/Build ID 和每个 source artifact SHA。伪造 summary、错 ELF、source 缺失、截断、uncovered 或 dynamic-only site 均关闭 gate。
- 案件 GUI 新增“Coverage-aware Claim Gate（手动 angr）”：可选择 exact ELF/OLLVM parent 与本地路径、claimScope 和 scope kind，生成/保存 `.py`、检查用户产生的 coverage JSON、显示五维覆盖率/未覆盖 offsets/dynamic-only conflict，并把结果绑定双 parent 导入。Replay Doctor 输出 `coverageReconciliations`，Claim Ledger 显示 coverage requirement/source/status/max；negative-existence 最高 Observed，global-invariance/exhaustive/complete-CFG 最高 Related，coverage 本身永不产生语义 Verified。当前 Tauri invoke handler 共 107 个 `commands::` 命令（另含 `toggle_devtools`）。
- 新增 `trace-ui/replay-doctor-v1`：重新计算每个 artifact 的 SHA-256、重跑严格 parser、核对 module/exact ELF、比较同 module/同 SHA-256 的 Unicorn 多轮覆盖，识别 supported missing-memory recapture、重复 stall → closer checkpoint/bounded angr，以及真实 `PC+4` post-call capture。
- 新增 `trace-ui/ai-evidence-pack-v1` 与 MCP `generate_analysis_case_evidence_pack`：从 `.traceui-case`/Replay Doctor/Claim Ledger 生成 JSON 或 Markdown，默认 8000 estimated tokens / 256 entries，硬范围 1024–65536 tokens、16–2048 entries。按优先级保留 claims、counter-evidence、invalid artifacts、supporting evidence 和 unknown/next-action，返回每类 total/omitted count；locator 只从结构化字符串解析 trace seq/line、memory address/range、module offset、event index，不从描述文本猜证据。
- Evidence Pack 明确声明“context packaging, not proof”；每个 claim 带 current 与 recommended maximum status、gate 状态和 blockers，support/counter/unknown/invalid 四节不能合并。自由文本摘要、artifact summary 或 Evidence Pack 本身都不能打开 Verified 门禁。
- 新增 `trace-ui/minimal-evidence-slice-v1` / inspection-v1：对选中的 persisted/generated claims 精确绑定 source artifact SHA-256、大小、路径、parent lineage、claim/reference fingerprint，并按 locator 物化 Trace 原始行、known-mask memory 与逐字节 provenance、一个精确 Frida event、ELF file-backed `PT_LOAD` bytes 或有界 JSON fragment。typed provenance graph 显式连接 case/claim/reference/artifact/build/process/event/record。
- Evidence Slice 默认排除寄存器变化、内存字节、Frida registers/captures/return 和 JSON fragment 等敏感负载；只有显式 `includeSensitiveValues=true` 才包含。独立 inspector 会重开源 Trace/Frida/ELF/JSON、复算 record/content hash、source identity、claim binding 和 graph；Replay Doctor 内部使用非递归 generated-binding 状态，standalone inspector 才完整重验当前 generated claims。
- Analysis Case 新增 `evidence-slice` artifact kind，导入时必须精确绑定切片声明的全部 source artifact parents；Replay Doctor、Claim Ledger、Evidence Pack 与 Accuracy Benchmark 均保留 unresolved、truncated、敏感值、claim/record/graph 漂移。切片完整性不能把 Crypto、OLLVM、IDA、angr 或 Unicorn 结构升级为 Verified。
- 新增 `trace-ui/memory-object-graph-v1` 与 pointer explanation：从 allocation/free/realloc、mmap/munmap、栈帧、memory access、call argument 和 `base+offset` 地址生成重建对象 generation、边界、别名、字段窗口与释放/复用状态；GUI 新增“对象/别名”页。过期访问、越界和地址复用只报告 Candidate，缺失生命周期事件保持 unknown，不证明所有权、类型或内存安全缺陷。
- 新增 `trace-ui/exact-call-summary-v1` / `trace-ui/exact-call-replay-authorization-v1`：普通 Frida Hook 可启用 Exact-call 双阶段记录，同一 `hookId+callId` 的 enter/leave 都捕获完整 GPR/NZCV、return 与配置的 byteArray，并保存 caller module、BL/BLR call-site、target、`PC+4` return。摘要严格重算 exact ELF/capture；授权默认阻止，必须显式接受 captured-memory、SIMD/FP、TLS/errno、system/syscall、thread/signal/callback 和 deterministic 六项假设。
- Unicorn exact-call replay 仅在 call-site、target、return、X0-X7/SP 与输入内存全部精确匹配时应用授权的寄存器/内存效果；未知调用或任一前置不匹配分别以 `call-boundary`、`call-replay-precondition-mismatch`、`call-replay-apply-error` 或 `call-replay-limit` 停止，绝不补零。MCP/Tauri/GUI 支持生成摘要、选择 callId、保存/导入授权并嵌入 Python；Analysis Case 会按父 artifact 重新复算并在 Replay Doctor 展示 capture-ready/authorized/blocked 统计和下一证据建议。所有结果为 Candidate/Related，`verificationGateMet=false`。
- 新增 `trace-ui/crypto-semantic-kat-v1` 与 `trace-ui/crypto-semantic-kat-verification-v1`：严格支持 AES ECB/CBC/CTR/GCM、MD5、SHA-1/256/384/512、HMAC 与 PBKDF2-HMAC。输入采用 bounded strict hex，PBKDF2 iterations/输出长度有硬上限；报告保存 exact 参数、重算输出、首个 mismatch offset/range 与 exact `claimScope`，状态只有 `verified-full`、`refuted`、`invalid`。导入已有报告时会重新计算所有字段，篡改 status、scope 或 output 会被拒绝。
- 全局 Verified 门禁收紧：当前仅 `runtime-image:*` + `verified-full` runtime attestation，或 `crypto:*` + exact-scope `verified-full` Crypto KAT 能由结构化 artifact 打开 Verified。自由文本 `semantic-known-answer`、ELF SHA、OLLVM/IDA/angr/Unicorn 结构和普通 report 均不能伪造门禁。
- Replay Doctor 新增 `trace-ui/information-gain-capture-plan-v1`：按 claim blocker/counter-evidence、exact ELF/runtime attestation、GPR/NZCV/stack/pointer/SIMD/system readiness、Unicorn stall/checkpoint 和受控实验缺口，排序下一次最有价值的 exact offset/register/memory/run。每项携带 competing hypotheses、success criteria 与 redundancy key；得分只是确定性优先级，不是概率。GUI 显示最高优先级目标。
- 新增 `trace-ui/frida-abi-inference-v1`：从重复的用户 Frida 捕获推断 X0-X7 参数角色、pointer+length、稳定 context pointer、enter/leave buffer mutation、`baseRegister + displacement` 字段窗口与返回值形态。默认至少两次观察，保留 exact event index；所有结果是 Candidate/Related，runtime pointer 明确为进程相关。
- 新增 `trace-ui/accuracy-benchmark-suite-v1` 与 `trace-ui/accuracy-benchmark-report-v1`：检查 Replay Doctor/capture-plan 排序漂移、claim gate/recommended status 漂移、Verified false positive/false negative、unexpected Verified 与 fixture error；任一失败都令 `gateMet=false`。CI 已显式运行 accuracy benchmark 集成测试，benchmark 标签仍需人工审阅，不能当作新证据。
- 新增 `trace-ui/claim-ledger-audit-v1` 反证门禁：验证 supporting/counter evidence 与 artifact 健康状态；普通 Verified 仍必须包含明确的 deterministic semantic/known-answer/output-match evidence。只有 `runtime-image:*` scope 且 supporting artifact 是经过 exact-ELF 严格复算的 `verified-full` runtime attestation 时，才允许运行时身份 Verified；描述字符串、单独 SHA、OLLVM、Unicorn 或 angr 结构不能伪造该门禁。
- 新增 `trace-ui/replay-state-readiness-v1`：分别报告 exact ELF、X0-X30/SP/PC、NZCV、SIMD/FP、stack、pointer/heap、TLS/system state 和 call boundary，明确区分 `not-executed`、`not-captured`、`unreadable`、`not-observed` 与 `hash-mismatch`。
- 新增 `trace-ui/experiment-matrix-v1` 与案件实验编辑：按 build SHA-256、key、input、environment 四轴寻找单变量 controlled pair、缺失组合和混杂 pair，为 AES/白盒和 OLLVM 跨版本比较推荐下一实验。
- MCP 新增 `reconstruct_memory_objects`、`explain_memory_pointer`、`summarize_exact_calls` 与 `authorize_exact_call_replay`，连同 Evidence Slice、KAT、capture plan、ABI、benchmark、案件、Evidence Pack、coverage 与 runtime attestation 工具后当前总数 86；health capabilities、registry、边界断言和端到端 handler smoke 已同步。
- 仓库自带的 trace、OLLVM 和 Frida AI 技能工作流已接入 `.traceui-case`、Replay Doctor、Claim Ledger 与 AES Detection Doctor，要求多 artifact/多轮模拟结论先经过完整性、反证和最高可信等级门禁，减少“工具已有但 AI 没调用”的误判。
- `diagnose_crypto_detection` 将“没有观察到”与“解析/范围/语义证据不足”分开；exact ELF 阶段进一步区分 `matched` 与 `completed-no-match`，避免把“文件扫描成功”误读成动态表已对齐。
- 真实 `sh_security_environment_nativeInfo_trace_0_0xf92d8.log` 回归：扫描 460,975 行；在 0 个 AES magic hit、0 条 AESE/AESMC/AESD/AESIMC 的情况下，得到 15 个 AES 函数候选、1 个标准 S-box fingerprint、1 个 AES-128 key schedule、7-block semantic recomputation，最终 `status=verified`、`verificationGateMet=true`。选择 `libsh_security.so` 后记录 SHA-256 `fbc6f6522e795b4b542d02bd14a7b87f0342810fd4ab566e65a4f30505637cf2`；动态/静态 table match 为 0，因此准确显示 `completed-no-match`，不宣称运行时镜像证明。
- 新增 analysis-case/Replay Doctor、runtime attestation、Crypto KAT、ABI inference、Evidence Pack、Evidence Slice、Memory Object、Exact-call、capture plan、coverage claim gate 与 accuracy benchmark 定向测试；当前 Core 441/441 通过（7 个私有 fixture ignored），Accuracy gate 1/1，MCP 27/27 覆盖 86-tool registry/边界测试，并实际调用 Memory Object、Exact-call summary→authorization、Evidence Slice、coverage、KAT、ABI、capture plan 与 benchmark handler。前端 Vitest 13/13 覆盖 Exact-call 六项显式授权、案件父链报告和 Unicorn 嵌入、Evidence Slice、Memory Object 等交互，并确认不会调用自动 Frida/angr/目标执行接口。真实 AES fixture 1/1 与 Memory Object fixture 1/1 已手动运行通过；release `trace-cli` / `trace-ui` 编译通过。CI 运行 MCP lib tests，并在前端 build 后实际 `cargo build -p trace-cli -p trace-ui`。Frida、Unicorn、angr、IDA 和目标程序仍保持用户手动执行边界；OLLVM/模拟结论仍为 Candidate/Related。

## 本轮 Unicorn OLLVM 模拟增强

- 新增 `trace-ui/unicorn-ollvm-v1` 生成器和严格结果解析器，强制 exact AArch64 ELF SHA-256 与 1–32 个精确 Frida seed。
- 生成的独立 Python 使用 Unicorn 2.x、Capstone 和 pyelftools，支持 next-dispatcher、return、call、loop、missing-memory/register、SIMD/system-state、timeout 和 instruction-limit 等显式停止原因。
- 新增 seed 完整度、dispatcher 转移矩阵、寄存器变化、内存写入和 `baseRegister + displacement` Frida 重捕获建议。
- OLLVM GUI 新增“模拟增强”页签；MCP 新增 `generate_unicorn_ollvm_script` 与 `inspect_unicorn_ollvm_results`。Trace UI 仍只生成/保存脚本并导入结果，不自动执行模拟器。
- 新增 `trace-ui/frida-unicorn-recapture-hook-v1` 与 MCP `generate_frida_unicorn_recapture_hook`：从 Unicorn `recaptureSuggestions` 选择最多 64 条 X0-X28/SP 正负位移窗口，聚合到最多 32 个原 exact seed offset，生成兼容 `trace-ui/frida-hook-v1` 的 Frida 16.x `hook-enter` 捕获。
- GUI“模拟增强”新增“Frida 精确重捕获”阶段，可筛选建议、生成/保存/复制 `.js`。窗口限制 1–4096 字节，空指针或不可读内存输出 `readError`，绝不补零；absolute、X29/X30 等建议明确保留为手动项。
- 新增协议闭环回归：构造重捕获 `hook-enter`，经 `parse_frida_capture_bundle` 与 `generate_angr_state_seed` 后验证原 `captureOffset`、`X19+0x20` 和 `SP-0x10` 内存区域均被保留。
- 新增多轮 seed 内存保留：Frida capture/angr seed 记录经过 runtime pointer 校验的 `baseRegister + displacement`；Unicorn 结果为每个 seed 输出 `seedRecapturePlans`，16 KiB 等大区域按 4096 字节拆窗。
- 重捕获 Hook 会把上一轮已验证的 key/input/stack 窗口与本轮 missing-memory 建议合并并去重，输出“保留旧窗口 / 新建议窗口 / unsupported region”统计。它在当前进程重新读取窗口，不复用旧绝对地址或陈旧字节；旧版结果仍兼容但会提示无法自动携带旧 seed 内存。
- 新增伪造相对地址元数据拒绝、plan 严格解析、窗口拆分、旧结果兼容及第二轮 seed 同时保留旧/新内存的回归。
- Dispatcher Frida 捕获扩展为可选 X0-X28 pointer snapshot 与从 SP 开始的 0–16 KiB 栈窗口；默认均关闭，读取失败保持 `readError`。
- Frida 捕获导入同步接受 X8-X28 和合成 SP 栈 capture index，避免新增内存在生成 angr/Unicorn seed 时被旧 X0-X7 过滤器静默丢弃。
- 新增 `trace-ui/unicorn-ollvm-round-comparison-v1`、MCP/Tauri `compare_unicorn_ollvm_rounds` 与 GUI“对比多轮 JSON”：严格比较 2–16 轮同 module、同 exact ELF SHA-256 的结果，按 exact `captureOffset` 聚合而不依赖跨文件不稳定的 event index。
- 多轮报告区分基线覆盖和后续首次新增，按 seed 输出新/丢失 offset/block、新 dispatcher、缺页前移、同点停滞、路径分歧、覆盖回退、seed 增删、配置漂移与截断警告，并建议继续有界重捕获、改用更近 checkpoint 或转 angr。回退优先级高于重复缺页停滞，所有分类保持 Candidate/Related。
- 核心比较器新增 7 个定向测试，覆盖进度、停滞、回退、新 dispatcher、ELF 不匹配、seed 集变化、配置漂移、截断、重复 seed、绝对地址缺页、round ID 和 2/16 边界。
- 新增 `trace-ui/frida-unicorn-checkpoint-hook-v1` 与 MCP `generate_frida_unicorn_checkpoint_hook`：从严格校验的上一轮 Unicorn 结果选择 1–32 个原 seed，把 Hook 前移到 supported stalled run 的实际 missing-memory PC 或 terminal PC，并生成兼容 `trace-ui/frida-hook-v1` 的 Frida 16.x `hook-enter`。
- checkpoint Hook 捕获 X0-X28、FP/LR/SP/PC/NZCV；只自动读取结果中已有的 X0-X28/SP register-relative suggestion。absolute、X29/X30、不支持停止原因和无法证明的内存关系保持 warning/manual，不复制旧绝对地址、陈旧字节，也不补零。
- `generate_unicorn_ollvm_script` 新增可选上一轮 checkpoint result：只有 module、result expected/actual SHA-256 与当前 exact ELF 全部匹配，且新 capture offset 属于该结果推导出的 checkpoint 集合时才接受；provenance 记录为 exact offset，Python 分类为 `frida-capture-exact-offset`。
- Tauri 增加 checkpoint Hook 生成/保存命令，MCP 工具数增至 64，Tauri invoke 命令增至 83；GUI 导入单轮或比较多轮结果后可选择停滞 seed、生成/保存/复制 checkpoint Hook，再导入新捕获继续 Unicorn。
- `generate_angr_ollvm_script` 新增 `checkpoint_result_path`；Core 复用同 module、prior expected/actual SHA-256、当前 exact ELF SHA-256 和 supported checkpoint offset 四重授权，生成 `frida-capture-authorized-checkpoint` seed。旧生成入口保持兼容并委托新入口。
- angr Python 新增 `checkpointProbes`：从授权 checkpoint blank state 应用完整 Frida GPR/NZCV/byteArray memory，按默认 depth 8 / states 32 有界探索下一 dispatcher、loop、external target、dead-end/unconstrained 或配置上限；严格 parser 同步校验 seed kind、offset、provenance、state values、flow bounds。
- GUI“模拟增强”新增第 6 步“checkpoint → bounded angr 接力”，可生成/保存/复制 `.py`、导入 `trace-ui/angr-ollvm-v1`，并显示 checkpoint probe 的状态、source state、bounded path 和命中 dispatcher。MCP/Tauri 工具/命令总数不变。
- Unicorn 的 `call-boundary` 结果现在记录 BL/BLR 的调用点、目标和 AArch64 固定 `PC+4` 返回续跑点；严格 checkpoint 授权可在该 post-call return site 生成 Frida Hook，只有真实调用返回时才会捕获状态。
- post-call checkpoint 会按上一轮 `seedRecapturePlans` 重新读取经过验证的 X0-X28/SP-relative byteArray 窗口，再合并当前缺页建议；只使用当前 checkpoint 寄存器计算地址，不复制旧绝对地址或陈旧字节。旧版没有 return offset 的结果仍可导入，但不会伪造 post-call 目标。
- Release Action 从真实 `src-tauri` 应用目录启动 Tauri，和本地 Windows MSI/NSIS 成功构建路径保持一致。

### 严重 OLLVM 样本的推荐顺序

1. 先用窄函数或窄 sequence 范围运行 `analyze_ollvm`，只把 dispatcher、state register 和 opaque branch 当作候选。
2. 对精确 module-relative offset 生成 Frida dispatcher/branch Hook，由用户手动运行；优先捕获完整 GPR/NZCV，再按缺失状态提示补充少量 X0-X28 pointer 或 SP 栈窗口。
3. 优先使用 Unicorn“模拟增强”做 exact-seed 具体重放。它速度快、路径确定，适合确认下一 dispatcher、循环、调用边界、寄存器变化和缺失内存。
4. 遇到 `missing-memory` 时，优先勾选可自动生成的建议创建精确 Frida 重捕获 Hook；遇到 `call-boundary` 时，优先生成 post-call return checkpoint，让真实 BL/BLR 返回后捕获状态。用户在相同构建/受控输入下手动运行，并把新捕获再次作为 Unicorn 或 angr seed。寄存器在 seed 点到缺失点之间若已变化，可能需要继续迭代或选择更近的人工捕获点。
5. 至少完成两轮后，用 GUI“对比多轮 JSON”或 MCP `compare_unicorn_ollvm_rounds` 按时间顺序比较；只有新增覆盖、新 dispatcher 或缺页前移时继续原点重捕获。相同缺页/终点重复时，用 `generate_frida_unicorn_checkpoint_hook` 生成更近 checkpoint，再把新捕获与该上一轮结果一起交给下一次 Unicorn 生成。
6. 如果更近 checkpoint 的具体重放仍缺少状态，在“模拟增强”第 6 步或 MCP `generate_angr_ollvm_script` 中同时提供 exact ELF、新 capture 和同一 `checkpoint_result_path`，生成 bounded angr；保持默认深度 8/状态 32，避免严重混淆样本发生状态爆炸。
7. 将 Unicorn/angr 结果导回 Trace UI，再用 IDA 注释和多运行对比人工确认。AI/MCP 负责选择候选、组织证据和生成脚本，不自动 attach Frida，也不把结构候选表述为已完成去混淆。

## 本轮 AES 与 Frida 语义验证增强

- 纯 trace 软件 AES 在没有函数名/API 注释时，也可从动态 S-box、AES-128 44-word schedule、连续 16-byte input/output 和逐 block 复算建立证据。
- `analyze_frida_crypto_materials` 按 `callId` 对齐 enter/leave 捕获，支持显式角色以及有界的 X0=input、X1=key、X2=output 候选 ABI，并尝试 AES-128/192/256 ECB Encrypt/Decrypt。
- 相同 hook、线程、函数、ABI 和 key 的连续单块调用可聚合覆盖；错误 key 不打开 gate，末块篡改只能得到 `VerifiedPartial`，跨调用拼接不能得到 `VerifiedFull`。
- 新增 `Native candidate · AES block X0/X1/X2` Frida 配方；从 Crypto Functions 候选进入时保留已预填的 module-relative offset。
- 真实 nativeInfo trace 回归识别为 AES-128-ECB Encrypt、PKCS#7、7 blocks、112/112 bytes、`VerifiedFull`；动态证据包含 1400 次 S-box read、252 个 distinct index 和 44/44 schedule words。
- 没有独立 OLLVM 控制流证据时，AES 实现仍保持 `StandardSoftware`，不会仅因查表或复杂代码误标为 `ObfuscatedStandardSoftware`。
- 2026-08-07 当前工作树回归已通过 `cargo fmt --all -- --check`、`cargo test --workspace`、真实 `sh_security_environment_nativeInfo_trace_0_0xf92d8.log` AES 回归、checkpoint/Frida 闭环定向测试、UI guards、Vitest 6/6、TypeScript/Vite production build 和 `cargo tauri build --ci`；本地成功生成 Windows MSI、NSIS 安装包与 release EXE。

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
- `generate_angr_ollvm_script_with_seeds_flow_identity_and_checkpoint`

生成的脚本输出 `trace-ui/angr-ollvm-v1`，内容包括 CFGFast/CFGEmulated 对账、blank-state probes、trace-register probes、Frida branch probes、dispatcher probes、checkpoint probes 和 bounded flows。

#### Exact ELF guard

GUI 的 `angr` 页面可以选择 exact AArch64 ELF。生成脚本时保存 SHA-256；用户运行 Python 脚本时，脚本在建立 angr Project 前重新计算哈希，若不一致则直接停止。

该机制验证的是用户选择的文件，不对原始 trace 的运行时映像做加密证明。

#### 多 Frida seed

同一份 Frida capture 最多可选择 32 个事件：

- `hook-enter`
- `ollvm-dispatcher-hit`

每个事件必须精确匹配 opaque branch、condition-source、dispatcher `startOffset`，或在同时提供上一轮 Unicorn result 时匹配其严格授权的更近 checkpoint offset。每个 seed 独立生成 probe，并在结果中保留 source event、offset、寄存器和内存 provenance。

#### 更近 checkpoint 授权

angr 与 Unicorn 共用同一授权器：report module、上一轮 result 的 expected/actual SHA-256、当前 exact ELF SHA-256 必须一致，且 capture offset 必须位于该结果从 supported stalled run 推导出的 checkpoint 集合。授权 seed 使用 `frida-capture-authorized-checkpoint`，结果写入 `checkpointProbes`；branch provenance 不能混入 checkpoint probe。GUI 通用 angr 页可以导入上一轮 Unicorn JSON，“模拟增强”页也可在第 6 步直接接力。

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
| `trace-ui/unicorn-ollvm-v1` | exact-seed Unicorn bounded concrete replay | 用户手动运行生成的 Python |
| `trace-ui/frida-unicorn-recapture-hook-v1` | 累积补全 Unicorn seed 内存的有界 Hook 元数据 | Trace UI |
| `trace-ui/unicorn-ollvm-round-comparison-v1` | 2–16 轮同 ELF Unicorn 结果的进度/停滞比较 | Trace UI |

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
  -> generate Unicorn Python and run it manually
  -> import trace-ui/unicorn-ollvm-v1 JSON
  -> recapture explicit missing memory and replay again while coverage advances
  -> compare 2-16 Unicorn rounds by exact seed offset
  -> generate a closer checkpoint Hook for stalled/diverged seeds
  -> import the new exact checkpoint capture
  -> continue Unicorn, or pass the same prior result to bounded angr
  -> import checkpointProbes and review Candidate/Related paths
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
