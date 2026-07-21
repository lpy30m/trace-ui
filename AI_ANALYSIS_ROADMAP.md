# Trace UI AI 分析能力路线图

更新日期：2026-07-18

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

## 3. 当前限制

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
- [ ] GUI 增加 Analysis History，用于查看和比较 MCP 创建的分析。

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
