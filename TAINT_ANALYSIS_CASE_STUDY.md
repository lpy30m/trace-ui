# Trace UI 污点分析样本复盘与改进建议

> 目的：把 `CryptoHelper.md5_crypt([BI[B)[B` 真实 ARM64/GumTrace 样本的污点分析结果、工具边界、MCP 问题和后续实现建议交给开发 AI。
>
> 本文基于实际 Trace UI MCP 调用、实际返回值和实际内存证据，不是泛泛的产品设想。

## 0. 给后续 AI 的执行说明

开始改代码前依次阅读：

1. `PROJECT_STATE.md`
2. `AI_ANALYSIS_ROADMAP.md`
3. 本文 `TAINT_ANALYSIS_CASE_STUDY.md`

不要一次性重构整个污点引擎。现有指令级依赖图和 BFS 已经能正确追踪本样本，优先完成本文 P0 的“外部调用语义 + 内存观察”再继续其他优化。

新增能力应保持同一核心模型，并按现有项目边界接线：

```text
trace-parser -> trace-core query/engine -> trace-mcp -> Tauri -> GUI
```

只改 MCP 展示层会导致 GUI/core 仍然不一致；只改 core 而不更新 MCP schema，AI 仍然无法稳定使用。

## 1. 样本与已验证算法

### 1.1 当前样本

```text
/Users/jiangxia/code/python/安卓逆向/瑞幸/cryptoDD_md5_core_trace_0_0x4095c.log
```

Trace 信息：

```text
format       : Gumtrace
total_lines  : 1042786
file_size    : 89280578
core         : libcryptoDD.so + 0x4095c
```

关键参数：

```text
core input pointer : 0xb400007956270730
core input length  : 0x2cf = 719
digest buffer      : 0x7fd84c7ac0
digest length      : 16
final string buf   : 0x7fd84c7ad0
```

digest 最后一次写入是 0-based `seq=1039464`，现有污点语法需要写成 1-based：

```text
mem:0x7fd84c7ac0:16@1039465
```

已验证算法：

```text
MD5(core input) = 6b2ffd810d376741c181cf680cffca63

big-endian signed int32:
  0x6b2ffd81 = 1798307201
  0x0d376741 = 221734721
  0xc181cf68 = -1048457368 -> cneg -> 1048457368
  0x0cffca63 = 218090083

final:
  17983072012217347211048457368218090083
```

### 1.2 第二组独立样本

```text
/Users/jiangxia/code/python/安卓逆向/瑞幸/cryptoDD_md5_crypt_trace_1_0x43bbc.log
```

```text
original MD5 : 5a6c165e5ece6da2084a5c4c39958092
AES suffix   : KcIufueoThQliBgs
core MD5     : fb62293048087cbcf36b786d158a2c2f
native final : 774530081208515772211060627361376815
```

Python 从第二组 trace 的真实 703 字节原文和 32 字节密文重算，最终结果与 native 返回值逐字节一致。两组样本值不同、结构相同，适合作为跨 trace 回归数据。

## 2. 已执行的 Trace UI 污点分析

### 2.1 digest -> 格式化流程：前向污点

```json
{
  "from_specs": ["mem:0x7fd84c7ac0:16@1039465"],
  "data_only": true,
  "start_seq": 1039464,
  "include_lines": 200,
  "max_nodes": 100000,
  "max_sinks": 100
}
```

保存的 analysis ID：

```text
4a16f127-1dee-492e-8b8d-5dbdefcf8c8a
```

结果：

```text
affected instructions : 101
traversed edges       : 139
truncated             : false
```

命中数据流：

```text
digest bytes
 -> ldrb
 -> lsl / bfi / orr / and / eor
 -> 4 x int32
 -> cneg
 -> sprintf boundary
 -> strcat boundary
 -> strlen / malloc / memmove boundary
```

四个 `cneg`：

```text
seq 1039619 : 0x6b2ffd81 -> 0x6b2ffd81
seq 1039768 : 0x0d376741 -> 0x0d376741
seq 1039966 : 0xc181cf68 -> 0x3e7e3098
seq 1040112 : 0x0cffca63 -> 0x0cffca63
```

调用位置：

```text
sprintf: seq 1039630, 1039828, 1039974, 1040120
strcat : seq 1040131, 1040142, 1040153
strlen : seq 1040163
memmove: seq 1040281 (branch), annotation follows
```

### 2.2 四个格式化整数 -> digest：反向污点

为了绕过 `sprintf` 外部调用边界，选择进入格式化阶段的寄存器：

```json
{
  "from_specs": [
    "reg:X2@1039624",
    "reg:X2@1039821",
    "reg:X2@1039967",
    "reg:X2@1040113"
  ],
  "data_only": true,
  "start_seq": 1039400,
  "end_seq": 1040112,
  "ignore_stack_ops": true,
  "include_lines": 200
}
```

保存的 analysis ID：

```text
96f2d5f2-acac-4bf9-95fa-2a179d4e178a
```

结果：

```text
marked_count       : 92
stack_ops_filtered : 8
total_after_filter : 84
```

映射关系：

```text
0x6b2ffd81 <- digest[0:4]
0x0d376741 <- digest[4:8]
0xc181cf68 <- digest[8:12]
0x0cffca63 <- digest[12:16]
```

这证明当前引擎确实在沿动态寄存器、栈内存、普通内存的定义-使用关系追踪，不是字符串搜索。

### 2.3 digest -> core：大范围反向污点

```text
source    : mem:0x7fd84c7ac0:16@1039465
data_only : true
start_seq : 100000
end_seq   : 1039464
```

保存的 analysis ID：

```text
fa284815-7d0e-49b2-bcb6-55d54543b637
```

结果规模：

```text
marked_count       : 44712
stack_ops_filtered : 441
total_after_filter : 44271
```

收窄到 `libcryptoDD.so 0x40900-0x41100` 后可见 core 参数：

```text
seq 114632: mov x0, x21 -> x0 = 0xb400007956270730
seq 114633: mov x1, x20 -> x1 = 0x2cf
seq 114642: ldur x2, [...] -> x2 = 0x7fd84c7ac0
```

这能定位 input pointer、input length 和 digest output pointer，但不能声称污点“反解了 MD5 明文”。原文内容仍依赖输入 hexdump、内存观察或更早的 hook。

### 2.4 最终返回证据

```text
call func: memmove(0xb400007896421f50, 0x7fd84c7ad0, 0x26)
```

`0x26 = 38`，调用摘要 hexdump 转 ASCII：

```text
17983072012217347211048457368218090083
```

但 `get_memory(0x7fd84c7ad0, length=38)` 返回 38 个 `known=false`，因为调用摘要中的 hexdump 没有进入指令内存索引。

### 2.5 正反向交叉比较

比较：

```text
96f2d5f2-acac-4bf9-95fa-2a179d4e178a  backward_taint
4a16f127-1dee-492e-8b8d-5dbdefcf8c8a  forward_taint
```

共同证据：

```text
memory    : 0x7fd84c7ac0 - 0x7fd84c7acf
operations: ldrb, lsl, bfi, orr, and, eor, ldr, str, strb, cneg, cmp, mov
module    : libcryptoDD.so
```

## 3. 当前实现已经做对的部分

- ARM64 寄存器和内存的动态依赖追踪正确。
- 1-4096 字节多字节、多来源污点可用。
- 正向、反向结果都能保存 `analysis_id`。
- `data_only`、地址范围、栈操作过滤可用。
- `cneg/ldrb/bfi/eor` 等关键指令没有丢失。
- `compare_analyses` 能交叉验证正反向共同节点。
- 调用注解能显示函数名、raw args、ret 和 hexdump。
- 分析记录可以持久化并在 Analyses 面板复核。

因此不需要推倒重做污点 BFS。最主要的缺口是：调用注解目前只是展示信息，没有成为依赖图和内存状态的一等输入。

## 4. 优先级总览

| 优先级 | 问题 | 当前影响 |
|---|---|---|
| P0 | 外部函数没有 call effect / memory transfer | final buffer 无法反向追踪 |
| P0 | `sprintf` raw args 缺少 ABI/类型语义 | 可能展示错误整数参数 |
| P1 | value/address/stack 依赖未细分 | digest 反向产生 44,712 节点噪声 |
| P1 | `get_tainted_lines` 读取最后一次全局 slice | 并发或多 analysis 会串结果 |
| P1 | `@LINE` 1-based 与 seq 0-based 混用 | 高风险 off-by-one |
| P1 | MCP JSON 作为 text 再嵌套 | 大结果截断、二次解析 |
| P1 | PLT thunk 与 annotation 未统一 | 同一调用既 unresolved 又 resolved |
| P2 | Source/Sink 命名过度推断 | `terminal_output` 容易误解 |
| P2 | 缺少跨 trace taint graph diff | 难验证“值不同、算法相同” |
| P2 | skill 缺少外部调用边界 fallback | AI 仍需人工跨过 libc |

## 5. P0-1：外部函数调用必须进入污点和内存模型

### 5.1 实测失败

```text
taint_analysis(mem:0x7fd84c7ad0:38@1040282)
```

返回：

```text
内存范围 0x7fd84c7ad0:38 没有可追踪的写入定义
```

同一 trace 明确记录了 `sprintf/strcat/memmove` 和最终 hexdump。这不是数据不存在，而是 annotation 没有并入依赖/内存索引。

### 5.2 代码根因

`crates/trace-parser/src/gumtrace.rs`：

```rust
pub struct CallAnnotation {
    pub func_name: String,
    pub is_jni: bool,
    pub args: Vec<(String, String)>,
    pub ret_value: Option<String>,
    pub raw_lines: Vec<String>,
}
```

`scan_unified.rs`/`merge.rs` 会合并 special lines，但不会把 annotation 变成：

```text
mem_last_def
MemAccessView record
dependency edge
forward consumer edge
```

`engine/query.rs::get_memory_at` 只查询 `MemAccessView`，所以 call hexdump 不可能变成 known byte。

### 5.3 建议的数据模型

保留 raw annotation，新增结构化观察和效果：

```rust
pub struct ObservedBuffer {
    pub address: u64,
    pub length: u32,
    pub bytes: Vec<u8>,
    pub seq: u32,
    pub role: BufferRole,
    pub provenance: MemoryProvenance,
}

pub enum MemoryProvenance {
    InstructionWrite,
    CallModel,
    CallHexdump,
    Unknown,
}

pub struct CallEffect {
    pub call_seq: u32,
    pub function_name: String,
    pub reads: Vec<MemoryRange>,
    pub writes: Vec<MemoryRange>,
    pub transfers: Vec<ByteTransfer>,
    pub confidence: String,
}
```

第一批模型：

```text
memcpy / memmove: src[i] -> dst[i]
memset: value -> dst[0:len]
strlen: src bytes -> return length
strcpy / strncpy: src -> dst
strcat / strncat: old dst + src -> new dst
sprintf / snprintf("%d"): int value -> ASCII bytes -> dst
```

效果必须同时服务：

1. `get_memory_at` 的 synthetic definitions；
2. backward/forward dependency edges；
3. GUI/MCP 的 provenance 和 confidence；
4. Source/Sink/Function Inspector 的统一 call 信息。

不要把 call model 伪装成逐指令证据。返回时区分：

```text
instruction_defined
call_model_defined
call_hexdump_observed
unknown
```

### 5.4 时间语义

hexdump 头和数据行应解析地址与长度，并记录 observation/completion seq。调用效果写入应该发生在调用完成后，而不是随意挂到入口前。

`memmove` 的 hexdump 通常是 source observation；destination 需要由函数模型从 source 合成。`sprintf` 需要结合 format 与 ABI 变参建模。

### 5.5 验收

当前样本：

```text
get_memory(0x7fd84c7ad0, seq=1040281, length=38)
```

应返回 38 个已知字节及 provenance，并且：

```text
taint_analysis(mem:0x7fd84c7ad0:38@1040282)
```

能回到 `strcat/sprintf` inputs，再回到 digest。

## 6. P0-2：调用参数需要 ABI 和类型语义

### 6.1 实测问题

`search_instructions("sprintf")` 的 raw annotation 出现：

```text
args0: 3
args0: \x8d\x80\xad\xeb
```

真实 `%d` 变参位于 `W2/X2`：

```text
1798307201
221734721
1048457368
218090083
```

当前 parser 是忠实保存 producer 日志，但 `CallInfoDto` 只有 `index/value`，没有说明这是 raw annotation、目标缓冲区预览还是 ABI 参数。AI 容易错误升级其置信度。

### 6.2 建议 DTO

```rust
pub struct TypedCallArgumentDto {
    pub index: String,
    pub register: Option<String>,
    pub role: Option<String>,
    pub type_name: Option<String>,
    pub value: String,
    pub raw_value: Option<String>,
    pub observation: String,
}
```

目标 MCP 输出：

```json
{
  "func_name": "sprintf",
  "raw_annotation_args": [{"index": "0", "value": "3"}],
  "typed_args": [
    {"register": "x0", "role": "destination", "value": "0x7fd84c7ad0"},
    {"register": "x1", "role": "format", "value": "%d"},
    {"register": "x2", "role": "variadic_int32", "value": "1798307201"}
  ],
  "observed_output": "1798307201",
  "return_value": "0xa"
}
```

`get_registers_at(seq)` 已存在，可结合函数签名 registry 补充 X0-X7。保留旧字段兼容，但必须标记 raw provenance。

### 6.3 验收

四次 `sprintf`：

```text
typed_args[value] == 1798307201
typed_args[value] == 221734721
typed_args[value] == 1048457368
typed_args[value] == 218090083
```

## 7. P1：污点精度

### 7.1 依赖类型

`data_only=true` 当前主要过滤 `CONTROL_DEP_BIT`，并不等于 strict value-only。建议将边分类为：

```text
Value
Address
Control
StackTransport
CallBoundary
```

新增可选项：

```json
{
  "include_value_dependencies": true,
  "include_address_dependencies": false,
  "include_stack_transport": false,
  "include_control_dependencies": false
}
```

旧 `data_only` 保持兼容。

### 7.2 pair/lane/byte 精度

当前 forward slice 明确采用 pair instruction conservative precision。建议增加：

```text
precision: instruction | register_lane | byte
```

优先支持：

```text
stp/ldp 的两个 lane
W/X 低 32 位 alias
str/ldr 的实际 byte width
SIMD lane 局部依赖
```

回归目标：不丢失四个 word 路径，同时显著降低 digest 大范围分析的 44,712 节点噪声。

## 8. P1：analysis_id、source spec 与错误模型

### 8.1 `get_tainted_lines` 必须绑定 analysis_id

当前 `GetTaintedLinesRequest` 没有 `analysis_id`，实现读取 `SessionState.slice_result`，也就是最后一次全局 slice。多 AI、多任务或 GUI/MCP 同时使用时会串结果。

建议：

```json
{
  "session_id": "...",
  "analysis_id": "96f2d5f2-...",
  "offset": 0,
  "limit": 100
}
```

实现方案：

- AnalysisRecord 保存压缩 bitmap 或 sorted seq list；或
- 用保存 request 重算并返回 `recomputed=true`；
- `SessionState.slice_result` 仅作为 GUI 当前活动污点，不再承担历史分页。

### 8.2 明确 line/seq

兼容新增：

```text
reg:X0@line:1234
reg:X0@seq:1233
mem:0xbffff000:32@line:5930
mem:0xbffff000:32@seq:5929
```

响应同时返回：

```json
{"display_line": 5930, "seq": 5929}
```

### 8.3 语义锚点

```text
call_arg:sprintf:2@seq:1039630
call_output:sprintf:dst@seq:1039630
call_input:memmove:src@seq:1040281
call_output:memmove:dst@seq:1040281
function_arg:md5_core:x0@entry
function_return:md5_core:x0@exit
```

### 8.4 结构化错误

内存无定义时建议返回：

```json
{
  "code": "NO_MEMORY_DEFINITION",
  "address": "0x7fd84c7ad0",
  "length": 38,
  "seq": 1040281,
  "nearby_call_annotations": [
    {"seq": 1040281, "func_name": "memmove", "has_hexdump": true}
  ],
  "suggested_sources": [
    "call_input:memmove:src@seq:1040281",
    "reg:X1@line:1040275"
  ]
}
```

## 9. P1：MCP 输出与调用节点

### 9.1 JSON 不应作为 text 再嵌套

`trace-mcp/src/tools.rs` 当前统一返回 `Result<String, String>`，`json()` helper 把结构序列化成文本。客户端最终得到 JSON 字符串套在 MCP text content 中，大型 `get_analysis` 会截断并要求二次解析。

建议使用 rmcp 的结构化 `CallToolResult`/JSON content：

```text
structuredContent.summary
structuredContent.evidence
structuredContent.page
```

文本 content 只放 bounded human summary。

### 9.2 大分析分页

增加：

```text
get_analysis_summary
get_analysis_lines
get_analysis_endpoints
get_analysis_evidence
```

或给 `get_analysis` 增加 `include/cursor/limit`。

### 9.3 logical call site

当前 `bl -> thunk -> br x17` 可能同时产生 unresolved call 和已解析 annotation。建议统一：

```rust
pub struct LogicalCallSite {
    pub entry_seq: u32,
    pub annotation_seq: u32,
    pub function_name: String,
    pub thunk_seqs: Vec<u32>,
    pub call_args: Vec<TypedCallArgumentDto>,
    pub effects: Option<CallEffect>,
}
```

污点、Source/Sink、Function Inspector、search 和 MCP 共用这个节点。

### 9.4 Source/Sink 命名

将含糊名称细分：

```text
external_sink
external_source
function_return
memory_write
call_boundary
graph_terminal
joined_input
unresolved_call
```

`graph_terminal` 必须说明“动态 trace 中未观察到后续消费者，不代表真实外部输出”。

### 9.5 MCP 健康检查

本次 Trace UI 和 `127.0.0.1:19821/mcp` 正常，但 Codex 当前会话没有注入工具，最终通过 HTTP 手动执行：

```text
initialize
tools/list
tools/call
```

这可能属于客户端启动时机，不一定是服务 bug。Trace UI 仍建议提供：

```text
GET /health
get_server_status
list_open_sessions
server_instance_id
server_build_revision
```

initialize instructions 返回 build revision、外部调用模型和 structured output 能力。README 继续强调“新增 MCP 工具后必须重建并重启 Trace UI”。

## 10. P2：跨 trace 数据流比较与自动识别

### 10.1 compare_taint_graphs

建议工具：

```text
compare_taint_graphs(left_session_id, left_analysis_id, right_session_id, right_analysis_id)
```

按以下字段做 ASLR 无关对齐：

```text
module + so_offset
operation
source/sink role
logical call name
```

两组样本预期共同结构：

```text
digest[0:4]   -> int32_be -> cneg -> sprintf
digest[4:8]   -> int32_be -> cneg -> sprintf
digest[8:12]  -> int32_be -> cneg -> sprintf
digest[12:16] -> int32_be -> cneg -> sprintf
sprintf x4 -> strcat x3 -> strlen -> memmove
```

### 10.2 formatting pipeline detector

建议确定性识别器：

```text
detect_formatting_pipeline
```

输出示例：

```json
{
  "pattern": "md5_words_to_decimal_concat",
  "confidence": "high",
  "word_count": 4,
  "byte_order": "big_endian",
  "signedness": "int32",
  "negative_handling": "cneg_mi",
  "format": "%d",
  "evidence_seqs": [1039491, 1039590, 1039619, 1039630, 1040131]
}
```

## 11. 推荐代码入口

### trace-parser

```text
crates/trace-parser/src/gumtrace.rs
```

- CallAnnotation 增加 typed args、hexdump records、start/completion seq。
- 解析 hexdump header 的 base/length 和每行地址。
- 保留 raw lines，避免 tooltip/search 回退。

### trace-core scan/build

```text
crates/trace-core/src/scan_unified.rs
crates/trace-core/src/merge.rs
crates/trace-core/src/engine/build.rs
crates/trace-core/src/session.rs
```

- 构建 `LogicalCallSite`、`ObservedMemoryIndex`、`CallEffectIndex`。
- 将 call effects 纳入 memory last definition 和 dependency graph。
- 新 index 纳入 cache，并随 trace 内容校验失效。

### trace-core query/engine

```text
crates/trace-core/src/engine/query.rs
crates/trace-core/src/engine/slice.rs
crates/trace-core/src/engine/forward_slice.rs
crates/trace-core/src/query/forward_slice.rs
crates/trace-core/src/query/source_sink.rs
crates/trace-core/src/api_types.rs
```

- `get_memory_at` 合并 instruction/call model/hexdump observations。
- backward/forward slice 支持精度模式。
- Source/Sink 消费 LogicalCallSite。
- TraceLine.call_info 增加 typed args/effects/provenance/confidence。
- MemorySnapshot 增加 `provenance[]`，保留旧 `known[]`。

### trace-mcp

```text
crates/trace-mcp/src/types.rs
crates/trace-mcp/src/tools.rs
```

- GetTaintedLinesRequest 增加 analysis_id。
- Taint 请求增加 explicit line/seq、precision 和 edge filter。
- 分页 summary/lines/endpoints/evidence。
- 逐步替换 `Result<String, String>` 为 structured MCP result。
- 错误返回 code、nearby annotations 和 suggested sources。

## 12. trace-analysis skill 改进

需要同步：

```text
/Users/jiangxia/安卓逆向/trace-ui/.claude/skills/trace-analysis/
/Users/jiangxia/.claude/skills/trace-analysis/
/Users/jiangxia/.codex/skills/trace-analysis/
```

### 外部调用边界 fallback

```text
当 final memory 返回 NO_MEMORY_DEFINITION：
1. 搜索地址附近 call annotation。
2. 检查 sprintf/strcat/memmove/memcpy/memset/strlen。
3. 使用 call boundary 或 typed call args 重新做 taint。
4. 将 final bytes 标为 call-summary/call-model evidence。
5. 不得升级为 instruction-defined evidence。
```

### formatting pipeline playbook

```text
digest buffer
 -> forward/backward taint
 -> cneg / sprintf / strcat / strlen / memmove
 -> big-endian word extraction
 -> signed int32 verification
 -> decimal concatenation
 -> final hexdump cross-check
```

### skill 必须明确

- 污点不会反解 MD5，只证明依赖。
- get_memory known 当前不包含 call hexdump。
- 未建 typed ABI 前，call_info.args 只是 raw annotation。
- terminal_output 不等于外部 sink。
- 每个示例同时标注 `line` 和 `seq`。
- 分页必须绑定 analysis_id，不能依赖最后一次污点。

## 13. 回归测试

不建议默认提交 89 MB/93 MB 原始 trace。采用：

```text
小型合成 GumTrace fixture：覆盖格式化、拼接、返回
可选真实 integration fixture：环境变量指向完整 trace
```

### Call annotation

```text
[ ] 四次 sprintf 解析为同一逻辑函数
[ ] typed int32 = 1798307201, 221734721, 1048457368, 218090083
[ ] 三次 strcat 的 dst/src/output 正确
[ ] memmove 的 src/dst/len/hexdump 正确
```

### Memory

```text
[ ] digest known=true, provenance=instruction_write
[ ] final bytes known=true, provenance=call_model/call_hexdump
```

### Forward taint

```text
[ ] digest 到达四个 cneg
[ ] 到达四个 logical sprintf
[ ] 到达三次 strcat 和最终 memmove effect
[ ] 不只停在 unresolved_function_call
```

### Backward taint

```text
[ ] 四个 int32 分别回到 digest 四个 byte range
[ ] final buffer 经 call effect 回到 strcat/sprintf inputs
```

### Precision

```text
[ ] byte/lane 模式不扩大成无关栈 frame
[ ] data_only 不包含 control-only edge
[ ] 在不丢核心路径前提下降低 44,712 节点噪声
```

### Analysis pagination

```text
[ ] 两个 backward analysis 同时存在
[ ] 按各自 analysis_id 分页不串线
[ ] 重开 trace 后 analysis_id 和分页结果仍可恢复
```

### Cross-trace

```text
sample A: fb62293048087cbcf36b786d158a2c2f
sample B: 6b2ffd810d376741c181cf680cffca63

值不同，但归一化 graph 都是：
4 words -> cneg -> sprintf x4 -> strcat x3 -> strlen -> memmove
```

## 14. 推荐实施阶段

### Phase 1：CallEffect + memory provenance

目标：`get_memory` 和 taint 都能看到 `sprintf/strcat/memmove` 模型写入。

验收：最终 38 字节可读、可反向追。

### Phase 2：typed args + LogicalCallSite

目标：修复 sprintf 参数歧义和 thunk unresolved。

验收：四个 `%d` 变参可用 semantic call_arg 直接追踪。

### Phase 3：analysis_id pagination + structured MCP

目标：消除最后一次污点状态污染和 JSON 套 JSON。

验收：并发、重启、分页互不影响。

### Phase 4：precision + cross-trace graph diff

目标：降低噪声，证明两组值不同但算法相同。

### Phase 5：skill + automatic recipe

目标：只给 trace 路径和已知 digest/final output，AI 能自动走：

```text
final value -> call boundary -> typed args -> digest -> core input
```

并明确 instruction/call-model/hexdump/external-recompute 四类 provenance。

## 15. 非目标与风险

- 不需要让污点反解 MD5 或猜未知明文。
- 不需要一次实现所有 libc；先覆盖常用 memory/string/format functions。
- call model/hexdump 不得默认标成逐指令同等级置信度。
- 不能为了降噪直接删除所有地址/栈依赖，应提供可选模式。
- MCP 层不应自行解析 tooltip；解析和 effects 应在 core。
- 跨 trace 不应按绝对地址或 seq 对齐，应按 module-relative offset 和逻辑角色。

## 16. 文档状态同步

`PROJECT_STATE.md` 已写明 Analysis History 和正向污点完成，但 `AI_ANALYSIS_ROADMAP.md` 的部分后续 checkbox 仍是旧状态，例如 GUI Analysis History。后续 AI 开始前应统一文档，避免重复实现。

建议在文档索引增加：

```markdown
- `TAINT_ANALYSIS_CASE_STUDY.md`：真实 GumTrace 污点复盘、外部调用边界和回归验收。
```

## 17. Definition of Done

```text
[ ] 无需人工整理最终日志，call effect 能产生 final buffer
[ ] final buffer backward taint 回到 strcat/sprintf inputs
[ ] typed sprintf vararg 不再把 destination preview 当整数
[ ] get_memory 区分 instruction/call model/hexdump provenance
[ ] get_tainted_lines 由 analysis_id 决定，不读取最后一次全局状态
[ ] line/seq 可明确表达，不依赖隐式 +1
[ ] forward/backward 通过 LogicalCallSite 跨 PLT thunk
[ ] 两组样本归一化污点图结构一致
[ ] MCP 返回 structured summary/evidence/page，不因嵌套文本截断
[ ] skill 同步到仓库、Claude、Codex 三处
```

最终自动报告应能输出：

```text
Observed input : 719 bytes at 0xb400007956270730
Observed digest: 6b2ffd810d376741c181cf680cffca63
Transform      : big-endian signed int32 + cneg/abs
Formatting     : sprintf("%d") x4
Join           : strcat x3
Return         : 38 bytes via memmove
Final output   : 17983072012217347211048457368218090083

Evidence provenance:
  instruction        : digest word assembly and cneg
  call_model         : sprintf/strcat/memmove transfer
  call_hexdump       : observed final bytes
  external_recompute : Python MD5 and formatting validation
```

