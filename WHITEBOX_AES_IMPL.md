# 软件查表 AES / 白盒密码识别：真实样本复盘、勘误与 v2 实施规格

> 文档状态：2026-07-20 真实 GumTrace 样本复核后的开发交接稿。
>
> 目标：解释旧密码扫描器为何漏检 libcryptoDD.so 中的 AES，修正当前 White-box 模块对样本角色和实现类型的误判，并给出可以直接交给开发 AI 落地的 core、MCP、GUI、测试与验收方案。
>
> 本文只描述建议和验收依据，不代表下述 v2 已经完成。仓库里现有 whitebox_aes.rs 和 analyze_whitebox_crypto 属于 v1。

## 0. 执行摘要

### 0.1 最重要的勘误

当前样本不是已经得到证明的白盒 AES。经完整 trace 数据流、运行时 key、轮密钥扩展、分组写出以及 Python 逐字节复算交叉验证，最准确的分类是：

~~~text
标准 AES-128
+ ECB
+ PKCS#7
+ 通用 ARM64 指令的软件字节/查表实现
+ 标准运行时 key expansion
+ 重度控制流平坦化/不透明谓词
~~~

建议对外分类：

~~~text
algorithm          = AES-128
mode               = ECB
padding            = PKCS#7
implementationKind = obfuscated_standard_software
tableDriven        = true
whiteboxStatus      = not_whitebox
verification       = semantic_reproduction
~~~

不能因为以下现象就把实现称为白盒：

- 没有 AESE/AESMC/AESD/AESIMC；
- 有大量查表；
- 控制流很乱；
- 约有十轮重复结构；
- 旧 magic scanner 命中为零。

真正白盒实现的关键区别通常是原始 key 不直接暴露、没有独立标准 round-key schedule，并且 key 已融合进带内部/外部编码的大型查找表。本样本恰好相反：原始 key 和标准 key expansion 都能在 trace 中看到。

### 0.2 v1 可以保留什么

现有 v1 并非完全无用。以下基础设施可以保留并复用：

- 模块内/模块外内存访问区分；
- 连续内存缓冲重组；
- 模块内高频读取区域聚类；
- 地址、seq、module offset 的可跳转证据；
- EvidenceAssessment 与 analysis_id；
- MCP、Tauri、前端 White-box 分页的接线；
- 结构化报告和缓存。

需要修改的是这些信号的语义解释、评分 gate、角色识别和命名，而不是推倒整个索引引擎。

### 0.3 建议优先级

优先级最高的不是继续增加更多 AES magic constants，而是：

1. 修正样本角色：Safe_box_1234567 是包装主密钥，不是明文。
2. 将 software/table/obfuscated/whitebox 分开分类。
3. 给检测器增加 AES key schedule、16-byte block stride 和语义复算。
4. 把 v2 结构信号接入统一的函数级 crypto report。
5. 只有在算法、模式、key、输入和输出能复算一致时才给 verified。

## 1. 真实样本与可复查产物

### 1.1 主样本

~~~text
/Users/jiangxia/安卓逆向/QTrace/luckylogs/
qbdi_20260719_230906_libcryptoDD.so+0x41ed8_1.gumtrace.txt
~~~

大小约 29 MiB，入口为：

~~~text
libcryptoDD.so + 0x41ed8
~~~

### 1.2 Python 复现

~~~text
/Users/jiangxia/code/python/安卓逆向/瑞幸/
reproduce_q_from_trace_sample.py
~~~

运行：

~~~bash
python3 /Users/jiangxia/code/python/安卓逆向/瑞幸/reproduce_q_from_trace_sample.py
~~~

已验证输出：

~~~text
wrapping_key:       Safe_box_1234567
business_key:       KcIufueoThQliBgs
json_length:        452 (0x1c4)
padded_length:      464 (0x1d0)
ciphertext_length:  464 (0x1d0)
ciphertext_first16: ae2af887f83430372469ccbf4b3d5916
ciphertext_last16:  98e234a6fb29bf721d7201f13f8952bc
ciphertext_sha256:  6d36a4ddf9a9fece32704646393248f499950f5bef6125fbe137e5e487dd6f95
q_length:           620
~~~

生成的 URL-safe Base64 q 与样本中的 rir4h_g0...T-JUrw= 完全一致。

### 1.3 已保存的污点分析

首个正文密文块的 backward taint：

~~~text
analysis_id = 8162a6a2-bbae-453b-906e-191ffe9a615c
~~~

该切片把首个密文块依赖回溯到明文块、业务 key 及其轮密钥扩展。后续重构时应保留此 analysis 作为人工核验入口，但自动测试不能只依赖本机持久化 analysis_id。

## 2. 已验证的两层密码流程

### 2.1 业务流程

~~~text
32-byte wrapped business key
        |
        | AES-128-ECB Decrypt
        | key = Safe_box_1234567
        | PKCS#7 unpad
        v
16-byte business key
KcIufueoThQliBgs
        |
        | AES-128-ECB Encrypt
        | plaintext = 452-byte JSON
        | PKCS#7 pad = 12 * 0x0c
        v
464-byte ciphertext / 29 blocks
        |
        | URL-safe Base64
        v
q = rir4h_g0...
~~~

### 2.2 key 角色

| 值 | 长度 | 真实角色 | 是否固定 |
|---|---:|---|---|
| Safe_box_1234567 | 16 | 包装主密钥，用于解开业务 key | 当前 SO 版本中硬编码；不能外推为永久固定 |
| KcIufueoThQliBgs | 16 | 当前样本正文 AES-128 key | 由 wrapped key 动态解出 |
| 8ce0755e...61ae343b | 32 | 包装后的业务 key 密文 | 输入样本相关 |
| 452-byte JSON | 452 | 正文 AES 明文 | 动态业务数据 |

v1 报告把最早可打印的 16 字节模块外读缓冲 Safe_box_1234567 标成 plaintext，这是角色推断错误。可打印性只能说明它像字符串，不能证明它是明文、key、IV、AAD 或中间态中的哪一种。

## 3. Trace 证据

### 3.1 固定包装主密钥

约在 trace 第 1523 至 1528 行：

~~~asm
add x9, x9, #0x954
mov w2, #0x80
ldr q0, [x9]
~~~

地址：

~~~text
libcryptoDD.so + 0x9954
~~~

内存值：

~~~text
0x786f625f65666153
0x373635343332315f
~~~

按小端重组：

~~~text
Safe_box_1234567
~~~

w2=0x80 是 128 bit key-size 参数。

### 3.2 标准 key expansion

轮密钥扩展入口：

~~~text
libcryptoDD.so + 0x1e698
~~~

内部判断：

~~~asm
cmp w2, #0x80
cmp w2, #0x100
cmp w2, #0xc0
~~~

分别覆盖 AES-128、AES-256、AES-192 的 key-size 分支。

标准 Rcon 数据从内存以向量/32-bit 排列加载。约在 trace 第 1918 至 1923 行可以观察到 01、02、04、08、10、20、40、80、1b、36 对应的序列。

轮扩展子过程：

~~~text
libcryptoDD.so + 0x1f06c
~~~

第一组出现 10 次，第二组出现 10 次。总计 20 次不是 AES-20-round，而是本 trace 包含两次 AES-128 key schedule：

1. Safe_box_1234567 的十轮扩展；
2. KcIufueoThQliBgs 的十轮扩展。

### 3.3 业务 key 明文出现

约在 trace 第 50317 行 JNI 注解中：

~~~text
GetByteArrayElements:
len=0x10
hex=4b6349756675656f5468516c69426773
str=KcIufueoThQliBgs
~~~

这条证据直接否定“key 只融合在白盒表中、运行时没有原始 key”的判断。

### 3.4 正文 AES 入口与分组数

正文加密入口：

~~~text
libcryptoDD.so + 0x18244
~~~

调用前：

~~~text
x0 = input
w1 = 0x1d0
x2 = output
x3 = key/context
w4 = 0x80
~~~

入口计算：

~~~asm
lsr w25, w1, #4
and w26, w1, #0xf
~~~

代入 0x1d0：

~~~text
0x1d0 >> 4 = 0x1d = 29 blocks
0x1d0 & 0xf = 0
~~~

这是强分组结构证据。

### 3.5 密文写出

每块在：

~~~text
libcryptoDD.so + 0x18940
~~~

通过：

~~~asm
str q0, [x21, x8]
~~~

写出 16 字节。x8 依次为：

~~~text
0x00, 0x10, 0x20, ..., 0x1c0
~~~

共 29 次。第一个密文块：

~~~text
ae2af887f83430372469ccbf4b3d5916
~~~

与 Python AES-128-ECB 复算一致。

### 3.6 没有硬件 AES 指令

整份 trace 搜索以下助记符均为零：

~~~text
aese
aesmc
aesd
aesimc
~~~

实现使用 ldrb/ldr/eor/lsl/lsr/and/str 等普通 ARM64 指令，并穿插大量随机状态常量和分支。

### 3.7 为什么确定是 ECB

三个相互独立的证据：

1. 调用中没有 IV 参数或 16-byte IV 初始化。
2. block 之间没有观察到上一块密文 XOR 下一块明文的 CBC chaining。
3. 标准 AES.MODE_ECB 对全部 29 块的输出与 trace 464 字节完全一致。

第 3 条是语义证明。即使参数角色推断存在偏差，完整输出匹配仍足以确定当前样本的算法和模式。

## 4. 旧扫描器为何漏检

### 4.1 当前只有两类输入信号

analyze_crypto_functions 当前聚合：

1. scan_crypto 的 magic constant 文本命中；
2. ARM64 专用 crypto instruction。

相关源码：

~~~text
crates/trace-core/src/engine/query.rs
crates/trace-core/src/query/crypto_functions.rs
crates/trace-core/src/engine/crypto_functions.rs
~~~

### 4.2 专用指令信号为零

AES 指令识别只包含：

~~~rust
"aese" | "aesd" | "aesmc" | "aesimc"
~~~

软件实现不使用这些指令，因此：

~~~text
cryptoInsnCount = 0
~~~

### 4.3 magic constant 信号为零

当前 AES magic 主要包括：

~~~text
C66363A5
F87C7C84
637C777B
F26B6FC5
3001672B
FEFED7AB
~~~

scan_chunk 对每条原始 trace 文本执行 ASCII hex 子串搜索。它不是内存区域重组器，也没有：

- endianness 变体匹配；
- 跨行拼接；
- byte/word/vector load 归一化；
- S-box permutation fingerprint；
- Rcon 识别；
- key schedule 识别；
- block stride；
- round repetition；
- 数据扩散；
- 语义复算。

本样本中的表被拆分、重排或通过动态地址访问；Rcon 又不在当前 magic 列表。因此：

~~~text
magicHitCount = 0
~~~

### 4.4 评分 gate 无法打开

当前 gate：

~~~text
has_dedicated_crypto_instruction
OR
(distinct_magic_constants >= 3 AND one_algorithm_family)
~~~

本样本：

~~~text
has_dedicated_crypto_instruction = false
distinct_magic_constants         = 0
~~~

结果：

~~~text
functions_with_signals = 0
candidates             = []
~~~

这是覆盖范围不足，不是检测器分析后证明“不是 AES”。

### 4.5 当前 limitations 已经承认这一点，但 UI 不够醒目

engine/crypto_functions.rs 已写明：

~~~text
Dedicated crypto instructions are strong evidence but absent from software
(table-based) implementations.
~~~

建议当 candidates 为空时，不要只展示 No crypto found，而应返回和展示 coverage explanation：

~~~text
No hardware crypto instructions or configured magic constants were observed.
Software, bitsliced, table-driven, obfuscated, white-box, or pre-trace
implementations are not excluded.
~~~

## 5. v1 White-box 模块的主要问题

### 5.1 名称先入为主

whitebox_aes.rs 看到高频表访问就假设 White-box，会把普通 OpenSSL T-table AES、自研 S-box AES、bitsliced 周边表、解释器表甚至控制流 dispatcher 表误归类为白盒候选。

建议先改成中性概念：

~~~text
software_crypto
table_crypto
obfuscated_crypto
~~~

White-box 只是后续 classification 的一种状态，而不是扫描入口的前提。

### 5.2 I/O 角色依赖可打印性，结论不可靠

当前 pick_plaintext 优先最早的 printable 16-byte buffer。真实样本说明：

~~~text
printable 16-byte buffer = Safe_box_1234567
actual role              = wrapping key
~~~

角色必须依赖数据流：

- 被送入 key expansion 的缓冲应标为 key candidate；
- 在 block round 前被读入 state 的缓冲应标为 plaintext/ciphertext candidate；
- 每轮 XOR 使用的扩展区应标为 round-key schedule；
- block chaining 使用的 16 字节缓冲应标为 IV/previous block candidate；
- JNI 字符串只是来源注解，不等于角色。

### 5.3 read_count / distinct_addrs 不是通用轮数公式

当前：

~~~text
rounds = round(table.read_count / table.distinct_addrs)
~~~

在校准样本中：

~~~text
13328 / 1351 = 9.87 -> 10
~~~

这个结果可以作为候选信号，但不是密码学结构不变量：

- 多 block 会让 read_count 随 block 数增长；
- distinct_addrs 的增长取决于输入覆盖，而非轮数；
- 多次 AES 调用可能被聚合；
- 地址聚类可能把相邻表合并；
- 控制流 dispatcher、字符分类表、Base64 表也可能高频读取；
- trace 只记录执行路径，单条输入覆盖不等于完整表大小。

因此该比值不能单独把 16-byte block 判成 AES-128，更不能给 verified。

建议改为 function/window scoped round segmentation：

1. 先定位单个 block 的输入和输出边界；
2. 在该 slice 内按 round-key consumption、state write/read barrier 或重复 lookup site 分段；
3. 对多个 block 做 module-relative 序列对齐；
4. 只有重复结构稳定为 10/12/14 时才产生 round-count signal；
5. 最终仍由语义复算确认算法。

### 5.4 block_bytes 当前被硬设为 16

当前逻辑大意是：

~~~rust
let block_bytes = if !input_candidates.is_empty() { 16 } else { 0 };
~~~

这并没有从真实 I/O 周期测出 block size。任何连续大于 16 字节的模块外读取都可能触发 128-bit 分类。

应从以下证据联合估计：

- 输入状态每次消费多少连续字节；
- 输出状态每次提交多少连续字节；
- pointer stride；
- loop trip count 与总长度；
- 跨 block 重复的 load/store site；
- taint slice 中单个输出 block 的输入覆盖范围。

### 5.5 verified 的语义过强

当前 dominant table + I/O + 估计轮数可以得到高分并标记 verified。但这些只证明“像查表分组变换”，不能证明：

- 是 AES 而不是 SM4、自定义 SPN 或编码器；
- key 是哪个缓冲；
- encrypt 还是 decrypt；
- ECB/CBC/CTR/GCM；
- 是否有 padding；
- 是否为白盒。

建议等级语义：

| 等级 | 含义 |
|---|---|
| uncertain | 单个或弱信号，可能偶然 |
| candidate | 多个结构信号支持某算法家族 |
| related | 数据流和函数边界与算法假设一致，但未复算 |
| verified | 捕获输入/key/IV/output 后按假设复算，至少一个 block 完全一致 |
| verified_full | 完整 buffer 或所有观察 block 完全一致 |

### 5.6 DCA/BGE 建议不应默认出现

v1 默认建议 DCA/BGE 取 key。但当前样本 raw key 已直接存在，先做 DCA 会浪费大量时间。

建议 nextSteps 根据 key exposure 动态生成：

~~~text
raw key observed
    -> 直接导出 key、key schedule、Python reproducer

expanded schedule observed but raw key missing
    -> 尝试从首轮 round key 或逆 key schedule 恢复

no raw/schedule, key-dependent tables suspected
    -> 才建议 DCA/BGE/DFA
~~~

## 6. v2 目标与非目标

### 6.1 目标

- 单条动态 trace 能识别硬件、普通软件、查表、bitsliced、混淆软件和白盒候选；
- 输出算法、方向、模式、padding、key/IV/输入/输出候选及证据；
- 明确区分 candidate、related、verified；
- 结果能够从 GUI 跳转到精确 seq、地址和内存；
- MCP 与 GUI 消费同一个 core DTO；
- candidates 为空时解释覆盖范围，而不是暗示没有密码算法；
- 能为已验证结果生成最小 Python reproducer；
- 多 trace 能比较动态 key、相同执行骨架和模式变化。

### 6.2 非目标

- 不承诺从任意单条白盒 trace 自动恢复 key；
- 不把单个 magic 或高频表当证明；
- 不对未执行分支做结论；
- 不默认执行任意 native 代码；
- 不把 AI 文本解释当确定性证据；
- 不在 MCP 层重新实现 parser、taint 或 crypto 逻辑。

## 7. 建议的实现分类体系

### 7.1 ImplementationKind

~~~rust
enum CryptoImplementationKind {
    HardwareAccelerated,
    StandardSoftware,
    TableDrivenSoftware,
    BitslicedSoftware,
    ObfuscatedStandardSoftware,
    WhiteBoxCandidate,
    WhiteBoxVerified,
    Unknown,
}
~~~

本样本：

~~~text
ObfuscatedStandardSoftware
~~~

### 7.2 KeyExposure

~~~rust
enum KeyExposure {
    RawKeyObserved,
    ExpandedScheduleObserved,
    DerivedKeyObserved,
    KeyDependentTablesOnly,
    NotObserved,
    Unknown,
}
~~~

本样本两次 AES 都应为：

~~~text
RawKeyObserved
~~~

### 7.3 WhiteBoxStatus

~~~rust
enum WhiteBoxStatus {
    NotWhiteBox,
    Candidate,
    Related,
    Verified,
    Unknown,
}
~~~

建议规则：

~~~text
raw key observed
AND standard key schedule observed
    -> NotWhiteBox

no raw key
AND no standalone standard key schedule
AND stable key-dependent encoded tables
AND state encoding/decoding evidence
    -> Candidate/Related

additional static or multi-trace evidence proves key fused into tables
    -> Verified
~~~

仅“高频大表 + 十轮”最多得到 WhiteBox Candidate，不得直接 verified。

## 8. v2 检测流水线

### 8.1 Stage A：统一内存事件

先把 trace 中不同宽度和不同格式的内存访问归一化为 byte-addressed event：

~~~rust
struct NormalizedMemAccess {
    seq: u32,
    insn_addr: u64,
    module_offset: Option<u64>,
    address: u64,
    direction: ReadOrWrite,
    bytes: Vec<u8>,
    source_width: u8,
    function_id: Option<u32>,
}
~~~

必须正确处理：

- 1/2/4/8/16 字节访问；
- ldp/stp 的两个区域；
- q/v 寄存器读写；
- 小端拆分；
- 同一 seq 多个 mem_r/mem_w；
- GumTrace 和 unidbg 表达差异；
- 跨行连续内存重组；
- 地址覆盖与后写覆盖。

### 8.2 Stage B：多入口候选生成

保留现有硬件指令和 magic scanner，并新增：

- key-size 参数 0x80/0xc0/0x100，但只作弱信号；
- 16-byte 输入/输出 stride；
- total_length >> 4 形式的 block count；
- AES Rcon 序列；
- 176/208/240-byte round-key schedule 写入；
- 10/12/14 次稳定 round-key consumption；
- byte-indexed 256-entry lookup；
- T-table 的 endian/permutation fingerprint；
- repeated XOR/substitution/diffusion shape；
- 相同 module-relative site 跨 block 重复；
- encrypt/decrypt 输入输出依赖；
- JNI/OpenSSL/mbedTLS/BoringSSL 调用注解；
- mode chaining 特征；
- PKCS#7、zero padding、NoPadding 候选。

这些信号先产出 candidate，不要直接命名为 AES verified。

### 8.3 Stage C：函数和调用实例作用域

禁止把整条 trace 的所有表访问直接混在一起估计轮数。分析层级应为：

~~~text
trace
  -> function
     -> call instance
        -> block instance
           -> candidate rounds
~~~

同一个函数可以被不同 key、不同方向或不同模式调用。报告应保留 call_instance_id，避免把两套 key schedule 的 20 次扩展误写成 20-round AES。

控制流平坦化会让 call tree 不完美，因此还需要 module-relative PC repetition 和数据流窗口作为后备边界。

### 8.4 Stage D：数据角色识别

角色不能靠 ASCII/可打印性。使用 backward/forward dependency：

~~~text
buffer -> key expansion              => raw_key_candidate
buffer -> initial state load         => block_input_candidate
expanded buffer -> each round XOR    => round_key_schedule
buffer -> chaining XOR               => iv_or_previous_block
state -> final 16-byte store          => block_output_candidate
buffer -> Base64 input                => ciphertext_buffer
~~~

每个角色都输出：

~~~text
role
address
length
first_seq / last_seq
producer
consumers
taint_analysis_id
confidence
evidence
alternatives
~~~

### 8.5 Stage E：标准 AES key schedule 验证

当观察到 raw key 或 round-key buffer 时：

1. 按 128/192/256 bit 生成标准 AES schedule；
2. 与 trace 写入/读取的 round keys 比较；
3. 允许按 word endian、state layout 做已知变换；
4. 输出首个不匹配 round 和变换方式；
5. 完全一致时标记 key_schedule_verified。

这条信号比 S-box magic 强得多，也能区分标准软件 AES 与真正 key-fused white-box 表。

### 8.6 Stage F：语义复算

当得到 input、output、key，必要时得到 IV/counter：

- AES-ECB encrypt/decrypt；
- AES-CBC encrypt/decrypt；
- AES-CTR；
- 后续再扩展 GCM/CCM/XTS；
- 分开判断 cipher core 与 padding；
- 至少比较 1 个完整 block；
- 有完整 buffer 时比较全部 block。

建议 core 内部使用经过审计的 RustCrypto aes/cipher crate，或将最小 AES verifier 作为可选 feature。不要通过 shell 调 Python 完成产品逻辑；Python 只用于开发期交叉验证和 reproducer。

语义复算成功后：

~~~text
algorithm/mode/direction = verified
~~~

否则必须输出 mismatch，而不是悄悄降级：

~~~text
firstMismatchBlock
expectedHex
observedHex
candidateAssumptions
~~~

### 8.7 Stage G：模式识别

ECB：

- 无 IV；
- block 独立；
- 标准 ECB 复算匹配。

CBC：

- 存在 16-byte IV；
- encrypt 为 plaintext XOR previous_ciphertext；
- decrypt 为 AES-decrypt 后 XOR previous_ciphertext；
- 第一块使用 IV。

CTR：

- 有 counter block；
- AES 输出作为 keystream；
- ciphertext = plaintext XOR keystream；
- counter 递增结构。

GCM：

- CTR 数据路径；
- GHASH/PMULL 或软件有限域乘；
- tag 输出与 AAD/nonce 依赖。

模式结论不能仅凭“有没有第四个指针参数”决定，应由依赖和复算共同验证。

### 8.8 Stage H：白盒判定

White-box candidate 的必要信号建议包括：

- raw key 未出现；
- 标准 round-key schedule 未出现；
- 大型表内容随 key/构建实例改变；
- table output 直接构成 encoded state；
- 存在输入/输出编码或跨轮内部编码；
- 普通 AES key+block 复算无法在表边界直接对齐；
- 多 trace 中相同 key 的表稳定，不同 key 的表改变。

若只满足“表很多、十轮、16 字节”，应返回：

~~~text
implementationKind = TableDrivenSoftware
whiteboxStatus      = Unknown 或 Candidate
~~~

## 9. 证据评分建议

### 9.1 信号权重参考

| 信号 | 建议分值 | 说明 |
|---|---:|---|
| 硬件 AES 指令成组出现 | +55 | 强 AES 家族信号 |
| 标准 AES key schedule 完整匹配 | +60 | 强标准 AES 信号 |
| 单 block 语义复算完全一致 | +80 | 可直接打开 verified gate |
| 完整 buffer 全部匹配 | +20 | 升级 verified_full |
| Rcon 完整序列 | +25 | 需与 schedule/function scope 配合 |
| 稳定 10/12/14 round structure | +25 | 结构信号 |
| 16-byte block input/output stride | +15 | 分组密码信号 |
| S-box/T-table fingerprint | +20 | AES 候选信号 |
| raw 16/24/32-byte key 流入 schedule | +25 | key 角色信号 |
| 无 IV 且 ECB 全块复算 | +30 | mode 证明 |
| 单一 magic constant | -10 到 +5 | 易误报 |
| 只存在高频表 | +5 | 很弱 |
| raw key + 标准 schedule | White-box 强反证 | 不应计作 White-box 正分 |

### 9.2 gate

建议拆开三个 gate：

~~~text
algorithm_candidate_gate:
    hardware AES group
    OR schedule match
    OR multiple coherent structural signals

semantic_verified_gate:
    at least one block recomputes exactly

whitebox_candidate_gate:
    no raw key
    AND no standard standalone schedule
    AND key-dependent encoded table evidence
~~~

不要让同一个 gate 同时表达“这是 AES”和“这是白盒”。

### 9.3 候选与证明必须分开

示例：

~~~text
16-byte stride + ~10 repeated regions
    => AES-128 candidate

raw key + standard key schedule match
    => standard AES-128 related/high confidence

raw key + plaintext + output recompute exactly
    => AES-128 verified

large tables + no raw key + encoded state
    => white-box candidate
~~~

## 10. 建议 DTO

~~~rust
struct CryptoImplementationReport {
    analysis_id: String,
    algorithm: Option<String>,
    direction: Option<CryptoDirection>,
    mode: Option<String>,
    padding: Option<String>,
    implementation_kind: CryptoImplementationKind,
    whitebox_status: WhiteBoxStatus,
    key_exposure: KeyExposure,

    function: Option<FunctionRef>,
    call_instances: Vec<CryptoCallInstance>,
    block_size: Option<u32>,
    key_bits: Option<u32>,
    round_count: Option<u32>,
    block_count: Option<u32>,

    inputs: Vec<CryptoBufferRole>,
    outputs: Vec<CryptoBufferRole>,
    keys: Vec<CryptoBufferRole>,
    ivs: Vec<CryptoBufferRole>,
    schedules: Vec<KeyScheduleEvidence>,
    tables: Vec<TableRegion>,

    verification: Option<CryptoSemanticVerification>,
    assessment: EvidenceAssessment,
    evidence: Vec<CryptoEvidence>,
    rejected_hypotheses: Vec<RejectedHypothesis>,
    coverage: CryptoDetectorCoverage,
    limitations: Vec<String>,
    next_steps: Vec<String>,
}
~~~

语义验证：

~~~rust
struct CryptoSemanticVerification {
    status: VerificationStatus,
    algorithm: String,
    direction: CryptoDirection,
    mode: String,
    padding: Option<String>,
    blocks_checked: u32,
    bytes_checked: u64,
    all_matched: bool,
    first_mismatch_block: Option<u32>,
    expected_hex: Option<String>,
    observed_hex: Option<String>,
}
~~~

证据必须可审计：

~~~rust
struct CryptoEvidence {
    kind: String,
    seq: Option<u32>,
    line_number_1_based: Option<u32>,
    insn_address: Option<String>,
    module_offset: Option<String>,
    memory_address: Option<String>,
    bytes_hex: Option<String>,
    function_id: Option<u32>,
    analysis_id: Option<String>,
    rationale: String,
    strength: EvidenceStrength,
}
~~~

同时返回 seq 和 1-based line number，字段名必须明确，避免 taint 的 @LINE 与 start_seq 混用。

## 11. 建议代码拆分

### 11.1 core query

建议新增或重命名：

~~~text
crates/trace-core/src/query/software_crypto.rs
crates/trace-core/src/query/crypto_roles.rs
crates/trace-core/src/query/aes_schedule.rs
crates/trace-core/src/query/crypto_semantic_verify.rs
crates/trace-core/src/query/whitebox_classification.rs
~~~

whitebox_aes.rs 可暂时保留兼容层，但内部调用新的中性分析器，并把旧 DTO 标记 deprecated。

### 11.2 engine

~~~text
crates/trace-core/src/engine/software_crypto.rs
~~~

职责：

- 从 mem_accesses、dependency graph、call tree、register checkpoints 收集信号；
- 按 function/call/block 分窗；
- 调纯逻辑 detector；
- 必要时创建或引用 taint analysis；
- 保存 report 与 analysis_id；
- 支持后台任务、进度和取消。

### 11.3 与 analyze_crypto_functions 合并

不建议继续让 Detection、Functions、White-box 三个面板各自给互相矛盾的算法结论。

建议 analyze_crypto_functions 聚合：

~~~text
hardware instruction signals
+ magic signals
+ software structural signals
+ role/taint signals
+ semantic verification
~~~

每个候选函数返回 implementationKind 和 verification。White-box 作为 classification 字段或过滤器。

为了兼容：

- analyze_whitebox_crypto 暂时保留；
- 内部转调统一分析器并过滤 WhiteBoxStatus；
- 返回 deprecationNotice；
- GUI White-box 分段可以继续显示，但数据来自统一 report。

## 12. MCP 改进建议

### 12.1 新高层工具

建议：

~~~text
analyze_crypto_implementations
start_crypto_implementation_analysis
verify_crypto_hypothesis
generate_crypto_reproducer
~~~

参数示例：

~~~json
{
  "session_id": "...",
  "algorithm_hint": "aes",
  "function_addr": "libcryptoDD.so+0x18244",
  "start_seq": 75866,
  "end_seq": null,
  "include_taint": true,
  "semantic_verify": true,
  "max_candidates": 20,
  "max_evidence": 200
}
~~~

### 12.2 verify_crypto_hypothesis

允许 AI 或 GUI 提交明确假设：

~~~json
{
  "algorithm": "AES-128",
  "direction": "encrypt",
  "mode": "ECB",
  "padding": "PKCS7",
  "key": {
    "address": "0x...",
    "seq": 50316,
    "length": 16
  },
  "input": {
    "address": "0x...",
    "seq": 75866,
    "length": 464
  },
  "output": {
    "address": "0x...",
    "seq": 85518,
    "length": 464
  }
}
~~~

工具必须从 trace memory/index 读取字节，不信任客户端随意提供的 hex；客户端 hex 可以作为 expected 辅助字段。

### 12.3 零命中解释

analyze_crypto_functions 即使 candidates 为空也应返回：

~~~json
{
  "coverage": {
    "hardwareInstructionScan": true,
    "magicScan": true,
    "softwareStructureScan": false,
    "semanticVerification": false
  },
  "zeroResultExplanation": [
    "No dedicated crypto instructions were observed.",
    "No configured magic constants were observed.",
    "This does not exclude software/table-driven/obfuscated crypto.",
    "Run analyze_crypto_implementations or enable softwareStructureScan."
  ]
}
~~~

### 12.4 结构化输出

不要把大 JSON 再序列化成 MCP text 内的一层字符串。返回 structuredContent，并把大证据分页：

~~~text
get_crypto_evidence(analysis_id, cursor, limit)
get_crypto_blocks(analysis_id, cursor, limit)
~~~

分页必须绑定 analysis_id，不能读取 SessionState 中最后一次全局结果。

### 12.5 build/capability 可见性

运行中的 Trace UI 可能是旧 build，源码有 analyze_whitebox_crypto，但 tools/list 没有。

建议 initialize 或 health 工具返回：

~~~json
{
  "buildRevision": "...",
  "buildTime": "...",
  "schemaVersion": 2,
  "capabilities": {
    "softwareCrypto": true,
    "semanticCryptoVerify": true,
    "whiteboxClassification": true
  }
}
~~~

GUI 也显示 build revision。新增工具后仍需在文档强调：重建并重启应用/MCP 才生效。

## 13. GUI 建议

### 13.1 统一 Crypto Implementations 视图

每个候选显示：

~~~text
AES-128 / ECB / Encrypt
Verified: 29/29 blocks matched
Implementation: Obfuscated standard software
Key exposure: Raw key observed
White-box: No
Function: libcryptoDD.so+0x18244
~~~

### 13.2 证据分层

推荐四层：

1. Conclusion：算法、模式、方向、实现类型；
2. Verification：复算块数、首个/最后一个匹配；
3. Evidence：key schedule、Rcon、stride、taint、表；
4. Raw：精确 trace 行、寄存器、内存。

不要在第一层显示大量随机 dispatcher 常量。

### 13.3 明确标签

使用：

~~~text
Candidate
Related
Verified 1 block
Verified full buffer
White-box candidate
Not white-box
~~~

避免只显示 High，因为用户不知道 High 是“像 AES”还是“复算证明”。

### 13.4 一键复现

仅在 key/input/output 角色已 verified 时启用 Generate reproducer。输出：

- Python/PyCryptodome；
- key 来源与是否敏感提示；
- exact plaintext bytes，而不是重新序列化 JSON；
- mode、IV、padding；
- expected ciphertext hash；
- assertions。

不要默认把真实账号、token、手机号或 UUID 写进仓库 fixture；需要脱敏或只保存 hash/小块。

## 14. 回归测试方案

### 14.1 当前真实样本金标准

对主样本期望：

~~~text
algorithm                 AES-128
direction                 encrypt（正文调用）
mode                      ECB
padding                   PKCS#7（调用外层）
key                       KcIufueoThQliBgs
inputLength               452
paddedLength              464
blockCount                29
firstCipherBlock          ae2af887f83430372469ccbf4b3d5916
lastCipherBlock           98e234a6fb29bf721d7201f13f8952bc
ciphertextSha256          6d36a4ddf9a9fece32704646393248f499950f5bef6125fbe137e5e487dd6f95
implementationKind        ObfuscatedStandardSoftware
keyExposure               RawKeyObserved
whiteboxStatus            NotWhiteBox
verification              VerifiedFull
~~~

包装 key 调用单独期望：

~~~text
algorithm                 AES-128
direction                 decrypt
mode                      ECB
wrappingKey               Safe_box_1234567
wrappedInputLength        32
unpaddedOutput            KcIufueoThQliBgs
~~~

### 14.2 必须有的负样本

- 只有一个 AES magic 常量的普通计算；
- 高频 256-entry 字符映射表；
- Base64 编码表；
- CRC 表；
- 控制流 dispatcher 表；
- 16-byte memcpy 循环；
- 10 次重复但没有 AES 扩散的自定义循环；
- 16-byte key-like printable 字符串但未进入 key schedule；
- random lookup trace。

这些不得得到 AES verified 或 White-box verified。

### 14.3 实现覆盖样本

至少准备：

- ARMv8 AESE/AESMC AES；
- OpenSSL/BoringSSL 普通软件 AES；
- T-table AES；
- byte/S-box AES；
- bitsliced AES；
- 当前控制流混淆 AES；
- AES-CBC；
- AES-CTR；
- AES-GCM；
- SM4 软件查表；
- 一个真正的 white-box AES fixture；
- 一个 key-dependent table 但证据不足的 White-box Candidate fixture。

### 14.4 单元测试不要依赖 29 MiB 原始 trace

从真实 trace 导出最小归一化 fixture：

~~~text
tests/fixtures/crypto/
  aes128_key_schedule_events.json
  aes128_ecb_first_block_events.json
  aes128_ecb_block_stride.json
  lookup_table_false_positive.json
  whitebox_candidate_events.json
~~~

每个 fixture 保存：

- module-relative PC；
- normalized mem events；
- 必要寄存器值；
- function/call/block 边界；
- expected role 和 verdict；
- 来源 trace hash 与抽取脚本版本。

原始 trace 可作为本地/CI 可选 integration test，不建议默认提交大型敏感日志。

### 14.5 多样本测试

动态参数样本应验证：

- wrapped key 改变时能得到不同业务 key；
- 函数/module-relative skeleton 仍能对齐；
- detector 不把某个业务 key 字符串硬编码为算法特征；
- 若解出的字符串不是合法 AES key 长度，工具返回 role candidate，不擅自截断或补零；
- 相同执行流程的不同输入仍能独立语义复算。

## 15. 性能建议

### 15.1 分阶段，避免默认全量 taint

推荐：

1. 便宜扫描：指令、stride、Rcon、schedule 写入模式；
2. function/call 聚类；
3. 只对 Top N 候选做局部 taint；
4. 只对角色齐全的候选做语义复算；
5. 大 trace 走后台任务并可取消。

### 15.2 缓存键

至少包含：

~~~text
trace content fingerprint
detector schema version
algorithm hint
function/seq scope
semantic verify flag
taint data/control mode
~~~

升级检测逻辑后必须使旧 cache 失效，避免 GUI 继续显示旧 White-box verified。

### 15.3 证据上限

表访问可能数万条。report 只保留摘要和代表证据：

- first/last；
- 每轮一个 landmark；
- 每 block 一个 output；
- top table regions；
- mismatch 附近窗口。

完整证据通过 analysis_id 分页。

## 16. 实施顺序

### P0：正确性

- [ ] 修改文案和 DTO，不再把当前样本称为已验证白盒；
- [ ] 修复 Safe_box_1234567 的角色；
- [ ] 增加 ImplementationKind、KeyExposure、WhiteBoxStatus；
- [ ] 识别 16-byte block stride 和 29 block；
- [ ] 实现 AES-128 key schedule 验证；
- [ ] 实现 AES-ECB 单 block/全 buffer 语义复算；
- [ ] verified gate 改为复算一致；
- [ ] 零命中返回 coverage explanation；
- [ ] 添加当前样本金标准测试和负样本。

### P1：统一能力

- [ ] 新建中性的 software_crypto analyzer；
- [ ] 按 function/call/block 分窗；
- [ ] 角色识别接入局部 backward/forward taint；
- [ ] analyze_crypto_functions 聚合软件结构信号；
- [ ] analyze_whitebox_crypto 改为兼容过滤器；
- [ ] MCP structuredContent 和 analysis_id 分页；
- [ ] GUI 统一 Crypto Implementations 视图；
- [ ] 生成 Python reproducer。

### P2：模式和实现覆盖

- [ ] CBC/CTR/GCM 依赖和复算；
- [ ] AES-192/AES-256 schedule；
- [ ] bitsliced 检测；
- [ ] SM4/DES 结构识别；
- [ ] 多 trace call/block 对齐；
- [ ] 真白盒多样本 classification；
- [ ] DCA/BGE/DFA 建议按 KeyExposure 条件生成。

### P3：研究增强

- [x] table fingerprint 对 endian/permutation/切分鲁棒；
- [x] 自动推断内部 state layout；
- [x] 跨版本 module-relative 函数聚类；
- [x] 控制流平坦化 dispatcher 降噪；
- [x] 静态 SO 表抽取与动态 trace 联合（已实现 ELF32/ELF64 `PT_LOAD` 映射、架构/Build ID 提取、静态文件偏移与动态 module-relative 表读取逐项核对、归一化 fingerprint 对照；匹配 Build ID `9f5dd9b43d965da8f77693f3be5a8522bfac32e7` 的真实 AArch64 `libcryptoDD.so` 已通过两份 AES trace 验收，分别为 1639/1639 和 1351/1351 条目精确一致）；
- [x] white-box encoding boundary 识别（模块外字节输入→稳定 stride 查表、查表值→模块外同宽写出的短窗口动态 Candidate；均要求 ≥16 匹配和 ≥16 外部地址，不打开 verification gate）。

## 17. 验收清单

### 17.1 当前样本

- [ ] 旧 Detection 零命中时明确说明不排除 software AES；
- [ ] software analyzer 定位 +0x1e698 key schedule；
- [ ] 检出 w2/w4=0x80；
- [ ] 检出十轮 schedule，而不是把总计 20 次写成 AES-20；
- [ ] Safe_box_1234567 标为 wrapping key；
- [ ] KcIufueoThQliBgs 标为正文 key；
- [ ] 定位 +0x18244 正文入口；
- [ ] 检出 0x1d0 / 29 blocks / 0x10 stride；
- [ ] 定位 +0x18940 block output；
- [ ] 29/29 blocks 复算一致；
- [ ] 输出 AES-128/ECB/PKCS#7；
- [ ] implementationKind 为 ObfuscatedStandardSoftware；
- [ ] whiteboxStatus 为 NotWhiteBox；
- [ ] 报告可跳到关键 trace 行；
- [ ] 能生成与现有 Python 脚本等价的 reproducer。

### 17.2 误报控制

- [ ] Base64/CRC/dispatcher 大表不报 AES verified；
- [ ] printable 16-byte 字符串不自动标 plaintext；
- [ ] 16-byte memcpy 不报分组密码；
- [ ] 单 magic 不开 verified gate；
- [ ] 轮数比值异常时不给具体 AES 变体；
- [ ] 没有 raw key 时不伪造 key；
- [ ] 没有复算时 UI 明确显示 Candidate/Related。

### 17.3 MCP

- [ ] tools/list 能看到新工具；
- [ ] health 返回 build revision 和 capabilities；
- [ ] 大结果使用 structuredContent；
- [ ] 证据分页绑定 analysis_id；
- [ ] 任务有进度、取消和缓存；
- [ ] 0-based seq 与 1-based line 字段明确；
- [ ] 重启后 analysis 仍可审计；
- [ ] 旧 analyze_whitebox_crypto 有兼容说明。

## 18. v1 已实现状态记录

以下是 2026-07-19 v1 已有接线，后续 AI 不要重复造一套平行基础设施：

- crates/trace-core/src/query/whitebox_aes.rs：DTO、I/O 候选、表聚类、轮数估计、分类、评分；
- crates/trace-core/src/engine/whitebox_aes.rs：从 mem_accesses 收集访问并调用纯逻辑；
- SessionState.whitebox_cache；
- trace-mcp 的 analyze_whitebox_crypto；
- Tauri analyze_whitebox_crypto command；
- 前端 WhiteBoxPanel 和 CryptoPanel White-box 分段；
- analysis-store 保存；
- 基础单元测试。

旧实现的校准结果曾写为：

~~~text
Safe_box_1234567 -> plaintext
13328 / 1351 -> 10 rounds
AES-128 -> verified white-box
~~~

复核后的正确解释：

~~~text
Safe_box_1234567 -> wrapping key
13328 / 1351     -> table-activity heuristic only
AES-128          -> 由 key schedule + block structure + 完整语义复算证明
white-box        -> false for this sample
~~~

## 19. 后续 AI 开工说明

后续开发 AI 在改代码前应依次完成：

1. 阅读本文；
2. 阅读 PROJECT_STATE.md 和 TAINT_ANALYSIS_CASE_STUDY.md；
3. 对照 query/whitebox_aes.rs、engine/whitebox_aes.rs；
4. 对照 query/crypto_functions.rs、engine/crypto_functions.rs、engine/query.rs；
5. 运行现有测试，记录 baseline；
6. 先写当前样本和负样本测试；
7. 再修改分类与 verified gate；
8. 最后接 MCP/GUI，避免展示层先于 core 产生第二套语义。

实现时必须坚持：

~~~text
结构信号产生候选；
数据流确定角色；
标准 schedule 提升算法置信度；
语义复算给 verified；
白盒属性单独判定。
~~~

不要把“看起来像 AES”“可以推断 AES”“复算证明 AES”“证明是白盒”混成同一个 High confidence。
