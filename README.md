# Trace UI

[![License: Personal Use](https://img.shields.io/badge/License-Personal%20Use-red.svg)](LICENSE)
[![Platform](https://img.shields.io/badge/Platform-Windows%20|%20macOS%20|%20Linux-green.svg)]()
[![Built with Tauri](https://img.shields.io/badge/Built%20with-Tauri%202-orange.svg)](https://tauri.app)

高性能 ARM64 执行 trace 可视化分析工具。基于 Tauri 2 + React 构建的桌面应用，专为安全研究员设计，支持千万行或亿行级大规模 trace 的流畅浏览、函数调用树折叠、反向污点追踪、密码算法识别、内存/寄存器实时查看等功能。内置 MCP Server，可与 Claude Code、Cursor 等 AI 工具无缝集成，让 AI 直接分析你的 trace。

![image-20260323181452253](docs/images/README/image-20260323181452253.png)

> 支持 [GumTrace](https://github.com/lidongyooo/GumTrace)（基于 Frida Stalker 的**真机 trace 采集工具**，支持 Android/iOS）和 [unidbg](https://github.com/zhkl0228/unidbg)（Android native 模拟执行框架）两种 ARM64 指令级 trace 日志格式，打开文件时自动检测。

## 特性亮点

- **大规模 Trace 浏览** — 虚拟滚动 + mmap 零拷贝，千万行 trace 流畅浏览，内存占用恒定。索引构建完成后自动缓存，再次打开同一文件秒级加载
- **反向污点追踪** — 从寄存器或内存地址反向切片追踪数据依赖，支持数据依赖/控制依赖独立开关，过滤和高亮两种查看模式，结果可导出为 JSON/TXT
- **数据依赖 DAG 图** — 从指定寄存器/内存地址构建依赖关系有向无环图，支持 C 风格表达式重建，直观展现数据流传播路径
- **密码算法识别** — 自动扫描 trace 中的密码算法常量模式，覆盖 AES、DES、SM3、MD5、SHA、CRC32、TEA、RC4 等 28 种魔数模式
- **Crypto Materials 索引** — 统一索引 key、password、salt、IV、nonce、counter、明文/密文、digest/MAC、AAD 和 tag，并对可观察的 AES、MD5/SHA、HMAC、PBKDF2 做确定性复算
- **Frida 16 Hook 与捕获回导** — 可套用常见 OpenSSL/CommonCrypto 配方，或按导出符号/module-relative offset 生成 ARM64 Interceptor/Stalker 脚本；寄存器快照覆盖 X0-X28、FP/LR/SP/PC 与可用的 NZCV，用户手动执行后可导回 JSON/NDJSON，索引密码材料并生成 angr state seed；应用不会 attach、spawn、load 或执行 Hook
- **Frida OLLVM Dispatcher Atlas** — 从 OLLVM 报告一次生成最多 64 个 ranked dispatcher `startOffset` 的 Frida 16.x 手动脚本；用户自行运行后导入 `ollvm-dispatcher-hit`，按 capture session、线程、flow 和连续 hit sequence 汇总 dispatcher 节点、状态寄存器分布、相邻 transition 与候选执行路径。legacy 捕获使用 idle-gap 启发式分 flow，所有结果保持 Candidate/Related。
- **IDA / OLLVM 动态桥接** — 按 module offset 构建动态 CFG、排序 dispatcher/opaque branch 候选，重建 dispatcher state-register 轨迹，并生成可手动运行的 IDAPython 注释/着色/双向 JSON 脚本
- **angr / OLLVM 静动态对账** — 生成由用户手动运行的 Python/angr 脚本，将 CFGFast/CFGEmulated 静态后继与动态 trace 边对账，执行 blank、trace-register 与 exact-offset Frida seed 候选探测；dispatcher-entry seed 可有界探索下一 dispatcher/循环/退出并回导候选 state-register 值
- **OLLVM 多运行稳定性矩阵** — 对比 2–16 条受控 trace 的 dispatcher、状态寄存器和分支结果；可为每条运行绑定 exact ELF，SHA-256 不一致时拒绝错位比较；alternate outcome 明确反对全局 opaque
- **OLLVM 跨版本结构候选映射** — 为 2–8 个不同 ELF 版本分别绑定 trace scope、version ID 和 exact SHA-256，允许模块重命名与 offset 迁移，按归一化操作序列、动态 CFG 形状和 state-register 行为寻找 dispatcher 对应候选并标记歧义
- **调用树与函数分析** — 自动识别 BL/BLR/RET 构建函数调用树，支持折叠/展开、函数重命名、函数列表聚合查看
- **字符串提取** — 自动从内存写操作中提取运行时字符串，支持搜索、XRefs 交叉引用、Hex/Text 详情查看
- **DEF/USE 箭头连线** — 点击寄存器名可视化数据定义与使用关系，快速追踪值在指令间的传播路径
- **寄存器 & 内存面板** — 实时查看任意指令处的寄存器值和内存 Hex Dump，支持内存访问历史追溯
- **AI 辅助分析（MCP）** — 内置 MCP Server，可与 Claude Code、Cursor 等 AI 工具集成，覆盖浏览、搜索、污点、密码材料、Frida 脚本、IDA/angr/OLLVM、跨 trace 对比和证据持久化
- **14 种编辑器主题** — 内置 Monokai、Dracula、Nord、Catppuccin、Gruvbox、Tokyo Night、Solarized、GitHub Light、High Contrast 等主题，一键切换
- **沉浸式交互体验** — 双击文本全局高亮同名标记、搜索结果关键词高亮、Minimap 缩略导航
- **多窗口浮动面板** — 搜索、内存、字符串、依赖树、密码学扫描等面板可独立浮出，支持多文件并行分析
- **高亮与注释** — IDA 风格快捷键（`;` 注释、`Alt+1~5` 高亮），5 色高亮、删除线、隐藏行、行内注释，状态持久化到本地

## AI 辅助分析（MCP）

Trace UI 内置 MCP（Model Context Protocol）Server，将完整的 trace 分析引擎以标准化接口暴露给 AI 工具。AI 可以直接打开 trace 文件、执行污点分析、查询函数调用树、读取内存和寄存器——无需人工手动操作界面。

### 支持的 AI 工具

任何支持 MCP 协议的 AI 客户端均可接入，包括 Claude Code、Claude Desktop、Cursor、VS Code Copilot 等。

![image-20260323184523831](docs/images/README/image-20260323184523831.png)

### 两种接入方式

**方式一：独立 CLI（推荐）**

将编译好的 `trace-cli` 注册为 MCP Server，AI 客户端自动管理进程生命周期：

```bash
# 注册到 Claude Code
claude mcp add trace-ui -- /path/to/trace-cli

# 注册到 Claude Desktop（编辑 claude_desktop_config.json）
{
  "mcpServers": {
    "trace-ui": { "command": "/path/to/trace-cli" }
  }
}
```

**方式二：桌面应用内置 HTTP 服务**

在桌面应用中启动 MCP Server（默认端口 19821），与 GUI 共享同一引擎和会话状态：

```bash
claude mcp add trace-ui --transport http http://127.0.0.1:19821/mcp
```

### 提示词示例

```
打开 /path/to/trace.log，帮我分析字符串：

1. 提取所有运行时字符串，搜索包含 "http" "token" "key" "sign" 的字符串
2. 对找到的敏感字符串，用 search_instructions 搜索其地址附近的指令，找出是哪些指令在读写这些字符串
3. 对最关键的字符串（比如包含 URL 或 token 的），用 taint_analysis 追踪其写入位置的数据来源
```

### MCP 工具一览

| 类别 | 工具 |
|------|------|
| 会话 | `open_trace`、`close_trace` |
| 浏览与搜索 | `get_trace_lines`、`get_memory`、`get_strings`、`search_instructions`、`search_value` |
| 污点分析 | `taint_analysis`、`forward_taint_analysis`、`get_tainted_lines` |
| 结构与对比 | `get_call_tree`、`analyze_function`、`compare_traces` |
| 密码分析 | `analyze_crypto_functions`、`analyze_crypto_implementations`、`analyze_crypto_materials`、`analyze_known_digest` |
| 多 trace 参数隔离 | `compare_crypto_material_traces`、`compare_crypto_table_traces` |
| Frida 16 脚本与回导 | `list_frida_hook_recipes`、`generate_frida_hook`、`generate_frida_ollvm_dispatcher_hook`、`inspect_frida_capture`、`analyze_frida_crypto_materials`、`analyze_frida_ollvm_dispatcher_capture`、`generate_angr_state_seed`（用户手动执行 Hook） |
| IDA / angr / OLLVM | `analyze_ollvm`、`compare_ollvm_traces`、`map_ollvm_versions`、`generate_ida_ollvm_script`、`inspect_ida_annotations`、`generate_angr_ollvm_script`、`inspect_angr_ollvm_results` |
| 证据与编排 | `list_analyses`、`get_analysis`、`compare_analyses`、`auto_investigate` |

> 详细的工具参数和分析套路请参考仓库内的 [trace-analysis MCP 工具表](.claude/skills/trace-analysis/references/mcp-tools.md) 与 [实战案例](.claude/skills/trace-analysis/references/playbook-examples.md)。

## 功能详解

### 大规模 Trace 浏览

基于 mmap 内存映射 + 虚拟滚动实现，仅渲染可见区域的数十行，无论 trace 文件有多大，内存占用和渲染性能保持恒定。首次打开 2400 万行 trace 索引构建约 15 秒，构建完成后自动缓存，再次打开同一文件秒级加载。

支持文本搜索和正则表达式搜索（`/pattern/` 语法），搜索结果列表可点击跳转，支持导航历史前进/后退（macOS: `Ctrl+⌘+←/→`，Windows: `Ctrl+Alt+←/→`）。

右侧 Minimap 缩略图可快速拖动定位。

### 反向污点追踪（Taint Analysis）

![image-20260323181624233](docs/images/README/image-20260323181624233.png)

![image-20260323181712173](docs/images/README/image-20260323181712173.png)

核心分析功能。指定一个或多个寄存器/内存地址作为污点源，工具会自动反向追踪所有数据依赖链，标记出影响该值的全部指令。

**控制依赖开关：** 污点配置对话框中新增 Dependencies 选项，可独立控制数据依赖和控制依赖的追踪。启用控制依赖后，污点分析会追踪通过条件分支等控制流传播的依赖关系，提供更全面的分析结果。

**三态按钮交互：** Taint 按钮根据当前状态呈现不同外观和行为：

- **默认灰色**（无污点分析）— 点击打开污点配置对话框
- **绿色按钮**（已选中寄存器）— 点击直接启动污点分析，自动填充选中寄存器和当前行号
- **橙色菜单**（污点分析激活）— 展开菜单提供 Tainted Only / Show All (Dimmed) / Go to Source / Re-configure / Clear 等操作

**两种查看模式：**

- **过滤模式（Filter）** — 仅显示与污点相关的行，大幅缩减视图

![image-20260323181825242](docs/images/README/image-20260323181825242.png)

- **高亮模式（Highlight）** — 显示全部行，污点相关行以颜色高亮

![image-20260323182153588](docs/images/README/image-20260323182153588.png)

污点追踪结果可导出为 TXT 或 JSON 格式。

### 数据依赖 DAG 图

从指定指令的寄存器或内存地址出发，构建数据依赖关系的有向无环图（DAG），直观展现该值是如何被计算出来的。

**两种视图模式：**

- **表达式树视图** — 以 C 风格表达式呈现依赖关系，快速理解计算逻辑
- **DAG 图视图** — 标准依赖关系图，节点为指令，边为数据流向

支持配置最大节点数限制，防止复杂依赖图爆炸。可从污点分析结果直接构建依赖树，将污点切片结果可视化。

![image-20260323182345732](docs/images/README/image-20260323182345732.png)

### 密码算法识别

自动扫描 trace 执行过程中出现的密码算法魔数常量，覆盖 28 种魔数模式：

- **对称加密**：AES、AES_SBOX、DES、DES1、DES_SBOX、Blowfish、Twofish、Threefish、Camellia、Camellia_IV、ChaCha20/Salsa20、TEA、RC4、RC6、Serpent
- **哈希函数**：MD5、SHA1、SHA256、SHA256_K2、SHA512_IV、SM3、Whirlpool_T0
- **校验和**：CRC32、CRC32C
- **其他**：HMAC、Poly1305、APLib

扫描结果显示匹配的算法名称、魔数值、出现位置的指令地址和汇编内容。结果支持缓存，避免重复扫描。

![image-20260323182741064](docs/images/README/image-20260323182741064.png)

### Crypto Materials、Frida 16、IDA 与 angr / OLLVM

Crypto 面板新增四条面向 native 逆向的工作流：

- **Materials**：从调用 ABI、hexdump 和语义复算中汇总 key/input/output/IV/nonce/salt/AAD/tag 等材料。只有确定性复算结果会进入 Verified；仅凭参数位置推断的角色保持 Related。
- **Frida Hook**：可从 Crypto Function/Material 或 OLLVM branch/condition-source/dispatcher-entry 候选预填 module-relative offset，也可套用 OpenSSL/BoringSSL、Apple CommonCrypto 的 MD5/SHA、HMAC、PBKDF2、EVP、CCCrypt 审计配方，生成 `trace-ui/frida-hook-v1` 的 Frida 16.x JavaScript。参数 buffer 仍限定 X0-X7；开启寄存器捕获时记录 X0-X28、FP/LR/SP/PC 和运行时可提供的 NZCV。支持固定长度、长度寄存器、返回时 `*Xn` 输出长度、backtrace 和有界 Stalker。长度指针读取失败会输出 `readError`，不会回退读取最大缓冲区。用户手动执行并保存结果；应用不会 attach、spawn、load 或执行脚本。
- **Frida OLLVM Dispatcher Atlas**：`generate_frida_ollvm_dispatcher_hook` 从当前 OLLVM report 的 ranked dispatcher 候选生成一个有界 Frida 16.x 脚本（默认 12 个目标、50,000 hits），脚本只在精确入口命中时发送完整 ARM64 GPR、运行时 `target - moduleBase`、`captureSessionId`、`flowId` 与 `hitSequence`。用户自行 attach/spawn/load/run 并保存 JSON/NDJSON 后，`analyze_frida_ollvm_dispatcher_capture` 只接受与当前报告 `startOffset` 精确匹配的事件，构建节点、相邻 transition、state-register value distribution、state changes 和 flow paths；不同 session/线程/flow 或缺失连续序号不会连边。module basename + offset 不能证明 exact binary，legacy flow 也只是 idle-gap 启发式。
- **IDA / OLLVM**：按 ASLR 稳定的 module offset 生成动态 basic blocks/edges，排序控制流平坦化 dispatcher 与 opaque branch 候选，并从寄存器 checkpoint 重建 dispatcher block-entry 状态值及变化边。IDAPython 会写入候选、状态变化和 branch register snapshot 注释。动态 trace 只覆盖实际执行路径，因此这些结论始终是候选证据，不代表完整静态 CFG 或自动去混淆。
- **多运行 OLLVM**：可为 2–16 个已打开 trace 分别填写 node/range，并为选中的运行绑定 exact ELF。默认要求所有 ELF 的 SHA-256 完全一致；不同哈希会直接拒绝按 module offset 对齐。报告同时保存 Build ID（若 ELF 提供）和身份状态。`alternate-outcomes-observed` 是反对“全局 opaque”的直接动态证据；`stable-single-outcome-across-runs` 仍不能证明未执行路径不可达，ELF 一致也不会把结构证据升级为 Verified。
- **跨版本 OLLVM**：独立的 Cross-version 页面和 `map_ollvm_versions` MCP 工具接受 2–8 个版本；每个版本必须提供唯一 version ID、独立 trace scope 与 exact AArch64 ELF，并要求 SHA-256 两两不同。baseline dispatcher 会在其他版本的动态 blocks 中按最长公共归一化操作序列、终止操作、出入度、edge kind、dispatcher role 和 state-register 行为匹配 top-N 候选；前两名分差不超过 5 时明确标记 ambiguous。模块名和 offset 可以变化，但 source offset、concrete state value、Frida capture 与 angr seed 绝不能直接套到目标版本，必须为每个版本重新生成 exact-offset Hook/seed。全部结果保持 Candidate/Related。
- **angr / OLLVM**：基于同一份动态报告生成独立 Python 脚本，用户在自己的 angr 环境中对 exact ELF 手动运行。默认 CFGFast，可选 CFGEmulated 并自动回退；结果对账 static successor、unobserved static successor 与 dynamic-only successor。每个 opaque 候选会做 blank-state 和 trace-register probe；首个 trace-register seed 以及 exact-offset Frida seed 还可继续做有界 symbolic flow exploration，默认深度 8、每个 probe 最多 32 个状态，并记录 loop/depth-limit/state-limit/dead-end/external-target、constraint 数量及末尾 4 条有界约束。Frida capture offset 必须精确匹配 branch、已记录的 condition-source 或 dispatcher startOffset，否则拒绝生成。dispatcher-entry seed 会在下一 dispatcher、循环、外部目标、死路或配置边界停止，并回导目标 state-register 的 `concrete`、最多两个 `symbolic` alternatives 或 `unavailable`；这只是 Candidate/Related 执行流线索，不代表自动去平坦化、完整 CFG 恢复或真实入口可达。

IDA 脚本中的 `export_ida_annotations()` 可手动导出 `trace-ui/ida-ollvm-v1` JSON，再导回 Trace UI 显示 IDA 名称与注释。

angr 脚本输出 `trace-ui/angr-ollvm-v1` JSON，并记录 exact ELF 的 SHA-256、mapped base、angr 版本和 CFG 类型。Trace UI 只生成/保存脚本和导入结果，不安装或自动执行 angr。

Frida 捕获回导支持 JSON object/array、标准 send envelope、NDJSON 和带前缀的 CLI 日志。选中一次捕获后可生成 `trace-ui/angr-state-seed-v1` Python，填充 X0-X7、X8-X28、可选 SP/LR、可用的 NZCV 和已捕获内存；module 内指针会按 mapped base 重定位，heap/stack 地址仍属于单次进程证据。NZCV 会优先按 AArch64 packed flags 写入 angr，必要时回退到 N/Z/C/V 单独寄存器，仍需人工确认捕获点语义一致。

专用 dispatcher 捕获事件使用同一 `trace-ui/frida-hook-v1` 协议，事件类型为 `ollvm-dispatcher-hit`；`dispatcherOffset` 与 `target/moduleBase` 会交叉校验。该 atlas 是执行样本的结构化索引，不是完整 CFG、自动去平坦化或函数调用边界证明。

捕获文件还可按 `callId` 建立独立密码材料索引：显式 label 可提示 key/password/salt/IV/nonce/AAD/tag/input/output/digest/MAC，若同一次调用内存在完整 byteArray，则会对 MD5/SHA、HMAC 与受限迭代次数的 PBKDF2 做确定性重算。只有重算匹配才打开 Verified gate；标签和方向推断保持 Related。

### 调用树与函数分析

![image-20260323183009369](docs/images/README/image-20260323183009369.png)

自动分析 `BL`/`BLR`（函数调用）和 `RET`（返回）指令，构建完整的函数调用树。左侧面板以树形结构展示调用层级，双击可跳转到对应函数入口。

在 trace 表格中，已识别的函数调用区域会显示折叠控件，点击可折叠/展开整个函数体，快速跳过不关心的代码区域。

**函数列表聚合：** 按函数名分组查看所有调用，快速了解哪些函数被调用了多少次、在哪些位置被调用。

![image-20260323183208679](docs/images/README/image-20260323183208679.png)

**函数重命名：** 右键点击函数树节点，选择 "Rename" 即可为该函数设置自定义别名，方便在大规模 trace 分析中标记和识别关键函数。别名自动持久化到本地存储。

![image-20260323183050556](docs/images/README/image-20260323183050556.png)

### 字符串提取（Strings View）

![image-20260323183328188](docs/images/README/image-20260323183328188.png)

自动从 trace 执行过程中的内存写操作提取运行时生成的字符串。通过增量内存镜像追踪字符串的创建与覆盖，还原程序实际使用的字符串内容。

**触发方式：**

- **手动扫描**：通过菜单 `Analysis → Scan Strings` 触发
- **自动扫描**：在 `Settings → Preferences → Analysis` 中勾选 "Scan strings during index build"，索引构建时自动提取

**面板功能：**

字符串面板作为独立标签页集成在 TabPanel 中（与 Memory、Registers 面板同级），支持浮出为独立窗口。

- **搜索框**：实时搜索字符串内容
- **Min Length 滑块**：调整最小字符串长度（2-20 字节），过滤噪声
- 虚拟滚动列表显示：Seq（序列号）、Address（内存地址）、Content（内容）、Enc（编码 ASCII/UTF-8）、Len（长度）、XRefs（交叉引用数）

**右键菜单：**

- **View Detail** — 弹出详情窗口，支持 Hex/Text 两种视图，Hex 视图支持拖选字节和复制
- **View in Memory** — 跳转到内存面板查看该字符串的原始内存内容
- **Show XRefs** — 打开独立窗口，列出所有读取该字符串的指令，点击可跳转到 trace 对应行
- **Copy String / Copy Address** — 复制字符串内容或地址到剪贴板

![image-20260323183419059](docs/images/README/image-20260323183419059.png)

### DEF/USE 箭头连线

![image-20260323183601112](docs/images/README/image-20260323183601112.png)

在 trace 表格中点击任意指令行的寄存器名，工具会自动查询该寄存器的 DEF/USE 链：向上箭头指向该寄存器值的**定义处**（DEF，最近一次写入该寄存器的指令），向下箭头指向所有**使用处**（USE，后续读取该寄存器值的指令）。

- 定义行（DEF）以绿色背景高亮
- 使用行（USE）以蓝色背景高亮
- 点击箭头标签可直接跳转到对应行
- 再次点击同一寄存器取消显示

配合污点追踪使用，可以快速追踪单个寄存器值在指令间的传播路径。

### 寄存器面板

![image-20260323183636873](docs/images/README/image-20260323183636873.png)选中任意指令行时，左下方寄存器面板实时显示该指令处的完整寄存器状态（x0-x30、sp、pc、lr、nzcv)。

- 红色色标记：当前指令修改（DEF）的寄存器
- 蓝色标记：当前指令读取（USE）的寄存器
- 双击寄存器值可快速复制

### 内存面板

![image-20260323183754861](docs/images/README/image-20260323183754861.png)

以 16 字节对齐的 Hex Dump 格式展示 trace 执行过程中的内存状态。

当选中包含内存操作的指令时，面板自动滚动到对应地址。右侧历史记录列出该地址的所有读写操作，点击可跳转到对应的 trace 行。

### 多窗口与浮动面板

![image-20260323184213863](docs/images/README/image-20260323184213863.png)

搜索、内存、内存访问列表、字符串、污点状态等面板支持从主窗口"浮出"为独立窗口。浮动窗口与主窗口实时同步状态。

支持同时打开多个 trace 文件，每个文件拥有独立的污点追踪状态，互不干扰。

### 高亮与注释

![image-20260323183936921](docs/images/README/image-20260323183936921.png)

- **颜色高亮**：5 种颜色（红/黄/绿/蓝/青），支持快捷键 Alt+1~5
- **删除线**：标记已分析或不相关的行
- **隐藏行**：批量隐藏选中行，隐藏位置显示指示器，可随时恢复
- **行内注释**：按 `;` 键为当前行添加自由文本注释

所有高亮和注释状态自动持久化到本地存储，关闭后重新打开不丢失。

### 缓存管理

![image-20260323184238835](docs/images/README/image-20260323184238835.png)

提供完整的缓存生命周期管理，解决大文件场景下的磁盘空间问题。

**访问方式：**

- **菜单**：`Settings → Open Cache Directory`（在文件管理器中打开）、`Settings → Clear Cache...`（清空所有缓存）
- **偏好设置**：`Settings → Preferences → Cache` 标签页

**Cache 标签页功能：**

- **自定义缓存目录**：通过输入框或 Browse 按钮设置缓存存储路径，留空使用默认路径，下次构建索引时生效
- **缓存占用信息**：实时显示当前缓存目录占用的磁盘空间
- **Clear Cache 按钮**：一键清空所有缓存文件

## 技术架构

```
┌─────────────────────────────────────────────────────┐
│                  Trace UI 桌面应用                     │
│              React 19 + TypeScript + Vite              │
│                                                        │
│   TraceTable(Canvas) │ CallTree │ Panels │ MCP 状态    │
│                      │          │        │             │
│──────────────── Tauri IPC (invoke) ────────────────────│
│                                                        │
│                  src-tauri (Tauri 2)                    │
│            Tauri Commands ─ 薄胶水层                    │
│                      │                                 │
├──────────────────────┼─────────────────────────────────┤
│                      │                                 │
│  ┌───────────────────┼───────────────────────┐         │
│  │            trace-core                     │         │
│  │  分析引擎 · 索引 · 污点 · 调用树 · 内存    │         │
│  └───────────────────┬───────────────────────┘         │
│                      │                                 │
│  ┌──────────┐  ┌─────┴──────┐  ┌──────────────┐       │
│  │trace-parser│  │ trace-mcp  │  │  trace-cli   │       │
│  │格式解析    │  │ MCP Server │  │ 独立 MCP 入口 │       │
│  │unidbg     │  │ HTTP/SSE   │  │ Stdio 传输    │       │
│  │GumTrace   │  │ 10 个工具  │  │              │       │
│  └──────────┘  └────────────┘  └──────────────┘       │
└───────────────────────────────────────────────────────┘
```

项目采用 Rust Workspace 结构，划分为 4 个 crate：

| Crate | 职责 |
|-------|------|
| `trace-parser` | Trace 日志格式解析（unidbg / GumTrace），自动格式检测 |
| `trace-core` | 核心分析引擎，包含索引构建、污点切片、调用树、内存追踪、寄存器检查点、字符串提取、密码算法扫描等全部分析能力 |
| `trace-mcp` | MCP 协议层，将 trace-core 的能力通过 10 个 MCP 工具暴露，支持 HTTP/SSE 和 Stdio 两种传输 |
| `trace-cli` | 独立 MCP Server 入口，供 AI 客户端直接调用 |

**后端**：通过 mmap 零拷贝映射 trace 文件，一遍扫描生成依赖图、调用树、内存访问索引和寄存器检查点，全部通过 bincode 持久化缓存。污点切片采用 BFS 反向传播算法，在预构建的依赖图上完成。

**前端**：基于 @tanstack/react-virtual 实现虚拟滚动，Canvas 原生渲染实现 ARM64 语法高亮和 DEF→USE 箭头连线。多会话隔离设计，每个打开的文件拥有独立的分析状态。

## 支持的 Trace 格式

工具同时支持两种 ARM64 指令级 trace 日志格式，打开文件时自动检测，无需手动选择。

### GumTrace 格式

由 [GumTrace](https://github.com/lidongyooo/GumTrace) 输出（基于 Frida Stalker 的真机 trace 工具），每行格式形如：

```
[libmetasec_ov.so] 0x79842a6d14!0x9ad14 mrs x1, nzcv; x1=0x79842a6d08 -> x1=0x60000000
```

包含模块名、绝对地址!偏移地址、反汇编指令及寄存器值。支持函数调用注解（`call func` / `call jni func`）、参数、返回值和 hexdump 等附加信息。

### Unidbg 格式

由 [unidbg](https://github.com/zhkl0228/unidbg) 输出，每行格式形如：

```
[07:23:05 407][libtiny.so 0x6f8814] [ec8e5fb8] 0x406f8814: "ldr w12, [x23, #-8]!" ; mem[READ] abs=0x41688658 x23=0x41688660 => w12=0x16e80 x23=0x41688658
```

包含时间戳、PC 地址、SO 偏移、机器码、反汇编指令及寄存器值。

#### Unidbg格式适配说明

unidbg的日志格式我增加了计算所有内存读取和写入指令的目标绝对地址，所以大家在使用前需要对uinidbg中打印这些信息，否则格式不太一样可能造成bug，修改点位于文件：`src/main/java/com/github/unidbg/AssemblyCodeDumper.java`的`hook`方法中，这样在内存读写的指令时打印的格式是这样的：

- 内存读

```
[07:23:05 407][libtiny.so 0x6fc114] [295a69b8] 0x406fc114: "ldr w9, [x17, w9, uxtw #2]" ; mem[READ] abs=0x416885f0 x17=0x416885d4 w9=0x7 => w9=0x88bd0
```

- 内存写

```
[07:23:05 408][libtiny.so 0x6f87ac] [69692838] 0x406f87ac: "strb w9, [x11, x8]" ; mem[WRITE] abs=0x410c8bd0 w9=0x63 x11=0x41040000 x8=0x88bd0 => w9=0x63
```

> abs是内存的绝对地址
>

`AssemblyCodeDumper.java`文件我放到项目里了，大家替换到自己的unidbg中即可

## 构建

### 环境要求

- [Rust](https://rustup.rs/) 1.75+
- [Node.js](https://nodejs.org/) 18+
- [Tauri CLI](https://tauri.app/)：`cargo install tauri-cli`

### 开发模式

```bash
./build.sh dev
```

Vite HMR + Rust 热重载，修改前端代码即时生效。

### Release 构建

```bash
./build.sh release
```

构建 release 版本的桌面应用和 trace-cli（MCP Server），产物位于 `target/release/`。

### 仅构建 trace-cli（MCP Server）

```bash
./build.sh cli
```

仅编译 `trace-cli` 二进制，用于 AI 客户端的 MCP 集成。产物位于 `target/release/trace-cli`。

### 打包安装程序

```bash
./build.sh bundle
```

生成平台对应的安装包（Windows `.msi` / macOS `.dmg` / Linux `.deb`）。

推送到 `main` 会触发 `.github/workflows/macos.yml`，分别构建并上传 Apple Silicon (`aarch64-apple-darwin`) 与 Intel (`x86_64-apple-darwin`) DMG artifact。

## 快捷键

> macOS 下 `Ctrl` 替换为 `⌘`

| 快捷键 | 功能 |
|--------|------|
| `Ctrl+O` | 打开 trace 文件 |
| `Ctrl+F` | 打开/聚焦搜索面板 |
| `Ctrl+C` | 复制选中行 |
| `Ctrl+/` | 隐藏选中行 |
| `Ctrl+⌘+←` / `Ctrl+Alt+←` | 导航后退（macOS / Windows） |
| `Ctrl+⌘+→` / `Ctrl+Alt+→` | 导航前进（macOS / Windows） |
| `Ctrl+Enter` | 保存注释 / 确认对话框 |
| `G` | 跳转到指定行号/内存地址 |
| `;` | 为当前行添加注释 |
| `Alt+1~5` | 为选中行设置颜色高亮（红/黄/绿/蓝/青） |
| `Alt+-` | 为选中行添加/移除删除线 |
| `Alt+0` | 重置选中行高亮 |
| `Shift+Click` | 范围选择 |
| `Ctrl+Click` | 多选 |
| `Esc` | 关闭浮窗 / 取消选择 |

## 常见问题

**Q: 首次打开大文件很慢？**

首次打开需要等待构建索引，构建完成后会自动缓存。再次打开同一文件可秒级加载。

**Q: 如何清除缓存？**

通过菜单 `Settings → Clear Cache...` 清空所有缓存，或在 `Settings → Preferences → Cache` 中管理缓存目录和查看占用空间。也可通过 `Settings → Open Cache Directory` 在文件管理器中手动管理。

**Q: 支持哪些平台？**

Windows、macOS、Linux 均支持。macOS 和 Windows 已适配原生窗口控制风格。

**Q: macOS 下载后无法打开，提示"已损坏"或被阻止运行？**

从 GitHub Release 下载的 `.dmg` 文件会被 macOS Gatekeeper 标记隔离属性。由于应用未经 Apple 公证，需要手动移除隔离标记：

```bash
xattr -cr "/Applications/Trace UI.app"
```

或者在首次打开时，右键点击 app → 选择"打开" → 确认打开。Apple Silicon (ARM64) 的 Mac 对此限制更严格，建议优先使用 `xattr -cr` 方式。

**Q: 能否支持其他 trace 格式？**

当前支持 GumTrace 和 unidbg 两种格式。如需支持其他格式，欢迎提交 Issue 讨论。

## 致谢

- [GumTrace](https://github.com/lidongyooo/GumTrace) — 本项目官方指定的真机 trace 采集工具，基于 Frida Gum (Stalker) 引擎的 ARM64 动态指令追踪工具，支持 Android 和 iOS 平台。支持**指令级追踪**、**寄存器快照** 、**内存访问追踪**、**函数调用拦截**、**系统调用追踪**、**Android JNI 追踪** 、**iOS ObjC 追踪**。GumTrace 与 Trace UI 深度适配，是在真机环境下获取高质量 trace 日志的推荐方案。感谢 [@lidongyooo](https://github.com/lidongyooo) 的开源贡献！
- [unidbg](https://github.com/zhkl0228/unidbg) — 优秀的 Android native 模拟执行框架，本项目同时支持其输出的 trace 日志格式。

## 许可证

[Personal Use License](LICENSE)

> **协议变更说明**：本项目自 v0.5.4 版本起（2026-03-20）从 GPL-3.0 变更为 Personal Use License。v0.5.4 之前的版本仍适用 GPL-3.0 协议。新协议仅允许个人学习和研究使用，商业使用需获得作者书面授权，详见 [LICENSE](LICENSE)。



## 联系作者

备注：github

<img src="docs/images/README/9255d35e99315231fee3bcd01587e3d9.jpg" alt="9255d35e99315231fee3bcd01587e3d9" style="zoom: 33%;" />
