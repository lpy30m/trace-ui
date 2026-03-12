# macOS 适配设计

## 目标

让 trace-ui 在 macOS 上提供符合平台习惯的用户体验：原生红绿灯窗口按钮 + Cmd 快捷键映射。

## 适配范围

### 1. 平台检测工具

新增 `src-web/src/utils/platform.ts`：
- `isMac: boolean` — 通过 `navigator.platform` 检测
- `modKey(key: string): string` — macOS 返回 `"⌘+key"`，其他返回 `"Ctrl+key"`
- `isModKey(e: KeyboardEvent): boolean` — macOS 检查 `e.metaKey`，其他检查 `e.ctrlKey`

### 2. 窗口控制按钮（WindowControls.tsx）

**macOS 样式：**
- 位置：左上角
- 外观：三个 12px 圆点（关闭红 #ff5f57、最小化黄 #febc2e、最大化绿 #28c840）
- hover 时显示对应图标（×、−、+）
- 窗口失焦时三个圆点变为统一灰色

**Windows/Linux：** 保持现有右上角 SVG 按钮不变。

### 3. 标题栏布局

**TitleBar.tsx：**
- macOS：`[红绿灯] [File][View][Analysis]... [拖动区域] [搜索框] [拖动区域]`
- Windows：`[File][View][Analysis]... [拖动区域] [搜索框] [拖动区域] [最小化][最大化][关闭]`

**FloatingWindowFrame.tsx：**
- macOS：`[红绿灯] [标题] [titleBarExtra] [📌]`
- Windows：`[标题] [titleBarExtra] [📌] [最小化][最大化][关闭]`

### 4. 快捷键适配

**逻辑层（App.tsx、TraceTable.tsx）：**
- 所有 `e.ctrlKey` 检查改为 `isModKey(e)`（已有 `e.metaKey` 的保持不变）

**显示层（TitleBar.tsx、TraceTable.tsx 菜单项）：**
- `"Ctrl+O"` → `modKey("O")`
- `"Ctrl+F"` → `modKey("F")`
- `"Ctrl+/"` → `modKey("/")`
- `"Alt+1~5"` → macOS 显示 `"⌥+1~5"`（Alt 在 macOS 上是 Option/⌥）
- tooltip 文本同理替换

## 不做的事

- macOS 原生菜单栏集成（工作量大，跨平台 App 常用自定义菜单）
- 系统主题检测（当前只有暗色主题）
- Touch Bar 支持（已被 Apple 淘汰）
