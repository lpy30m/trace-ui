# macOS 适配 实现计划

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** 让 trace-ui 在 macOS 上显示原生红绿灯窗口按钮 + 使用 Cmd 快捷键。

**Architecture:** 添加平台检测工具模块，根据 `isMac` 条件切换 WindowControls 样式和位置、快捷键检测逻辑和显示文本。所有修改在前端 React 层，不涉及 Rust 后端。

**Tech Stack:** React 19 + TypeScript 5

---

### Task 1: 平台检测工具模块

**Files:**
- Create: `src-web/src/utils/platform.ts`

**Step 1: 创建平台检测模块**

```typescript
// macOS 平台检测
export const isMac = /Mac|iPhone|iPad|iPod/.test(navigator.platform);

// 修饰键显示文本：macOS 用 ⌘，其他用 Ctrl
export function modKey(key: string): string {
  return isMac ? `⌘+${key}` : `Ctrl+${key}`;
}

// Alt 键显示文本：macOS 用 ⌥，其他用 Alt
export function altKey(key: string): string {
  return isMac ? `⌥+${key}` : `Alt+${key}`;
}

// 检查事件中修饰键是否按下：macOS 检查 metaKey，其他检查 ctrlKey
export function isModKey(e: KeyboardEvent | React.KeyboardEvent): boolean {
  return isMac ? e.metaKey : e.ctrlKey;
}
```

**Step 2: 验证文件无 TypeScript 错误**

```bash
cd E:/android_reverse/trace-ui/src-web && npx tsc --noEmit 2>&1 | head -20
```

Expected: 无与 platform.ts 相关的错误。

**Step 3: 提交**

```bash
cd E:/android_reverse/trace-ui && git add src-web/src/utils/platform.ts && git commit -m "feat: add platform detection utils (isMac, modKey, isModKey)"
```

---

### Task 2: macOS 红绿灯窗口控制按钮

**Files:**
- Modify: `src-web/src/components/WindowControls.tsx`

**Step 1: 重写 WindowControls 支持双平台**

将整个文件替换为以下内容：

```typescript
import { getCurrentWindow } from "@tauri-apps/api/window";
import { useCallback, useState, useEffect } from "react";
import { isMac } from "../utils/platform";

// macOS 红绿灯颜色
const MAC_COLORS = {
  close: { bg: "#ff5f57", icon: "#4d0000" },
  minimize: { bg: "#febc2e", icon: "#5a3e00" },
  maximize: { bg: "#28c840", icon: "#003a00" },
  inactive: "#3d3d3d",
};

function MacTrafficLights() {
  const [hovered, setHovered] = useState(false);
  const [focused, setFocused] = useState(true);

  useEffect(() => {
    const onFocus = () => setFocused(true);
    const onBlur = () => setFocused(false);
    window.addEventListener("focus", onFocus);
    window.addEventListener("blur", onBlur);
    return () => { window.removeEventListener("focus", onFocus); window.removeEventListener("blur", onBlur); };
  }, []);

  const handleClose = useCallback(() => getCurrentWindow().close(), []);
  const handleMinimize = useCallback(() => getCurrentWindow().minimize(), []);
  const handleMaximize = useCallback(() => getCurrentWindow().toggleMaximize(), []);

  const buttons = [
    { id: "close", action: handleClose, icon: "×" },
    { id: "minimize", action: handleMinimize, icon: "−" },
    { id: "maximize", action: handleMaximize, icon: "+" },
  ] as const;

  return (
    <div
      style={{ display: "flex", gap: 8, alignItems: "center", padding: "0 8px", flexShrink: 0 }}
      onMouseEnter={() => setHovered(true)}
      onMouseLeave={() => setHovered(false)}
    >
      {buttons.map(({ id, action, icon }) => (
        <div
          key={id}
          onClick={action}
          style={{
            width: 12,
            height: 12,
            borderRadius: "50%",
            background: focused
              ? MAC_COLORS[id as keyof typeof MAC_COLORS] !== undefined
                ? (MAC_COLORS[id as keyof typeof MAC_COLORS] as { bg: string }).bg
                : MAC_COLORS.inactive
              : MAC_COLORS.inactive,
            display: "flex",
            alignItems: "center",
            justifyContent: "center",
            cursor: "pointer",
            fontSize: 9,
            fontWeight: 700,
            lineHeight: 1,
            color: hovered
              ? (MAC_COLORS[id as keyof typeof MAC_COLORS] as { icon: string }).icon
              : "transparent",
          }}
        >
          {icon}
        </div>
      ))}
    </div>
  );
}

function WinControls() {
  const [hovered, setHovered] = useState<string | null>(null);

  const handleMinimize = useCallback(() => getCurrentWindow().minimize(), []);
  const handleToggleMaximize = useCallback(() => getCurrentWindow().toggleMaximize(), []);
  const handleClose = useCallback(() => getCurrentWindow().close(), []);

  const btnStyle = (id: string): React.CSSProperties => ({
    display: "inline-flex",
    alignItems: "center",
    justifyContent: "center",
    width: 46,
    height: "100%",
    border: "none",
    background:
      hovered === id
        ? id === "close"
          ? "#e81123"
          : "var(--bg-selected)"
        : "transparent",
    color:
      hovered === "close" && id === "close"
        ? "#ffffff"
        : "var(--text-secondary)",
    cursor: "pointer",
    padding: 0,
  });

  return (
    <div style={{ display: "flex", height: "100%", flexShrink: 0 }}>
      <button
        style={btnStyle("minimize")}
        onClick={handleMinimize}
        onMouseEnter={() => setHovered("minimize")}
        onMouseLeave={() => setHovered(null)}
        aria-label="Minimize"
      >
        <svg width="10" height="1" viewBox="0 0 10 1">
          <rect fill="currentColor" width="10" height="1" />
        </svg>
      </button>
      <button
        style={btnStyle("maximize")}
        onClick={handleToggleMaximize}
        onMouseEnter={() => setHovered("maximize")}
        onMouseLeave={() => setHovered(null)}
        aria-label="Maximize"
      >
        <svg width="10" height="10" viewBox="0 0 10 10">
          <rect fill="none" stroke="currentColor" strokeWidth="1" x="0.5" y="0.5" width="9" height="9" />
        </svg>
      </button>
      <button
        style={btnStyle("close")}
        onClick={handleClose}
        onMouseEnter={() => setHovered("close")}
        onMouseLeave={() => setHovered(null)}
        aria-label="Close"
      >
        <svg width="10" height="10" viewBox="0 0 10 10">
          <line x1="0" y1="0" x2="10" y2="10" stroke="currentColor" strokeWidth="1.2" />
          <line x1="10" y1="0" x2="0" y2="10" stroke="currentColor" strokeWidth="1.2" />
        </svg>
      </button>
    </div>
  );
}

// 导出：macOS 用红绿灯（左侧），Windows/Linux 用方块按钮（右侧）
export default function WindowControls() {
  return isMac ? <MacTrafficLights /> : <WinControls />;
}
```

**Step 2: 验证无 TypeScript 错误**

```bash
cd E:/android_reverse/trace-ui/src-web && npx tsc --noEmit 2>&1 | head -20
```

**Step 3: 提交**

```bash
cd E:/android_reverse/trace-ui && git add src-web/src/components/WindowControls.tsx && git commit -m "feat: macOS traffic light window controls"
```

---

### Task 3: TitleBar 布局适配

**Files:**
- Modify: `src-web/src/components/TitleBar.tsx`

**Step 1: 导入 platform 工具**

在文件顶部的 import 区域添加：

```typescript
import { isMac, modKey, altKey } from "../utils/platform";
```

**Step 2: macOS 时 WindowControls 移到左侧**

找到标题栏容器（第 86-421 行），做以下修改：

1. 在第 98 行 `{/* File 下拉菜单 */}` **之前**添加：
```typescript
        {isMac && <WindowControls />}
```

2. 将第 420 行的 `<WindowControls />` 改为：
```typescript
        {!isMac && <WindowControls />}
```

**Step 3: 替换快捷键显示文本**

做以下替换（使用 `modKey()` 和 `altKey()`）：

- 第 101 行：`shortcut="Ctrl+O"` → `shortcut={modKey("O")}`
- 第 255 行：`shortcut="Ctrl+/"` → `shortcut={modKey("/")}`
- 第 325 行：`title="Back (Ctrl+Alt+←)"` → `title={`Back (${isMac ? "⌘+⌥+←" : "Ctrl+Alt+←"})`}`
- 第 330 行：`title="Forward (Ctrl+Alt+→)"` → `title={`Forward (${isMac ? "⌘+⌥+→" : "Ctrl+Alt+→"})`}`

替换 HIGHLIGHT_COLORS 数组中的 shortcut（第 42-46 行）：
```typescript
const HIGHLIGHT_COLORS: { key: string; label: string; color: string; shortcut: () => string }[] = [
  { key: "red", label: "Red", color: "rgba(220,60,60,0.20)", shortcut: () => altKey("1") },
  { key: "yellow", label: "Yellow", color: "rgba(220,200,50,0.20)", shortcut: () => altKey("2") },
  { key: "green", label: "Green", color: "rgba(80,200,120,0.20)", shortcut: () => altKey("3") },
  { key: "blue", label: "Blue", color: "rgba(60,120,220,0.20)", shortcut: () => altKey("4") },
  { key: "cyan", label: "Cyan", color: "rgba(60,200,200,0.20)", shortcut: () => altKey("5") },
];
```

同步更新所有使用 `hc.shortcut` 的地方改为 `hc.shortcut()`（第 230 行附近）。

替换第 241 行 `Alt+-` 和第 250 行 `Alt+0` 的显示文本：
- `Alt+-` → `{isMac ? "⌥+-" : "Alt+-"}`
- `Alt+0` → `{isMac ? "⌥+0" : "Alt+0"}`

**Step 4: 验证无 TypeScript 错误**

```bash
cd E:/android_reverse/trace-ui/src-web && npx tsc --noEmit 2>&1 | head -20
```

**Step 5: 提交**

```bash
cd E:/android_reverse/trace-ui && git add src-web/src/components/TitleBar.tsx && git commit -m "feat: TitleBar macOS layout and shortcut labels"
```

---

### Task 4: FloatingWindowFrame 布局适配

**Files:**
- Modify: `src-web/src/components/FloatingWindowFrame.tsx`

**Step 1: 导入 isMac**

```typescript
import { isMac } from "../utils/platform";
```

**Step 2: macOS 时 WindowControls 移到左侧**

将第 47-88 行的标题栏内容区改为：

```typescript
      {/* 顶部标题栏 */}
      <div
        data-tauri-drag-region
        onContextMenu={(e) => {
          e.preventDefault();
          setCtxMenu({ x: e.clientX, y: e.clientY });
        }}
        style={{
          display: "flex",
          alignItems: "center",
          padding: isMac ? "0 8px 0 0" : "0 0 0 12px",
          height: 36,
          background: "var(--bg-secondary)",
          borderBottom: "1px solid var(--border-color)",
          flexShrink: 0,
          fontSize: 13,
          fontWeight: 600,
          gap: 8,
        }}
      >
        {isMac && <WindowControls />}
        <span
          data-tauri-drag-region
          style={{ flex: 1, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}
        >
          {title}
        </span>
        {titleBarExtra}
        <span
          onClick={togglePin}
          title={isPinned ? "Unpin (disable always on top)" : "Pin (always on top)"}
          style={{
            cursor: "pointer",
            fontSize: 14,
            color: isPinned ? "var(--btn-primary)" : "var(--text-secondary)",
            transform: isPinned ? "rotate(-45deg)" : "none",
            transition: "transform 0.2s, color 0.2s",
            userSelect: "none",
            lineHeight: 1,
          }}
        >{"\uD83D\uDCCC"}</span>
        {!isMac && <WindowControls />}
      </div>
```

**Step 3: 验证无 TypeScript 错误**

```bash
cd E:/android_reverse/trace-ui/src-web && npx tsc --noEmit 2>&1 | head -20
```

**Step 4: 提交**

```bash
cd E:/android_reverse/trace-ui && git add src-web/src/components/FloatingWindowFrame.tsx && git commit -m "feat: FloatingWindowFrame macOS traffic lights on left"
```

---

### Task 5: App.tsx 全局快捷键适配

**Files:**
- Modify: `src-web/src/App.tsx`

**Step 1: 导入 isModKey**

在文件顶部添加：

```typescript
import { isModKey } from "./utils/platform";
```

**Step 2: 替换全局快捷键中的 ctrlKey 检查**

在第 545-606 行的全局快捷键 handler 中：

- 第 548 行：`e.ctrlKey && e.altKey && e.key === "ArrowLeft"` → `isModKey(e) && e.altKey && e.key === "ArrowLeft"`
- 第 551 行：`e.ctrlKey && e.altKey && e.key === "ArrowRight"` → `isModKey(e) && e.altKey && e.key === "ArrowRight"`
- 第 554 行：`e.ctrlKey && !e.altKey && !e.shiftKey && e.key === "o"` → `isModKey(e) && !e.altKey && !e.shiftKey && e.key === "o"`
- 第 571 行：`e.ctrlKey && !e.altKey && !e.shiftKey && e.key === "f"` → `isModKey(e) && !e.altKey && !e.shiftKey && e.key === "f"`
- 第 606 行的 `!e.ctrlKey && !e.altKey` 检查保持不变（这是排除修饰键的检查）

**Step 3: 验证无 TypeScript 错误**

```bash
cd E:/android_reverse/trace-ui/src-web && npx tsc --noEmit 2>&1 | head -20
```

**Step 4: 提交**

```bash
cd E:/android_reverse/trace-ui && git add src-web/src/App.tsx && git commit -m "feat: App global shortcuts support Cmd on macOS"
```

---

### Task 6: TraceTable.tsx 快捷键显示文本

**Files:**
- Modify: `src-web/src/components/TraceTable.tsx`

**Step 1: 导入 altKey**

```typescript
import { altKey } from "../utils/platform";
```

**Step 2: 替换 HIGHLIGHT_COLORS 快捷键显示**

将第 17-23 行的 HIGHLIGHT_COLORS 改为使用 `altKey()`：

```typescript
const HIGHLIGHT_COLORS: { key: string; label: string; color: string; shortcut: () => string }[] = [
  { key: "red", label: "Red", color: "rgba(220,60,60,0.20)", shortcut: () => altKey("1") },
  { key: "yellow", label: "Yellow", color: "rgba(220,200,50,0.20)", shortcut: () => altKey("2") },
  { key: "green", label: "Green", color: "rgba(80,200,120,0.20)", shortcut: () => altKey("3") },
  { key: "blue", label: "Blue", color: "rgba(60,120,220,0.20)", shortcut: () => altKey("4") },
  { key: "cyan", label: "Cyan", color: "rgba(60,200,200,0.20)", shortcut: () => altKey("5") },
];
```

同步更新所有使用 `hc.shortcut` 的地方改为 `hc.shortcut()`。

**Step 3: 验证无 TypeScript 错误**

```bash
cd E:/android_reverse/trace-ui/src-web && npx tsc --noEmit 2>&1 | head -20
```

**Step 4: 提交**

```bash
cd E:/android_reverse/trace-ui && git add src-web/src/components/TraceTable.tsx && git commit -m "feat: TraceTable shortcut labels adapt to macOS"
```

---

### Task 7: 验证前端构建

**Step 1: 完整前端构建**

```bash
cd E:/android_reverse/trace-ui/src-web && npm run build
```

Expected: 构建成功，无错误。

**Step 2: 如有编译错误则修复并提交**

```bash
cd E:/android_reverse/trace-ui && git add -A && git commit -m "fix: resolve build errors from macOS adaptation"
```
