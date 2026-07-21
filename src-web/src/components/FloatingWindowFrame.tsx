import { useState, useCallback, useEffect } from "react";
import { getCurrentWindow } from "@tauri-apps/api/window";
import { LogicalSize, LogicalPosition } from "@tauri-apps/api/dpi";
import WindowControls from "./WindowControls";
import ContextMenu, { ContextMenuItem } from "./ContextMenu";
import { isMac } from "../utils/platform";

interface FloatingWindowFrameProps {
  title: React.ReactNode;
  children: React.ReactNode;
  onClose?: () => void;
  /** 标题栏右侧额外控件（位于 pin 按钮左侧） */
  titleBarExtra?: React.ReactNode;
  /** 窗口最大宽度限制（逻辑像素）。设置后最大化时宽度不超过此值 */
  maxWidth?: number;
}

export default function FloatingWindowFrame({ title, children, onClose, titleBarExtra, maxWidth }: FloatingWindowFrameProps) {
  // 置顶锁定
  const [isPinned, setIsPinned] = useState(false);
  const [ctxMenu, setCtxMenu] = useState<{ x: number; y: number } | null>(null);

  const togglePin = useCallback(() => {
    setIsPinned(prev => {
      const next = !prev;
      getCurrentWindow().setAlwaysOnTop(next);
      return next;
    });
  }, []);

  // 限制窗口最大宽度：使用原生 setMaxSize 约束
  useEffect(() => {
    if (!maxWidth) return;
    const win = getCurrentWindow();
    win.setMaxSize(new LogicalSize(maxWidth, 99999));
    return () => { win.setMaxSize(null); };
  }, [maxWidth]);

  // 受限最大化：宽度不超过 maxWidth，高度铺满屏幕，居中
  const constrainedMaximize = useCallback(async () => {
    const win = getCurrentWindow();
    const screenW = window.screen.availWidth;
    const screenH = window.screen.availHeight;
    const w = maxWidth ? Math.min(maxWidth, screenW) : screenW;
    const x = Math.round((screenW - w) / 2);
    await win.setSize(new LogicalSize(w, screenH));
    await win.setPosition(new LogicalPosition(x, 0));
  }, [maxWidth]);

  return (
    <div style={{
      height: "100vh",
      display: "flex",
      flexDirection: "column",
      background: "var(--bg-primary)",
      color: "var(--text-primary)",
      borderRadius: 8,
      overflow: "hidden",
    }}>
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
        {isMac && <WindowControls onMaximize={maxWidth ? constrainedMaximize : undefined} />}
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
        {!isMac && <WindowControls onMaximize={maxWidth ? constrainedMaximize : undefined} />}
      </div>

      {/* 右键上下文菜单 */}
      {ctxMenu && (
        <ContextMenu x={ctxMenu.x} y={ctxMenu.y} onClose={() => setCtxMenu(null)} minWidth={160}>
          <ContextMenuItem
            label="Always on Top"
            checked={isPinned}
            onClick={() => { togglePin(); setCtxMenu(null); }}
          />
        </ContextMenu>
      )}

      {/* 内容区域 */}
      {children}
    </div>
  );
}
