import { useRef, useEffect, type ReactNode } from "react";

interface ContextMenuProps {
  x: number;
  y: number;
  onClose: () => void;
  children: ReactNode;
  minWidth?: number;
}

/** 统一风格的右键上下文菜单 */
export default function ContextMenu({ x, y, onClose, children, minWidth = 180 }: ContextMenuProps) {
  const ref = useRef<HTMLDivElement>(null);

  useEffect(() => {
    const handler = (e: MouseEvent) => {
      if (ref.current && !ref.current.contains(e.target as Node)) onClose();
    };
    document.addEventListener("mousedown", handler);
    return () => document.removeEventListener("mousedown", handler);
  }, [onClose]);

  // 防止菜单超出视口
  const style: React.CSSProperties = {
    position: "fixed",
    left: Math.min(x, window.innerWidth - minWidth - 8),
    top: Math.min(y, window.innerHeight - 100),
    background: "var(--bg-dialog)",
    border: "1px solid var(--border-color)",
    borderRadius: 6,
    boxShadow: "0 4px 16px rgba(0,0,0,0.4)",
    zIndex: 10000,
    padding: "4px 0",
    minWidth,
  };

  return <div ref={ref} style={style}>{children}</div>;
}

/** 右键菜单项 */
export function ContextMenuItem({ label, shortcut, disabled, onClick, checked }: {
  label: ReactNode;
  shortcut?: string;
  disabled?: boolean;
  onClick?: () => void;
  checked?: boolean;
}) {
  return (
    <div
      onClick={() => { if (!disabled && onClick) onClick(); }}
      onMouseEnter={(e) => { if (!disabled) (e.currentTarget as HTMLElement).style.background = "var(--bg-selected)"; }}
      onMouseLeave={(e) => { (e.currentTarget as HTMLElement).style.background = "transparent"; }}
      style={{
        display: "flex",
        alignItems: "center",
        padding: "6px 12px",
        fontSize: 12,
        color: disabled ? "var(--text-secondary)" : "var(--text-primary)",
        cursor: disabled ? "default" : "pointer",
        whiteSpace: "nowrap",
        gap: 8,
      }}
    >
      {checked !== undefined && (
        <span style={{ width: 16, flexShrink: 0, textAlign: "center", fontSize: 11 }}>
          {checked ? "✓" : ""}
        </span>
      )}
      <span style={{ flex: 1 }}>{label}</span>
      {shortcut && (
        <span style={{ marginLeft: 16, fontSize: 11, color: "var(--text-secondary)" }}>{shortcut}</span>
      )}
    </div>
  );
}

/** 右键菜单分隔线 */
export function ContextMenuSeparator() {
  return <div style={{ height: 1, background: "var(--border-color)", margin: "4px 0" }} />;
}
