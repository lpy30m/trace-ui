import { useState, useRef, useEffect, useCallback } from "react";
import type { McpStatusInfo } from "../hooks/useMcpStatus";

interface McpIndicatorProps {
  mcpStatus: McpStatusInfo;
  onStart: (port?: number) => Promise<McpStatusInfo>;
  onStop: () => Promise<McpStatusInfo>;
  configuredPort: number | null;
}

const DOT_COLORS: Record<string, string> = {
  running: "#4ade80",
  stopped: "var(--text-tertiary)",
  error: "#f87171",
};

export default function McpIndicator({ mcpStatus, onStart, onStop, configuredPort }: McpIndicatorProps) {
  const [open, setOpen] = useState(false);
  const [copied, setCopied] = useState(false);
  const containerRef = useRef<HTMLDivElement>(null);

  // 点击外部关闭
  useEffect(() => {
    if (!open) return;
    const handler = (e: MouseEvent) => {
      if (containerRef.current && !containerRef.current.contains(e.target as Node)) {
        setOpen(false);
      }
    };
    document.addEventListener("mousedown", handler);
    return () => document.removeEventListener("mousedown", handler);
  }, [open]);

  const handleCopy = useCallback(async () => {
    if (mcpStatus.url) {
      await navigator.clipboard.writeText(mcpStatus.url);
      setCopied(true);
      setTimeout(() => setCopied(false), 1500);
    }
  }, [mcpStatus.url]);

  const handleRestart = useCallback(() => {
    onStart(configuredPort ?? undefined).catch(console.error);
  }, [onStart, configuredPort]);

  const handleStop = useCallback(() => {
    onStop().catch(console.error);
  }, [onStop]);

  const dotColor = DOT_COLORS[mcpStatus.status] ?? DOT_COLORS.stopped;

  return (
    <div ref={containerRef} style={{ position: "relative", display: "flex", alignItems: "center" }}>
      {/* 指示器 */}
      <button
        onClick={() => setOpen((v) => !v)}
        style={{
          background: "transparent",
          border: "none",
          cursor: "pointer",
          display: "flex",
          alignItems: "center",
          gap: 4,
          padding: "0 6px",
          fontSize: 11,
          color: "var(--text-secondary)",
          height: "100%",
        }}
        onMouseEnter={(e) => { e.currentTarget.style.color = "var(--text-primary)"; }}
        onMouseLeave={(e) => { e.currentTarget.style.color = "var(--text-secondary)"; }}
      >
        <span>MCP</span>
        {mcpStatus.status === "running" && mcpStatus.port && (
          <span>:{mcpStatus.port}</span>
        )}
        <span
          style={{
            width: 6,
            height: 6,
            borderRadius: "50%",
            background: dotColor,
            display: "inline-block",
            flexShrink: 0,
          }}
        />
      </button>

      {/* Popover */}
      {open && (
        <div
          style={{
            position: "absolute",
            bottom: "100%",
            right: 0,
            marginBottom: 4,
            background: "var(--bg-dialog)",
            border: "1px solid var(--border-color)",
            borderRadius: 6,
            boxShadow: "0 4px 16px rgba(0,0,0,0.4)",
            padding: "10px 14px",
            minWidth: 220,
            zIndex: 9999,
            fontSize: 12,
            color: "var(--text-primary)",
          }}
        >
          <div style={{ fontWeight: 600, marginBottom: 8, fontSize: 11, color: "var(--text-secondary)" }}>
            MCP Server
          </div>

          {/* Status */}
          <div style={{ display: "flex", alignItems: "center", gap: 6, marginBottom: 4 }}>
            <span style={{
              width: 7, height: 7, borderRadius: "50%", background: dotColor,
              display: "inline-block", flexShrink: 0,
            }} />
            <span style={{ textTransform: "capitalize" }}>{mcpStatus.status}</span>
          </div>

          {/* URL (Running) */}
          {mcpStatus.status === "running" && mcpStatus.url && (
            <div style={{
              fontSize: 11, color: "var(--text-secondary)",
              marginBottom: 8, wordBreak: "break-all",
              fontFamily: "var(--font-mono)",
            }}>
              {mcpStatus.url}
            </div>
          )}

          {/* Port mismatch hint */}
          {mcpStatus.status === "running" && mcpStatus.port != null &&
            configuredPort != null && mcpStatus.port !== configuredPort && (
            <div style={{
              fontSize: 10, color: "#fbbf24",
              marginBottom: 8, lineHeight: 1.4,
            }}>
              Port {configuredPort} was unavailable, auto-switched to {mcpStatus.port}
            </div>
          )}

          {/* Error message */}
          {mcpStatus.status === "error" && mcpStatus.error && (
            <div style={{
              fontSize: 11, color: "#f87171",
              marginBottom: 8, lineHeight: 1.4,
              wordBreak: "break-word",
            }}>
              {mcpStatus.error}
            </div>
          )}

          {/* Actions */}
          <div style={{
            display: "flex", alignItems: "center", gap: 6,
            marginTop: 6, paddingTop: 6,
            borderTop: "1px solid var(--border-color)",
          }}>
            {mcpStatus.status === "running" && (
              <button
                onClick={handleCopy}
                onMouseEnter={(e) => { e.currentTarget.style.opacity = "0.85"; }}
                onMouseLeave={(e) => { e.currentTarget.style.opacity = "1"; }}
                style={{
                  padding: "3px 10px", fontSize: 11,
                  background: "var(--btn-primary)", color: "#fff",
                  border: "none", borderRadius: 4, cursor: "pointer",
                }}
              >
                {copied ? "Copied!" : "Copy URL"}
              </button>
            )}

            {mcpStatus.status !== "stopped" && (
              <button
                onClick={handleRestart}
                onMouseEnter={(e) => { e.currentTarget.style.background = "var(--bg-selected)"; }}
                onMouseLeave={(e) => { e.currentTarget.style.background = "var(--bg-input)"; }}
                style={{
                  padding: "3px 10px", fontSize: 11,
                  background: "var(--bg-input)", color: "var(--text-primary)",
                  border: "1px solid var(--border-color)", borderRadius: 4, cursor: "pointer",
                }}
              >
                Restart
              </button>
            )}

            {mcpStatus.status === "stopped" && (
              <button
                onClick={handleRestart}
                onMouseEnter={(e) => { e.currentTarget.style.opacity = "0.85"; }}
                onMouseLeave={(e) => { e.currentTarget.style.opacity = "1"; }}
                style={{
                  padding: "3px 10px", fontSize: 11,
                  background: "var(--btn-primary)", color: "#fff",
                  border: "none", borderRadius: 4, cursor: "pointer",
                }}
              >
                Start
              </button>
            )}

            {mcpStatus.status === "running" && (
              <button
                onClick={handleStop}
                onMouseEnter={(e) => { e.currentTarget.style.color = "var(--text-primary)"; }}
                onMouseLeave={(e) => { e.currentTarget.style.color = "var(--text-secondary)"; }}
                style={{
                  background: "transparent", border: "none",
                  color: "var(--text-secondary)", fontSize: 11,
                  cursor: "pointer", padding: "3px 4px",
                  marginLeft: "auto",
                }}
              >
                Stop
              </button>
            )}
          </div>
        </div>
      )}
    </div>
  );
}
