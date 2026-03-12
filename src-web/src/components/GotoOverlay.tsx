import { useState, useEffect, useRef, useCallback } from "react";
import { invoke } from "@tauri-apps/api/core";
import type { SearchMatch, SearchResult } from "../types/trace";

interface Props {
  onJumpToSeq: (seq: number) => void;
  onClose: () => void;
  sessionId: string | null;
  totalLines: number;
}

function isHexAddress(input: string): boolean {
  if (input.startsWith("0x") || input.startsWith("0X")) return true;
  return /[a-fA-F]/.test(input) && /^[0-9a-fA-F]+$/.test(input);
}

export default function GotoOverlay({ onJumpToSeq, onClose, sessionId, totalLines }: Props) {
  const [input, setInput] = useState("");
  const [matches, setMatches] = useState<SearchMatch[]>([]);
  const [searching, setSearching] = useState(false);
  const [selectedIdx, setSelectedIdx] = useState(0);
  const inputRef = useRef<HTMLInputElement>(null);
  const listRef = useRef<HTMLDivElement>(null);

  // 自动聚焦
  useEffect(() => {
    setTimeout(() => inputRef.current?.focus(), 50);
  }, []);

  // 点击遮罩关闭
  const handleBackdropClick = useCallback((e: React.MouseEvent) => {
    if (e.target === e.currentTarget) onClose();
  }, [onClose]);

  // 地址搜索（防抖 300ms，版本号防竞态）
  const searchTimer = useRef<ReturnType<typeof setTimeout> | null>(null);
  const searchVersion = useRef(0);
  useEffect(() => {
    if (!input.trim()) { setMatches([]); return; }
    if (!isHexAddress(input)) { setMatches([]); return; }
    if (!sessionId) return;

    const version = ++searchVersion.current;
    if (searchTimer.current) clearTimeout(searchTimer.current);
    searchTimer.current = setTimeout(async () => {
      setSearching(true);
      try {
        const result = await invoke<SearchResult>("search_trace", {
          sessionId,
          request: { query: input, max_results: 50 },
        });
        if (version !== searchVersion.current) return; // 过期请求，丢弃
        setMatches(result.matches);
        setSelectedIdx(0);
      } catch {
        if (version !== searchVersion.current) return;
        setMatches([]);
      } finally {
        if (version === searchVersion.current) {
          setSearching(false);
        }
      }
    }, 300);

    return () => { if (searchTimer.current) clearTimeout(searchTimer.current); };
  }, [input, sessionId]);

  const jumpAndClose = useCallback((seq: number) => {
    onJumpToSeq(seq);
    onClose();
  }, [onJumpToSeq, onClose]);

  const handleKeyDown = useCallback((e: React.KeyboardEvent) => {
    if (e.key === "Escape") {
      e.preventDefault();
      onClose();
    } else if (e.key === "Enter") {
      e.preventDefault();
      const trimmed = input.trim();
      if (!trimmed) return;

      if (!isHexAddress(trimmed)) {
        // 纯数字 → 行号跳转（用户输入从 1 开始，内部 seq 从 0 开始）
        const lineNum = parseInt(trimmed, 10);
        if (!isNaN(lineNum) && lineNum >= 1 && lineNum <= totalLines) {
          jumpAndClose(lineNum - 1);
        }
      } else if (matches.length > 0) {
        // 地址搜索有结果 → 跳转选中项
        jumpAndClose(matches[selectedIdx].seq);
      }
    } else if (e.key === "ArrowDown") {
      e.preventDefault();
      if (matches.length > 0) {
        setSelectedIdx(i => Math.min(i + 1, matches.length - 1));
      }
    } else if (e.key === "ArrowUp") {
      e.preventDefault();
      if (matches.length > 0) {
        setSelectedIdx(i => Math.max(i - 1, 0));
      }
    }
  }, [input, matches, selectedIdx, totalLines, jumpAndClose, onClose]);

  // 选中项自动滚入视野
  useEffect(() => {
    const el = listRef.current?.children[selectedIdx] as HTMLElement | undefined;
    el?.scrollIntoView({ block: "nearest" });
  }, [selectedIdx]);

  const trimmed = input.trim();
  const isLineNum = trimmed.length > 0 && !isHexAddress(trimmed);
  const parsedLine = isLineNum ? parseInt(trimmed, 10) : NaN;
  const lineValid = !isNaN(parsedLine) && parsedLine >= 1 && parsedLine <= totalLines;

  return (
    <div
      onClick={handleBackdropClick}
      style={{
        position: "fixed", top: 0, left: 0, right: 0, bottom: 0,
        background: "rgba(0,0,0,0.35)",
        display: "flex", alignItems: "flex-start", justifyContent: "center",
        paddingTop: "18vh",
        zIndex: 9998,
      }}
    >
      <div style={{
        width: 580, maxHeight: "50vh",
        background: "var(--bg-primary)",
        border: "1px solid var(--border-color)",
        borderRadius: 6,
        boxShadow: "0 8px 32px rgba(0,0,0,0.5)",
        display: "flex", flexDirection: "column",
        overflow: "hidden",
      }}>
        {/* 输入框 */}
        <div style={{ padding: "10px 12px 6px", flexShrink: 0 }}>
          <input
            ref={inputRef}
            type="text"
            placeholder="行号 (如 12345) 或地址 (如 0x406bd430)"
            value={input}
            onChange={(e) => setInput(e.target.value)}
            onKeyDown={handleKeyDown}
            style={{
              width: "100%", padding: "6px 10px",
              background: "var(--bg-input)", color: "var(--text-primary)",
              border: "1px solid var(--border-color)", borderRadius: 4,
              fontFamily: "var(--font-mono)", fontSize: "var(--font-size-sm)",
              outline: "none",
            }}
          />
        </div>

        {/* 提示/结果 */}
        <div style={{ flex: 1, overflow: "auto", fontSize: "var(--font-size-sm)" }}>
          {isLineNum && trimmed.length > 0 ? (
            <div style={{ padding: "8px 12px", color: lineValid ? "var(--text-primary)" : "var(--reg-changed)" }}>
              {lineValid
                ? <span>按 Enter 跳转到第 <b>{parsedLine.toLocaleString()}</b> 行</span>
                : <span>行号超出范围 (1 ~ {totalLines.toLocaleString()})</span>
              }
            </div>
          ) : searching ? (
            <div style={{ padding: "8px 12px", color: "var(--text-secondary)" }}>搜索中...</div>
          ) : matches.length > 0 ? (
            <div ref={listRef}>
              {matches.map((m, i) => (
                <div
                  key={`${m.seq}-${i}`}
                  onClick={() => jumpAndClose(m.seq)}
                  style={{
                    padding: "3px 12px",
                    cursor: "pointer",
                    display: "flex", gap: 8,
                    background: i === selectedIdx ? "var(--bg-selected)" : "transparent",
                    color: "var(--text-primary)",
                  }}
                  onMouseEnter={() => setSelectedIdx(i)}
                >
                  <span style={{ width: 60, color: "var(--text-secondary)", flexShrink: 0 }}>#{m.seq + 1}</span>
                  <span style={{ width: 100, color: "var(--text-address)", flexShrink: 0 }}>{m.address}</span>
                  <span style={{ flex: 1, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{m.disasm}</span>
                  <span style={{ width: 140, color: "var(--text-changes)", flexShrink: 0, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap", textAlign: "right" }}>{m.changes}</span>
                </div>
              ))}
            </div>
          ) : input.trim() && isHexAddress(input.trim()) ? (
            <div style={{ padding: "8px 12px", color: "var(--text-secondary)" }}>无匹配结果</div>
          ) : null}
        </div>
      </div>
    </div>
  );
}
