import React, { useState, useEffect, useRef, useCallback, useMemo } from "react";
import { invoke } from "@tauri-apps/api/core";
import { emit } from "@tauri-apps/api/event";
import { useVirtualizerNoSync } from "../hooks/useVirtualizerNoSync";
import { useResizableColumn } from "../hooks/useResizableColumn";
import ContextMenu, { ContextMenuItem } from "./ContextMenu";
import type { CryptoMatch, CryptoScanResult, CryptoFunctionContext } from "../types/trace";

const ROW_HEIGHT = 22;

interface Props {
  sessionId: string | null;
  cryptoResults: CryptoScanResult | null;
  cryptoScanning: boolean;
  onJumpToSeq: (seq: number) => void;
}

/** Format hex string as hexdump: 16 bytes per line, hex + ASCII sidebar */
function formatHexdump(hex: string): string {
  const bytes: number[] = [];
  for (let i = 0; i < hex.length; i += 2) {
    bytes.push(parseInt(hex.substring(i, i + 2), 16));
  }
  const lines: string[] = [];
  for (let i = 0; i < bytes.length; i += 16) {
    const chunk = bytes.slice(i, i + 16);
    const hexPart = chunk.map(b => b.toString(16).padStart(2, "0")).join(" ");
    const asciiPart = chunk.map(b => (b >= 0x20 && b <= 0x7e) ? String.fromCharCode(b) : ".").join("");
    lines.push(`${hexPart.padEnd(47)}  ${asciiPart}`);
  }
  return lines.join("\n");
}

export default function CryptoPanel({ sessionId, cryptoResults, cryptoScanning, onJumpToSeq }: Props) {
  const seqCol = useResizableColumn(70, "right", 40, "crypto:seq");
  const algoCol = useResizableColumn(100, "left", 50, "crypto:algo");
  const magicCol = useResizableColumn(110, "left", 60, "crypto:magic");
  const addrCol = useResizableColumn(110, "right", 50, "crypto:addr");

  const HANDLE_STYLE: React.CSSProperties = {
    width: 8, cursor: "col-resize", flexShrink: 0,
    display: "flex", alignItems: "center", justifyContent: "center",
  };

  const [search, setSearch] = useState("");
  const [selectedSeq, setSelectedSeq] = useState<number | null>(null);
  const [algoFilter, setAlgoFilter] = useState<string | null>(null);
  const [contextMenu, setContextMenu] = useState<{ x: number; y: number; match: CryptoMatch } | null>(null);

  // Expand/collapse state
  const [expandedSeq, setExpandedSeq] = useState<number | null>(null);
  const [contextCache, setContextCache] = useState<Map<number, CryptoFunctionContext>>(new Map());
  const [loadingSeq, setLoadingSeq] = useState<number | null>(null);

  const parentRef = useRef<HTMLDivElement>(null);

  const filtered = useMemo(() => {
    if (!cryptoResults) return [];
    let items = cryptoResults.matches;
    if (algoFilter) {
      items = items.filter(m => m.algorithm === algoFilter);
    }
    if (search) {
      const q = search.toLowerCase();
      items = items.filter(m =>
        m.algorithm.toLowerCase().includes(q) ||
        m.magic_hex.toLowerCase().includes(q) ||
        m.address.toLowerCase().includes(q) ||
        m.disasm.toLowerCase().includes(q)
      );
    }
    return items;
  }, [cryptoResults, search, algoFilter]);

  const virtualizer = useVirtualizerNoSync({
    count: filtered.length,
    getScrollElement: () => parentRef.current,
    estimateSize: (i: number) => {
      const m = filtered[i];
      return m && m.seq === expandedSeq ? ROW_HEIGHT + 160 : ROW_HEIGHT;
    },
    overscan: 20,
  });
  const virtualItems = virtualizer.getVirtualItems();

  const handleRowClick = useCallback((match: CryptoMatch) => {
    setSelectedSeq(match.seq);
    onJumpToSeq(match.seq);
  }, [onJumpToSeq]);

  const handleToggleExpand = useCallback((e: React.MouseEvent, match: CryptoMatch) => {
    e.stopPropagation();
    const seq = match.seq;
    if (expandedSeq === seq) {
      setExpandedSeq(null);
      return;
    }
    setExpandedSeq(seq);
    // Load context if not cached
    if (!contextCache.has(seq) && sessionId) {
      setLoadingSeq(seq);
      invoke<CryptoFunctionContext>("get_crypto_context", {
        sessionId,
        seq,
        algorithm: match.algorithm,
      }).then(ctx => {
        setContextCache(prev => {
          const next = new Map(prev);
          next.set(seq, ctx);
          return next;
        });
        setLoadingSeq(null);
      }).catch(() => {
        setLoadingSeq(null);
      });
    }
  }, [expandedSeq, contextCache, sessionId]);

  const handleContextMenu = useCallback((e: React.MouseEvent, match: CryptoMatch) => {
    e.preventDefault();
    setSelectedSeq(match.seq);
    setContextMenu({ x: e.clientX, y: e.clientY, match });
  }, []);

  const handleCopyDisasm = useCallback(() => {
    if (contextMenu) navigator.clipboard.writeText(contextMenu.match.disasm);
    setContextMenu(null);
  }, [contextMenu]);

  const handleCopyAddr = useCallback(() => {
    if (contextMenu) navigator.clipboard.writeText(contextMenu.match.address);
    setContextMenu(null);
  }, [contextMenu]);

  const handleViewInMemory = useCallback(() => {
    if (!contextMenu) return;
    const { address, seq } = contextMenu.match;
    setContextMenu(null);
    emit("action:view-in-memory", { addr: address, seq });
  }, [contextMenu]);

  // Reset state when results change
  useEffect(() => {
    setAlgoFilter(null);
    setSelectedSeq(null);
    setExpandedSeq(null);
    setContextCache(new Map());
  }, [cryptoResults]);

  // Re-measure when expanded row changes
  useEffect(() => {
    virtualizer.measure();
  }, [expandedSeq, contextCache]);

  if (cryptoScanning) {
    return (
      <div style={{ flex: 1, display: "flex", alignItems: "center", justifyContent: "center", gap: 8 }}>
        <span style={{
          display: "inline-block", width: 14, height: 14,
          border: "2px solid var(--border-color)",
          borderTop: "2px solid var(--btn-primary)",
          borderRadius: "50%",
          animation: "spin 1s linear infinite",
        }} />
        <span style={{ color: "var(--text-secondary)", fontSize: 12 }}>Scanning for crypto constants...</span>
      </div>
    );
  }

  if (!cryptoResults) {
    return (
      <div style={{ flex: 1, display: "flex", alignItems: "center", justifyContent: "center" }}>
        <span style={{ color: "var(--text-secondary)", fontSize: 12 }}>
          No crypto scan results. Use Analysis &gt; Scan Crypto to start.
        </span>
      </div>
    );
  }

  const labelStyle: React.CSSProperties = {
    color: "var(--text-secondary)", fontSize: 11, flexShrink: 0, width: 60, textAlign: "right", marginRight: 8,
  };
  const monoStyle: React.CSSProperties = {
    fontFamily: "var(--font-mono, monospace)", fontSize: 11, color: "var(--text-primary)",
    whiteSpace: "pre", lineHeight: 1.4,
  };

  return (
    <div style={{ flex: 1, display: "flex", flexDirection: "column", overflow: "hidden" }}>
      {/* Toolbar */}
      <div style={{
        display: "flex", alignItems: "center", gap: 8, padding: "4px 8px",
        borderBottom: "1px solid var(--border-color)", flexShrink: 0,
      }}>
        <input
          value={search}
          onChange={e => setSearch(e.target.value)}
          placeholder="Filter results..."
          style={{
            width: 260, background: "var(--input-bg)", border: "1px solid var(--border-color)",
            color: "var(--text-primary)", padding: "3px 8px", borderRadius: 3, fontSize: 12,
          }}
        />
        {search && (
          <span
            onClick={() => setSearch("")}
            style={{ cursor: "pointer", color: "var(--text-secondary)", fontSize: 14, lineHeight: 1 }}
            onMouseEnter={e => (e.currentTarget.style.color = "var(--text-primary)")}
            onMouseLeave={e => (e.currentTarget.style.color = "var(--text-secondary)")}
          >×</span>
        )}
        <div style={{ display: "flex", gap: 4, flexWrap: "wrap" }}>
          {cryptoResults.algorithms_found.map(algo => (
            <span
              key={algo}
              onClick={() => setAlgoFilter(algoFilter === algo ? null : algo)}
              style={{
                padding: "1px 6px", borderRadius: 3, fontSize: 11, cursor: "pointer",
                background: algoFilter === algo ? "var(--btn-primary)" : "var(--bg-secondary)",
                color: algoFilter === algo ? "#fff" : "var(--text-secondary)",
                border: "1px solid var(--border-color)",
              }}
            >{algo}</span>
          ))}
        </div>
        <span style={{ flex: 1 }} />
        <span style={{ color: "var(--text-tertiary)", fontSize: 11, whiteSpace: "nowrap" }}>
          {filtered.length.toLocaleString()} matches
          {cryptoResults.scan_duration_ms > 0 && ` · ${(cryptoResults.scan_duration_ms / 1000).toFixed(2)}s`}
        </span>
      </div>

      {/* Header */}
      <div style={{
        display: "flex", padding: "4px 8px",
        background: "var(--bg-secondary)",
        borderBottom: "1px solid var(--border-color)",
        fontSize: "var(--font-size-sm)", color: "var(--text-secondary)", flexShrink: 0,
      }}>
        <span style={{ width: 20, flexShrink: 0 }} />
        <span style={{ width: seqCol.width, flexShrink: 0 }}>Line#</span>
        <div onMouseDown={seqCol.onMouseDown} style={HANDLE_STYLE}><div style={{ width: 1, height: "100%", background: "var(--border-color)" }} /></div>
        <span style={{ width: algoCol.width, flexShrink: 0 }}>Algorithm</span>
        <div onMouseDown={algoCol.onMouseDown} style={HANDLE_STYLE}><div style={{ width: 1, height: "100%", background: "var(--border-color)" }} /></div>
        <span style={{ width: magicCol.width, flexShrink: 0 }}>Magic Number</span>
        <div onMouseDown={magicCol.onMouseDown} style={HANDLE_STYLE}><div style={{ width: 1, height: "100%", background: "var(--border-color)" }} /></div>
        <span style={{ width: addrCol.width, flexShrink: 0 }}>Address</span>
        <div onMouseDown={addrCol.onMouseDown} style={HANDLE_STYLE}><div style={{ width: 1, height: "100%", background: "var(--border-color)" }} /></div>
        <span style={{ flex: 1 }}>Disasm</span>
      </div>

      {/* Virtual list */}
      <div ref={parentRef} style={{ flex: 1, overflow: "auto" }}>
        {filtered.length === 0 ? (
          <div style={{ padding: 16, textAlign: "center", color: "var(--text-secondary)", fontSize: 12 }}>
            No matches for current filter
          </div>
        ) : (
          <div style={{ height: virtualizer.getTotalSize(), width: "100%", position: "relative" }}>
            {virtualItems.map(virtualRow => {
              const match = filtered[virtualRow.index];
              if (!match) return null;
              const isSelected = match.seq === selectedSeq;
              const isExpanded = match.seq === expandedSeq;
              const ctx = contextCache.get(match.seq);
              const isLoading = loadingSeq === match.seq;
              return (
                <div
                  key={virtualRow.key}
                  data-index={virtualRow.index}
                  ref={virtualizer.measureElement}
                  style={{
                    position: "absolute", top: 0, left: 0, width: "100%",
                    transform: `translateY(${virtualRow.start}px)`,
                  }}
                >
                  {/* Main row */}
                  <div
                    onClick={() => handleRowClick(match)}
                    onContextMenu={e => handleContextMenu(e, match)}
                    style={{
                      display: "flex", alignItems: "center", padding: "0 8px",
                      height: ROW_HEIGHT,
                      cursor: "pointer", fontSize: "var(--font-size-sm)",
                      background: isSelected ? "var(--bg-selected)"
                        : virtualRow.index % 2 === 0 ? "var(--bg-row-even)" : "var(--bg-row-odd)",
                    }}
                    onMouseEnter={(e) => { if (!isSelected) e.currentTarget.style.background = "var(--bg-hover)"; }}
                    onMouseLeave={(e) => { if (!isSelected) e.currentTarget.style.background = isSelected ? "var(--bg-selected)" : virtualRow.index % 2 === 0 ? "var(--bg-row-even)" : "var(--bg-row-odd)"; }}
                  >
                    <span
                      onClick={(e) => handleToggleExpand(e, match)}
                      style={{
                        width: 20, flexShrink: 0, cursor: "pointer",
                        color: "var(--text-secondary)", fontSize: 10, textAlign: "center",
                        userSelect: "none",
                      }}
                    >{isExpanded ? "\u25BC" : "\u25B6"}</span>
                    <span style={{ width: seqCol.width, flexShrink: 0, color: "var(--syntax-number)" }}>{match.seq + 1}</span>
                    <span style={{ width: 8, flexShrink: 0 }} />
                    <span style={{ width: algoCol.width, flexShrink: 0, color: "var(--syntax-keyword)" }}>{match.algorithm}</span>
                    <span style={{ width: 8, flexShrink: 0 }} />
                    <span style={{ width: magicCol.width, flexShrink: 0, color: "var(--syntax-literal)" }}>{match.magic_hex}</span>
                    <span style={{ width: 8, flexShrink: 0 }} />
                    <span style={{ width: addrCol.width, flexShrink: 0, color: "var(--syntax-literal)" }}>{match.address}</span>
                    <span style={{ width: 8, flexShrink: 0 }} />
                    <span style={{
                      flex: 1, color: "var(--text-primary)",
                      overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap",
                    }}>{match.disasm}</span>
                  </div>
                  {/* Expanded context */}
                  {isExpanded && (
                    <div style={{
                      padding: "6px 12px 6px 28px",
                      background: "var(--bg-secondary)",
                      borderBottom: "1px solid var(--border-color)",
                      fontSize: 11,
                    }}>
                      {isLoading && !ctx ? (
                        <div style={{ display: "flex", alignItems: "center", gap: 6, padding: "4px 0" }}>
                          <span style={{
                            display: "inline-block", width: 12, height: 12,
                            border: "2px solid var(--border-color)",
                            borderTop: "2px solid var(--btn-primary)",
                            borderRadius: "50%",
                            animation: "spin 1s linear infinite",
                          }} />
                          <span style={{ color: "var(--text-secondary)" }}>Loading context...</span>
                        </div>
                      ) : ctx ? (
                        <div style={{ display: "flex", flexDirection: "column", gap: 4 }}>
                          {/* Inner function */}
                          <div style={{ display: "flex", alignItems: "baseline" }}>
                            <span style={labelStyle}>Inner</span>
                            <span style={{ color: "var(--syntax-keyword)", fontWeight: 500 }}>
                              {ctx.func_name ?? ctx.func_addr}
                            </span>
                            {ctx.func_name && (
                              <span style={{ color: "var(--text-tertiary)", marginLeft: 6, fontSize: 10, fontFamily: "var(--font-mono, monospace)" }}>
                                {ctx.func_addr}
                              </span>
                            )}
                            <span style={{ color: "var(--text-tertiary)", marginLeft: 8, fontSize: 10 }}>
                              seq {ctx.entry_seq + 1} ~ {ctx.exit_seq + 1}
                            </span>
                          </div>
                          {/* Caller function */}
                          {ctx.caller_addr && (
                            <div style={{ display: "flex", alignItems: "baseline" }}>
                              <span style={labelStyle}>Caller</span>
                              <span style={{ color: "var(--syntax-func, var(--syntax-keyword))", fontWeight: 500 }}>
                                {ctx.caller_name ?? ctx.caller_addr}
                              </span>
                              {ctx.caller_name && (
                                <span style={{ color: "var(--text-tertiary)", marginLeft: 6, fontSize: 10, fontFamily: "var(--font-mono, monospace)" }}>
                                  {ctx.caller_addr}
                                </span>
                              )}
                              {ctx.caller_entry_seq != null && ctx.caller_exit_seq != null && (
                                <span style={{ color: "var(--text-tertiary)", marginLeft: 8, fontSize: 10 }}>
                                  seq {ctx.caller_entry_seq + 1} ~ {ctx.caller_exit_seq + 1}
                                </span>
                              )}
                            </div>
                          )}
                          {/* Args */}
                          <div style={{ display: "flex", alignItems: "baseline" }}>
                            <span style={labelStyle}>Args</span>
                            <span style={{ ...monoStyle, fontSize: 11 }}>
                              x0={ctx.args[0]}, x1={ctx.args[1]}, x2={ctx.args[2]}, x3={ctx.args[3]}
                            </span>
                            <span style={{ color: "var(--text-tertiary)", marginLeft: 8, fontSize: 10 }}>
                              ({ctx.param_hint})
                            </span>
                          </div>
                          {/* Input */}
                          {ctx.input_hex && (
                            <div style={{ display: "flex", alignItems: "flex-start" }}>
                              <span style={labelStyle}>Input</span>
                              <pre style={{ ...monoStyle, margin: 0, background: "var(--bg-primary)", padding: "2px 6px", borderRadius: 3, overflow: "auto", maxWidth: "100%" }}>
                                {formatHexdump(ctx.input_hex)}
                              </pre>
                            </div>
                          )}
                          {/* Output */}
                          {ctx.output_hex && (
                            <div style={{ display: "flex", alignItems: "flex-start" }}>
                              <span style={labelStyle}>Output</span>
                              <pre style={{ ...monoStyle, margin: 0, background: "var(--bg-primary)", padding: "2px 6px", borderRadius: 3, overflow: "auto", maxWidth: "100%" }}>
                                {formatHexdump(ctx.output_hex)}
                              </pre>
                            </div>
                          )}
                          {!ctx.input_hex && !ctx.output_hex && (
                            <div style={{ display: "flex", alignItems: "baseline" }}>
                              <span style={labelStyle}>Memory</span>
                              <span style={{ color: "var(--text-tertiary)", fontStyle: "italic" }}>No memory data available</span>
                            </div>
                          )}
                        </div>
                      ) : (
                        <span style={{ color: "var(--text-tertiary)" }}>Failed to load context</span>
                      )}
                    </div>
                  )}
                </div>
              );
            })}
          </div>
        )}
      </div>

      {/* Context menu */}
      {contextMenu && (
        <ContextMenu x={contextMenu.x} y={contextMenu.y} onClose={() => setContextMenu(null)} minWidth={160}>
          <ContextMenuItem label="View in Memory" onClick={handleViewInMemory} />
          <ContextMenuItem label="Copy Address" onClick={handleCopyAddr} />
          <ContextMenuItem label="Copy Disasm" onClick={handleCopyDisasm} />
        </ContextMenu>
      )}
    </div>
  );
}
