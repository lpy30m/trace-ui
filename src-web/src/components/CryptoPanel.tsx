import React, { useState, useEffect, useRef, useCallback, useMemo } from "react";
import { emit } from "@tauri-apps/api/event";
import { useVirtualScroll } from "../hooks/useVirtualScroll";
import { useResizableColumn } from "../hooks/useResizableColumn";
import VirtualScrollArea from "./VirtualScrollArea";
import ContextMenu, { ContextMenuItem } from "./ContextMenu";
import Minimap, { MINIMAP_WIDTH } from "./Minimap";
import KnownDigestPanel from "./KnownDigestPanel";
import CryptoFunctionsPanel from "./CryptoFunctionsPanel";
import type { CryptoMatch, CryptoScanResult, HashMatchResult, TraceLine } from "../types/trace";
import type { ResolvedRow } from "../hooks/useFoldState";

const ROW_HEIGHT = 22;

interface Props {
  sessionId: string | null;
  hasStringIndex: boolean;
  cryptoResults: CryptoScanResult | null;
  cryptoScanning: boolean;
  onJumpToSeq: (seq: number) => void;
  onScanStrings?: () => Promise<void> | void;
  onTraceInput?: (match: HashMatchResult) => Promise<void> | void;
}

interface DetectionProps {
  cryptoResults: CryptoScanResult | null;
  cryptoScanning: boolean;
  onJumpToSeq: (seq: number) => void;
}

function DetectionPanel({ cryptoResults, cryptoScanning, onJumpToSeq }: DetectionProps) {
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

  const vs = useVirtualScroll({ totalCount: filtered.length, rowHeight: ROW_HEIGHT, overscan: 20 });

  const handleRowClick = useCallback((match: CryptoMatch) => {
    setSelectedSeq(match.seq);
    onJumpToSeq(match.seq);
  }, [onJumpToSeq]);

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

  // ── Minimap callbacks ──
  const resolveVirtualIndex = useCallback((vi: number): ResolvedRow => {
    return { type: "line", seq: filtered[vi]?.seq ?? vi } as ResolvedRow;
  }, [filtered]);

  const getLines = useCallback(async (seqs: number[]): Promise<TraceLine[]> => {
    const seqMap = new Map<number, CryptoMatch>();
    for (const m of filtered) seqMap.set(m.seq, m);
    return seqs
      .map(seq => seqMap.get(seq))
      .filter((m): m is CryptoMatch => m !== undefined)
      .map(m => ({
        seq: m.seq,
        address: m.address,
        so_offset: m.address,
        so_name: null,
        disasm: m.disasm,
        changes: m.algorithm,
        reg_before: "",
        mem_rw: null,
        mem_addr: null,
        mem_size: null,
        raw: "",
        call_info: null,
      } as TraceLine));
  }, [filtered]);

  const handleScrollbarScroll = useCallback((row: number) => {
    vs.scrollToRow(row);
  }, [vs]);

  // Reset filter when results change
  useEffect(() => {
    setAlgoFilter(null);
    setSelectedSeq(null);
  }, [cryptoResults]);

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
        <span style={{ width: seqCol.width, flexShrink: 0 }}>Line#</span>
        <div onMouseDown={seqCol.onMouseDown} style={HANDLE_STYLE}><div style={{ width: 1, height: "100%", background: "var(--border-color)" }} /></div>
        <span style={{ width: algoCol.width, flexShrink: 0 }}>Algorithm</span>
        <div onMouseDown={algoCol.onMouseDown} style={HANDLE_STYLE}><div style={{ width: 1, height: "100%", background: "var(--border-color)" }} /></div>
        <span style={{ width: magicCol.width, flexShrink: 0 }}>Magic Number</span>
        <div onMouseDown={magicCol.onMouseDown} style={HANDLE_STYLE}><div style={{ width: 1, height: "100%", background: "var(--border-color)" }} /></div>
        <span style={{ width: addrCol.width, flexShrink: 0 }}>Address</span>
        <div onMouseDown={addrCol.onMouseDown} style={HANDLE_STYLE}><div style={{ width: 1, height: "100%", background: "var(--border-color)" }} /></div>
        <span style={{ flex: 1 }}>Disasm</span>
        <span style={{ width: MINIMAP_WIDTH + 12, flexShrink: 0 }}></span>
      </div>

      {/* Virtual list */}
      <VirtualScrollArea
        containerRef={vs.containerRef}
        containerStyle={vs.containerStyle}
        containerHeight={vs.containerHeight}
        scrollbarProps={vs.scrollbarProps}
        gutterWidth={MINIMAP_WIDTH + 12}
        gutterContent={
          <Minimap
            virtualTotalRows={filtered.length}
            visibleRows={vs.visibleRows}
            currentRow={vs.currentRow}
            maxRow={vs.maxRow}
            height={vs.containerHeight}
            onScroll={handleScrollbarScroll}
            resolveVirtualIndex={resolveVirtualIndex}
            getLines={getLines}
            selectedSeq={selectedSeq}
            rightOffset={12}
            showSoName={false}
            showAbsAddress={false}
          />
        }
      >
        {filtered.length === 0 ? (
          <div style={{ padding: 16, textAlign: "center", color: "var(--text-secondary)", fontSize: 12 }}>
            No matches for current filter
          </div>
        ) : (
          Array.from({ length: Math.max(0, vs.endIdx - vs.startIdx + 1) }, (_, i) => {
            const index = vs.startIdx + i;
            const match = filtered[index];
            if (!match) return null;
            const isSelected = match.seq === selectedSeq;
            return (
              <div
                key={index}
                onClick={() => handleRowClick(match)}
                onContextMenu={e => handleContextMenu(e, match)}
                style={{
                  position: "absolute", top: 0, left: 0, width: "100%", height: ROW_HEIGHT,
                  transform: `translateY(${vs.getItemY(index)}px)`,
                  display: "flex", alignItems: "center", padding: "0 8px",
                  cursor: "pointer", fontSize: "var(--font-size-sm)",
                  background: isSelected ? "var(--bg-selected)"
                    : index % 2 === 0 ? "var(--bg-row-even)" : "var(--bg-row-odd)",
                }}
                onMouseEnter={(e) => { if (!isSelected) e.currentTarget.style.background = "var(--bg-hover)"; }}
                onMouseLeave={(e) => { if (!isSelected) e.currentTarget.style.background = index % 2 === 0 ? "var(--bg-row-even)" : "var(--bg-row-odd)"; }}
              >
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
            );
          })
        )}
      </VirtualScrollArea>

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

export default function CryptoPanel(props: Props) {
  const [view, setView] = useState<"detection" | "known-digest" | "functions">("detection");

  const segmentStyle = (active: boolean): React.CSSProperties => ({
    height: 26,
    padding: "0 12px",
    border: "none",
    borderRight: "1px solid var(--border-color)",
    background: active ? "var(--bg-selected)" : "var(--bg-input)",
    color: active ? "var(--text-primary)" : "var(--text-secondary)",
    cursor: "pointer",
    fontSize: 12,
    fontFamily: "inherit",
  });

  return (
    <div style={{ flex: 1, minWidth: 0, minHeight: 0, display: "flex", flexDirection: "column", overflow: "hidden" }}>
      <div style={{
        height: 35, padding: "4px 8px", display: "flex", alignItems: "center",
        borderBottom: "1px solid var(--border-color)", flexShrink: 0,
      }}>
        <div style={{ display: "flex", border: "1px solid var(--border-color)", borderRadius: 4, overflow: "hidden" }}>
          <button type="button" style={segmentStyle(view === "detection")} onClick={() => setView("detection")}>
            Detection
          </button>
          <button
            type="button"
            style={segmentStyle(view === "known-digest")}
            onClick={() => setView("known-digest")}
          >
            Known Digest
          </button>
          <button
            type="button"
            style={{ ...segmentStyle(view === "functions"), borderRight: "none" }}
            onClick={() => setView("functions")}
          >
            Functions
          </button>
        </div>
      </div>
      <div style={{ flex: 1, minHeight: 0, display: "flex", overflow: "hidden" }}>
        <div style={{ flex: 1, minWidth: 0, minHeight: 0, display: view === "detection" ? "flex" : "none" }}>
          <DetectionPanel
            cryptoResults={props.cryptoResults}
            cryptoScanning={props.cryptoScanning}
            onJumpToSeq={props.onJumpToSeq}
          />
        </div>
        <div style={{ flex: 1, minWidth: 0, minHeight: 0, display: view === "known-digest" ? "flex" : "none" }}>
          <KnownDigestPanel
            sessionId={props.sessionId}
            hasStringIndex={props.hasStringIndex}
            onJumpToSeq={props.onJumpToSeq}
            onScanStrings={props.onScanStrings}
            onTraceInput={props.onTraceInput}
          />
        </div>
        <div style={{ flex: 1, minWidth: 0, minHeight: 0, display: view === "functions" ? "flex" : "none" }}>
          <CryptoFunctionsPanel
            sessionId={props.sessionId}
            onJumpToSeq={props.onJumpToSeq}
          />
        </div>
      </div>
    </div>
  );
}
