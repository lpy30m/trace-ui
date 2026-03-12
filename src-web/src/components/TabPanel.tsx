import React, { useState, useCallback, useEffect, useMemo } from "react";
import { useDragToFloat } from "../hooks/useDragToFloat";
import { useResizableColumn } from "../hooks/useResizableColumn";
import type { SearchMatch, SliceResult } from "../types/trace";
import MemoryPanel from "./MemoryPanel";
import SearchResultList from "./SearchResultList";

const TABS = ["Memory", "Accesses", "Taint State", "Search"] as const;
type TabName = typeof TABS[number];

const TAB_TO_PANEL: Record<string, string> = {
  "Memory": "memory",
  "Accesses": "accesses",
  "Taint State": "taint-state",
  "Search": "search",
};

interface Props {
  searchResults: SearchMatch[];
  searchQuery: string;
  isSearching: boolean;
  searchStatus: string;
  searchTotalMatches: number;
  onJumpToSeq: (seq: number) => void;
  selectedSeq: number | null;
  isPhase2Ready: boolean;
  memAddr: string | null;
  memRw: string | null;
  memSize: number | null;
  floatedPanels: Set<string>;
  onFloat: (panel: string, position?: { x: number; y: number }) => void;
  sessionId: string | null;
  sliceActive: boolean;
  sliceInfo: SliceResult | null;
  sliceFromSpecs: string[];
}

export default function TabPanel({
  searchResults, searchQuery, isSearching, searchStatus, searchTotalMatches, onJumpToSeq,
  selectedSeq, isPhase2Ready, memAddr, memRw, memSize,
  floatedPanels, onFloat, sessionId,
  sliceActive, sliceInfo, sliceFromSpecs,
}: Props) {
  const [active, setActive] = useState<TabName>("Memory");
  const changesCol = useResizableColumn(Math.min(300, Math.round(window.innerWidth * 0.2)));
  const [memResetKey, setMemResetKey] = useState(0);

  // 过滤已浮动的 tab
  const visibleTabs = useMemo(
    () => TABS.filter(tab => !floatedPanels.has(TAB_TO_PANEL[tab])),
    [floatedPanels],
  );

  // 搜索自动切换（仅在 Search 未浮动时）
  useEffect(() => {
    if (isSearching && !floatedPanels.has("search")) {
      setActive("Search");
    }
  }, [isSearching, floatedPanels]);

  // 当前 active tab 被浮动后，自动切到第一个可见 tab
  useEffect(() => {
    if (floatedPanels.has(TAB_TO_PANEL[active]) && visibleTabs.length > 0) {
      setActive(visibleTabs[0]);
    }
  }, [floatedPanels, active, visibleTabs]);

  const searchBadge = searchTotalMatches > 0 ? ` (${searchTotalMatches.toLocaleString()})` : "";

  // ── 拖拽浮出逻辑 ──
  const handleFloatPanel = useCallback((panel: string, pos: { x: number; y: number }) => {
    onFloat(panel, pos);
  }, [onFloat]);

  const handleActivateTab = useCallback((panel: string) => {
    // panel key → TabName 反查
    const tab = TABS.find(t => TAB_TO_PANEL[t] === panel);
    if (tab) setActive(tab);
  }, []);

  const startDrag = useDragToFloat({ onFloat: handleFloatPanel, onActivate: handleActivateTab });

  function renderContent(): React.ReactNode {
    switch (active) {
      case "Search":
        return (
          <div style={{ flex: 1, display: "flex", flexDirection: "column", overflow: "hidden" }}>
            {isSearching ? (
              <div style={{ flex: 1, display: "flex", alignItems: "center", justifyContent: "center" }}>
                <span style={{ color: "var(--text-secondary)", fontSize: 12 }}>Searching...</span>
              </div>
            ) : searchResults.length === 0 ? (
              <div style={{ flex: 1, display: "flex", alignItems: "center", justifyContent: "center" }}>
                <span style={{ color: "var(--text-secondary)", fontSize: 12 }}>
                  {""}
                </span>
              </div>
            ) : (
              <>
                <SearchResultList
                  results={searchResults}
                  selectedSeq={selectedSeq}
                  onJumpToSeq={onJumpToSeq}
                  changesWidth={changesCol.width}
                  onResizeChanges={changesCol.onMouseDown}
                />
                {searchStatus && (
                  <div style={{
                    padding: "3px 8px", flexShrink: 0,
                    borderTop: "1px solid var(--border-color)",
                    background: "var(--bg-secondary)",
                    fontSize: 11, color: "var(--text-secondary)",
                  }}>
                    {searchStatus}
                  </div>
                )}
              </>
            )}
          </div>
        );
      case "Memory":
        return (
          <div style={{ flex: 1, display: "flex", flexDirection: "column", overflow: "hidden" }}>
            <MemoryPanel
              selectedSeq={selectedSeq}
              isPhase2Ready={isPhase2Ready}
              memAddr={memAddr}
              memRw={memRw}
              memSize={memSize}
              onJumpToSeq={onJumpToSeq}
              sessionId={sessionId}
              resetKey={memResetKey}
            />
          </div>
        );
      case "Taint State":
        return (
          <div style={{ flex: 1, display: "flex", alignItems: "center", justifyContent: "center", padding: 16 }}>
            {sliceActive && sliceInfo ? (
              <div style={{ color: "var(--text-secondary)", fontSize: 12, textAlign: "center", lineHeight: 1.8 }}>
                <span style={{ color: "var(--text-primary)", fontSize: 14 }}>
                  {sliceInfo.markedCount.toLocaleString()} / {sliceInfo.totalLines.toLocaleString()} lines tainted ({sliceInfo.percentage.toFixed(1)}%)
                </span>
                <br />
                {sliceFromSpecs.map((spec, i) => (
                  <span key={i} style={{ color: "var(--text-secondary)" }}>
                    {i > 0 ? ", " : "Source: "}{spec}
                  </span>
                ))}
              </div>
            ) : (
              <span style={{ color: "var(--text-secondary)", fontSize: 12 }}></span>
            )}
          </div>
        );
      default:
        return (
          <div style={{ flex: 1, display: "flex", alignItems: "center", justifyContent: "center" }}>
            <span style={{ color: "var(--text-secondary)", fontSize: 12 }}></span>
          </div>
        );
    }
  }

  // 所有 tab 都浮动时显示空状态
  if (visibleTabs.length === 0) {
    return (
      <div style={{ height: "100%", display: "flex", alignItems: "center", justifyContent: "center", background: "var(--bg-primary)" }}>
        <span style={{ color: "var(--text-secondary)", fontSize: 12 }}>All panels are floating</span>
      </div>
    );
  }

  return (
    <div style={{ height: "100%", display: "flex", flexDirection: "column", background: "var(--bg-primary)", overflow: "hidden" }}>
      <div style={{ display: "flex", alignItems: "center", borderBottom: "1px solid var(--border-color)", flexShrink: 0 }}>
        {visibleTabs.map(tab => (
          <div key={tab} style={{ display: "flex", alignItems: "center" }}>
            <button
              onMouseDown={(e) => startDrag(TAB_TO_PANEL[tab], tab === "Search" ? `Search${searchBadge}` : tab, e)}
              onDoubleClick={() => { if (tab === "Memory") setMemResetKey(k => k + 1); }}
              style={{
                padding: "6px 14px", fontSize: "var(--font-size-sm)",
                background: active === tab ? "var(--bg-secondary)" : "transparent",
                color: active === tab ? "var(--text-primary)" : "var(--text-secondary)",
                cursor: "grab",
                border: "none",
                borderBottom: active === tab ? "2px solid var(--btn-primary)" : "2px solid transparent",
              }}
            >{tab === "Search" ? `Search${searchBadge}` : tab}</button>
          </div>
        ))}
        <div style={{ marginLeft: "auto", paddingRight: 8 }} />
      </div>

      {renderContent()}
    </div>
  );
}
