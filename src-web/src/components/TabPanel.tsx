import React, { useState, useCallback, useEffect, useMemo, useRef } from "react";
import { listen } from "@tauri-apps/api/event";
import { invoke } from "@tauri-apps/api/core";
import { openDepTreeWindow } from "../utils/openDepTreeWindow";
import { useDragToFloat } from "../hooks/useDragToFloat";
import { useSearchMatchCache } from "../hooks/useSearchMatchCache";
import { useSearchPages } from "../hooks/useSearchPages";
import { findNearestSeqIndex } from "../utils/binarySearch";
import type { SearchMatch, SliceResult, CryptoScanResult, HashMatchResult, StringRecordDto } from "../types/trace";
import MemoryPanel from "./MemoryPanel";
import MemoryObjectsPanel from "./MemoryObjectsPanel";
import SearchResultList from "./SearchResultList";
import SearchBar, { SearchOptions } from "./SearchBar";
import StringsPanel from "./StringsPanel";
import CryptoPanel from "./CryptoPanel";
import AnalysisHistoryPanel from "./AnalysisHistoryPanel";
import FunctionInspectorPanel from "./FunctionInspectorPanel";
import TaintResultViews from "./TaintResultViews";
import { useSelectedSeq } from "../stores/selectedSeqStore";
import { explainTaintError } from "../utils/taintError";

const TABS = ["Memory", "Objects", "Accesses", "Taint State", "Search", "Strings", "Crypto", "Analyses", "Function"] as const;
type TabName = typeof TABS[number];
const TAB_LABELS: Record<TabName, string> = { Memory: "内存", Objects: "对象/别名", Accesses: "访问记录", "Taint State": "污点状态", Search: "搜索", Strings: "字符串", Crypto: "加密分析", Analyses: "分析历史", Function: "函数" };

function DepTreeFromSliceButton({ sessionId }: { sessionId: string | null }) {
  const handleClick = useCallback(() => {
    if (!sessionId) return;
    openDepTreeWindow({ sessionId, fromSlice: true });
  }, [sessionId]);

  return (
    <div style={{ marginTop: 4 }}>
      <button
        onClick={handleClick}
        style={{
          padding: "3px 10px",
          fontSize: 11,
          background: "var(--btn-secondary, #3e4451)",
          color: "var(--text-primary)",
          border: "1px solid var(--border-color)",
          borderRadius: 4,
          cursor: "pointer",
        }}
      >
       以依赖树查看
      </button>
    </div>
  );
}

const TAB_TO_PANEL: Record<string, string> = {
  "Memory": "memory",
  "Objects": "objects",
  "Accesses": "accesses",
  "Taint State": "taint-state",
  "Search": "search",
  "Strings": "strings",
  "Crypto": "crypto",
  "Analyses": "analyses",
  "Function": "function",
};

const FLOATABLE_PANELS = new Set(["memory", "search", "strings"]);

interface Props {
  matchSeqs: number[];
  searchQuery: string;
  isSearching: boolean;
  searchStatus: string;
  searchTotalMatches: number;
  onJumpToSeq: (seq: number) => void;
  onJumpToSearchMatch: (match: SearchMatch) => void;
  isPhase2Ready: boolean;
  floatedPanels: Set<string>;
  onFloat: (panel: string, position?: { x: number; y: number }) => void;
  sessionId: string | null;
  sliceActive: boolean;
  sliceInfo: SliceResult | null;
  sliceFromSpecs: string[];
  isSlicing: boolean;
  sliceDuration: number | null;
  sliceError: string | null;
  stringsScanning?: boolean;
  hasStringIndex: boolean;
  cryptoResults: CryptoScanResult | null;
  cryptoScanning: boolean;
  onScanStrings: () => Promise<void> | void;
  onTraceDigestInput: (match: HashMatchResult) => Promise<void> | void;
  onTraceStringCreation: (record: StringRecordDto) => Promise<void> | void;
  onTraceMemory: (request: { addr: string; size: number; seq: number }) => Promise<void> | void;
  onSearch: (query: string, options: SearchOptions) => void;
  showSoName?: boolean;
  showAbsAddress?: boolean;
  addrColorHighlight?: boolean;
}

export default function TabPanel({
  matchSeqs, searchQuery, isSearching, searchStatus, searchTotalMatches, onJumpToSeq, onJumpToSearchMatch,
  isPhase2Ready,
  floatedPanels, onFloat, sessionId,
  sliceActive, sliceInfo, sliceFromSpecs,
  isSlicing, sliceDuration, sliceError,
  stringsScanning,
  hasStringIndex,
  cryptoResults,
  cryptoScanning,
  onScanStrings,
  onTraceDigestInput,
  onTraceStringCreation,
  onTraceMemory,
  onSearch,
  showSoName = false,
  showAbsAddress = false,
  addrColorHighlight = false,
}: Props) {
  const [active, setActive] = useState<TabName>("Memory");
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

  // 污点分析自动切换（仅在 Taint State 未浮动时）
  useEffect(() => {
    if ((isSlicing || sliceActive) && !floatedPanels.has("taint-state")) {
      setActive("Taint State");
    }
  }, [isSlicing, sliceActive, floatedPanels]);

  // Crypto 扫描开始和完成时自动切换到 Crypto tab
  const prevCryptoScanningRef = useRef(false);
  useEffect(() => {
    if (!floatedPanels.has("crypto")) {
      const scanStarted = !prevCryptoScanningRef.current && cryptoScanning;
      const scanFinished = prevCryptoScanningRef.current && !cryptoScanning && cryptoResults;
      if (scanStarted || scanFinished) {
        setActive("Crypto");
      }
    }
    prevCryptoScanningRef.current = cryptoScanning;
  }, [cryptoScanning, cryptoResults, floatedPanels]);

  // View in Memory：自动切换到 Memory tab（仅在 Memory 未浮动时）
  useEffect(() => {
    const unlisten = listen("action:view-in-memory", () => {
      if (!floatedPanels.has("memory")) {
        setActive("Memory");
        setMemResetKey(k => k + 1);
      }
    });
    return () => { unlisten.then(fn => fn()); };
  }, [floatedPanels]);

  // 当前 active tab 被浮动后，自动切到第一个可见 tab
  useEffect(() => {
    if (floatedPanels.has(TAB_TO_PANEL[active]) && visibleTabs.length > 0) {
      setActive(visibleTabs[0]);
    }
  }, [floatedPanels, active, visibleTabs]);

  const searchBadge = searchTotalMatches > 0 ? ` (${searchTotalMatches.toLocaleString()})` : "";

  const currentSeq = useSelectedSeq();
  const searchInputRef = useRef<HTMLInputElement>(null);
  const [localSearchQuery, setLocalSearchQuery] = useState(searchQuery);
  const [selectedSearchIdx, setSelectedSearchIdx] = useState(0);
  const [searchOptions, setSearchOptions] = useState<SearchOptions>({ caseSensitive: false, wholeWord: false, useRegex: false, fuzzyMatch: false });

  const [searchGen, setSearchGen] = useState(0);
  const searchGenRef = useRef(0);

  // 新搜索开始时递增 generation 并清空缓存（绑定到 searchQuery 变化，而非 matchSeqs）
  useEffect(() => {
    searchGenRef.current++;
    setSearchGen(searchGenRef.current);
    cache.clear();
  }, [searchQuery]);

  const queryParams = useMemo(() =>
    searchQuery ? { query: searchQuery, caseSensitive: searchOptions.caseSensitive, useRegex: searchOptions.useRegex, fuzzy: searchOptions.fuzzyMatch } : null,
  [searchQuery, searchOptions]);

  const cache = useSearchMatchCache(sessionId, queryParams, searchGen);
  const searchPages = useSearchPages();

  // 耦合两层加载：seq 页加载完成后通知 prefetch effect 重新请求
  // 注意：不在此处请求全页详情（5000条会阻塞后端，淹没可见行请求）
  // pageVersion 变化已自动触发 SearchResultList 的 prefetch effect

  // 同步外部 searchQuery 变化
  useEffect(() => { setLocalSearchQuery(searchQuery); }, [searchQuery]);

  // 监听浮窗 ESC 还原时同步的 query 和 toggle 状态
  useEffect(() => {
    const unlistenQuery = listen<{ query: string }>("sync:search-query-back", (e) => {
      setLocalSearchQuery(e.payload.query);
    });
    const unlistenOptions = listen<SearchOptions>("sync:search-options", (e) => {
      setSearchOptions(e.payload);
    });
    return () => {
      unlistenQuery.then(fn => fn());
      unlistenOptions.then(fn => fn());
    };
  }, []);

  // 搜索结果变化时，重置分页状态，自动选中距离当前 TraceTable 选中行最近的结果
  useEffect(() => {
    if (matchSeqs.length === 0 && searchTotalMatches === 0) {
      searchPages.reset(0, [], sessionId ?? "");
      setSelectedSearchIdx(-1);
      return;
    }
    searchPages.reset(searchTotalMatches, matchSeqs, sessionId ?? "");
    if (currentSeq == null) { setSelectedSearchIdx(0); return; }
    setSelectedSearchIdx(findNearestSeqIndex(matchSeqs, currentSeq));
    cache.getMatches(matchSeqs.slice(0, 50));
  }, [matchSeqs, searchTotalMatches]);

  // 监听 action:activate-search-tab 事件
  useEffect(() => {
    const unlisten = listen("action:activate-search-tab", () => {
      if (!floatedPanels.has("search")) {
        setActive("Search");
      }
    });
    return () => { unlisten.then(fn => fn()); };
  }, [floatedPanels]);

  // 监听 search:focus-input 事件（Ctrl+F 时聚焦搜索框）
  useEffect(() => {
    const unlisten = listen("search:focus-input", () => {
      if (!floatedPanels.has("search")) {
        searchInputRef.current?.focus();
        searchInputRef.current?.select();
      }
    });
    return () => { unlisten.then(fn => fn()); };
  }, [floatedPanels]);

  const handlePrevMatch = useCallback(() => {
    if (searchPages.totalCount === 0) return;
    setSelectedSearchIdx(prev =>
      prev <= 0 ? searchPages.totalCount - 1 : prev - 1
    );
  }, [searchPages.totalCount]);

  const handleNextMatch = useCallback(() => {
    if (searchPages.totalCount === 0) return;
    setSelectedSearchIdx(prev =>
      (prev + 1) % searchPages.totalCount
    );
  }, [searchPages.totalCount]);

  const searchMatchInfo = isSearching
    ? "搜索中…"
    : searchPages.totalCount === 0
      ? (searchQuery ? "无结果" : "")
      : selectedSearchIdx < 0
        ? `${searchTotalMatches.toLocaleString()} 个结果`
        : `${selectedSearchIdx + 1}/${searchTotalMatches.toLocaleString()}`;

  // ── 拖拽浮出逻辑 ──
  const handleActivateTab = useCallback((panel: string) => {
    // panel key → TabName 反查
    const tab = TABS.find(t => TAB_TO_PANEL[t] === panel);
    if (tab) setActive(tab);
  }, []);

  const startDrag = useDragToFloat({ onFloat, onActivate: handleActivateTab });
  const taintErrorInfo = sliceError ? explainTaintError(sliceError) : null;

  // 容器样式：所有 tab 用 absolute 堆叠，active 可见，其他 visibility:hidden
  // 不用 display:none —— 浏览器会重置 scrollTop，导致虚拟列表焦点丢失
  const tabStyle = (tab: TabName): React.CSSProperties => ({
    position: "absolute", inset: 0,
    display: "flex", flexDirection: "column", overflow: "hidden",
    visibility: active === tab ? "visible" : "hidden",
  });

  // 所有 tab 都浮动时显示空状态
  if (visibleTabs.length === 0) {
    return (
      <div style={{ height: "100%", display: "flex", alignItems: "center", justifyContent: "center", background: "var(--bg-primary)" }}>
        <span style={{ color: "var(--text-secondary)", fontSize: 12 }}>所有面板都已浮动</span>
      </div>
    );
  }

  return (
    <div style={{ height: "100%", display: "flex", flexDirection: "column", background: "var(--bg-primary)", overflow: "hidden" }}>
      <div style={{
        display: "flex", alignItems: "center", borderBottom: "1px solid var(--border-color)",
        flexShrink: 0, overflowX: "auto", overflowY: "hidden",
      }}>
        {visibleTabs.map(tab => {
          const panel = TAB_TO_PANEL[tab];
          const canFloat = FLOATABLE_PANELS.has(panel);
          return (
          <div key={tab} style={{ display: "flex", alignItems: "center", flexShrink: 0 }}>
            <button
              onMouseDown={canFloat ? (e) => startDrag(panel, tab === "Search" ? `搜索${searchBadge}` : TAB_LABELS[tab], e) : undefined}
              onClick={canFloat ? undefined : () => setActive(tab)}
              onDoubleClick={() => { if (tab === "Memory") setMemResetKey(k => k + 1); }}
              title={canFloat ? "可拖动为独立窗口" : "该面板暂不支持独立窗口"}
              style={{
                padding: "6px 14px", fontSize: "var(--font-size-sm)",
                background: active === tab ? "var(--bg-secondary)" : "transparent",
                color: active === tab ? "var(--text-primary)" : "var(--text-secondary)",
                cursor: canFloat ? "grab" : "default",
                border: "none",
                borderBottom: active === tab ? "2px solid var(--btn-primary)" : "2px solid transparent",
              }}
            >{tab === "Search" ? `搜索${searchBadge}` : TAB_LABELS[tab]}</button>
          </div>
          );
        })}
        <div style={{ marginLeft: "auto", paddingRight: 8, flexShrink: 0 }} />
      </div>

      {/* 内容区域：relative 容器，所有 tab 用 absolute 堆叠 */}
      <div style={{ flex: 1, position: "relative", overflow: "hidden" }}>
      <div style={tabStyle("Memory")}>
        <MemoryPanel
          isPhase2Ready={isPhase2Ready}
          onJumpToSeq={onJumpToSeq}
          sessionId={sessionId}
          resetKey={memResetKey}
          onTraceMemory={onTraceMemory}
        />
      </div>

      <div style={tabStyle("Objects")}>
        <MemoryObjectsPanel
          sessionId={sessionId}
          isPhase2Ready={isPhase2Ready}
          onJumpToSeq={onJumpToSeq}
        />
      </div>

      <div style={tabStyle("Search")}>
        <SearchBar
          query={localSearchQuery}
          onQueryChange={setLocalSearchQuery}
          onSearch={onSearch}
          onPrevMatch={handlePrevMatch}
          onNextMatch={handleNextMatch}
          matchInfo={searchMatchInfo}
          inputRef={searchInputRef}
          initialOptions={searchOptions}
          onOptionsChange={setSearchOptions}
        />
        {isSearching || (searchPages.totalCount > 0 && cache.cacheSize === 0) ? (
          <div style={{ flex: 1, display: "flex", alignItems: "center", justifyContent: "center" }}>
            <span style={{ color: "var(--text-secondary)", fontSize: 12 }}>搜索中…</span>
          </div>
        ) : searchPages.totalCount === 0 ? (
          <div style={{ flex: 1, display: "flex", alignItems: "center", justifyContent: "center" }}>
            <span style={{ color: "var(--text-secondary)", fontSize: 12 }}>
              {searchQuery ? `未找到“${searchQuery}”的结果` : "请输入搜索内容并按 Enter"}
            </span>
          </div>
        ) : (
          <>
            <SearchResultList
              totalCount={searchPages.totalCount}
              getSeqAtIndex={searchPages.getSeqAtIndex}
              ensureRange={searchPages.ensureRange}
              findSeqIndex={searchPages.findSeqIndex}
              getMatchDetail={cache.getMatch}
              selectedSeq={searchPages.getSeqAtIndex(selectedSearchIdx) ?? null}
              onJumpToSeq={onJumpToSeq}
              onJumpToMatch={onJumpToSearchMatch}
              searchQuery={searchQuery}
              caseSensitive={searchOptions.caseSensitive}
              fuzzy={searchOptions.fuzzyMatch}
              useRegex={searchOptions.useRegex}
              showSoName={showSoName}
              showAbsAddress={showAbsAddress}
              addrColorHighlight={addrColorHighlight}
              requestDetails={(seqs) => { cache.requestImmediate(seqs); }}
              cacheVersion={cache.cacheSize}
              pageVersion={searchPages.pageVersion}
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

      <div style={{ ...tabStyle("Taint State"), alignItems: "flex-start", justifyContent: "center", padding: 16, overflow: "auto" }}>
        {isSlicing ? (
          <div style={{ display: "flex", alignItems: "center", gap: 8, width: "100%", justifyContent: "center" }}>
            <span style={{
              display: "inline-block", width: 14, height: 14,
              border: "2px solid var(--border-color)",
              borderTop: "2px solid var(--btn-primary)",
              borderRadius: "50%",
              animation: "spin 1s linear infinite",
            }} />
            <span style={{ color: "var(--text-secondary)", fontSize: 12 }}>分析中…</span>
          </div>
        ) : taintErrorInfo ? (
          <div style={{ width: "100%", maxWidth: 760, fontSize: 12, lineHeight: 1.6 }}>
            <div style={{ color: "var(--text-error)", fontWeight: 600 }}>{taintErrorInfo.title}</div>
            <div style={{ color: "var(--text-primary)", marginTop: 4 }}>{taintErrorInfo.suggestion}</div>
            {taintErrorInfo.detail !== taintErrorInfo.title && (
              <details style={{ color: "var(--text-secondary)", marginTop: 8 }}>
                <summary style={{ cursor: "pointer" }}>技术详情</summary>
                <div style={{ marginTop: 4, fontFamily: "monospace", overflowWrap: "anywhere" }}>{taintErrorInfo.detail}</div>
              </details>
            )}
          </div>
        ) : sliceActive && sliceInfo ? (
          <div style={{ width: "100%", minWidth: 0, fontSize: 12, lineHeight: 2, color: "var(--text-secondary)" }}>
            <div>
              <span style={{ color: "var(--text-secondary)", display: "inline-block", width: 52 }}>来源：</span>
              <span style={{ color: "var(--text-primary)" }}>{sliceFromSpecs.join(", ")}</span>
            </div>
            <div>
              <span style={{ color: "var(--text-secondary)", display: "inline-block", width: 52 }}>结果：</span>
              <span style={{ color: "var(--text-primary)" }}>
                {sliceInfo.markedCount.toLocaleString()} / {sliceInfo.totalLines.toLocaleString()} lines ({sliceInfo.percentage.toFixed(1)}%)
              </span>
            </div>
            {sliceDuration != null && (
              <div>
                <span style={{ color: "var(--text-secondary)", display: "inline-block", width: 52 }}>耗时：</span>
                <span style={{ color: "var(--text-primary)" }}>{(sliceDuration / 1000).toFixed(2)}s</span>
              </div>
            )}
            {sliceInfo.warnings.length > 0 && (
              <div style={{
                marginTop: 8, padding: "7px 9px", maxWidth: 760,
                border: "1px solid var(--text-changes)", borderRadius: 4,
                color: "var(--text-changes)", lineHeight: 1.5,
              }}>
                {sliceInfo.warnings.map((warning, index) => (
                  <div key={`${warning.code}-${warning.sourceSpec}-${index}`} style={{ marginBottom: index + 1 < sliceInfo.warnings.length ? 6 : 0 }}>
                    <div>{warning.message}</div>
                    {warning.missingRanges.length > 0 && (
                      <div style={{ color: "var(--text-secondary)", marginTop: 2 }}>
                        Missing: {warning.missingRanges.map((range) => `${range.startAddr}..${range.endAddr} (${range.size} bytes)`).join(", ")}
                      </div>
                    )}
                    <div style={{ color: "var(--text-primary)", marginTop: 3 }}>
                      Continue with the available bytes, or move to a later instruction to include the missing writes.
                    </div>
                  </div>
                ))}
              </div>
            )}
            {sliceInfo.percentage > 50 && (
              <div style={{ marginTop: 6, color: "var(--text-changes)", lineHeight: 1.5 }}>
                Large result. Use Focused scope or shorten the history range for a clearer dependency chain.
              </div>
            )}
            {sliceInfo.markedCount <= 2 && (
              <div style={{ marginTop: 6, color: "var(--text-secondary)", lineHeight: 1.5 }}>
                Short chain. Expand the history range or use Broad scope if earlier inputs are missing.
              </div>
            )}
            <DepTreeFromSliceButton sessionId={sessionId} />
            {sessionId && (
              <div style={{ marginTop: 12, paddingTop: 10, borderTop: "1px solid var(--border-color)", minWidth: 0 }}>
                <TaintResultViews
                  sessionId={sessionId}
                  sources={sliceFromSpecs}
                  sliceInfo={sliceInfo}
                  onJumpToSeq={onJumpToSeq}
                />
              </div>
            )}
          </div>
        ) : (
          <div style={{ width: "100%", textAlign: "center" }}>
            <span style={{ color: "var(--text-secondary)", fontSize: 12 }}>
              No taint analysis results. Right-click a line to start.
            </span>
          </div>
        )}
      </div>

      <div style={tabStyle("Strings")}>
        <StringsPanel
          sessionId={sessionId}
          isPhase2Ready={isPhase2Ready}
          onJumpToSeq={onJumpToSeq}
          stringsScanning={stringsScanning}
          onTraceCreation={onTraceStringCreation}
        />
      </div>

      <div style={tabStyle("Crypto")}>
        <CryptoPanel
          sessionId={sessionId}
          hasStringIndex={hasStringIndex}
          cryptoResults={cryptoResults}
          cryptoScanning={cryptoScanning}
          onJumpToSeq={onJumpToSeq}
          onScanStrings={onScanStrings}
          onTraceInput={onTraceDigestInput}
          onTraceMemory={onTraceMemory}
        />
      </div>

      <div style={tabStyle("Analyses")}>
        <AnalysisHistoryPanel sessionId={sessionId} />
      </div>

      <div style={tabStyle("Function")}>
        <FunctionInspectorPanel sessionId={sessionId} onJumpToSeq={onJumpToSeq} active={active === "Function"} />
      </div>

      <div style={tabStyle("Accesses")}>
        <div style={{ flex: 1, display: "flex", alignItems: "center", justifyContent: "center" }}>
          <span style={{ color: "var(--text-secondary)", fontSize: 12 }}></span>
        </div>
      </div>
      </div>{/* 关闭 relative 容器 */}
    </div>
  );
}
