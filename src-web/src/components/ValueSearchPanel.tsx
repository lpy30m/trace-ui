import React, { useCallback, useMemo, useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import { emit } from "@tauri-apps/api/event";
import type {
  ForwardSliceResult,
  ValueEndian,
  ValueSearchKind,
  ValueSearchMatch,
  ValueSearchRequest,
  ValueSearchResponse,
} from "../types/trace";

interface Props {
  sessionId: string | null;
  onJumpToSeq: (seq: number) => void;
  onTraceMemory?: (request: { addr: string; size: number; seq: number }) => Promise<void> | void;
}

const buttonStyle: React.CSSProperties = {
  height: 26,
  padding: "0 9px",
  border: "1px solid var(--border-color)",
  borderRadius: 4,
  background: "var(--bg-input)",
  color: "var(--text-primary)",
  cursor: "pointer",
  fontFamily: "inherit",
  fontSize: 11,
  whiteSpace: "nowrap",
};

const inputStyle: React.CSSProperties = {
  height: 28,
  border: "1px solid var(--border-color)",
  borderRadius: 4,
  background: "var(--bg-input)",
  color: "var(--text-primary)",
  fontFamily: "inherit",
  fontSize: 12,
  padding: "0 8px",
};

const sourceLabel = (source: string) => ({ strings: "字符串", memory: "内存", trace: "Trace" })[source] ?? source;

export default function ValueSearchPanel({ sessionId, onJumpToSeq, onTraceMemory }: Props) {
  const [query, setQuery] = useState("");
  const [kind, setKind] = useState<ValueSearchKind>("auto");
  const [endian, setEndian] = useState<ValueEndian>("both");
  const [width, setWidth] = useState("");
  const [includeNul, setIncludeNul] = useState(false);
  const [searchStrings, setSearchStrings] = useState(true);
  const [searchMemory, setSearchMemory] = useState(true);
  const [searchTrace, setSearchTrace] = useState(true);
  const [advanced, setAdvanced] = useState(false);
  const [response, setResponse] = useState<ValueSearchResponse | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [forwardStatus, setForwardStatus] = useState<string | null>(null);

  const request = useMemo<ValueSearchRequest>(() => ({
    query,
    kind,
    endian,
    integerWidth: width ? Number(width) : null,
    includeUtf8: true,
    includeUtf16le: true,
    includeNul,
    searchStrings,
    searchMemory,
    searchTrace,
    maxResults: 500,
  }), [endian, includeNul, kind, query, searchMemory, searchStrings, searchTrace, width]);

  const runSearch = useCallback(async () => {
    if (!sessionId) {
      setError("请先打开 trace，再搜索值。");
      return;
    }
    if (!query) {
      setError("请输入要搜索的值。文本会按原样匹配，包括空格和大小写。");
      return;
    }
    if (!searchStrings && !searchMemory && !searchTrace) {
      setError("请至少启用一种搜索来源。");
      return;
    }
    setLoading(true);
    setError(null);
    setForwardStatus(null);
    try {
      setResponse(await invoke<ValueSearchResponse>("search_value", { sessionId, request }));
    } catch (searchError) {
      setError(String(searchError));
    } finally {
      setLoading(false);
    }
  }, [query, request, searchMemory, searchStrings, searchTrace, sessionId]);

  const interpretationFor = useCallback((match: ValueSearchMatch) =>
    response?.interpretations[match.interpretationIndex], [response]);

  const viewMemory = useCallback((match: ValueSearchMatch) => {
    if (!match.addr) return;
    emit("action:view-in-memory", { addr: match.addr, seq: match.lastSeq });
  }, []);

  const traceBackward = useCallback((match: ValueSearchMatch) => {
    const interpretation = interpretationFor(match);
    if (!match.addr || !interpretation || !onTraceMemory) return;
    void onTraceMemory({ addr: match.addr, size: interpretation.byteLen, seq: match.lastSeq });
  }, [interpretationFor, onTraceMemory]);

  const traceForward = useCallback(async (match: ValueSearchMatch) => {
    if (!sessionId || !match.addr) return;
    const interpretation = interpretationFor(match);
    if (!interpretation) return;
    setForwardStatus("正在向前追踪…");
    setError(null);
    try {
      const result = await invoke<ForwardSliceResult>("run_forward_value_taint", {
        sessionId,
        addr: match.addr,
        size: interpretation.byteLen,
        seq: match.lastSeq,
      });
      setForwardStatus(
        `${result.affectedCount.toLocaleString()} 条受影响指令，${result.terminalSeqs.length.toLocaleString()} 个终点${result.truncated ? "（结果已截断）" : ""}`,
      );
      const endpoint = result.terminalSeqs[result.terminalSeqs.length - 1];
      if (endpoint !== undefined) onJumpToSeq(endpoint);
    } catch (traceError) {
      setError(`向前污点追踪失败：${String(traceError)}`);
      setForwardStatus(null);
    }
  }, [interpretationFor, onJumpToSeq, sessionId]);

  return (
    <div style={{ flex: 1, minWidth: 0, minHeight: 0, display: "flex", flexDirection: "column", overflow: "hidden" }}>
      <div style={{ padding: 8, borderBottom: "1px solid var(--border-color)", flexShrink: 0 }}>
        <div style={{ display: "flex", gap: 6 }}>
          <input
            value={query}
            onChange={(event) => setQuery(event.target.value)}
            onKeyDown={(event) => { if (event.key === "Enter") void runSearch(); }}
            placeholder="文本、0x 地址、整数、十六进制字节或摘要"
            style={{ ...inputStyle, flex: 1, minWidth: 160 }}
          />
          <select value={kind} onChange={(event) => setKind(event.target.value as ValueSearchKind)} style={inputStyle}>
            <option value="auto">自动识别</option>
            <option value="text">文本</option>
            <option value="hex">十六进制</option>
            <option value="integer">整数</option>
            <option value="address">地址</option>
            <option value="digest">摘要字节</option>
          </select>
          <button type="button" style={buttonStyle} onClick={() => setAdvanced(value => !value)}>高级选项</button>
          <button type="button" style={buttonStyle} disabled={loading} onClick={() => void runSearch()}>
            {loading ? "搜索中…" : "搜索"}
          </button>
        </div>
        {advanced && (
          <div style={{ display: "flex", gap: 12, alignItems: "center", marginTop: 7, flexWrap: "wrap", color: "var(--text-secondary)", fontSize: 11 }}>
            <label>字节序 <select value={endian} onChange={(event) => setEndian(event.target.value as ValueEndian)} style={{ ...inputStyle, height: 24, marginLeft: 4 }}>
              <option value="both">两者</option><option value="little">小端</option><option value="big">大端</option>
            </select></label>
            <label>宽度 <select value={width} onChange={(event) => setWidth(event.target.value)} style={{ ...inputStyle, height: 24, marginLeft: 4 }}>
              <option value="">自动</option><option value="1">1</option><option value="2">2</option><option value="4">4</option><option value="8">8</option>
            </select></label>
            <label><input type="checkbox" checked={includeNul} onChange={(event) => setIncludeNul(event.target.checked)} /> NUL 形式</label>
            <label><input type="checkbox" checked={searchStrings} onChange={(event) => setSearchStrings(event.target.checked)} /> 字符串索引</label>
            <label><input type="checkbox" checked={searchMemory} onChange={(event) => setSearchMemory(event.target.checked)} /> 内存历史</label>
            <label><input type="checkbox" checked={searchTrace} onChange={(event) => setSearchTrace(event.target.checked)} /> Trace 文本</label>
          </div>
        )}
        <div style={{ marginTop: 5, color: "var(--text-secondary)", fontSize: 10 }}>
          自动模式会列出所有解释方式；十六进制保持输入顺序，整数和地址会标注字节序。
        </div>
      </div>

      {(error || forwardStatus || response) && (
        <div style={{ padding: "6px 8px", borderBottom: "1px solid var(--border-color)", flexShrink: 0, fontSize: 11 }}>
          {error && <div style={{ color: "var(--text-changes)" }}>{error}</div>}
          {forwardStatus && <div style={{ color: "var(--syntax-string)" }}>{forwardStatus}</div>}
          {response && (
            <>
              <div style={{ color: "var(--text-secondary)" }}>
                {response.totalMatches.toLocaleString()} 个匹配 · 扫描 {response.stringsScanned.toLocaleString()} 个字符串 · {response.writesScanned.toLocaleString()} 次写入 · {response.traceLinesScanned.toLocaleString()} 行 trace
                {response.truncated ? " · 结果已截断" : ""}
              </div>
              <div style={{ display: "flex", gap: 5, flexWrap: "wrap", marginTop: 5 }}>
                {response.interpretations.map((item, index) => (
                  <span key={`${item.kind}-${item.bytesHex}-${index}`} title={item.bytesHex} style={{ padding: "2px 5px", border: "1px solid var(--border-color)", borderRadius: 3, color: "var(--text-primary)" }}>
                    {index}: {item.label} · {item.byteLen}B · {item.bytesHex.length > 32 ? `${item.bytesHex.slice(0, 32)}…` : item.bytesHex}
                  </span>
                ))}
              </div>
              {response.warnings.map((warning, index) => <div key={index} style={{ color: "var(--syntax-number)", marginTop: 3 }}>{warning}</div>)}
            </>
          )}
        </div>
      )}

      <div style={{ flex: 1, minHeight: 0, overflow: "auto" }}>
        {response && response.matches.length === 0 && (
          <div style={{ padding: 18, textAlign: "center", color: "var(--text-secondary)", fontSize: 12 }}>没有找到值匹配项。</div>
        )}
        {response?.matches.map((match, index) => {
          const interpretation = response.interpretations[match.interpretationIndex];
          const canTaint = Boolean(match.addr && match.source !== "trace");
          return (
            <div key={`${match.source}-${match.seq}-${match.addr}-${match.interpretationIndex}-${index}`} style={{ display: "grid", gridTemplateColumns: "72px 88px minmax(180px, 1fr) auto", gap: 8, alignItems: "center", minHeight: 34, padding: "4px 8px", borderBottom: "1px solid var(--border-color)", background: index % 2 ? "var(--bg-row-odd)" : "var(--bg-row-even)", fontSize: 11 }}>
              <span style={{ color: "var(--syntax-keyword)" }}>{sourceLabel(match.source)}</span>
              <span style={{ color: "var(--syntax-number)" }}>第 {match.seq + 1} 行</span>
              <div style={{ minWidth: 0 }}>
                <div style={{ color: "var(--text-primary)", overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }} title={match.preview}>{match.preview || "（无预览）"}</div>
                <div style={{ color: "var(--text-secondary)", overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
                  [{match.interpretationIndex}] {interpretation?.label} · {match.addr ?? "无内存地址"}
                  {match.writeSeqs.length > 1 ? ` · 写入行 ${match.writeSeqs.map(seq => seq + 1).join(", ")}` : ""}
                </div>
              </div>
              <div style={{ display: "flex", gap: 4 }}>
                <button type="button" style={buttonStyle} onClick={() => onJumpToSeq(match.seq)}>跳转</button>
                <button type="button" style={{ ...buttonStyle, opacity: match.addr ? 1 : 0.45 }} disabled={!match.addr} onClick={() => viewMemory(match)}>查看内存</button>
                <button type="button" style={{ ...buttonStyle, opacity: canTaint && onTraceMemory ? 1 : 0.45 }} disabled={!canTaint || !onTraceMemory} onClick={() => traceBackward(match)}>向后追踪</button>
                <button type="button" style={{ ...buttonStyle, opacity: canTaint ? 1 : 0.45 }} disabled={!canTaint} onClick={() => void traceForward(match)}>向前追踪</button>
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
}
