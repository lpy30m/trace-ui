import React, { useState, useEffect, useCallback } from "react";
import { invoke } from "@tauri-apps/api/core";
import AnalysisCasePanel from "./AnalysisCasePanel";
import type {
  AnalysisRecordSummary,
  AnalysisRecord,
  AnalysisComparison,
  AnalysisEvidence,
} from "../types/trace";

interface Props {
  sessionId: string | null;
}

const KIND_COLORS: Record<string, string> = {
  crypto_functions: "#e5484d",
  known_digest: "#8e4ec6",
  backward_taint: "#0091ff",
  forward_taint: "#12a594",
  crypto_flow: "#f5a623",
  auto_investigation: "#e5484d",
  trace_diff: "#d6409f",
  recipe_run: "#5b5bd6",
  analysis_recipe: "#5b5bd6",
};

function kindColor(kind: string): string {
  return KIND_COLORS[kind] || "#8a8f98";
}

function fmtTime(ms: number): string {
  try {
    return new Date(ms).toLocaleString();
  } catch {
    return String(ms);
  }
}

const EVIDENCE_GROUPS: Array<[keyof AnalysisEvidence, string]> = [
  ["algorithms", "算法"],
  ["digests", "摘要"],
  ["functions", "函数"],
  ["modules", "模块"],
  ["keyStrings", "Key 字符串"],
  ["memoryReads", "内存读取"],
  ["memoryWrites", "内存写入"],
  ["addresses", "地址"],
  ["operations", "操作"],
  ["warnings", "警告"],
];

function EvidenceView({ evidence }: { evidence: AnalysisEvidence }) {
  const groups = EVIDENCE_GROUPS.filter(([k]) => (evidence[k]?.length ?? 0) > 0);
  if (groups.length === 0) {
    return <div style={{ color: "var(--text-tertiary)", fontSize: 11 }}>暂无记录证据。</div>;
  }
  return (
    <div style={{ display: "flex", flexDirection: "column", gap: 4 }}>
      {groups.map(([k, label]) => (
        <div key={k} style={{ display: "flex", gap: 6, alignItems: "baseline" }}>
          <span style={{ width: 78, flexShrink: 0, color: "var(--text-tertiary)", fontSize: 10, textAlign: "right" }}>
            {label}
          </span>
          <div style={{ display: "flex", flexWrap: "wrap", gap: 3 }}>
            {evidence[k].map((v, i) => (
              <span
                key={i}
                style={{
                  padding: "0 5px", borderRadius: 3, fontSize: 10,
                  background: k === "warnings" ? "rgba(229,72,77,0.15)" : "var(--bg-secondary)",
                  color: k === "warnings" ? "#e5484d" : "var(--text-secondary)",
                  border: "1px solid var(--border-color)",
                  maxWidth: 260, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap",
                }}
                title={v}
              >{v}</span>
            ))}
          </div>
        </div>
      ))}
    </div>
  );
}

function DetailView({ sessionId, id, onDeleted }: { sessionId: string; id: string; onDeleted: () => void }) {
  const [record, setRecord] = useState<AnalysisRecord | null>(null);
  const [err, setErr] = useState<string | null>(null);
  const [showJson, setShowJson] = useState(false);
  const [copied, setCopied] = useState<string | null>(null);

  useEffect(() => {
    let alive = true;
    setRecord(null);
    setErr(null);
    invoke<AnalysisRecord>("get_analysis", { sessionId, analysisId: id })
      .then(r => { if (alive) setRecord(r); })
      .catch(e => { if (alive) setErr(String(e)); });
    return () => { alive = false; };
  }, [sessionId, id]);

  const copyReport = useCallback(async (format: "markdown" | "json") => {
    try {
      const text = await invoke<string>("render_analysis_report", { sessionId, analysisId: id, format });
      await navigator.clipboard.writeText(text);
      setCopied(format);
      setTimeout(() => setCopied(null), 1500);
    } catch (e) {
      setErr(String(e));
    }
  }, [sessionId, id]);

  const del = useCallback(async () => {
    try {
      await invoke<boolean>("delete_analysis", { sessionId, analysisId: id });
      onDeleted();
    } catch (e) {
      setErr(String(e));
    }
  }, [sessionId, id, onDeleted]);

  if (err) return <div style={{ padding: 8, color: "#e5484d", fontSize: 11 }}>{err}</div>;
  if (!record) return <div style={{ padding: 8, color: "var(--text-secondary)", fontSize: 11 }}>加载中…</div>;

  const btn: React.CSSProperties = {
    fontSize: 11, padding: "2px 8px", cursor: "pointer",
    background: "var(--bg-input)", color: "var(--text-secondary)",
    border: "1px solid var(--border-color)", borderRadius: 3,
  };

  return (
    <div style={{ padding: "8px 12px 12px 30px", background: "var(--bg-secondary)", fontSize: 11 }}>
      <div style={{ display: "flex", gap: 6, marginBottom: 8 }}>
        <button style={btn} onClick={() => copyReport("markdown")}>{copied === "markdown" ? "已复制" : "复制 Markdown"}</button>
        <button style={btn} onClick={() => copyReport("json")}>{copied === "json" ? "已复制" : "复制 JSON"}</button>
        <span style={{ flex: 1 }} />
        <button style={{ ...btn, color: "#e5484d" }} onClick={del}>删除</button>
      </div>
      <EvidenceView evidence={record.evidence} />
      <div style={{ marginTop: 8 }}>
        <span
          onClick={() => setShowJson(s => !s)}
          style={{ cursor: "pointer", color: "var(--text-tertiary)", fontSize: 10 }}
        >{showJson ? "▼" : "▶"} 原始请求 / 结果 JSON</span>
        {showJson && (
          <pre style={{
            marginTop: 4, maxHeight: 320, overflow: "auto", fontSize: 10, lineHeight: 1.45,
            background: "var(--bg-primary)", border: "1px solid var(--border-color)", borderRadius: 3,
            padding: 8, color: "var(--text-primary)", whiteSpace: "pre-wrap", overflowWrap: "anywhere",
          }}>
{JSON.stringify({ request: record.request, result: record.result }, null, 2)}
          </pre>
        )}
      </div>
    </div>
  );
}

function AnalysisHistoryList({ sessionId }: Props) {
  const [list, setList] = useState<AnalysisRecordSummary[]>([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [expandedId, setExpandedId] = useState<string | null>(null);
  const [selected, setSelected] = useState<Set<string>>(new Set());
  const [comparison, setComparison] = useState<AnalysisComparison | null>(null);
  const [comparing, setComparing] = useState(false);

  const refresh = useCallback(async () => {
    if (!sessionId) { setList([]); return; }
    setLoading(true);
    setError(null);
    try {
      const r = await invoke<AnalysisRecordSummary[]>("list_analyses", { sessionId, limit: 100 });
      setList(r);
    } catch (e) {
      setError(String(e));
    } finally {
      setLoading(false);
    }
  }, [sessionId]);

  useEffect(() => {
    setExpandedId(null);
    setSelected(new Set());
    setComparison(null);
    refresh();
  }, [sessionId, refresh]);

  const toggleSelect = useCallback((id: string) => {
    setSelected(prev => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id); else next.add(id);
      return next;
    });
  }, []);

  const doCompare = useCallback(async () => {
    if (!sessionId || selected.size < 2) return;
    setComparing(true);
    setError(null);
    try {
      const c = await invoke<AnalysisComparison>("compare_analyses", {
        sessionId,
        analysisIds: Array.from(selected),
      });
      setComparison(c);
    } catch (e) {
      setError(String(e));
    } finally {
      setComparing(false);
    }
  }, [sessionId, selected]);

  return (
    <div style={{ flex: 1, display: "flex", flexDirection: "column", overflow: "hidden" }}>
      <div style={{
        display: "flex", alignItems: "center", gap: 8, padding: "4px 8px",
        borderBottom: "1px solid var(--border-color)", flexShrink: 0,
      }}>
        <button
          type="button"
          onClick={refresh}
          disabled={!sessionId || loading}
          style={{
            height: 24, padding: "0 10px", fontSize: 12, cursor: sessionId ? "pointer" : "default",
            background: "var(--bg-input)", color: "var(--text-primary)",
            border: "1px solid var(--border-color)", borderRadius: 3, opacity: loading ? 0.6 : 1,
          }}
        >{loading ? "…" : "刷新"}</button>
        <button
          type="button"
          onClick={doCompare}
          disabled={selected.size < 2 || comparing}
          style={{
            height: 24, padding: "0 10px", fontSize: 12,
            cursor: selected.size >= 2 ? "pointer" : "default",
            background: selected.size >= 2 ? "var(--btn-primary)" : "var(--bg-input)",
            color: selected.size >= 2 ? "#fff" : "var(--text-tertiary)",
            border: "1px solid var(--border-color)", borderRadius: 3,
          }}
        >比较（{selected.size}）</button>
        <span style={{ flex: 1 }} />
        <span style={{ color: "var(--text-tertiary)", fontSize: 11 }}>{list.length} 条记录</span>
      </div>

      <div style={{ flex: 1, overflow: "auto" }}>
        {error && <div style={{ padding: 12, color: "#e5484d", fontSize: 12 }}>{error}</div>}

        {comparison && (
          <div style={{ padding: 12, borderBottom: "2px solid var(--border-color)", background: "var(--bg-secondary)" }}>
            <div style={{ display: "flex", alignItems: "center", marginBottom: 6 }}>
              <span style={{ fontSize: 12, color: "var(--text-primary)" }}>
                比较 {comparison.analysisIds.length} 条记录 · 类型：{comparison.kinds.join(", ")}
              </span>
              <span style={{ flex: 1 }} />
              <span
                onClick={() => setComparison(null)}
                style={{ cursor: "pointer", color: "var(--text-secondary)", fontSize: 14 }}
              >×</span>
            </div>
            <div style={{ fontSize: 10, color: "var(--text-tertiary)", marginBottom: 3 }}>共同证据</div>
            <EvidenceView evidence={comparison.commonEvidence} />
            {comparison.uniqueEvidence.map(u => (
              <div key={u.analysisId} style={{ marginTop: 8 }}>
                <div style={{ fontSize: 10, color: "var(--text-tertiary)", marginBottom: 3 }}>
                  UNIQUE · {u.analysisId.slice(0, 8)}
                </div>
                <EvidenceView evidence={u.evidence} />
              </div>
            ))}
          </div>
        )}

        {!loading && !error && list.length === 0 && (
          <div style={{ padding: 16, color: "var(--text-secondary)", fontSize: 12, lineHeight: 1.6 }}>
            暂无保存的分析记录。可通过 AI/MCP 工具运行密码、污点、摘要或自动调查；记录会随 trace 保存并显示在这里。
          </div>
        )}

        {list.map(item => {
          const isExpanded = expandedId === item.analysisId;
          const isSelected = selected.has(item.analysisId);
          return (
            <div key={item.analysisId} style={{ borderBottom: "1px solid var(--border-color)" }}>
              <div
                style={{ display: "flex", alignItems: "center", gap: 8, padding: "5px 8px", cursor: "pointer", fontSize: 12 }}
                onClick={() => setExpandedId(isExpanded ? null : item.analysisId)}
              >
                <input
                  type="checkbox"
                  checked={isSelected}
                  onClick={(e) => e.stopPropagation()}
                  onChange={() => toggleSelect(item.analysisId)}
                  style={{ cursor: "pointer" }}
                />
                <span style={{
                  minWidth: 96, textAlign: "center", padding: "1px 4px", borderRadius: 3,
                  background: kindColor(item.kind), color: "#fff", fontSize: 9,
                  overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap",
                }}>{item.kind}</span>
                <span style={{ color: "var(--text-primary)", overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
                  {item.title}
                </span>
                <span style={{ flex: 1 }} />
                {item.warningCount > 0 && (
                  <span style={{ color: "#f5a623", fontSize: 10 }}>⚠ {item.warningCount}</span>
                )}
                <span style={{ color: "var(--text-tertiary)", fontSize: 10, whiteSpace: "nowrap" }}>
                  {fmtTime(item.createdAtMs)}
                </span>
              </div>
              {isExpanded && sessionId && (
                <DetailView
                  sessionId={sessionId}
                  id={item.analysisId}
                  onDeleted={() => { setExpandedId(null); refresh(); }}
                />
              )}
            </div>
          );
        })}
      </div>
    </div>
  );
}

export default function AnalysisHistoryPanel({ sessionId }: Props) {
  const [mode, setMode] = useState<"history" | "case">("history");
  const tabStyle = (selected: boolean): React.CSSProperties => ({
    height: 25,
    padding: "0 12px",
    border: "none",
    borderBottom: selected ? "2px solid var(--btn-primary)" : "2px solid transparent",
    background: "transparent",
    color: selected ? "var(--text-primary)" : "var(--text-secondary)",
    cursor: "pointer",
    fontSize: 11,
  });
  return (
    <div style={{ height: "100%", display: "flex", flexDirection: "column", overflow: "hidden" }}>
      <div style={{ display: "flex", alignItems: "center", padding: "0 8px", borderBottom: "1px solid var(--border-color)", flexShrink: 0 }}>
        <button style={tabStyle(mode === "history")} onClick={() => setMode("history")}>分析记录</button>
        <button style={tabStyle(mode === "case")} onClick={() => setMode("case")}>案件 / Replay Doctor</button>
      </div>
      <div style={{ flex: 1, minHeight: 0, overflow: "hidden" }}>
        {mode === "history" ? <AnalysisHistoryList sessionId={sessionId} /> : <AnalysisCasePanel sessionId={sessionId} />}
      </div>
    </div>
  );
}
