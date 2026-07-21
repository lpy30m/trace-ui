import React, { useState, useCallback } from "react";
import { invoke } from "@tauri-apps/api/core";
import type { CryptoFunctionReport, CryptoFunctionCandidate } from "../types/trace";

interface Props {
  sessionId: string | null;
  onJumpToSeq: (seq: number) => void;
  onCreateHook?: (candidate: CryptoFunctionCandidate) => void;
}

function confColor(confidence: string): string {
  switch (confidence) {
    case "high": return "#e5484d";
    case "medium": return "#f5a623";
    default: return "#8a8f98";
  }
}

function CandidateRow({ c, onJumpToSeq, onCreateHook }: {
  c: CryptoFunctionCandidate;
  onJumpToSeq: (s: number) => void;
  onCreateHook?: (candidate: CryptoFunctionCandidate) => void;
}) {
  const [open, setOpen] = useState(false);
  const insn = Object.entries(c.cryptoInsnCounts)
    .map(([k, v]) => `${k}×${v}`)
    .join(" ");
  const shapes = Object.entries(c.softwareShapeCounts)
    .map(([k, v]) => `${k}×${v}`)
    .join(" ");
  return (
    <div style={{ borderBottom: "1px solid var(--border-color)" }}>
      <div
        onClick={() => setOpen(o => !o)}
        style={{
          display: "flex", alignItems: "center", gap: 8, padding: "5px 8px",
          cursor: "pointer", fontSize: 12,
        }}
      >
        <span style={{
          minWidth: 54, textAlign: "center", padding: "1px 6px", borderRadius: 3,
          background: confColor(c.assessment.confidence), color: "#fff", fontSize: 10, textTransform: "uppercase",
        }}>{c.assessment.confidence}</span>
        <span style={{ width: 34, color: "var(--text-tertiary)" }}>{c.assessment.score}</span>
        <span style={{ color: "var(--syntax-keyword)", minWidth: 120 }}>
          {c.algorithms.join(", ") || "—"}
        </span>
        <span
          onClick={(e) => { e.stopPropagation(); onJumpToSeq(c.entrySeq); }}
          style={{ color: "var(--syntax-literal)", textDecoration: "underline", cursor: "pointer" }}
          title="Jump to function entry"
        >{c.funcName || c.funcAddr}</span>
        <span style={{ flex: 1 }} />
        {onCreateHook && (
          <button
            type="button"
            onClick={event => { event.stopPropagation(); onCreateHook(c); }}
            style={{ height: 23, padding: "0 8px", border: "1px solid var(--border-color)", borderRadius: 3, background: "var(--bg-input)", color: "var(--text-primary)", cursor: "pointer", fontSize: 11 }}
          >Hook</button>
        )}
        <span style={{ color: "var(--text-tertiary)", fontSize: 11 }}>
          {c.magicHits > 0 && `${c.distinctMagics} const`}
          {c.cryptoInsnTotal > 0 && `  ${insn}`}
          {`  ·${c.lineCount} ln`}
        </span>
      </div>
      {open && (
        <div style={{ padding: "6px 12px 10px 68px", fontSize: 11, color: "var(--text-secondary)", background: "var(--bg-secondary)" }}>
          <div style={{ marginBottom: 4 }}>
            entry seq {c.entrySeq + 1} · exit seq {c.exitSeq + 1} · {c.funcAddr}
          </div>
          {c.io.entryArgs.length > 0 && (
            <div style={{ marginBottom: 4 }}>
              args: {c.io.entryArgs.map(a => `${a.reg}=${a.value}`).join("  ")}
            </div>
          )}
          {c.io.returnValue && <div style={{ marginBottom: 4 }}>return X0={c.io.returnValue}</div>}
          {c.io.callAnnotation && (
            <div style={{ marginBottom: 4, color: "var(--syntax-comment)" }}>
              call: {c.io.callAnnotation.funcName}
              {c.io.callAnnotation.retValue ? ` → ${c.io.callAnnotation.retValue}` : ""}
            </div>
          )}
          {c.implementationHints.length > 0 && (
            <div style={{ marginBottom: 4 }}>
              implementation: {c.implementationHints.join(", ")}
            </div>
          )}
          {c.softwareShapeTotal > 0 && (
            <div style={{ marginBottom: 4 }}>
              software shape: {shapes} ({c.softwareShapeTotal} total)
            </div>
          )}
          <div style={{ marginTop: 6, borderTop: "1px solid var(--border-color)", paddingTop: 6 }}>
            {c.assessment.factors.filter(f => f.observed).map(f => (
              <div key={f.code} style={{ display: "flex", gap: 8 }}>
                <span style={{ width: 40, color: f.awardedPoints >= 0 ? "#3fb950" : "#e5484d" }}>
                  {f.awardedPoints >= 0 ? "+" : ""}{f.awardedPoints}
                </span>
                <span>{f.label}</span>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}

export default function CryptoFunctionsPanel({ sessionId, onJumpToSeq, onCreateHook }: Props) {
  const [report, setReport] = useState<CryptoFunctionReport | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const analyze = useCallback(async () => {
    if (!sessionId) return;
    setLoading(true);
    setError(null);
    try {
      const r = await invoke<CryptoFunctionReport>("analyze_crypto_functions", { sessionId });
      setReport(r);
    } catch (e) {
      setError(String(e));
      setReport(null);
    } finally {
      setLoading(false);
    }
  }, [sessionId]);

  return (
    <div style={{ flex: 1, display: "flex", flexDirection: "column", overflow: "hidden" }}>
      <div style={{
        display: "flex", alignItems: "center", gap: 8, padding: "4px 8px",
        borderBottom: "1px solid var(--border-color)", flexShrink: 0,
      }}>
        <button
          type="button"
          onClick={analyze}
          disabled={!sessionId || loading}
          style={{
            height: 24, padding: "0 12px", fontSize: 12, cursor: sessionId ? "pointer" : "default",
            background: "var(--btn-primary)", color: "#fff", border: "none", borderRadius: 3,
            opacity: !sessionId || loading ? 0.6 : 1,
          }}
        >{loading ? "Analyzing..." : "Analyze Functions"}</button>
        {report && (
          <span style={{ color: "var(--text-tertiary)", fontSize: 11 }}>
            {report.candidates.length} candidates · {report.magicHitCount} const hits · {report.cryptoInsnCount} crypto insns
            {report.candidatesTruncated && " (truncated)"}
          </span>
        )}
      </div>

      <div style={{ flex: 1, overflow: "auto" }}>
        {error && <div style={{ padding: 16, color: "#e5484d", fontSize: 12 }}>{error}</div>}
        {!error && !report && !loading && (
          <div style={{ padding: 16, color: "var(--text-secondary)", fontSize: 12 }}>
            Click "Analyze Functions" to aggregate crypto evidence by function.
          </div>
        )}
        {report && report.candidates.length === 0 && (
          <div style={{ padding: 16, color: "var(--text-secondary)", fontSize: 12 }}>
            No crypto signals found in any function.
          </div>
        )}
        {report && report.candidates.map(c => (
          <CandidateRow key={c.funcId} c={c} onJumpToSeq={onJumpToSeq} onCreateHook={onCreateHook} />
        ))}
      </div>
    </div>
  );
}
