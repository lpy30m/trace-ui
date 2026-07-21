import React, { useCallback, useEffect, useMemo, useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import { emit } from "@tauri-apps/api/event";
import type {
  CryptoFormula,
  CryptoMaterial,
  CryptoMaterialMultiTraceReport,
  CryptoMaterialReport,
  CryptoMaterialTraceCase,
  TraceSessionInfo,
} from "../types/trace";

interface Props {
  sessionId: string | null;
  onJumpToSeq: (seq: number) => void;
  onCreateHook?: (material: CryptoMaterial) => void;
}

interface EditableCase extends CryptoMaterialTraceCase {
  selected: boolean;
}

const buttonStyle: React.CSSProperties = {
  height: 24,
  padding: "0 10px",
  border: "1px solid var(--border-color)",
  borderRadius: 3,
  background: "var(--bg-input)",
  color: "var(--text-primary)",
  cursor: "pointer",
  fontFamily: "inherit",
  fontSize: 11,
};

const inputStyle: React.CSSProperties = {
  height: 24,
  padding: "0 6px",
  border: "1px solid var(--border-color)",
  borderRadius: 3,
  background: "var(--input-bg)",
  color: "var(--text-primary)",
  fontFamily: "inherit",
  fontSize: 11,
};

function gradeColor(grade: string): string {
  if (grade === "verified") return "#238636";
  if (grade === "related") return "#9e6a03";
  return "#6e7681";
}

function kindColor(kind: string): string {
  switch (kind) {
    case "key":
    case "expandedKey":
    case "derivedKey": return "#e5484d";
    case "password":
    case "salt": return "#d29922";
    case "iv":
    case "nonce":
    case "counter": return "#a371f7";
    case "digest":
    case "mac":
    case "authTag": return "#2f81f7";
    default: return "var(--text-secondary)";
  }
}

function GradeBadge({ grade, score }: { grade: string; score: number }) {
  return (
    <span style={{
      minWidth: 70,
      padding: "1px 6px",
      borderRadius: 3,
      textAlign: "center",
      color: "#fff",
      background: gradeColor(grade),
      fontSize: 10,
      textTransform: "uppercase",
    }}>
      {grade} {score}
    </span>
  );
}

function MaterialRow({ material, onJumpToSeq, onCreateHook }: {
  material: CryptoMaterial;
  onJumpToSeq: (seq: number) => void;
  onCreateHook?: (material: CryptoMaterial) => void;
}) {
  const [open, setOpen] = useState(false);
  const hexPreview = material.bytesHex
    ? `${material.bytesHex.slice(0, 96)}${material.bytesHex.length > 96 ? "…" : ""}`
    : "bytes not captured";
  return (
    <div style={{ borderBottom: "1px solid var(--border-color)" }}>
      <div
        onClick={() => setOpen(value => !value)}
        style={{ display: "flex", alignItems: "center", gap: 8, minHeight: 31, padding: "4px 8px", cursor: "pointer", fontSize: 11 }}
      >
        <GradeBadge grade={material.assessment.grade} score={material.assessment.score} />
        <span style={{ width: 78, color: kindColor(material.kind), fontWeight: 600 }}>{material.kind}</span>
        <span style={{ width: 120, color: "var(--text-secondary)" }}>{material.role}</span>
        <span style={{ width: 112, color: "var(--asm-mnemonic)" }}>{material.algorithm || "—"}</span>
        <code title={material.bytesHex || undefined} style={{ flex: 1, minWidth: 80, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap", color: "var(--text-primary)" }}>
          {hexPreview}
        </code>
        <span style={{ width: 56, color: "var(--text-tertiary)", textAlign: "right" }}>
          {material.byteLen == null ? "—" : `${material.byteLen} B`}
        </span>
        {material.observationSeq != null && (
          <button
            type="button"
            style={buttonStyle}
            onClick={event => { event.stopPropagation(); onJumpToSeq(material.observationSeq!); }}
          >
            Line {material.observationSeq + 1}
          </button>
        )}
      </div>
      {open && (
        <div style={{ padding: "7px 12px 10px 87px", background: "var(--bg-secondary)", color: "var(--text-secondary)", fontSize: 11 }}>
          <div style={{ display: "flex", gap: 6, flexWrap: "wrap", marginBottom: 6 }}>
            {material.bytesHex && (
              <button type="button" style={buttonStyle} onClick={() => navigator.clipboard.writeText(material.bytesHex!)}>Copy hex</button>
            )}
            {material.address && material.observationSeq != null && (
              <button
                type="button"
                style={buttonStyle}
                onClick={() => emit("action:view-in-memory", { addr: material.address, seq: material.observationSeq })}
              >
                View memory
              </button>
            )}
            {onCreateHook && (
              <button type="button" style={buttonStyle} onClick={() => onCreateHook(material)}>Hook capture</button>
            )}
            <span>{material.address || "no address"}</span>
            <span>{material.functionName || material.source}</span>
            {material.register && <span>{material.register}</span>}
          </div>
          {material.asciiPreview && <div style={{ marginBottom: 5 }}>ASCII: <code>{material.asciiPreview}</code></div>}
          {material.evidence.map((item, index) => <div key={index}>• {item}</div>)}
          {material.assessment.limitations.map((item, index) => (
            <div key={`limit-${index}`} style={{ color: "var(--text-tertiary)" }}>△ {item}</div>
          ))}
        </div>
      )}
    </div>
  );
}

function FormulaRow({ formula, onJumpToSeq }: { formula: CryptoFormula; onJumpToSeq: (seq: number) => void }) {
  return (
    <div style={{ display: "flex", alignItems: "center", gap: 8, padding: "6px 8px", borderBottom: "1px solid var(--border-color)", fontSize: 11 }}>
      <GradeBadge grade={formula.assessment.grade} score={formula.assessment.score} />
      <span style={{ width: 62, color: "var(--syntax-keyword)" }}>{formula.operation}</span>
      <code style={{ flex: 1, color: "var(--text-primary)", overflowWrap: "anywhere" }}>{formula.expression}</code>
      {formula.callSeq != null && (
        <button type="button" style={buttonStyle} onClick={() => onJumpToSeq(formula.callSeq!)}>Jump</button>
      )}
    </div>
  );
}

export default function CryptoMaterialsPanel({ sessionId, onJumpToSeq, onCreateHook }: Props) {
  const [report, setReport] = useState<CryptoMaterialReport | null>(null);
  const [comparison, setComparison] = useState<CryptoMaterialMultiTraceReport | null>(null);
  const [cases, setCases] = useState<EditableCase[]>([]);
  const [includeUnknown, setIncludeUnknown] = useState(false);
  const [loading, setLoading] = useState(false);
  const [comparing, setComparing] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [section, setSection] = useState<"materials" | "formulas" | "compare">("materials");

  useEffect(() => {
    setReport(null);
    setComparison(null);
    setError(null);
  }, [sessionId]);

  const refreshSessions = useCallback(async () => {
    try {
      const sessions = await invoke<TraceSessionInfo[]>("list_trace_sessions");
      setCases(previous => sessions.map((session, index) => {
        const existing = previous.find(item => item.sessionId === session.sessionId);
        const fileName = session.filePath.split(/[\\/]/).pop() || `trace-${index + 1}`;
        return existing || {
          sessionId: session.sessionId,
          label: fileName,
          inputGroup: "input-a",
          selected: session.sessionId === sessionId,
        };
      }));
    } catch (reason) {
      setError(String(reason));
    }
  }, [sessionId]);

  useEffect(() => {
    if (section === "compare") void refreshSessions();
  }, [section, refreshSessions]);

  const analyze = useCallback(async () => {
    if (!sessionId) return;
    setLoading(true);
    setError(null);
    try {
      const value = await invoke<CryptoMaterialReport>("analyze_crypto_materials", {
        sessionId,
        maxMaterials: 1000,
        includeUnknown,
      });
      setReport(value);
    } catch (reason) {
      setError(String(reason));
      setReport(null);
    } finally {
      setLoading(false);
    }
  }, [includeUnknown, sessionId]);

  const selectedCases = useMemo(() => cases.filter(item => item.selected), [cases]);
  const compare = useCallback(async () => {
    if (selectedCases.length < 2) return;
    setComparing(true);
    setError(null);
    try {
      const value = await invoke<CryptoMaterialMultiTraceReport>("compare_crypto_material_traces", {
        request: {
          cases: selectedCases.map(({ sessionId: selectedSessionId, label, inputGroup }) => ({
            sessionId: selectedSessionId,
            label,
            inputGroup,
          })),
        },
      });
      setComparison(value);
    } catch (reason) {
      setError(String(reason));
      setComparison(null);
    } finally {
      setComparing(false);
    }
  }, [selectedCases]);

  const updateCase = (index: number, patch: Partial<EditableCase>) => {
    setCases(items => items.map((item, itemIndex) => itemIndex === index ? { ...item, ...patch } : item));
  };

  return (
    <div style={{ flex: 1, minWidth: 0, minHeight: 0, display: "flex", flexDirection: "column", overflow: "hidden" }}>
      <div style={{
        display: "flex", alignItems: "center", gap: 7, padding: "4px 8px",
        borderBottom: "1px solid var(--border-color)", flexShrink: 0,
        overflowX: "auto", overflowY: "hidden",
      }}>
        <button
          type="button"
          style={{ ...buttonStyle, background: "var(--btn-primary)", color: "#fff", border: "none", opacity: !sessionId || loading ? 0.6 : 1 }}
          disabled={!sessionId || loading}
          onClick={analyze}
        >
          {loading ? "Indexing…" : "Index Materials"}
        </button>
        <label style={{ display: "flex", alignItems: "center", gap: 4, fontSize: 11, color: "var(--text-secondary)", flexShrink: 0, whiteSpace: "nowrap" }}>
          <input type="checkbox" checked={includeUnknown} onChange={event => setIncludeUnknown(event.target.checked)} />
          Include unclassified call buffers
        </label>
        <span style={{ flex: 1 }} />
        {report && (
          <span style={{ color: "var(--text-tertiary)", fontSize: 11, flexShrink: 0, whiteSpace: "nowrap" }}>
            {report.materials.length} materials · {report.verifiedMaterials} verified · {report.formulas.length} formulas
          </span>
        )}
      </div>
      <div style={{ display: "flex", borderBottom: "1px solid var(--border-color)", flexShrink: 0, overflowX: "auto", overflowY: "hidden" }}>
        {(["materials", "formulas", "compare"] as const).map(item => (
          <button
            key={item}
            type="button"
            style={{
              ...buttonStyle,
              height: 27,
              border: "none",
              borderRight: "1px solid var(--border-color)",
              borderRadius: 0,
              background: section === item ? "var(--bg-selected)" : "var(--bg-input)",
              textTransform: "capitalize",
              flexShrink: 0,
            }}
            onClick={() => setSection(item)}
          >
            {item === "compare" ? "Multi-trace Salt/Nonce" : item}
          </button>
        ))}
      </div>

      <div style={{ flex: 1, minHeight: 0, overflow: "auto" }}>
        {error && <div style={{ padding: 12, color: "#e5484d", fontSize: 11 }}>{error}</div>}
        {!report && !loading && section !== "compare" && (
          <div style={{ padding: 16, color: "var(--text-secondary)", fontSize: 12 }}>
            Index observed key, input, output, IV/nonce, digest, HMAC and KDF material. Verified means the observed bytes were deterministically recomputed.
          </div>
        )}
        {section === "materials" && report?.materials.map(material => (
          <MaterialRow key={material.materialId} material={material} onJumpToSeq={onJumpToSeq} onCreateHook={onCreateHook} />
        ))}
        {section === "materials" && report && report.materials.length === 0 && (
          <div style={{ padding: 16, color: "var(--text-secondary)", fontSize: 12 }}>
            No material-bearing crypto calls or semantically verified cipher buffers were observed in this trace.
          </div>
        )}
        {section === "formulas" && report?.formulas.map(formula => (
          <FormulaRow key={formula.formulaId} formula={formula} onJumpToSeq={onJumpToSeq} />
        ))}
        {section === "formulas" && report && report.formulas.length === 0 && (
          <div style={{ padding: 16, color: "var(--text-secondary)", fontSize: 12 }}>No complete crypto formulas reconstructed.</div>
        )}
        {section === "compare" && (
          <div style={{ padding: 8, fontSize: 11 }}>
            <div style={{ color: "var(--text-secondary)", marginBottom: 8 }}>
              Label traces with the same primary input group. A changing digest-input range is reported as a salt/nonce candidate, never as proof by itself.
            </div>
            <div style={{ display: "grid", gridTemplateColumns: "26px minmax(160px, 1fr) minmax(120px, 220px) minmax(120px, 220px)", gap: 5, alignItems: "center" }}>
              <span />
              <strong>Open trace</strong>
              <strong>Case label</strong>
              <strong>Primary input group</strong>
              {cases.map((item, index) => (
                <React.Fragment key={item.sessionId}>
                  <input type="checkbox" checked={item.selected} onChange={event => updateCase(index, { selected: event.target.checked })} />
                  <span title={item.sessionId} style={{ overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{item.label}</span>
                  <input style={inputStyle} value={item.label} onChange={event => updateCase(index, { label: event.target.value })} />
                  <input style={inputStyle} value={item.inputGroup} onChange={event => updateCase(index, { inputGroup: event.target.value })} />
                </React.Fragment>
              ))}
            </div>
            <div style={{ display: "flex", gap: 6, marginTop: 9 }}>
              <button type="button" style={buttonStyle} onClick={refreshSessions}>Refresh sessions</button>
              <button
                type="button"
                style={{ ...buttonStyle, background: "var(--btn-primary)", color: "#fff", border: "none", opacity: selectedCases.length < 2 || comparing ? 0.6 : 1 }}
                disabled={selectedCases.length < 2 || comparing}
                onClick={compare}
              >
                {comparing ? "Comparing…" : `Compare ${selectedCases.length} traces`}
              </button>
            </div>
            {comparison && (
              <div style={{ marginTop: 12, borderTop: "1px solid var(--border-color)" }}>
                <div style={{ padding: "8px 0", color: "var(--text-secondary)" }}>
                  {comparison.dynamicParameterCandidates.length} dynamic parameter candidates · verification gate remains closed
                </div>
                {comparison.dynamicParameterCandidates.map((candidate, index) => (
                  <div key={`${candidate.leftLabel}-${candidate.rightLabel}-${index}`} style={{ padding: "7px 8px", border: "1px solid var(--border-color)", borderRadius: 4, marginBottom: 6, background: "var(--bg-secondary)" }}>
                    <div style={{ display: "flex", alignItems: "center", gap: 7 }}>
                      <GradeBadge grade={candidate.assessment.grade} score={candidate.assessment.score} />
                      <strong>{candidate.roleHint}</strong>
                      <span>{candidate.algorithm}</span>
                      <span>{candidate.leftLabel} ↔ {candidate.rightLabel}</span>
                      <span>offset +{candidate.byteOffset}</span>
                    </div>
                    <div style={{ marginTop: 5 }}>left: <code>{candidate.leftVariableHex || "∅"}</code></div>
                    <div>right: <code>{candidate.rightVariableHex || "∅"}</code></div>
                    <div style={{ color: "var(--text-tertiary)", marginTop: 4 }}>{candidate.rationale}</div>
                  </div>
                ))}
              </div>
            )}
          </div>
        )}
      </div>
    </div>
  );
}
