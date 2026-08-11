import { useMemo, useState } from "react";
import type { CSSProperties } from "react";
import { invoke } from "@tauri-apps/api/core";
import type {
  MemoryObjectGraphReport,
  MemoryObjectRecord,
  MemoryPointerExplanation,
} from "../types/trace";
import { useSelectedSeq } from "../stores/selectedSeqStore";

interface Props {
  sessionId: string | null;
  isPhase2Ready: boolean;
  onJumpToSeq: (seq: number) => void;
}

const buttonStyle: CSSProperties = {
  border: "1px solid var(--border-color)",
  borderRadius: 4,
  background: "var(--btn-secondary, #3e4451)",
  color: "var(--text-primary)",
  padding: "4px 10px",
  fontSize: 11,
  cursor: "pointer",
};

const inputStyle: CSSProperties = {
  border: "1px solid var(--border-color)",
  borderRadius: 4,
  background: "var(--bg-primary)",
  color: "var(--text-primary)",
  padding: "4px 7px",
  fontFamily: "var(--font-mono)",
  fontSize: 11,
};

function count(value: number): string {
  return value.toLocaleString();
}

function objectLabel(object: MemoryObjectRecord): string {
  return object.functionName || object.allocator || object.kind;
}

function lifetimeColor(value: string): string {
  if (value.includes("live")) return "var(--text-address)";
  if (value.includes("released")) return "var(--text-changes)";
  return "var(--text-secondary)";
}

export default function MemoryObjectsPanel({ sessionId, isPhase2Ready, onJumpToSeq }: Props) {
  const selectedSeq = useSelectedSeq();
  const [report, setReport] = useState<MemoryObjectGraphReport | null>(null);
  const [selectedObjectId, setSelectedObjectId] = useState<string | null>(null);
  const [filter, setFilter] = useState("");
  const [includeStackFrames, setIncludeStackFrames] = useState(true);
  const [includeRuntimeClusters, setIncludeRuntimeClusters] = useState(true);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [pointer, setPointer] = useState("");
  const [pointerLoading, setPointerLoading] = useState(false);
  const [explanation, setExplanation] = useState<MemoryPointerExplanation | null>(null);

  const selectedObject = useMemo(
    () => report?.objects.find(object => object.objectId === selectedObjectId) ?? null,
    [report, selectedObjectId],
  );

  const visibleObjects = useMemo(() => {
    if (!report) return [];
    const query = filter.trim().toLowerCase();
    if (!query) return report.objects;
    return report.objects.filter(object => [
      object.objectId,
      object.baseAddress,
      object.kind,
      object.allocator || "",
      object.releaseFunction || "",
      object.functionName || "",
    ].some(value => value.toLowerCase().includes(query)));
  }, [report, filter]);

  const reconstruct = async () => {
    if (!sessionId) return;
    setLoading(true);
    setError(null);
    try {
      const next = await invoke<MemoryObjectGraphReport>("reconstruct_memory_objects", {
        sessionId,
        options: {
          includeStackFrames,
          includeRuntimeClusters,
          maxObjects: 1000,
          maxAliasesPerObject: 64,
          maxFieldWindowsPerObject: 64,
          maxAccessSamplesPerObject: 16,
          maxAnomalies: 512,
          maxRuntimeClusters: 256,
          maxAccesses: 5000000,
          maxStackDistance: 1048576,
        },
      });
      setReport(next);
      setSelectedObjectId(next.objects[0]?.objectId ?? null);
    } catch (cause) {
      setError(String(cause));
      setReport(null);
    } finally {
      setLoading(false);
    }
  };

  const explainPointer = async () => {
    if (!sessionId || !pointer.trim()) return;
    setPointerLoading(true);
    setError(null);
    try {
      setExplanation(await invoke<MemoryPointerExplanation>("explain_memory_pointer", {
        sessionId,
        address: pointer.trim(),
        seq: selectedSeq ?? null,
        includeStackFrames,
      }));
    } catch (cause) {
      setError(String(cause));
      setExplanation(null);
    } finally {
      setPointerLoading(false);
    }
  };

  if (!sessionId || !isPhase2Ready) {
    return (
      <div style={{ height: "100%", display: "flex", alignItems: "center", justifyContent: "center", color: "var(--text-secondary)", fontSize: 12 }}>
        Build the trace index before reconstructing memory objects.
      </div>
    );
  }

  return (
    <div style={{ height: "100%", display: "flex", flexDirection: "column", minWidth: 0, background: "var(--bg-primary)" }}>
      <div style={{ padding: "6px 8px", borderBottom: "1px solid var(--border-color)", display: "flex", alignItems: "center", gap: 8, flexWrap: "wrap", flexShrink: 0 }}>
        <button
          style={{ ...buttonStyle, background: "var(--btn-primary)", opacity: loading ? 0.65 : 1 }}
          disabled={loading}
          onClick={reconstruct}
        >
          {loading ? "Reconstructing…" : "Reconstruct objects"}
        </button>
        <label style={{ display: "flex", alignItems: "center", gap: 4, color: "var(--text-secondary)", fontSize: 11 }}>
          <input type="checkbox" checked={includeStackFrames} onChange={event => setIncludeStackFrames(event.target.checked)} />
          stack frames
        </label>
        <label style={{ display: "flex", alignItems: "center", gap: 4, color: "var(--text-secondary)", fontSize: 11 }}>
          <input type="checkbox" checked={includeRuntimeClusters} onChange={event => setIncludeRuntimeClusters(event.target.checked)} />
          unattributed pages
        </label>
        <input
          aria-label="Memory object filter"
          style={{ ...inputStyle, width: 170 }}
          value={filter}
          onChange={event => setFilter(event.target.value)}
          placeholder="filter object/address"
        />
        <div style={{ marginLeft: "auto", display: "flex", alignItems: "center", gap: 5 }}>
          <input
            aria-label="Pointer address"
            style={{ ...inputStyle, width: 155 }}
            value={pointer}
            onChange={event => setPointer(event.target.value)}
            onKeyDown={event => { if (event.key === "Enter") void explainPointer(); }}
            placeholder="0x pointer"
          />
          <button style={buttonStyle} disabled={pointerLoading || !pointer.trim()} onClick={explainPointer}>
            {pointerLoading ? "Explaining…" : `Explain @ ${selectedSeq == null ? "end" : `#${selectedSeq + 1}`}`}
          </button>
        </div>
      </div>

      {error && (
        <div style={{ padding: "6px 8px", color: "var(--text-error)", fontSize: 11, borderBottom: "1px solid var(--border-color)" }}>
          {error}
        </div>
      )}

      {!report ? (
        <div style={{ flex: 1, display: "flex", alignItems: "center", justifyContent: "center", color: "var(--text-secondary)", fontSize: 12, textAlign: "center", padding: 20 }}>
          Reconstruct allocation generations, aliases, stack lifetimes, and candidate boundary violations.<br />
          Results remain Candidate/Related until exact capture and replay confirm them.
        </div>
      ) : (
        <>
          <div style={{ display: "flex", gap: 12, padding: "5px 8px", borderBottom: "1px solid var(--border-color)", color: "var(--text-secondary)", fontSize: 11, flexWrap: "wrap", flexShrink: 0 }}>
            <span>objects <b style={{ color: "var(--text-primary)" }}>{count(report.statistics.totalObjects)}</b></span>
            <span>heap <b style={{ color: "var(--text-primary)" }}>{count(report.statistics.heapObjects)}</b></span>
            <span>mmap <b style={{ color: "var(--text-primary)" }}>{count(report.statistics.mmapObjects)}</b></span>
            <span>stack <b style={{ color: "var(--text-primary)" }}>{count(report.statistics.stackFrameObjects)}</b></span>
            <span>reuse <b style={{ color: "var(--text-primary)" }}>{count(report.statistics.reusedAddressCount)}</b></span>
            <span>aliases <b style={{ color: "var(--text-primary)" }}>{count(report.statistics.aliasCount)}</b></span>
            <span>candidate anomalies <b style={{ color: "var(--text-changes)" }}>{count(report.statistics.anomalyCount)}</b></span>
            {(report.objectsTruncated || report.accessesTruncated || report.anomaliesTruncated) && (
              <span style={{ color: "var(--text-changes)" }}>truncated — absence claims disabled</span>
            )}
          </div>

          <div style={{ flex: 1, display: "grid", gridTemplateColumns: "minmax(360px, 44%) minmax(340px, 56%)", overflow: "hidden" }}>
            <div style={{ overflow: "auto", borderRight: "1px solid var(--border-color)", fontFamily: "var(--font-mono)", fontSize: 11 }}>
              {visibleObjects.map(object => {
                const selected = object.objectId === selectedObjectId;
                const accesses = object.accessSummary.readCount + object.accessSummary.writeCount;
                return (
                  <button
                    key={object.objectId}
                    onClick={() => setSelectedObjectId(object.objectId)}
                    style={{
                      width: "100%", display: "grid", gridTemplateColumns: "108px 1fr 72px", gap: 8,
                      border: "none", borderBottom: "1px solid var(--border-color)", textAlign: "left",
                      padding: "5px 8px", cursor: "pointer",
                      background: selected ? "var(--bg-selected)" : "transparent", color: "var(--text-primary)",
                    }}
                  >
                    <span style={{ color: "var(--text-address)" }}>{object.baseAddress}</span>
                    <span style={{ overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
                      {objectLabel(object)} <span style={{ color: "var(--text-secondary)" }}>g{object.generation} · {object.kind}</span>
                    </span>
                    <span style={{ color: lifetimeColor(object.lifecycleState), textAlign: "right" }}>{count(accesses)}</span>
                  </button>
                );
              })}
              {visibleObjects.length === 0 && (
                <div style={{ padding: 12, color: "var(--text-secondary)" }}>No matching objects.</div>
              )}
            </div>

            <div style={{ overflow: "auto", padding: 10, minWidth: 0, fontSize: 11, color: "var(--text-secondary)" }}>
              {explanation && (
                <section style={{ border: "1px solid var(--border-color)", borderRadius: 5, marginBottom: 10, overflow: "hidden" }}>
                  <div style={{ padding: "5px 8px", background: "var(--bg-secondary)", color: "var(--text-primary)" }}>
                    Pointer {explanation.address} @ #{explanation.seq + 1} — {explanation.assessment}
                  </div>
                  <div style={{ padding: 8 }}>
                    {explanation.objectMatches.map(match => (
                      <div key={`${match.objectId}-${match.lifetimeStateAtSeq}`} style={{ marginBottom: 5 }}>
                        <b style={{ color: lifetimeColor(match.lifetimeStateAtSeq) }}>{match.lifetimeStateAtSeq}</b>{" "}
                        {match.objectId} + {match.offset}
                      </div>
                    ))}
                    {explanation.registerAliases.length > 0 && (
                      <div>registers: {explanation.registerAliases.map(alias => `${alias.register}${alias.displacement === "0x0" ? "" : ` ${alias.displacement}`}`).join(", ")}</div>
                    )}
                    {explanation.risks.map((risk, index) => <div key={index} style={{ color: "var(--text-changes)", marginTop: 4 }}>Candidate: {risk}</div>)}
                    {explanation.unknowns.map((unknown, index) => <div key={index} style={{ marginTop: 4 }}>Unknown: {unknown}</div>)}
                  </div>
                </section>
              )}

              {selectedObject ? (
                <>
                  <div style={{ color: "var(--text-primary)", fontFamily: "var(--font-mono)", fontSize: 12, marginBottom: 6 }}>
                    {selectedObject.objectId}
                  </div>
                  <div style={{ display: "grid", gridTemplateColumns: "112px 1fr", rowGap: 4 }}>
                    <span>range</span><span style={{ color: "var(--text-address)" }}>{selectedObject.baseAddress} – {selectedObject.endAddress || "unknown"}</span>
                    <span>lifetime</span>
                    <button onClick={() => onJumpToSeq(selectedObject.startSeq)} style={{ ...buttonStyle, justifySelf: "start", padding: "2px 7px" }}>
                      #{selectedObject.startSeq + 1} → {selectedObject.endSeq == null ? "scope end" : `#${selectedObject.endSeq + 1}`}
                    </button>
                    <span>state</span><span style={{ color: lifetimeColor(selectedObject.lifecycleState) }}>{selectedObject.lifecycleState} · {selectedObject.evidenceLevel}</span>
                    <span>owner/call</span><span>{objectLabel(selectedObject)}</span>
                    <span>reads/writes</span><span>{count(selectedObject.accessSummary.readCount)} / {count(selectedObject.accessSummary.writeCount)}</span>
                  </div>

                  <h4 style={{ color: "var(--text-primary)", margin: "12px 0 5px" }}>Aliases</h4>
                  {selectedObject.aliases.length === 0 ? <div>None captured.</div> : selectedObject.aliases.map((alias, index) => (
                    <div key={`${alias.seq}-${alias.source}-${index}`} style={{ padding: "3px 0", borderBottom: "1px dotted var(--border-color)" }}>
                      <button onClick={() => onJumpToSeq(alias.seq)} style={{ border: "none", background: "transparent", color: "var(--text-address)", cursor: "pointer", padding: 0 }}>#{alias.seq + 1}</button>{" "}
                      {alias.source}: {alias.pointer} + {alias.offset} ({alias.relation}, {alias.lifetimeState})
                    </div>
                  ))}

                  <h4 style={{ color: "var(--text-primary)", margin: "12px 0 5px" }}>Hot field windows</h4>
                  {selectedObject.fieldWindows.slice(0, 16).map(field => (
                    <div key={field.offset} style={{ display: "grid", gridTemplateColumns: "90px 1fr", padding: "2px 0" }}>
                      <span style={{ color: "var(--text-address)" }}>{field.offset}–{field.endOffset}</span>
                      <span>R {count(field.readCount)} / W {count(field.writeCount)} · #{field.firstSeq + 1}–#{field.lastSeq + 1}</span>
                    </div>
                  ))}
                  {selectedObject.warnings.map((warning, index) => (
                    <div key={index} style={{ color: "var(--text-changes)", marginTop: 5 }}>{warning}</div>
                  ))}
                </>
              ) : (
                <div>Select an object to inspect its lifetime, aliases, and field windows.</div>
              )}

              {report.anomalies.length > 0 && (
                <section style={{ marginTop: 14 }}>
                  <h4 style={{ color: "var(--text-primary)", margin: "0 0 5px" }}>Candidate anomalies</h4>
                  {report.anomalies.slice(0, 32).map((anomaly, index) => (
                    <div key={`${anomaly.kind}-${anomaly.seq}-${index}`} style={{ borderTop: "1px solid var(--border-color)", padding: "5px 0" }}>
                      <button onClick={() => onJumpToSeq(anomaly.seq)} style={{ border: "none", background: "transparent", color: "var(--text-address)", cursor: "pointer", padding: 0 }}>#{anomaly.seq + 1}</button>{" "}
                      <b style={{ color: "var(--text-changes)" }}>{anomaly.kind}</b> ×{count(anomaly.occurrenceCount)} — {anomaly.reason}
                    </div>
                  ))}
                </section>
              )}

              <details style={{ marginTop: 14 }}>
                <summary style={{ cursor: "pointer", color: "var(--text-primary)" }}>Accuracy boundaries and next evidence</summary>
                {report.limitations.map((item, index) => <div key={`l-${index}`} style={{ marginTop: 5 }}>Limit: {item}</div>)}
                {report.nextSteps.map((item, index) => <div key={`n-${index}`} style={{ marginTop: 5 }}>Next: {item}</div>)}
              </details>
            </div>
          </div>
        </>
      )}
    </div>
  );
}
