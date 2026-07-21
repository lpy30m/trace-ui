import React, { useCallback, useEffect, useMemo, useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import { useSelectedSeq } from "../stores/selectedSeqStore";
import type {
  DynamicBasicBlock,
  FunctionInspection,
  IdaAnnotationBundle,
  IdaOllvmScript,
  OllvmAnalysisOptions,
  OllvmReport,
} from "../types/trace";

interface Props {
  sessionId: string | null;
  onJumpToSeq: (seq: number) => void;
}

const buttonStyle: React.CSSProperties = {
  height: 25,
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
  height: 25,
  minWidth: 0,
  padding: "0 7px",
  border: "1px solid var(--border-color)",
  borderRadius: 3,
  background: "var(--input-bg)",
  color: "var(--text-primary)",
  fontFamily: "inherit",
  fontSize: 11,
};

function optionalNumber(value: string): number | null {
  if (!value.trim()) return null;
  const parsed = Number(value);
  return Number.isInteger(parsed) && parsed >= 0 ? parsed : null;
}

function scoreColor(score: number): string {
  if (score >= 70) return "#b35c00";
  if (score >= 40) return "#9e6a03";
  return "#6e7681";
}

function Score({ score, grade }: { score: number; grade: string }) {
  return (
    <span style={{ minWidth: 78, padding: "1px 6px", textAlign: "center", borderRadius: 3, background: scoreColor(score), color: "#fff", fontSize: 10, textTransform: "uppercase" }}>
      {grade} {score}
    </span>
  );
}

export default function OllvmPanel({ sessionId, onJumpToSeq }: Props) {
  const selectedSeq = useSelectedSeq();
  const [nodeId, setNodeId] = useState("");
  const [moduleName, setModuleName] = useState("");
  const [startSeq, setStartSeq] = useState("");
  const [endSeq, setEndSeq] = useState("");
  const [includeChildCalls, setIncludeChildCalls] = useState(false);
  const [report, setReport] = useState<OllvmReport | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [section, setSection] = useState<"dispatchers" | "opaque" | "blocks" | "edges" | "ida">("dispatchers");
  const [openBlock, setOpenBlock] = useState<string | null>(null);
  const [idaImageBase, setIdaImageBase] = useState("");
  const [addUserXrefs, setAddUserXrefs] = useState(false);
  const [idaScript, setIdaScript] = useState<IdaOllvmScript | null>(null);
  const [idaAnnotations, setIdaAnnotations] = useState<IdaAnnotationBundle | null>(null);
  const [savedPath, setSavedPath] = useState<string | null>(null);

  useEffect(() => {
    setReport(null);
    setIdaScript(null);
    setIdaAnnotations(null);
    setSavedPath(null);
    setError(null);
  }, [sessionId]);

  const options = useMemo<OllvmAnalysisOptions>(() => ({
    nodeId: optionalNumber(nodeId),
    moduleName: moduleName.trim() || null,
    startSeq: optionalNumber(startSeq),
    endSeq: optionalNumber(endSeq),
    includeChildCalls,
    maxBlocks: 1_000,
    maxEdges: 3_000,
  }), [endSeq, includeChildCalls, moduleName, nodeId, startSeq]);

  const useSelectedFunction = useCallback(async () => {
    if (!sessionId || selectedSeq == null) return;
    setError(null);
    try {
      const inspection = await invoke<FunctionInspection>("inspect_function_at_seq", { sessionId, seq: selectedSeq });
      setNodeId(String(inspection.funcId));
      setStartSeq(String(inspection.entrySeq));
      setEndSeq(String(inspection.exitSeq));
    } catch (reason) {
      setError(String(reason));
    }
  }, [selectedSeq, sessionId]);

  const analyze = useCallback(async () => {
    if (!sessionId) return;
    setLoading(true);
    setError(null);
    setIdaScript(null);
    try {
      const result = await invoke<OllvmReport>("analyze_ollvm", { sessionId, options });
      setReport(result);
      setModuleName(result.scope.moduleName);
      setStartSeq(String(result.scope.startSeq));
      setEndSeq(String(result.scope.endSeq));
    } catch (reason) {
      setError(String(reason));
      setReport(null);
    } finally {
      setLoading(false);
    }
  }, [options, sessionId]);

  const blockById = useMemo(() => new Map(report?.blocks.map(block => [block.blockId, block]) || []), [report]);
  const annotationByOffset = useMemo(() => new Map(
    idaAnnotations?.annotations.map(annotation => [annotation.offset.toLowerCase(), annotation]) || [],
  ), [idaAnnotations]);

  const jumpBlock = useCallback((block: DynamicBasicBlock | undefined) => {
    const seq = block?.sampleSeqs[0] ?? block?.instructions[0]?.sampleSeq;
    if (seq != null) onJumpToSeq(seq);
  }, [onJumpToSeq]);

  const jumpOffset = useCallback((offset: string) => {
    const normalized = offset.toLowerCase();
    const instruction = report?.blocks
      .flatMap(block => block.instructions)
      .find(item => item.offset.toLowerCase() === normalized);
    if (instruction) onJumpToSeq(instruction.sampleSeq);
  }, [onJumpToSeq, report]);

  const generateIdaScript = useCallback(async (): Promise<IdaOllvmScript | null> => {
    if (!report) return null;
    setError(null);
    try {
      const generated = await invoke<IdaOllvmScript>("generate_ida_ollvm_script", {
        report,
        idaImageBase: idaImageBase.trim() || null,
        addUserXrefs,
      });
      setIdaScript(generated);
      return generated;
    } catch (reason) {
      setError(String(reason));
      return null;
    }
  }, [addUserXrefs, idaImageBase, report]);

  const saveIdaScript = useCallback(async () => {
    if (!report) return;
    const generated = idaScript || await generateIdaScript();
    if (!generated) return;
    const { save } = await import("@tauri-apps/plugin-dialog");
    const path = await save({
      defaultPath: generated.fileName,
      filters: [{ name: "IDAPython", extensions: ["py"] }],
    });
    if (typeof path !== "string") return;
    try {
      const written = await invoke<string>("save_ida_ollvm_script", {
        path,
        report,
        idaImageBase: idaImageBase.trim() || null,
        addUserXrefs,
      });
      setSavedPath(written);
    } catch (reason) {
      setError(String(reason));
    }
  }, [addUserXrefs, generateIdaScript, idaImageBase, idaScript, report]);

  const importIdaAnnotations = useCallback(async () => {
    const { open } = await import("@tauri-apps/plugin-dialog");
    const path = await open({ multiple: false, directory: false, filters: [{ name: "Trace UI IDA annotations", extensions: ["json"] }] });
    if (typeof path !== "string") return;
    try {
      const bundle = await invoke<IdaAnnotationBundle>("load_ida_annotations", { path });
      setIdaAnnotations(bundle);
      setError(null);
    } catch (reason) {
      setError(String(reason));
    }
  }, []);

  const sectionButton = (key: typeof section, label: string) => (
    <button
      type="button"
      style={{ ...buttonStyle, height: 28, border: "none", borderRight: "1px solid var(--border-color)", borderRadius: 0, background: section === key ? "var(--bg-selected)" : "var(--bg-input)", flexShrink: 0 }}
      onClick={() => setSection(key)}
    >{label}</button>
  );

  return (
    <div style={{ flex: 1, minWidth: 0, minHeight: 0, display: "flex", flexDirection: "column", overflow: "hidden" }}>
      <div style={{
        display: "grid", gridTemplateColumns: "70px 80px 62px 90px 52px 90px 70px minmax(120px, 1fr) auto auto",
        gap: 6, alignItems: "center", padding: "6px 8px", borderBottom: "1px solid var(--border-color)",
        fontSize: 11, overflowX: "auto", overflowY: "hidden", flexShrink: 0,
      }}>
        <label htmlFor="ollvm-node">Node ID</label>
        <input id="ollvm-node" style={inputStyle} value={nodeId} onChange={event => setNodeId(event.target.value)} placeholder="optional" />
        <label htmlFor="ollvm-start">Start seq</label>
        <input id="ollvm-start" style={inputStyle} value={startSeq} onChange={event => setStartSeq(event.target.value)} placeholder="auto" />
        <label htmlFor="ollvm-end">End seq</label>
        <input id="ollvm-end" style={inputStyle} value={endSeq} onChange={event => setEndSeq(event.target.value)} placeholder="auto" />
        <label htmlFor="ollvm-module">Module</label>
        <input id="ollvm-module" style={inputStyle} value={moduleName} onChange={event => setModuleName(event.target.value)} placeholder="infer from trace" />
        <button type="button" style={{ ...buttonStyle, opacity: sessionId && selectedSeq != null ? 1 : 0.5 }} disabled={!sessionId || selectedSeq == null} onClick={useSelectedFunction}>Use selected function</button>
        <button type="button" style={{ ...buttonStyle, background: "var(--btn-primary)", color: "#fff", border: "none", opacity: !sessionId || loading ? 0.6 : 1 }} disabled={!sessionId || loading} onClick={analyze}>{loading ? "Analyzing..." : "Analyze OLLVM"}</button>
      </div>
      <div style={{
        display: "flex", alignItems: "center", minHeight: 30, borderBottom: "1px solid var(--border-color)",
        overflowX: "auto", overflowY: "hidden", flexShrink: 0,
      }}>
        {sectionButton("dispatchers", `Dispatchers${report ? ` (${report.dispatcherCandidates.length})` : ""}`)}
        {sectionButton("opaque", `Opaque branches${report ? ` (${report.opaqueBranchCandidates.length})` : ""}`)}
        {sectionButton("blocks", `Dynamic blocks${report ? ` (${report.blockCount})` : ""}`)}
        {sectionButton("edges", `Edges${report ? ` (${report.edgeCount})` : ""}`)}
        {sectionButton("ida", "IDA bridge")}
        <label style={{ display: "flex", alignItems: "center", gap: 4, marginLeft: 10, color: "var(--text-secondary)", fontSize: 10, flexShrink: 0, whiteSpace: "nowrap" }}>
          <input type="checkbox" checked={includeChildCalls} onChange={event => setIncludeChildCalls(event.target.checked)} />
          Include child calls
        </label>
        {report && (
          <span style={{ marginLeft: "auto", paddingRight: 8, color: "var(--text-tertiary)", fontSize: 10, flexShrink: 0, whiteSpace: "nowrap" }}>
            {report.scope.moduleName} base {report.scope.moduleBase} | {report.executedInstructionCount.toLocaleString()} executions | {report.uniqueInstructionCount.toLocaleString()} unique
          </span>
        )}
      </div>

      {error && <div style={{ padding: "7px 10px", color: "#e5484d", borderBottom: "1px solid var(--border-color)", fontSize: 11 }}>{error}</div>}
      {!report && !loading && (
        <div style={{ flex: 1, display: "flex", alignItems: "center", justifyContent: "center", color: "var(--text-secondary)", fontSize: 12 }}>
          Select a function invocation or provide a trace range.
        </div>
      )}

      {report && section === "dispatchers" && (
        <div style={{ flex: 1, overflow: "auto" }}>
          {report.dispatcherCandidates.map(candidate => (
            <div key={candidate.blockId} style={{ display: "flex", alignItems: "center", gap: 8, padding: "6px 8px", borderBottom: "1px solid var(--border-color)", fontSize: 11 }}>
              <Score score={candidate.assessment.score} grade={candidate.assessment.grade} />
              <button type="button" style={buttonStyle} onClick={() => jumpBlock(blockById.get(candidate.blockId))}>{candidate.startOffset}</button>
              <span>{candidate.visitCount} visits</span>
              <span>{candidate.predecessorCount} in / {candidate.successorCount} out</span>
              <span>{candidate.indirectBranchCount} indirect</span>
              <code>{candidate.stateRegisters.join(", ") || "no state register"}</code>
              <span style={{ flex: 1, color: "var(--text-secondary)" }}>{candidate.rationale}</span>
            </div>
          ))}
          {report.dispatcherCandidates.length === 0 && <div style={{ padding: 14, color: "var(--text-secondary)", fontSize: 11 }}>No dispatcher candidate crossed the evidence threshold.</div>}
        </div>
      )}

      {report && section === "opaque" && (
        <div style={{ flex: 1, overflow: "auto" }}>
          {report.opaqueBranchCandidates.map(candidate => (
            <div key={candidate.branchOffset} style={{ padding: "7px 8px", borderBottom: "1px solid var(--border-color)", fontSize: 11 }}>
              <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
                <Score score={candidate.assessment.score} grade={candidate.assessment.grade} />
                <button type="button" style={buttonStyle} onClick={() => jumpOffset(candidate.branchOffset)}>{candidate.branchOffset}</button>
                <code style={{ color: "var(--text-primary)" }}>{candidate.disasm}</code>
                <span>{candidate.executionCount} executions</span>
                <span>taken {candidate.observedTakenCount} / fallthrough {candidate.observedFallthroughCount}</span>
              </div>
              <div style={{ marginTop: 4, paddingLeft: 88, color: "var(--text-secondary)" }}>{candidate.rationale}</div>
            </div>
          ))}
          {report.opaqueBranchCandidates.length === 0 && <div style={{ padding: 14, color: "var(--text-secondary)", fontSize: 11 }}>No repeated single-outcome conditional branch was observed.</div>}
        </div>
      )}

      {report && section === "blocks" && (
        <div style={{ flex: 1, overflow: "auto" }}>
          {report.blocks.map(block => {
            const annotation = annotationByOffset.get(block.startOffset.toLowerCase());
            const open = openBlock === block.blockId;
            return (
              <div key={block.blockId} style={{ borderBottom: "1px solid var(--border-color)" }}>
                <div onClick={() => setOpenBlock(open ? null : block.blockId)} style={{ display: "flex", alignItems: "center", gap: 8, minHeight: 31, padding: "4px 8px", cursor: "pointer", fontSize: 11 }}>
                  <button type="button" style={buttonStyle} onClick={event => { event.stopPropagation(); jumpBlock(block); }}>{block.startOffset}</button>
                  <span>to {block.endOffset}</span>
                  <span>{block.visitCount} visits</span>
                  <span>{block.predecessorCount} in / {block.successorCount} out</span>
                  <code>{block.terminalOperation}</code>
                  {annotation?.name && <strong style={{ color: "#3fb950" }}>{annotation.name}</strong>}
                  <span style={{ flex: 1, color: "var(--text-tertiary)", overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{annotation?.comment || annotation?.repeatableComment || ""}</span>
                </div>
                {open && (
                  <div style={{ padding: "5px 10px 8px 98px", background: "var(--bg-secondary)", fontFamily: "monospace", fontSize: 10 }}>
                    {block.instructions.map(instruction => (
                      <div key={instruction.offset} style={{ display: "grid", gridTemplateColumns: "90px 72px minmax(0, 1fr)", gap: 8 }}>
                        <span>{instruction.offset}</span><span>x{instruction.executionCount}</span><span>{instruction.disasm}</span>
                      </div>
                    ))}
                  </div>
                )}
              </div>
            );
          })}
        </div>
      )}

      {report && section === "edges" && (
        <div style={{ flex: 1, overflow: "auto" }}>
          {report.edges.map((edge, index) => (
            <div key={`${edge.sourceBlockId}-${edge.targetBlockId}-${edge.kind}-${index}`} style={{ display: "grid", gridTemplateColumns: "110px 22px 110px 150px 90px 1fr", gap: 7, alignItems: "center", padding: "5px 8px", borderBottom: "1px solid var(--border-color)", fontSize: 11 }}>
              <button type="button" style={buttonStyle} onClick={() => jumpOffset(edge.sourceOffset)}>{edge.sourceOffset}</button>
              <span>{edge.backward ? "<-" : "->"}</span>
              <button type="button" style={buttonStyle} onClick={() => jumpOffset(edge.targetOffset)}>{edge.targetOffset}</button>
              <span>{edge.kind}</span>
              <span>x{edge.executionCount}</span>
              <span style={{ color: "var(--text-tertiary)" }}>line {edge.sampleSeq + 1}</span>
            </div>
          ))}
        </div>
      )}

      {report && section === "ida" && (
        <div style={{ flex: 1, minHeight: 0, display: "flex", overflow: "hidden" }}>
          <div style={{ width: 360, padding: 10, borderRight: "1px solid var(--border-color)", overflow: "auto", fontSize: 11 }}>
            <div style={{ display: "grid", gridTemplateColumns: "110px minmax(0, 1fr)", gap: 7, alignItems: "center" }}>
              <label htmlFor="ida-image-base">IDA image base</label>
              <input id="ida-image-base" style={inputStyle} value={idaImageBase} onChange={event => { setIdaImageBase(event.target.value); setIdaScript(null); }} placeholder="use idaapi.get_imagebase()" />
              <span>User xrefs</span>
              <label style={{ display: "flex", alignItems: "center", gap: 5 }}>
                <input type="checkbox" checked={addUserXrefs} onChange={event => { setAddUserXrefs(event.target.checked); setIdaScript(null); }} />
                Add observed CFG edges
              </label>
            </div>
            <div style={{ display: "flex", gap: 6, flexWrap: "wrap", marginTop: 10 }}>
              <button type="button" style={{ ...buttonStyle, background: "var(--btn-primary)", color: "#fff", border: "none" }} onClick={generateIdaScript}>Generate IDAPython</button>
              <button type="button" style={buttonStyle} onClick={saveIdaScript}>Save .py</button>
              <button type="button" style={buttonStyle} onClick={importIdaAnnotations}>Import IDA JSON</button>
              <button type="button" style={{ ...buttonStyle, opacity: idaScript ? 1 : 0.5 }} disabled={!idaScript} onClick={() => idaScript && navigator.clipboard.writeText(idaScript.script)}>Copy script</button>
            </div>
            {savedPath && <div title={savedPath} style={{ marginTop: 8, color: "#3fb950", overflow: "hidden", textOverflow: "ellipsis" }}>Saved: {savedPath}</div>}
            {idaAnnotations && (
              <div style={{ marginTop: 10, paddingTop: 8, borderTop: "1px solid var(--border-color)" }}>
                <strong>{idaAnnotations.annotations.length} imported annotations</strong>
                <div>{idaAnnotations.moduleName} at {idaAnnotations.imageBase}</div>
              </div>
            )}
            {idaScript?.warnings.map((warning, index) => <div key={index} style={{ marginTop: 5, color: "#d29922" }}>{warning}</div>)}
          </div>
          <pre style={{ flex: 1, minWidth: 0, margin: 0, padding: 10, overflow: "auto", background: "var(--bg-primary)", color: "var(--text-primary)", fontSize: 10, lineHeight: 1.45, whiteSpace: "pre" }}>{idaScript?.script || ""}</pre>
        </div>
      )}
    </div>
  );
}
