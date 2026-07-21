import React, { useCallback, useEffect, useMemo, useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import { useSelectedSeq } from "../stores/selectedSeqStore";
import type {
  AngrOllvmResultBundle,
  AngrOllvmScript,
  DynamicBasicBlock,
  FunctionInspection,
  IdaAnnotationBundle,
  IdaOllvmScript,
  OllvmAnalysisOptions,
  OllvmMultiTraceReport,
  OllvmReport,
  TraceSessionInfo,
} from "../types/trace";

interface Props {
  sessionId: string | null;
  onJumpToSeq: (seq: number) => void;
}

interface EditableOllvmCase {
  sessionId: string;
  label: string;
  selected: boolean;
  nodeId: string;
  startSeq: string;
  endSeq: string;
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
  const [comparison, setComparison] = useState<OllvmMultiTraceReport | null>(null);
  const [compareCases, setCompareCases] = useState<EditableOllvmCase[]>([]);
  const [comparing, setComparing] = useState(false);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [section, setSection] = useState<"dispatchers" | "state" | "opaque" | "blocks" | "edges" | "compare" | "ida" | "angr">("dispatchers");
  const [openBlock, setOpenBlock] = useState<string | null>(null);
  const [idaImageBase, setIdaImageBase] = useState("");
  const [addUserXrefs, setAddUserXrefs] = useState(false);
  const [idaScript, setIdaScript] = useState<IdaOllvmScript | null>(null);
  const [idaAnnotations, setIdaAnnotations] = useState<IdaAnnotationBundle | null>(null);
  const [savedPath, setSavedPath] = useState<string | null>(null);
  const [angrProbeOpaque, setAngrProbeOpaque] = useState(true);
  const [angrCfgEmulated, setAngrCfgEmulated] = useState(false);
  const [angrScript, setAngrScript] = useState<AngrOllvmScript | null>(null);
  const [angrResults, setAngrResults] = useState<AngrOllvmResultBundle | null>(null);
  const [angrSavedPath, setAngrSavedPath] = useState<string | null>(null);
  const [angrDisplay, setAngrDisplay] = useState<"script" | "results">("script");

  useEffect(() => {
    setReport(null);
    setComparison(null);
    setIdaScript(null);
    setIdaAnnotations(null);
    setSavedPath(null);
    setAngrScript(null);
    setAngrResults(null);
    setAngrSavedPath(null);
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
    setAngrScript(null);
    setAngrResults(null);
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

  const refreshCompareSessions = useCallback(async () => {
    try {
      const sessions = await invoke<TraceSessionInfo[]>("list_trace_sessions");
      setCompareCases(previous => sessions.map((session, index) => {
        const existing = previous.find(item => item.sessionId === session.sessionId);
        if (existing) return existing;
        const fileName = session.filePath.split(/[\\/]/).pop() || `trace-${index + 1}`;
        const current = session.sessionId === sessionId;
        return {
          sessionId: session.sessionId,
          label: fileName,
          selected: current,
          nodeId: current ? nodeId : "",
          startSeq: current ? startSeq : "",
          endSeq: current ? endSeq : "",
        };
      }));
    } catch (reason) {
      setError(String(reason));
    }
  }, [endSeq, nodeId, sessionId, startSeq]);

  useEffect(() => {
    if (section === "compare") void refreshCompareSessions();
  }, [refreshCompareSessions, section]);

  const selectedCompareCases = useMemo(() => compareCases.filter(item => item.selected), [compareCases]);
  const compareRuns = useCallback(async () => {
    if (selectedCompareCases.length < 2) return;
    setComparing(true);
    setError(null);
    try {
      const result = await invoke<OllvmMultiTraceReport>("compare_ollvm_traces", {
        request: {
          cases: selectedCompareCases.map(item => ({
            sessionId: item.sessionId,
            label: item.label,
            nodeId: optionalNumber(item.nodeId),
            moduleName: moduleName.trim() || null,
            startSeq: optionalNumber(item.startSeq),
            endSeq: optionalNumber(item.endSeq),
            includeChildCalls,
          })),
          maxBlocks: 1_000,
          maxEdges: 3_000,
        },
      });
      setComparison(result);
    } catch (reason) {
      setError(String(reason));
      setComparison(null);
    } finally {
      setComparing(false);
    }
  }, [includeChildCalls, moduleName, selectedCompareCases]);

  const updateCompareCase = (index: number, patch: Partial<EditableOllvmCase>) => {
    setCompareCases(items => items.map((item, itemIndex) => itemIndex === index ? { ...item, ...patch } : item));
  };

  const blockById = useMemo(() => new Map(report?.blocks.map(block => [block.blockId, block]) || []), [report]);
  const annotationByOffset = useMemo(() => new Map(
    idaAnnotations?.annotations.map(annotation => [annotation.offset.toLowerCase(), annotation]) || [],
  ), [idaAnnotations]);
  const angrBlockByOffset = useMemo(() => new Map(
    angrResults?.blocks.map(block => [block.offset.toLowerCase(), block]) || [],
  ), [angrResults]);

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

  const generateAngrScript = useCallback(async (): Promise<AngrOllvmScript | null> => {
    if (!report) return null;
    setError(null);
    try {
      const generated = await invoke<AngrOllvmScript>("generate_angr_ollvm_script", {
        report,
        probeOpaqueBranches: angrProbeOpaque,
        useCfgEmulated: angrCfgEmulated,
      });
      setAngrScript(generated);
      setAngrDisplay("script");
      return generated;
    } catch (reason) {
      setError(String(reason));
      return null;
    }
  }, [angrCfgEmulated, angrProbeOpaque, report]);

  const saveAngrScript = useCallback(async () => {
    if (!report) return;
    const generated = angrScript || await generateAngrScript();
    if (!generated) return;
    const { save } = await import("@tauri-apps/plugin-dialog");
    const path = await save({
      defaultPath: generated.fileName,
      filters: [{ name: "Python", extensions: ["py"] }],
    });
    if (typeof path !== "string") return;
    try {
      const written = await invoke<string>("save_angr_ollvm_script", {
        path,
        report,
        probeOpaqueBranches: angrProbeOpaque,
        useCfgEmulated: angrCfgEmulated,
      });
      setAngrSavedPath(written);
    } catch (reason) {
      setError(String(reason));
    }
  }, [angrCfgEmulated, angrProbeOpaque, angrScript, generateAngrScript, report]);

  const importAngrResults = useCallback(async () => {
    if (!report) return;
    const { open } = await import("@tauri-apps/plugin-dialog");
    const path = await open({ multiple: false, directory: false, filters: [{ name: "Trace UI angr results", extensions: ["json"] }] });
    if (typeof path !== "string") return;
    try {
      const bundle = await invoke<AngrOllvmResultBundle>("load_angr_ollvm_results", { path });
      if (bundle.moduleName !== report.scope.moduleName) {
        throw new Error(`angr result module ${bundle.moduleName} does not match analyzed module ${report.scope.moduleName}`);
      }
      setAngrResults(bundle);
      setAngrDisplay("results");
      setError(null);
    } catch (reason) {
      setError(String(reason));
    }
  }, [report]);

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
        {sectionButton("state", "State machine")}
        {sectionButton("opaque", `Opaque branches${report ? ` (${report.opaqueBranchCandidates.length})` : ""}`)}
        {sectionButton("blocks", `Dynamic blocks${report ? ` (${report.blockCount})` : ""}`)}
        {sectionButton("edges", `Edges${report ? ` (${report.edgeCount})` : ""}`)}
        {sectionButton("compare", "Multi-run")}
        {sectionButton("ida", "IDA bridge")}
        {sectionButton("angr", "angr bridge")}
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
      {!report && !loading && section !== "compare" && (
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
              <span>{candidate.stateSnapshots.length} states / {candidate.stateTransitions.length} transitions</span>
              <span style={{ flex: 1, color: "var(--text-secondary)" }}>{candidate.rationale}</span>
            </div>
          ))}
          {report.dispatcherCandidates.length === 0 && <div style={{ padding: 14, color: "var(--text-secondary)", fontSize: 11 }}>No dispatcher candidate crossed the evidence threshold.</div>}
        </div>
      )}

      {report && section === "state" && (
        <div style={{ flex: 1, overflow: "auto", fontSize: 11 }}>
          <div style={{ padding: "8px 10px", borderBottom: "1px solid var(--border-color)", color: "var(--text-secondary)" }}>
            Values are reconstructed at dispatcher block entry from trace register checkpoints. They reveal an observed state trajectory, not the complete flattened state machine.
          </div>
          {report.dispatcherCandidates.map(candidate => (
            <div key={candidate.blockId} style={{ borderBottom: "1px solid var(--border-color)", padding: "8px 10px" }}>
              <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
                <Score score={candidate.assessment.score} grade={candidate.assessment.grade} />
                <button type="button" style={buttonStyle} onClick={() => jumpBlock(blockById.get(candidate.blockId))}>{candidate.startOffset}</button>
                <strong>{candidate.stateSnapshots.length} snapshots</strong>
                <span>{candidate.stateTransitions.length} changing transitions</span>
                {candidate.stateSnapshotsTruncated && <span style={{ color: "#d29922" }}>snapshot list truncated</span>}
              </div>
              {candidate.stateTransitions.length > 0 && (
                <div style={{ marginTop: 7, display: "grid", gridTemplateColumns: "70px 170px 22px 170px 70px 80px", gap: 6, alignItems: "center" }}>
                  <strong>Register</strong><strong>From</strong><span /><strong>To</strong><strong>Count</strong><strong>Trace</strong>
                  {candidate.stateTransitions.map((transition, index) => (
                    <React.Fragment key={`${transition.register}-${transition.fromValue}-${transition.toValue}-${index}`}>
                      <code>{transition.register}</code>
                      <code>{transition.fromValue}</code>
                      <span>→</span>
                      <code>{transition.toValue}</code>
                      <span>x{transition.executionCount}</span>
                      <button type="button" style={buttonStyle} onClick={() => onJumpToSeq(transition.sampleSeq)}>line {transition.sampleSeq + 1}</button>
                    </React.Fragment>
                  ))}
                </div>
              )}
              {candidate.stateTransitions.length === 0 && (
                <div style={{ marginTop: 6, color: "var(--text-tertiary)" }}>No changing value was reconstructed for the candidate state registers.</div>
              )}
            </div>
          ))}
          {report.dispatcherCandidates.length === 0 && <div style={{ padding: 14, color: "var(--text-secondary)" }}>No dispatcher candidate crossed the evidence threshold.</div>}
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
                <span>{candidate.observations.filter(item => Object.keys(item.registers).length > 0).length} seeded states</span>
              </div>
              <div style={{ marginTop: 4, paddingLeft: 88, color: "var(--text-secondary)" }}>{candidate.rationale}</div>
              {candidate.observations.some(item => Object.keys(item.registers).length > 0) && (
                <div style={{ marginTop: 5, paddingLeft: 88, display: "flex", gap: 6, flexWrap: "wrap" }}>
                  {candidate.observations.filter(item => Object.keys(item.registers).length > 0).map(item => (
                    <button key={`${candidate.branchOffset}-${item.seq}`} type="button" style={buttonStyle} onClick={() => onJumpToSeq(item.seq)}>
                      line {item.seq + 1} · {item.outcome} · {Object.entries(item.registers).map(([name, value]) => `${name}=${value}`).join(", ")}
                    </button>
                  ))}
                </div>
              )}
            </div>
          ))}
          {report.opaqueBranchCandidates.length === 0 && <div style={{ padding: 14, color: "var(--text-secondary)", fontSize: 11 }}>No repeated single-outcome conditional branch was observed.</div>}
        </div>
      )}

      {report && section === "blocks" && (
        <div style={{ flex: 1, overflow: "auto" }}>
          {report.blocks.map(block => {
            const annotation = annotationByOffset.get(block.startOffset.toLowerCase());
            const angrBlock = angrBlockByOffset.get(block.startOffset.toLowerCase());
            const open = openBlock === block.blockId;
            return (
              <div key={block.blockId} style={{ borderBottom: "1px solid var(--border-color)" }}>
                <div onClick={() => setOpenBlock(open ? null : block.blockId)} style={{ display: "flex", alignItems: "center", gap: 8, minHeight: 31, padding: "4px 8px", cursor: "pointer", fontSize: 11 }}>
                  <button type="button" style={buttonStyle} onClick={event => { event.stopPropagation(); jumpBlock(block); }}>{block.startOffset}</button>
                  <span>to {block.endOffset}</span>
                  <span>{block.visitCount} visits</span>
                  <span>{block.predecessorCount} in / {block.successorCount} out</span>
                  <code>{block.terminalOperation}</code>
                  {angrBlock && (
                    <span style={{ color: angrBlock.cfgNodeFound ? "#3fb950" : "#d29922", whiteSpace: "nowrap" }}>
                      angr {angrBlock.staticSuccessors.length} static / {angrBlock.unobservedStaticSuccessors.length} unseen / {angrBlock.dynamicOnlySuccessors.length} dynamic-only
                    </span>
                  )}
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

      {section === "compare" && (
        <div style={{ flex: 1, minHeight: 0, overflow: "auto", padding: 10, fontSize: 11 }}>
          <div style={{ color: "var(--text-secondary)", marginBottom: 9 }}>
            Compare the same module/function across controlled runs. A branch that shows both outcomes is evidence against treating it as globally opaque; stable single-outcome results remain candidates only.
          </div>
          <div style={{ display: "grid", gridTemplateColumns: "26px minmax(150px, 1fr) minmax(120px, 220px) 90px 90px 90px", gap: 5, alignItems: "center" }}>
            <span /><strong>Open trace</strong><strong>Case label</strong><strong>Node ID</strong><strong>Start seq</strong><strong>End seq</strong>
            {compareCases.map((item, index) => (
              <React.Fragment key={item.sessionId}>
                <input type="checkbox" checked={item.selected} onChange={event => updateCompareCase(index, { selected: event.target.checked })} />
                <span title={item.sessionId} style={{ overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{item.label}</span>
                <input style={inputStyle} value={item.label} onChange={event => updateCompareCase(index, { label: event.target.value })} />
                <input style={inputStyle} value={item.nodeId} onChange={event => updateCompareCase(index, { nodeId: event.target.value })} placeholder="optional" />
                <input style={inputStyle} value={item.startSeq} onChange={event => updateCompareCase(index, { startSeq: event.target.value })} placeholder="auto" />
                <input style={inputStyle} value={item.endSeq} onChange={event => updateCompareCase(index, { endSeq: event.target.value })} placeholder="auto" />
              </React.Fragment>
            ))}
          </div>
          <div style={{ display: "flex", gap: 6, marginTop: 9 }}>
            <button type="button" style={buttonStyle} onClick={refreshCompareSessions}>Refresh sessions</button>
            <button
              type="button"
              style={{ ...buttonStyle, background: "var(--btn-primary)", color: "#fff", border: "none", opacity: selectedCompareCases.length < 2 || comparing ? 0.6 : 1 }}
              disabled={selectedCompareCases.length < 2 || comparing}
              onClick={compareRuns}
            >
              {comparing ? "Comparing..." : `Compare ${selectedCompareCases.length} runs`}
            </button>
            <span style={{ alignSelf: "center", color: "var(--text-tertiary)" }}>Module: {moduleName.trim() || "infer per run"}</span>
          </div>
          {comparison && (
            <div style={{ marginTop: 12, borderTop: "1px solid var(--border-color)" }}>
              <div style={{ padding: "8px 0", color: "var(--text-secondary)" }}>
                {comparison.cases.length} runs · {comparison.dispatcherStability.length} dispatcher offsets · {comparison.branchStability.length} conditional branch offsets · verification gate remains closed
              </div>
              <h4 style={{ margin: "8px 0" }}>Dispatcher stability</h4>
              {comparison.dispatcherStability.map(candidate => (
                <div key={candidate.startOffset} style={{ padding: 8, border: "1px solid var(--border-color)", borderRadius: 4, marginBottom: 6, background: "var(--bg-secondary)" }}>
                  <div style={{ display: "flex", gap: 8, alignItems: "center" }}>
                    <Score score={candidate.assessment.score} grade={candidate.assessment.grade} />
                    <code>{candidate.startOffset}</code>
                    <span>{candidate.candidateInRuns}/{comparison.cases.length} dispatcher runs</span>
                    <span>{candidate.presentInRuns}/{comparison.cases.length} present</span>
                    <code>{candidate.commonStateRegisters.join(", ") || "no common state register"}</code>
                  </div>
                  <div style={{ marginTop: 4, color: "var(--text-tertiary)" }}>{candidate.rationale}</div>
                </div>
              ))}
              <h4 style={{ margin: "12px 0 8px" }}>Branch outcome stability</h4>
              {comparison.branchStability.filter(branch => branch.stableSingleOutcome || branch.alternateOutcomesObserved).map(branch => (
                <div key={branch.branchOffset} style={{ padding: 8, border: `1px solid ${branch.alternateOutcomesObserved ? "#e5484d" : "var(--border-color)"}`, borderRadius: 4, marginBottom: 6, background: "var(--bg-secondary)" }}>
                  <div style={{ display: "flex", gap: 8, alignItems: "center" }}>
                    <Score score={branch.assessment.score} grade={branch.assessment.grade} />
                    <code>{branch.branchOffset}</code>
                    <strong style={{ color: branch.alternateOutcomesObserved ? "#e5484d" : "#d29922" }}>{branch.classification}</strong>
                    <span>{branch.presentInRuns}/{comparison.cases.length} runs</span>
                  </div>
                  <div style={{ marginTop: 4 }}>{branch.cases.filter(item => item.present).map(item => `${item.label}: T${item.observedTakenCount}/F${item.observedFallthroughCount}/O${item.observedOtherCount}`).join(" · ")}</div>
                  <div style={{ marginTop: 4, color: "var(--text-tertiary)" }}>{branch.rationale}</div>
                </div>
              ))}
            </div>
          )}
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

      {report && section === "angr" && (
        <div style={{ flex: 1, minHeight: 0, display: "flex", overflow: "hidden" }}>
          <div style={{ width: 390, padding: 10, borderRight: "1px solid var(--border-color)", overflow: "auto", fontSize: 11 }}>
            <div style={{ color: "var(--text-secondary)", lineHeight: 1.5 }}>
              Generates a standalone Python bridge. Trace UI does not install or run angr; execute the saved script manually against the exact ELF/shared object used by this trace.
            </div>
            <div style={{ display: "grid", gridTemplateColumns: "150px minmax(0, 1fr)", gap: 7, alignItems: "center", marginTop: 10 }}>
              <span>Opaque branch probes</span>
              <label style={{ display: "flex", alignItems: "center", gap: 5 }}>
                <input type="checkbox" checked={angrProbeOpaque} onChange={event => { setAngrProbeOpaque(event.target.checked); setAngrScript(null); }} />
                unconstrained candidate probe
              </label>
              <span>CFG strategy</span>
              <label style={{ display: "flex", alignItems: "center", gap: 5 }}>
                <input type="checkbox" checked={angrCfgEmulated} onChange={event => { setAngrCfgEmulated(event.target.checked); setAngrScript(null); }} />
                prefer CFGEmulated
              </label>
            </div>
            <div style={{ display: "flex", gap: 6, flexWrap: "wrap", marginTop: 10 }}>
              <button type="button" style={{ ...buttonStyle, background: "var(--btn-primary)", color: "#fff", border: "none" }} onClick={generateAngrScript}>Generate Python</button>
              <button type="button" style={buttonStyle} onClick={saveAngrScript}>Save .py</button>
              <button type="button" style={buttonStyle} onClick={importAngrResults}>Import angr JSON</button>
              <button type="button" style={{ ...buttonStyle, opacity: angrScript ? 1 : 0.5 }} disabled={!angrScript} onClick={() => angrScript && navigator.clipboard.writeText(angrScript.script)}>Copy script</button>
            </div>
            <div style={{ display: "flex", gap: 6, marginTop: 8 }}>
              <button type="button" style={{ ...buttonStyle, background: angrDisplay === "script" ? "var(--bg-selected)" : "var(--bg-input)" }} onClick={() => setAngrDisplay("script")}>Script</button>
              <button type="button" style={{ ...buttonStyle, background: angrDisplay === "results" ? "var(--bg-selected)" : "var(--bg-input)", opacity: angrResults ? 1 : 0.5 }} disabled={!angrResults} onClick={() => setAngrDisplay("results")}>Imported results</button>
            </div>
            {angrSavedPath && <div title={angrSavedPath} style={{ marginTop: 8, color: "#3fb950", overflow: "hidden", textOverflow: "ellipsis" }}>Saved: {angrSavedPath}</div>}
            {angrResults && (
              <div style={{ marginTop: 10, paddingTop: 8, borderTop: "1px solid var(--border-color)", lineHeight: 1.5 }}>
                <strong>{angrResults.cfgKind} / angr {angrResults.angrVersion}</strong>
                <div>{angrResults.architecture} mapped at {angrResults.mappedBase}</div>
                <div title={angrResults.binarySha256} style={{ overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>SHA-256 {angrResults.binarySha256}</div>
                <div>{angrResults.blocks.length} blocks / {angrResults.branchProbes.length} probes</div>
              </div>
            )}
            {angrScript?.warnings.map((warning, index) => <div key={`script-${index}`} style={{ marginTop: 5, color: "#d29922" }}>{warning}</div>)}
            {angrResults?.warnings.map((warning, index) => <div key={`result-${index}`} style={{ marginTop: 5, color: "#d29922" }}>{warning}</div>)}
          </div>
          {angrDisplay === "script" && (
            <pre style={{ flex: 1, minWidth: 0, margin: 0, padding: 10, overflow: "auto", background: "var(--bg-primary)", color: "var(--text-primary)", fontSize: 10, lineHeight: 1.45, whiteSpace: "pre" }}>{angrScript?.script || ""}</pre>
          )}
          {angrDisplay === "results" && angrResults && (
            <div style={{ flex: 1, minWidth: 0, overflow: "auto", fontSize: 11 }}>
              <div style={{ padding: "8px 10px", borderBottom: "1px solid var(--border-color)", color: "var(--text-secondary)" }}>
                Unobserved static successors may be unexecuted, infeasible, or CFG recovery artifacts. A blank-state probe does not prove reachability from the real entry state.
              </div>
              {angrResults.blocks.map(block => (
                <div key={block.offset} style={{ display: "grid", gridTemplateColumns: "100px 90px 110px 130px minmax(180px, 1fr)", gap: 7, alignItems: "center", padding: "6px 8px", borderBottom: "1px solid var(--border-color)" }}>
                  <button type="button" style={buttonStyle} onClick={() => jumpOffset(block.offset)}>{block.offset}</button>
                  <span style={{ color: block.cfgNodeFound ? "#3fb950" : "#d29922" }}>{block.cfgNodeFound ? "CFG node" : "not found"}</span>
                  <span>{block.staticSuccessors.length} static</span>
                  <span>{block.unobservedStaticSuccessors.length} unseen / {block.dynamicOnlySuccessors.length} dynamic-only</span>
                  <span style={{ color: "var(--text-secondary)", overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
                    {block.functionName || ""} {block.unobservedStaticSuccessors.length ? `unseen: ${block.unobservedStaticSuccessors.join(", ")}` : ""}
                  </span>
                </div>
              ))}
              {angrResults.branchProbes.length > 0 && (
                <div style={{ padding: "9px 10px", borderBottom: "1px solid var(--border-color)", fontWeight: 600 }}>Opaque branch probes</div>
              )}
              {angrResults.branchProbes.map(probe => (
                <div key={probe.offset} style={{ padding: "7px 8px", borderBottom: "1px solid var(--border-color)" }}>
                  <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
                    <button type="button" style={buttonStyle} onClick={() => jumpOffset(probe.offset)}>{probe.offset}</button>
                    <code>{probe.status}</code>
                    <span>{probe.seedKind || "legacy seed"}{probe.sourceSeq != null ? ` @ line ${probe.sourceSeq + 1}` : ""}</span>
                    {probe.seededRegisters.length > 0 && <code>{probe.seededRegisters.join(", ")}</code>}
                    <span>{probe.successors.filter(successor => successor.satisfiable).length} satisfiable successors</span>
                    {probe.error && <span style={{ color: "#e5484d" }}>{probe.error}</span>}
                  </div>
                  <div style={{ marginTop: 4, paddingLeft: 108, color: "var(--text-secondary)" }}>{probe.limitation}</div>
                </div>
              ))}
            </div>
          )}
        </div>
      )}
    </div>
  );
}
