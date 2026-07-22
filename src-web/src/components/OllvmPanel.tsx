import React, { useCallback, useEffect, useMemo, useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import { useSelectedSeq } from "../stores/selectedSeqStore";
import type {
  AngrOllvmResultBundle,
  AngrOllvmScript,
  DynamicBasicBlock,
  FridaCaptureBundle,
  FridaCaptureEvent,
  FridaHookSeed,
  FunctionInspection,
  IdaAnnotationBundle,
  IdaOllvmScript,
  OllvmAnalysisOptions,
  OllvmMultiTraceReport,
  OllvmReport,
  OllvmVersionMapReport,
  TraceSessionInfo,
} from "../types/trace";

interface Props {
  sessionId: string | null;
  onJumpToSeq: (seq: number) => void;
  onPrepareFridaHook: (seed: FridaHookSeed) => void;
}

interface EditableOllvmCase {
  sessionId: string;
  label: string;
  versionId: string;
  moduleName: string;
  selected: boolean;
  nodeId: string;
  startSeq: string;
  endSeq: string;
  staticBinaryPath: string;
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

export default function OllvmPanel({ sessionId, onJumpToSeq, onPrepareFridaHook }: Props) {
  const selectedSeq = useSelectedSeq();
  const [nodeId, setNodeId] = useState("");
  const [moduleName, setModuleName] = useState("");
  const [startSeq, setStartSeq] = useState("");
  const [endSeq, setEndSeq] = useState("");
  const [includeChildCalls, setIncludeChildCalls] = useState(false);
  const [report, setReport] = useState<OllvmReport | null>(null);
  const [comparison, setComparison] = useState<OllvmMultiTraceReport | null>(null);
  const [versionMap, setVersionMap] = useState<OllvmVersionMapReport | null>(null);
  const [compareCases, setCompareCases] = useState<EditableOllvmCase[]>([]);
  const [baselineVersionId, setBaselineVersionId] = useState("");
  const [requireMatchingBinary, setRequireMatchingBinary] = useState(true);
  const [comparing, setComparing] = useState(false);
  const [mappingVersions, setMappingVersions] = useState(false);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [section, setSection] = useState<"dispatchers" | "state" | "opaque" | "blocks" | "edges" | "compare" | "versions" | "ida" | "angr">("dispatchers");
  const [openBlock, setOpenBlock] = useState<string | null>(null);
  const [idaImageBase, setIdaImageBase] = useState("");
  const [addUserXrefs, setAddUserXrefs] = useState(false);
  const [idaScript, setIdaScript] = useState<IdaOllvmScript | null>(null);
  const [idaAnnotations, setIdaAnnotations] = useState<IdaAnnotationBundle | null>(null);
  const [savedPath, setSavedPath] = useState<string | null>(null);
  const [angrProbeOpaque, setAngrProbeOpaque] = useState(true);
  const [angrCfgEmulated, setAngrCfgEmulated] = useState(false);
  const [angrExploreFlows, setAngrExploreFlows] = useState(true);
  const [angrFlowDepth, setAngrFlowDepth] = useState("8");
  const [angrFlowStates, setAngrFlowStates] = useState("32");
  const [angrScript, setAngrScript] = useState<AngrOllvmScript | null>(null);
  const [angrResults, setAngrResults] = useState<AngrOllvmResultBundle | null>(null);
  const [angrSavedPath, setAngrSavedPath] = useState<string | null>(null);
  const [angrDisplay, setAngrDisplay] = useState<"script" | "results">("script");
  const [angrFridaBundle, setAngrFridaBundle] = useState<FridaCaptureBundle | null>(null);
  const [angrFridaPath, setAngrFridaPath] = useState<string | null>(null);
  const [angrFridaEventIndex, setAngrFridaEventIndex] = useState("");
  const [angrFridaIncludeSp, setAngrFridaIncludeSp] = useState(false);
  const [angrFridaIncludeLr, setAngrFridaIncludeLr] = useState(true);

  useEffect(() => {
    setReport(null);
    setComparison(null);
    setVersionMap(null);
    setIdaScript(null);
    setIdaAnnotations(null);
    setSavedPath(null);
    setAngrScript(null);
    setAngrResults(null);
    setAngrSavedPath(null);
    setAngrFridaBundle(null);
    setAngrFridaPath(null);
    setAngrFridaEventIndex("");
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

  const angrFridaEvents = useMemo<FridaCaptureEvent[]>(() => (
    angrFridaBundle?.events.filter(event => event.event === "hook-enter" && Object.keys(event.registers).length > 0) || []
  ), [angrFridaBundle]);
  const selectedAngrFridaEvent = useMemo(() => {
    const index = optionalNumber(angrFridaEventIndex);
    return index == null ? null : angrFridaEvents.find(event => event.index === index) || null;
  }, [angrFridaEventIndex, angrFridaEvents]);

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
          versionId: `version-${index + 1}`,
          moduleName: current ? moduleName : "",
          selected: current,
          nodeId: current ? nodeId : "",
          startSeq: current ? startSeq : "",
          endSeq: current ? endSeq : "",
          staticBinaryPath: "",
        };
      }));
    } catch (reason) {
      setError(String(reason));
    }
  }, [endSeq, moduleName, nodeId, sessionId, startSeq]);

  useEffect(() => {
    if (section === "compare" || section === "versions") void refreshCompareSessions();
  }, [refreshCompareSessions, section]);

  const selectedCompareCases = useMemo(() => compareCases.filter(item => item.selected), [compareCases]);
  const compareBinaryReady = !requireMatchingBinary || selectedCompareCases.every(item => item.staticBinaryPath.trim());
  const selectElfForSelectedCases = useCallback(async () => {
    if (selectedCompareCases.length === 0) return;
    const { open } = await import("@tauri-apps/plugin-dialog");
    const selected = await open({
      multiple: false,
      directory: false,
      title: "Select exact ELF/shared object for selected OLLVM runs",
      filters: [{ name: "ELF/shared object", extensions: ["so", "elf", "bin"] }],
    });
    if (typeof selected !== "string") return;
    const selectedIds = new Set(selectedCompareCases.map(item => item.sessionId));
    setCompareCases(items => items.map(item => selectedIds.has(item.sessionId)
      ? { ...item, staticBinaryPath: selected }
      : item));
    setComparison(null);
  }, [selectedCompareCases]);
  const compareRuns = useCallback(async () => {
    if (selectedCompareCases.length < 2 || !compareBinaryReady) return;
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
            staticBinaryPath: item.staticBinaryPath.trim() || null,
          })),
          requireMatchingBinary,
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
  }, [compareBinaryReady, includeChildCalls, moduleName, requireMatchingBinary, selectedCompareCases]);

  const updateCompareCase = (index: number, patch: Partial<EditableOllvmCase>) => {
    setCompareCases(items => items.map((item, itemIndex) => itemIndex === index ? { ...item, ...patch } : item));
  };

  const versionInputsReady = selectedCompareCases.length >= 2
    && selectedCompareCases.every(item => item.versionId.trim() && item.staticBinaryPath.trim());
  const selectVersionElf = useCallback(async (index: number) => {
    const { open } = await import("@tauri-apps/plugin-dialog");
    const selected = await open({
      multiple: false,
      directory: false,
      title: "Select exact ELF/shared object for this binary version",
      filters: [{ name: "ELF/shared object", extensions: ["so", "elf", "bin"] }],
    });
    if (typeof selected !== "string") return;
    updateCompareCase(index, { staticBinaryPath: selected });
    setVersionMap(null);
  }, []);
  const mapVersions = useCallback(async () => {
    if (!versionInputsReady) return;
    setMappingVersions(true);
    setError(null);
    try {
      const result = await invoke<OllvmVersionMapReport>("map_ollvm_versions", {
        request: {
          versions: selectedCompareCases.map(item => ({
            versionId: item.versionId.trim(),
            sessionId: item.sessionId,
            nodeId: optionalNumber(item.nodeId),
            moduleName: item.moduleName.trim() || null,
            startSeq: optionalNumber(item.startSeq),
            endSeq: optionalNumber(item.endSeq),
            includeChildCalls,
            staticBinaryPath: item.staticBinaryPath.trim(),
          })),
          baselineVersionId: baselineVersionId.trim() || null,
          maxBlocks: 1_000,
          maxEdges: 3_000,
          maxMatchesPerBlock: 3,
          minScore: 55,
        },
      });
      setVersionMap(result);
      if (!baselineVersionId) setBaselineVersionId(result.baselineVersionId);
    } catch (reason) {
      setError(String(reason));
      setVersionMap(null);
    } finally {
      setMappingVersions(false);
    }
  }, [baselineVersionId, includeChildCalls, selectedCompareCases, versionInputsReady]);

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

  const prepareFridaOffsetHook = useCallback((offset: string, role: "branch" | "condition-source") => {
    if (!report) return;
    onPrepareFridaHook({
      sourceLabel: `OLLVM ${role} candidate ${report.scope.moduleName}+${offset}`,
      moduleName: report.scope.moduleName,
      targetMode: "offset",
      symbol: "",
      offset,
      functionName: `ollvm-${role}-${offset.replace(/^0x/i, "")}`,
      arguments: [],
    });
  }, [onPrepareFridaHook, report]);

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

  const importAngrFridaCapture = useCallback(async () => {
    const { open } = await import("@tauri-apps/plugin-dialog");
    const path = await open({
      multiple: false,
      directory: false,
      title: "Select manually captured Frida 16 hook output",
      filters: [{ name: "Frida capture", extensions: ["json", "jsonl", "ndjson", "log", "txt"] }],
    });
    if (typeof path !== "string") return;
    try {
      const bundle = await invoke<FridaCaptureBundle>("load_frida_capture", { path });
      const events = bundle.events.filter(event => event.event === "hook-enter" && Object.keys(event.registers).length > 0);
      if (events.length === 0) throw new Error("capture has no hook-enter event with registers");
      setAngrFridaBundle(bundle);
      setAngrFridaPath(path);
      setAngrFridaEventIndex(String(events[0].index));
      setAngrProbeOpaque(true);
      setAngrScript(null);
      setError(null);
    } catch (reason) {
      setError(String(reason));
    }
  }, []);

  const clearAngrFridaCapture = useCallback(() => {
    setAngrFridaBundle(null);
    setAngrFridaPath(null);
    setAngrFridaEventIndex("");
    setAngrScript(null);
  }, []);

  const generateAngrScript = useCallback(async (): Promise<AngrOllvmScript | null> => {
    if (!report) return null;
    setError(null);
    try {
      const generated = await invoke<AngrOllvmScript>("generate_angr_ollvm_script", {
        report,
        probeOpaqueBranches: angrProbeOpaque,
        useCfgEmulated: angrCfgEmulated,
        exploreSeededFlows: angrExploreFlows,
        flowMaxDepth: optionalNumber(angrFlowDepth) ?? 8,
        flowMaxStatesPerProbe: optionalNumber(angrFlowStates) ?? 32,
        fridaBundle: selectedAngrFridaEvent ? angrFridaBundle : null,
        fridaEventIndex: selectedAngrFridaEvent?.index ?? null,
        fridaIncludeSp: angrFridaIncludeSp,
        fridaIncludeLr: angrFridaIncludeLr,
      });
      setAngrScript(generated);
      setAngrDisplay("script");
      return generated;
    } catch (reason) {
      setError(String(reason));
      return null;
    }
  }, [angrCfgEmulated, angrExploreFlows, angrFlowDepth, angrFlowStates, angrFridaBundle, angrFridaIncludeLr, angrFridaIncludeSp, angrProbeOpaque, report, selectedAngrFridaEvent]);

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
        exploreSeededFlows: angrExploreFlows,
        flowMaxDepth: optionalNumber(angrFlowDepth) ?? 8,
        flowMaxStatesPerProbe: optionalNumber(angrFlowStates) ?? 32,
        fridaBundle: selectedAngrFridaEvent ? angrFridaBundle : null,
        fridaEventIndex: selectedAngrFridaEvent?.index ?? null,
        fridaIncludeSp: angrFridaIncludeSp,
        fridaIncludeLr: angrFridaIncludeLr,
      });
      setAngrSavedPath(written);
    } catch (reason) {
      setError(String(reason));
    }
  }, [angrCfgEmulated, angrExploreFlows, angrFlowDepth, angrFlowStates, angrFridaBundle, angrFridaIncludeLr, angrFridaIncludeSp, angrProbeOpaque, angrScript, generateAngrScript, report, selectedAngrFridaEvent]);

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
        {sectionButton("versions", "Cross-version")}
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
      {!report && !loading && section !== "compare" && section !== "versions" && (
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
                <button type="button" style={buttonStyle} onClick={() => prepareFridaOffsetHook(candidate.branchOffset, "branch")}>Prepare branch Hook</button>
              </div>
              <div style={{ marginTop: 4, paddingLeft: 88, color: "var(--text-secondary)" }}>{candidate.rationale}</div>
              {candidate.conditionSourceOffsets.length > 0 && (
                <div style={{ marginTop: 5, paddingLeft: 88, display: "flex", gap: 6, alignItems: "center", flexWrap: "wrap" }}>
                  <span style={{ color: "var(--text-tertiary)" }}>Condition sources</span>
                  {candidate.conditionSourceOffsets.map(offset => (
                    <button key={`${candidate.branchOffset}-condition-${offset}`} type="button" style={buttonStyle} onClick={() => prepareFridaOffsetHook(offset, "condition-source")}>
                      {offset} · Prepare Hook
                    </button>
                  ))}
                </div>
              )}
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
          <div style={{ display: "grid", gridTemplateColumns: "26px minmax(140px, 1fr) minmax(110px, 180px) 80px 80px 80px minmax(190px, 1.4fr)", gap: 5, alignItems: "center" }}>
            <span /><strong>Open trace</strong><strong>Case label</strong><strong>Node ID</strong><strong>Start seq</strong><strong>End seq</strong><strong>Exact ELF</strong>
            {compareCases.map((item, index) => (
              <React.Fragment key={item.sessionId}>
                <input type="checkbox" checked={item.selected} onChange={event => updateCompareCase(index, { selected: event.target.checked })} />
                <span title={item.sessionId} style={{ overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{item.label}</span>
                <input style={inputStyle} value={item.label} onChange={event => updateCompareCase(index, { label: event.target.value })} />
                <input style={inputStyle} value={item.nodeId} onChange={event => updateCompareCase(index, { nodeId: event.target.value })} placeholder="optional" />
                <input style={inputStyle} value={item.startSeq} onChange={event => updateCompareCase(index, { startSeq: event.target.value })} placeholder="auto" />
                <input style={inputStyle} value={item.endSeq} onChange={event => updateCompareCase(index, { endSeq: event.target.value })} placeholder="auto" />
                <input style={inputStyle} value={item.staticBinaryPath} onChange={event => { updateCompareCase(index, { staticBinaryPath: event.target.value }); setComparison(null); }} placeholder="required by default" title={item.staticBinaryPath} />
              </React.Fragment>
            ))}
          </div>
          <div style={{ display: "flex", gap: 6, marginTop: 9 }}>
            <button type="button" style={buttonStyle} onClick={refreshCompareSessions}>Refresh sessions</button>
            <button type="button" style={buttonStyle} disabled={selectedCompareCases.length === 0} onClick={selectElfForSelectedCases}>Apply ELF to selected</button>
            <label style={{ display: "flex", alignItems: "center", gap: 4 }}>
              <input type="checkbox" checked={requireMatchingBinary} onChange={event => { setRequireMatchingBinary(event.target.checked); setComparison(null); }} />
              Require exact SHA-256 match
            </label>
            <button
              type="button"
              style={{ ...buttonStyle, background: "var(--btn-primary)", color: "#fff", border: "none", opacity: selectedCompareCases.length < 2 || !compareBinaryReady || comparing ? 0.6 : 1 }}
              disabled={selectedCompareCases.length < 2 || !compareBinaryReady || comparing}
              onClick={compareRuns}
            >
              {comparing ? "Comparing..." : `Compare ${selectedCompareCases.length} runs`}
            </button>
            <span style={{ alignSelf: "center", color: "var(--text-tertiary)" }}>Module: {moduleName.trim() || "infer per run"}</span>
          </div>
          {!compareBinaryReady && <div style={{ marginTop: 7, color: "#d29922" }}>Select the exact ELF for every selected run, or explicitly disable the matching requirement.</div>}
          {comparison && (
            <div style={{ marginTop: 12, borderTop: "1px solid var(--border-color)" }}>
              <div style={{ padding: "8px 0", color: "var(--text-secondary)" }}>
                {comparison.cases.length} runs · {comparison.dispatcherStability.length} dispatcher offsets · {comparison.branchStability.length} conditional branch offsets · verification gate remains closed
              </div>
              <div style={{ padding: 8, marginBottom: 8, border: `1px solid ${comparison.sameBinaryConfirmed ? "#2da44e" : "#d29922"}`, borderRadius: 4, background: "var(--bg-secondary)" }}>
                <strong>{comparison.binaryIdentityStatus}</strong>
                {comparison.binarySha256 && <code style={{ display: "block", marginTop: 4, overflowWrap: "anywhere" }}>SHA-256 {comparison.binarySha256}</code>}
                {comparison.buildId && <code style={{ display: "block", marginTop: 3 }}>Build ID {comparison.buildId}</code>}
                <div style={{ marginTop: 4, color: "var(--text-tertiary)" }}>Identity confirmation applies to the selected ELF files; OLLVM classifications remain Candidate/Related.</div>
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

      {section === "versions" && (
        <div style={{ flex: 1, minHeight: 0, overflow: "auto", padding: 10, fontSize: 11 }}>
          <div style={{ color: "var(--text-secondary)", marginBottom: 9, lineHeight: 1.5 }}>
            Map baseline dispatcher/state structure across different binary builds. Every selected version needs its own exact AArch64 ELF and trace scope. SHA-256 values must differ; offsets and concrete state values are never copied across versions. Results remain Candidate/Related.
          </div>
          <div style={{ display: "grid", gridTemplateColumns: "26px minmax(130px, 1fr) 120px minmax(110px, 160px) 90px 80px 80px minmax(190px, 1.4fr) 70px", gap: 5, alignItems: "center" }}>
            <span /><strong>Open trace</strong><strong>Version ID</strong><strong>Module</strong><strong>Node ID</strong><strong>Start</strong><strong>End</strong><strong>Exact ELF</strong><span />
            {compareCases.map((item, index) => (
              <React.Fragment key={`version-${item.sessionId}`}>
                <input type="checkbox" checked={item.selected} onChange={event => { updateCompareCase(index, { selected: event.target.checked }); setVersionMap(null); }} />
                <span title={item.sessionId} style={{ overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{item.label}</span>
                <input style={inputStyle} value={item.versionId} onChange={event => { updateCompareCase(index, { versionId: event.target.value }); setVersionMap(null); }} placeholder="unique build" />
                <input style={inputStyle} value={item.moduleName} onChange={event => { updateCompareCase(index, { moduleName: event.target.value }); setVersionMap(null); }} placeholder="infer" />
                <input style={inputStyle} value={item.nodeId} onChange={event => { updateCompareCase(index, { nodeId: event.target.value }); setVersionMap(null); }} placeholder="optional" />
                <input style={inputStyle} value={item.startSeq} onChange={event => { updateCompareCase(index, { startSeq: event.target.value }); setVersionMap(null); }} placeholder="auto" />
                <input style={inputStyle} value={item.endSeq} onChange={event => { updateCompareCase(index, { endSeq: event.target.value }); setVersionMap(null); }} placeholder="auto" />
                <input style={inputStyle} value={item.staticBinaryPath} onChange={event => { updateCompareCase(index, { staticBinaryPath: event.target.value }); setVersionMap(null); }} placeholder="required" title={item.staticBinaryPath} />
                <button type="button" style={buttonStyle} onClick={() => selectVersionElf(index)}>Browse</button>
              </React.Fragment>
            ))}
          </div>
          <div style={{ display: "flex", gap: 6, alignItems: "center", marginTop: 9 }}>
            <button type="button" style={buttonStyle} onClick={refreshCompareSessions}>Refresh sessions</button>
            <label htmlFor="ollvm-baseline-version">Baseline</label>
            <select id="ollvm-baseline-version" style={{ ...inputStyle, minWidth: 150 }} value={baselineVersionId} onChange={event => { setBaselineVersionId(event.target.value); setVersionMap(null); }}>
              <option value="">First selected version</option>
              {selectedCompareCases.filter(item => item.versionId.trim()).map(item => <option key={item.sessionId} value={item.versionId.trim()}>{item.versionId.trim()}</option>)}
            </select>
            <button
              type="button"
              style={{ ...buttonStyle, background: "var(--btn-primary)", color: "#fff", border: "none", opacity: !versionInputsReady || mappingVersions ? 0.6 : 1 }}
              disabled={!versionInputsReady || mappingVersions}
              onClick={mapVersions}
            >
              {mappingVersions ? "Mapping..." : `Map ${selectedCompareCases.length} versions`}
            </button>
          </div>
          {!versionInputsReady && <div style={{ marginTop: 7, color: "#d29922" }}>Select at least two traces and provide a unique version ID plus exact ELF path for every selected version.</div>}
          {versionMap && (
            <div style={{ marginTop: 12, borderTop: "1px solid var(--border-color)" }}>
              <div style={{ padding: "8px 0", color: "var(--text-secondary)" }}>
                Baseline <strong>{versionMap.baselineVersionId}</strong> · {versionMap.versions.length} distinct ELFs · {versionMap.dispatcherMappings.length} baseline dispatcher candidates · verification gate remains closed
              </div>
              <div style={{ display: "grid", gridTemplateColumns: "120px minmax(130px, 1fr) 100px minmax(220px, 1.4fr)", gap: 6, marginBottom: 10 }}>
                <strong>Version</strong><strong>Module</strong><strong>Dynamic CFG</strong><strong>Exact ELF identity</strong>
                {versionMap.versions.map(version => (
                  <React.Fragment key={version.versionId}>
                    <code>{version.versionId}</code>
                    <span>{version.moduleName}</span>
                    <span>{version.blockCount} blocks / {version.edgeCount} edges</span>
                    <code title={version.binaryIdentity.binarySha256} style={{ overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{version.binaryIdentity.binarySha256}</code>
                  </React.Fragment>
                ))}
              </div>
              {versionMap.dispatcherMappings.map(mapping => (
                <div key={mapping.sourceBlock.blockId} style={{ padding: 8, border: "1px solid var(--border-color)", borderRadius: 4, marginBottom: 8, background: "var(--bg-secondary)" }}>
                  <div style={{ display: "flex", gap: 8, alignItems: "center", flexWrap: "wrap" }}>
                    <strong>Baseline dispatcher</strong>
                    <code>{mapping.sourceBlock.moduleName}+{mapping.sourceBlock.startOffset}</code>
                    <span>{mapping.sourceBlock.instructionCount} instructions</span>
                    <code>{mapping.sourceBlock.normalizedOperations.join(" · ")}</code>
                  </div>
                  {mapping.targets.map(target => (
                    <div key={target.targetVersionId} style={{ marginTop: 7, paddingTop: 7, borderTop: "1px solid var(--border-color)" }}>
                      <div style={{ display: "flex", gap: 8, alignItems: "center" }}>
                        <strong>{target.targetVersionId}</strong>
                        {target.ambiguous && <span style={{ color: "#d29922" }}>ambiguous top candidates</span>}
                        <span>{target.candidates.length} retained</span>
                      </div>
                      {target.candidates.map(candidate => (
                        <div key={candidate.targetBlock.blockId} style={{ display: "grid", gridTemplateColumns: "82px 150px 100px 120px minmax(200px, 1fr)", gap: 7, alignItems: "center", marginTop: 5 }}>
                          <Score score={candidate.score} grade={candidate.assessment.grade} />
                          <code>{candidate.targetBlock.moduleName}+{candidate.targetBlock.startOffset}</code>
                          <span>{candidate.operationSimilarity}% operations</span>
                          <strong style={{ color: candidate.score >= 80 && !target.ambiguous ? "#3fb950" : "#d29922" }}>{candidate.classification}</strong>
                          <span title={candidate.rationale} style={{ color: "var(--text-tertiary)", overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
                            {candidate.stateRegisterMatches.map(item => `${item.sourceRegister}→${item.targetRegister} ${item.score}`).join(", ") || "no state-register role match"}
                          </span>
                        </div>
                      ))}
                      {target.candidates.length === 0 && <div style={{ marginTop: 5, color: "var(--text-tertiary)" }}>No block reached the bounded score threshold; collect wider coverage or inspect manually.</div>}
                    </div>
                  ))}
                </div>
              ))}
              {versionMap.dispatcherMappings.length === 0 && <div style={{ color: "var(--text-tertiary)" }}>The baseline trace has no dispatcher candidate to map.</div>}
              {versionMap.limitations.map((limitation, index) => <div key={index} style={{ marginTop: 5, color: "#d29922" }}>{limitation}</div>)}
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
          <div style={{ width: 440, padding: 10, borderRight: "1px solid var(--border-color)", overflow: "auto", fontSize: 11 }}>
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
              <span>Seeded flow</span>
              <label style={{ display: "flex", alignItems: "center", gap: 5 }}>
                <input type="checkbox" disabled={!angrProbeOpaque} checked={angrExploreFlows && angrProbeOpaque} onChange={event => { setAngrExploreFlows(event.target.checked); setAngrScript(null); }} />
                bounded continuation
              </label>
              <span>Flow bounds</span>
              <div style={{ display: "flex", alignItems: "center", gap: 5 }}>
                <input aria-label="Seeded flow depth" title="Maximum symbolic flow depth" type="number" min={1} max={64} disabled={!angrProbeOpaque || !angrExploreFlows} style={{ ...inputStyle, width: 58 }} value={angrFlowDepth} onChange={event => { setAngrFlowDepth(event.target.value); setAngrScript(null); }} />
                <span>depth /</span>
                <input aria-label="Seeded flow states" title="Maximum symbolic states per probe" type="number" min={1} max={256} disabled={!angrProbeOpaque || !angrExploreFlows} style={{ ...inputStyle, width: 64 }} value={angrFlowStates} onChange={event => { setAngrFlowStates(event.target.value); setAngrScript(null); }} />
                <span>states</span>
              </div>
            </div>
            <div style={{ marginTop: 6, color: "var(--text-tertiary)", lineHeight: 1.4 }}>
              Flow continuation applies only to the first trace-register seed per candidate and an exact-offset Frida seed. Blank-state probes remain single-step.
            </div>
            <div style={{ marginTop: 10, paddingTop: 9, borderTop: "1px solid var(--border-color)" }}>
              <div style={{ display: "flex", alignItems: "center", gap: 6 }}>
                <strong>Exact-offset Frida seed</strong>
                <span style={{ flex: 1 }} />
                <button type="button" style={buttonStyle} onClick={importAngrFridaCapture}>Import capture</button>
                <button type="button" style={{ ...buttonStyle, opacity: angrFridaBundle ? 1 : 0.5 }} disabled={!angrFridaBundle} onClick={clearAngrFridaCapture}>Clear</button>
              </div>
              <div style={{ marginTop: 5, color: "var(--text-tertiary)", lineHeight: 1.4 }}>
                The selected hook-enter target must exactly match an opaque branch or its recorded condition-source module offset. Trace UI embeds the seed but never runs Frida or angr.
              </div>
              {angrFridaBundle && (
                <div style={{ marginTop: 7 }}>
                  <div title={angrFridaPath || ""} style={{ overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap", color: "var(--text-secondary)" }}>{angrFridaPath?.split(/[\\/]/).pop()}</div>
                  <select style={{ ...inputStyle, width: "100%", marginTop: 5 }} value={angrFridaEventIndex} onChange={event => { setAngrFridaEventIndex(event.target.value); setAngrScript(null); }}>
                    {angrFridaEvents.map(event => (
                      <option key={event.index} value={event.index}>#{event.index} · {event.functionName} · {event.moduleName || "unknown module"} · {event.target || "no target"}</option>
                    ))}
                  </select>
                  {selectedAngrFridaEvent && (
                    <div style={{ marginTop: 5, color: "var(--text-secondary)", lineHeight: 1.4 }}>
                      {Object.keys(selectedAngrFridaEvent.registers).length} registers · {selectedAngrFridaEvent.captures.length} buffers · thread {selectedAngrFridaEvent.threadId}
                    </div>
                  )}
                  <div style={{ display: "flex", gap: 12, marginTop: 5 }}>
                    <label style={{ display: "flex", alignItems: "center", gap: 4 }}><input type="checkbox" checked={angrFridaIncludeLr} onChange={event => { setAngrFridaIncludeLr(event.target.checked); setAngrScript(null); }} />Include LR</label>
                    <label style={{ display: "flex", alignItems: "center", gap: 4 }}><input type="checkbox" checked={angrFridaIncludeSp} onChange={event => { setAngrFridaIncludeSp(event.target.checked); setAngrScript(null); }} />Include SP</label>
                  </div>
                </div>
              )}
              {angrScript?.fridaSeed && (
                <div style={{ marginTop: 7, padding: 7, border: "1px solid #d29922", borderRadius: 4, background: "var(--bg-secondary)", lineHeight: 1.4 }}>
                  <strong>Embedded Candidate seed</strong>
                  <div><code>{angrScript.fridaSeed.captureOffset}</code> → {angrScript.fridaSeed.matchedProbeOffsets.join(", ")}</div>
                  <div>{angrScript.fridaSeed.registersSeeded.length} registers · {angrScript.fridaSeed.memoryRegionCount} memory regions · event #{angrScript.fridaSeed.sourceEventIndex}</div>
                </div>
              )}
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
                {angrResults.flowConfig?.enabled && <div>{angrResults.branchProbes.filter(probe => probe.flowExploration).length} bounded flows / depth {angrResults.flowConfig.maxDepth} / {angrResults.flowConfig.maxStatesPerProbe} states each</div>}
                {angrResults.fridaSeed && <div>Frida event #{angrResults.fridaSeed.sourceEventIndex} at {angrResults.fridaSeed.captureOffset} → {angrResults.fridaSeed.matchedProbeOffsets.join(", ")}</div>}
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
                Unobserved static successors may be unexecuted, infeasible, or CFG recovery artifacts. Blank-state and bounded seeded-flow probes do not prove reachability from the real entry state.
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
              {angrResults.branchProbes.map((probe, probeIndex) => (
                <div key={`${probe.offset}-${probe.seedKind || "legacy"}-${probe.sourceSeq ?? probe.sourceEventIndex ?? probeIndex}`} style={{ padding: "7px 8px", borderBottom: "1px solid var(--border-color)" }}>
                  <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
                    <button type="button" style={buttonStyle} onClick={() => jumpOffset(probe.offset)}>{probe.offset}</button>
                    <code>{probe.status}</code>
                    <span>{probe.seedKind || "legacy seed"}{probe.sourceSeq != null ? ` @ line ${probe.sourceSeq + 1}` : ""}{probe.sourceEventIndex != null ? ` · Frida event #${probe.sourceEventIndex}` : ""}{probe.sourceOffset ? ` · ${probe.sourceOffset}` : ""}</span>
                    {probe.seededRegisters.length > 0 && <code>{probe.seededRegisters.join(", ")}</code>}
                    {probe.seededMemoryRegions.length > 0 && <span>{probe.seededMemoryRegions.length} memory regions</span>}
                    <span>{probe.successors.filter(successor => successor.satisfiable).length} satisfiable successors</span>
                    {probe.error && <span style={{ color: "#e5484d" }}>{probe.error}</span>}
                  </div>
                  <div style={{ marginTop: 4, paddingLeft: 108, color: "var(--text-secondary)" }}>{probe.limitation}</div>
                  {probe.flowExploration && (
                    <details style={{ marginTop: 6, marginLeft: 108 }}>
                      <summary style={{ cursor: "pointer", color: probe.flowExploration.truncated ? "#d29922" : "#3fb950" }}>
                        {probe.flowExploration.paths.length} bounded paths / {probe.flowExploration.exploredStates} states{probe.flowExploration.truncated ? " / truncated" : ""}
                      </summary>
                      <div style={{ marginTop: 5, color: "var(--text-tertiary)" }}>{probe.flowExploration.limitation}</div>
                      {probe.flowExploration.paths.map((path, pathIndex) => (
                        <div key={`${probe.offset}-flow-${pathIndex}`} style={{ display: "grid", gridTemplateColumns: "110px minmax(180px, 1fr) 90px", gap: 7, alignItems: "center", marginTop: 5, padding: "4px 6px", background: "var(--bg-secondary)", borderRadius: 3 }}>
                          <code title={path.constraints.join("\n")}>{path.status} · {path.constraintCount}c</code>
                          <span title={path.offsets.join(" -> ")} style={{ overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{path.offsets.join(" -> ") || path.terminalAddress}</span>
                          {path.terminalOffset
                            ? <button type="button" style={buttonStyle} onClick={() => jumpOffset(path.terminalOffset!)}>{path.terminalOffset}</button>
                            : <code>{path.terminalAddress}</code>}
                          {path.error && <span style={{ gridColumn: "1 / -1", color: "#e5484d" }}>{path.error}</span>}
                        </div>
                      ))}
                    </details>
                  )}
                </div>
              ))}
            </div>
          )}
        </div>
      )}
    </div>
  );
}
