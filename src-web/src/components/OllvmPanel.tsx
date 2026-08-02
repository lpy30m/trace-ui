import React, { useCallback, useEffect, useMemo, useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import { useSelectedSeq } from "../stores/selectedSeqStore";
import OllvmUnicornPanel from "./OllvmUnicornPanel";
import type {
  AngrOllvmResultBundle,
  AngrOllvmScript,
  DynamicBasicBlock,
  FridaCaptureBundle,
  FridaCaptureEvent,
  FridaHookSeed,
  FridaOllvmDispatcherAtlas,
  FridaOllvmDispatcherHookScript,
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

function parsePointerRegisters(value: string): number[] | null {
  const trimmed = value.trim();
  if (!trimmed) return [];
  const result = new Set<number>();
  for (const token of trimmed.split(/[\s,;]+/)) {
    const match = /^x?([0-9]|1[0-9]|2[0-8])$/i.exec(token);
    if (!match) return null;
    result.add(Number(match[1]));
  }
  return [...result].sort((left, right) => left - right);
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
  const [section, setSection] = useState<"dispatchers" | "state" | "opaque" | "blocks" | "edges" | "compare" | "versions" | "atlas" | "ida" | "angr" | "unicorn">("dispatchers");
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
  const [angrFridaEventIndices, setAngrFridaEventIndices] = useState<number[]>([]);
  const [angrFridaIncludeSp, setAngrFridaIncludeSp] = useState(false);
  const [angrFridaIncludeLr, setAngrFridaIncludeLr] = useState(true);
  const [angrStaticBinaryPath, setAngrStaticBinaryPath] = useState<string | null>(null);
  const [atlasMaxDispatchers, setAtlasMaxDispatchers] = useState("12");
  const [atlasIdleGapMs, setAtlasIdleGapMs] = useState("1000");
  const [atlasMaxEvents, setAtlasMaxEvents] = useState("50000");
  const [atlasPointerRegisters, setAtlasPointerRegisters] = useState("");
  const [atlasPointerBytes, setAtlasPointerBytes] = useState("64");
  const [atlasStackBytes, setAtlasStackBytes] = useState("0");
  const [atlasScript, setAtlasScript] = useState<FridaOllvmDispatcherHookScript | null>(null);
  const [atlasBundle, setAtlasBundle] = useState<FridaCaptureBundle | null>(null);
  const [atlasCapturePath, setAtlasCapturePath] = useState<string | null>(null);
  const [atlasResult, setAtlasResult] = useState<FridaOllvmDispatcherAtlas | null>(null);
  const [atlasSavedPath, setAtlasSavedPath] = useState<string | null>(null);
  const [atlasResultSavedPath, setAtlasResultSavedPath] = useState<string | null>(null);
  const [atlasDisplay, setAtlasDisplay] = useState<"script" | "result">("script");
  const [atlasBusy, setAtlasBusy] = useState(false);

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
    setAngrFridaEventIndices([]);
    setAngrStaticBinaryPath(null);
    setAtlasScript(null);
    setAtlasBundle(null);
    setAtlasCapturePath(null);
    setAtlasResult(null);
    setAtlasSavedPath(null);
    setAtlasResultSavedPath(null);
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
    angrFridaBundle?.events.filter(event => (event.event === "hook-enter" || event.event === "ollvm-dispatcher-hit") && Object.keys(event.registers).length > 0) || []
  ), [angrFridaBundle]);
  const selectedAngrFridaEvents = useMemo(() => {
    const selected = new Set(angrFridaEventIndices);
    return angrFridaEvents.filter(event => selected.has(event.index));
  }, [angrFridaEventIndices, angrFridaEvents]);

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
    setAtlasScript(null);
    setAtlasResult(null);
    setAtlasSavedPath(null);
    setAtlasResultSavedPath(null);
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

  const prepareFridaOffsetHook = useCallback((offset: string, role: "branch" | "condition-source" | "dispatcher") => {
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

  const generateAtlasHook = useCallback(async (): Promise<FridaOllvmDispatcherHookScript | null> => {
    if (!report) return null;
    setAtlasBusy(true);
    setError(null);
    try {
      const capturePointerRegisters = parsePointerRegisters(atlasPointerRegisters);
      if (capturePointerRegisters == null) throw new Error("Pointer registers must be a comma-separated subset of X0-X28");
      const generated = await invoke<FridaOllvmDispatcherHookScript>("generate_frida_ollvm_dispatcher_hook", {
        report,
        maxDispatchers: optionalNumber(atlasMaxDispatchers) ?? 12,
        idleGapMs: optionalNumber(atlasIdleGapMs) ?? 1_000,
        maxEvents: optionalNumber(atlasMaxEvents) ?? 50_000,
        capturePointerRegisters,
        pointerCaptureBytes: optionalNumber(atlasPointerBytes) ?? 64,
        stackCaptureBytes: optionalNumber(atlasStackBytes) ?? 0,
      });
      setAtlasScript(generated);
      setAtlasDisplay("script");
      return generated;
    } catch (reason) {
      setError(String(reason));
      return null;
    } finally {
      setAtlasBusy(false);
    }
  }, [atlasIdleGapMs, atlasMaxDispatchers, atlasMaxEvents, atlasPointerBytes, atlasPointerRegisters, atlasStackBytes, report]);

  const saveAtlasHook = useCallback(async () => {
    if (!report) return;
    const generated = atlasScript || await generateAtlasHook();
    if (!generated) return;
    const { save } = await import("@tauri-apps/plugin-dialog");
    const path = await save({
      defaultPath: generated.fileName,
      filters: [{ name: "Frida JavaScript", extensions: ["js"] }],
    });
    if (typeof path !== "string") return;
    try {
      const capturePointerRegisters = parsePointerRegisters(atlasPointerRegisters);
      if (capturePointerRegisters == null) throw new Error("Pointer registers must be a comma-separated subset of X0-X28");
      const written = await invoke<string>("save_frida_ollvm_dispatcher_hook", {
        path,
        report,
        maxDispatchers: optionalNumber(atlasMaxDispatchers) ?? 12,
        idleGapMs: optionalNumber(atlasIdleGapMs) ?? 1_000,
        maxEvents: optionalNumber(atlasMaxEvents) ?? 50_000,
        capturePointerRegisters,
        pointerCaptureBytes: optionalNumber(atlasPointerBytes) ?? 64,
        stackCaptureBytes: optionalNumber(atlasStackBytes) ?? 0,
      });
      setAtlasSavedPath(written);
      setError(null);
    } catch (reason) {
      setError(String(reason));
    }
  }, [atlasIdleGapMs, atlasMaxDispatchers, atlasMaxEvents, atlasPointerBytes, atlasPointerRegisters, atlasScript, atlasStackBytes, generateAtlasHook, report]);

  const importAtlasCapture = useCallback(async () => {
    const { open } = await import("@tauri-apps/plugin-dialog");
    const path = await open({
      multiple: false,
      directory: false,
      title: "Select manually captured dispatcher Frida 16 output",
      filters: [{ name: "Frida capture", extensions: ["json", "jsonl", "ndjson", "log", "txt"] }],
    });
    if (typeof path !== "string") return;
    try {
      const bundle = await invoke<FridaCaptureBundle>("load_frida_capture", { path });
      const events = bundle.events.filter(event => (event.event === "ollvm-dispatcher-hit" || event.event === "hook-enter") && Object.keys(event.registers).length > 0);
      if (events.length === 0) throw new Error("capture has no dispatcher-compatible event with registers");
      setAtlasBundle(bundle);
      setAtlasCapturePath(path);
      setAtlasResult(null);
      setAtlasResultSavedPath(null);
      setError(null);
    } catch (reason) {
      setError(String(reason));
    }
  }, []);

  const analyzeAtlasCapture = useCallback(async (): Promise<FridaOllvmDispatcherAtlas | null> => {
    if (!report || !atlasBundle) return null;
    setAtlasBusy(true);
    setError(null);
    try {
      const atlas = await invoke<FridaOllvmDispatcherAtlas>("analyze_frida_ollvm_dispatcher_capture", {
        report,
        bundle: atlasBundle,
        idleGapMs: optionalNumber(atlasIdleGapMs) ?? 1_000,
        maxEvents: optionalNumber(atlasMaxEvents) ?? 50_000,
        maxValuesPerRegister: 64,
        maxStateChangesPerTransition: 128,
        maxFlowLength: 256,
        maxFlows: 2_048,
      });
      setAtlasResult(atlas);
      setAtlasDisplay("result");
      return atlas;
    } catch (reason) {
      setError(String(reason));
      return null;
    } finally {
      setAtlasBusy(false);
    }
  }, [atlasBundle, atlasIdleGapMs, atlasMaxEvents, report]);

  const saveAtlasResult = useCallback(async () => {
    if (!report || !atlasBundle) return;
    const atlas = atlasResult || await analyzeAtlasCapture();
    if (!atlas) return;
    const { save } = await import("@tauri-apps/plugin-dialog");
    const path = await save({
      defaultPath: `${report.scope.moduleName.replace(/[^A-Za-z0-9_.-]+/g, "_")}-ollvm-dispatcher-atlas.json`,
      filters: [{ name: "Trace UI dispatcher atlas", extensions: ["json"] }],
    });
    if (typeof path !== "string") return;
    try {
      const written = await invoke<string>("save_frida_ollvm_dispatcher_atlas", {
        path,
        report,
        bundle: atlasBundle,
        idleGapMs: optionalNumber(atlasIdleGapMs) ?? 1_000,
        maxEvents: optionalNumber(atlasMaxEvents) ?? 50_000,
        maxValuesPerRegister: 64,
        maxStateChangesPerTransition: 128,
        maxFlowLength: 256,
        maxFlows: 2_048,
      });
      setAtlasResultSavedPath(written);
      setError(null);
    } catch (reason) {
      setError(String(reason));
    }
  }, [analyzeAtlasCapture, atlasBundle, atlasIdleGapMs, atlasMaxEvents, atlasResult, report]);

  const clearAtlasCapture = useCallback(() => {
    setAtlasBundle(null);
    setAtlasCapturePath(null);
    setAtlasResult(null);
    setAtlasResultSavedPath(null);
  }, []);

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
      const events = bundle.events.filter(event => (event.event === "hook-enter" || event.event === "ollvm-dispatcher-hit") && Object.keys(event.registers).length > 0);
      if (events.length === 0) throw new Error("capture has no hook-enter or dispatcher-hit event with registers");
      setAngrFridaBundle(bundle);
      setAngrFridaPath(path);
      setAngrFridaEventIndices([events[0].index]);
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
    setAngrFridaEventIndices([]);
    setAngrScript(null);
  }, []);

  const selectAngrStaticBinary = useCallback(async () => {
    const { open } = await import("@tauri-apps/plugin-dialog");
    const path = await open({
      multiple: false,
      directory: false,
      title: "Select exact AArch64 ELF/shared object",
      filters: [{ name: "ELF/shared object", extensions: ["so", "elf", "bin"] }],
    });
    if (typeof path !== "string") return;
    setAngrStaticBinaryPath(path);
    setAngrScript(null);
  }, []);

  const toggleAngrFridaEvent = useCallback((eventIndex: number) => {
    setAngrFridaEventIndices(current => {
      if (current.includes(eventIndex)) return current.filter(index => index !== eventIndex);
      if (current.length >= 32) return current;
      return [...current, eventIndex].sort((left, right) => left - right);
    });
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
        fridaBundle: selectedAngrFridaEvents.length > 0 ? angrFridaBundle : null,
        fridaEventIndex: null,
        fridaEventIndices: selectedAngrFridaEvents.map(event => event.index),
        fridaIncludeSp: angrFridaIncludeSp,
        fridaIncludeLr: angrFridaIncludeLr,
        staticBinaryPath: angrStaticBinaryPath,
      });
      setAngrScript(generated);
      setAngrDisplay("script");
      return generated;
    } catch (reason) {
      setError(String(reason));
      return null;
    }
  }, [angrCfgEmulated, angrExploreFlows, angrFlowDepth, angrFlowStates, angrFridaBundle, angrFridaIncludeLr, angrFridaIncludeSp, angrProbeOpaque, angrStaticBinaryPath, report, selectedAngrFridaEvents]);

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
        fridaBundle: selectedAngrFridaEvents.length > 0 ? angrFridaBundle : null,
        fridaEventIndex: null,
        fridaEventIndices: selectedAngrFridaEvents.map(event => event.index),
        fridaIncludeSp: angrFridaIncludeSp,
        fridaIncludeLr: angrFridaIncludeLr,
        staticBinaryPath: angrStaticBinaryPath,
      });
      setAngrSavedPath(written);
    } catch (reason) {
      setError(String(reason));
    }
  }, [angrCfgEmulated, angrExploreFlows, angrFlowDepth, angrFlowStates, angrFridaBundle, angrFridaIncludeLr, angrFridaIncludeSp, angrProbeOpaque, angrScript, angrStaticBinaryPath, generateAngrScript, report, selectedAngrFridaEvents]);

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
        <label htmlFor="ollvm-node">节点 ID</label>
        <input id="ollvm-node" style={inputStyle} value={nodeId} onChange={event => setNodeId(event.target.value)} placeholder="可选" />
        <label htmlFor="ollvm-start">起始序号</label>
        <input id="ollvm-start" style={inputStyle} value={startSeq} onChange={event => setStartSeq(event.target.value)} placeholder="自动" />
        <label htmlFor="ollvm-end">结束序号</label>
        <input id="ollvm-end" style={inputStyle} value={endSeq} onChange={event => setEndSeq(event.target.value)} placeholder="自动" />
        <label htmlFor="ollvm-module">模块</label>
        <input id="ollvm-module" style={inputStyle} value={moduleName} onChange={event => setModuleName(event.target.value)} placeholder="从 trace 推断" />
        <button type="button" style={{ ...buttonStyle, opacity: sessionId && selectedSeq != null ? 1 : 0.5 }} disabled={!sessionId || selectedSeq == null} onClick={useSelectedFunction}>使用选中函数</button>
        <button type="button" style={{ ...buttonStyle, background: "var(--btn-primary)", color: "#fff", border: "none", opacity: !sessionId || loading ? 0.6 : 1 }} disabled={!sessionId || loading} onClick={analyze}>{loading ? "分析中…" : "分析 OLLVM"}</button>
      </div>
      <div style={{ padding: "6px 10px", borderBottom: "1px solid var(--border-color)", background: "var(--bg-secondary)", color: "var(--text-secondary)", fontSize: 11, lineHeight: 1.5 }}>
        <strong style={{ color: "var(--text-primary)" }}>手动工作流：</strong>
        分析候选 → 生成 Frida/IDA/angr 脚本 → 用户在目标环境中手动运行 → 导入结果。OLLVM 结构结论始终保持 Candidate/Related，需要人工复核。
      </div>
      <div style={{
        display: "flex", alignItems: "center", minHeight: 30, borderBottom: "1px solid var(--border-color)",
        overflowX: "auto", overflowY: "hidden", flexShrink: 0,
      }}>
        {sectionButton("dispatchers", `Dispatchers${report ? ` (${report.dispatcherCandidates.length})` : ""}`)}
        {sectionButton("state", "状态机")}
        {sectionButton("opaque", `Opaque 分支${report ? ` (${report.opaqueBranchCandidates.length})` : ""}`)}
        {sectionButton("blocks", `动态块${report ? ` (${report.blockCount})` : ""}`)}
        {sectionButton("edges", `边${report ? ` (${report.edgeCount})` : ""}`)}
        {sectionButton("compare", "多运行比较")}
        {sectionButton("versions", "跨版本")}
        {sectionButton("atlas", "Frida Atlas")}
        {sectionButton("ida", "IDA 桥接")}
        {sectionButton("angr", "angr 桥接")}
        {sectionButton("unicorn", "模拟增强")}
        <label style={{ display: "flex", alignItems: "center", gap: 4, marginLeft: 10, color: "var(--text-secondary)", fontSize: 10, flexShrink: 0, whiteSpace: "nowrap" }}>
          <input type="checkbox" checked={includeChildCalls} onChange={event => setIncludeChildCalls(event.target.checked)} />
          包含子调用
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
          请选择一次函数调用，或提供 trace 范围。
        </div>
      )}

      {report && section === "dispatchers" && (
        <div style={{ flex: 1, overflow: "auto" }}>
          {report.dispatcherCandidates.map(candidate => (
            <div key={candidate.blockId} style={{ display: "flex", alignItems: "center", gap: 8, padding: "6px 8px", borderBottom: "1px solid var(--border-color)", fontSize: 11 }}>
              <Score score={candidate.assessment.score} grade={candidate.assessment.grade} />
              <button type="button" style={buttonStyle} onClick={() => jumpBlock(blockById.get(candidate.blockId))}>{candidate.startOffset}</button>
              <span>{candidate.visitCount} 次访问</span>
              <span>{candidate.predecessorCount} 个入边 / {candidate.successorCount} 个出边</span>
              <span>{candidate.indirectBranchCount} 个间接分支</span>
              <code>{candidate.stateRegisters.join(", ") || "no state register"}</code>
              <span>{candidate.stateSnapshots.length} 个状态 / {candidate.stateTransitions.length} 次转换</span>
              <button type="button" style={buttonStyle} onClick={() => prepareFridaOffsetHook(candidate.startOffset, "dispatcher")}>准备 dispatcher Hook</button>
              <span style={{ flex: 1, color: "var(--text-secondary)" }}>{candidate.rationale}</span>
            </div>
          ))}
          {report.dispatcherCandidates.length === 0 && <div style={{ padding: 14, color: "var(--text-secondary)", fontSize: 11 }}>没有 dispatcher 候选达到证据阈值。</div>}
        </div>
      )}

      {report && section === "state" && (
        <div style={{ flex: 1, overflow: "auto", fontSize: 11 }}>
          <div style={{ padding: "8px 10px", borderBottom: "1px solid var(--border-color)", color: "var(--text-secondary)" }}>
            状态值由 dispatcher 块入口处的 trace 寄存器检查点重建，只表示已观察到的状态轨迹，不代表完整的控制流平坦化状态机。
          </div>
          {report.dispatcherCandidates.map(candidate => (
            <div key={candidate.blockId} style={{ borderBottom: "1px solid var(--border-color)", padding: "8px 10px" }}>
              <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
                <Score score={candidate.assessment.score} grade={candidate.assessment.grade} />
                <button type="button" style={buttonStyle} onClick={() => jumpBlock(blockById.get(candidate.blockId))}>{candidate.startOffset}</button>
                <strong>{candidate.stateSnapshots.length} 个快照</strong>
                <span>{candidate.stateTransitions.length} 次状态变化</span>
                {candidate.stateSnapshotsTruncated && <span style={{ color: "#d29922" }}>快照列表已截断</span>}
              </div>
              {candidate.stateTransitions.length > 0 && (
                <div style={{ marginTop: 7, display: "grid", gridTemplateColumns: "70px 170px 22px 170px 70px 80px", gap: 6, alignItems: "center" }}>
                  <strong>寄存器</strong><strong>从</strong><span /><strong>到</strong><strong>次数</strong><strong>Trace</strong>
                  {candidate.stateTransitions.map((transition, index) => (
                    <React.Fragment key={`${transition.register}-${transition.fromValue}-${transition.toValue}-${index}`}>
                      <code>{transition.register}</code>
                      <code>{transition.fromValue}</code>
                      <span>→</span>
                      <code>{transition.toValue}</code>
                      <span>x{transition.executionCount}</span>
                      <button type="button" style={buttonStyle} onClick={() => onJumpToSeq(transition.sampleSeq)}>第 {transition.sampleSeq + 1} 行</button>
                    </React.Fragment>
                  ))}
                </div>
              )}
              {candidate.stateTransitions.length === 0 && (
                <div style={{ marginTop: 6, color: "var(--text-tertiary)" }}>未能为候选状态寄存器重建出变化值。</div>
              )}
            </div>
          ))}
          {report.dispatcherCandidates.length === 0 && <div style={{ padding: 14, color: "var(--text-secondary)" }}>没有 dispatcher 候选达到证据阈值。</div>}
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
                <span>{candidate.executionCount} 次执行</span>
                <span>命中 {candidate.observedTakenCount} / 顺落 {candidate.observedFallthroughCount}</span>
                <span>{candidate.observations.filter(item => Object.keys(item.registers).length > 0).length} 个种子状态</span>
                <button type="button" style={buttonStyle} onClick={() => prepareFridaOffsetHook(candidate.branchOffset, "branch")}>准备分支 Hook</button>
              </div>
              <div style={{ marginTop: 4, paddingLeft: 88, color: "var(--text-secondary)" }}>{candidate.rationale}</div>
              {candidate.conditionStateProfile.sourceRegister && (
                <div style={{ marginTop: 5, marginLeft: 88, padding: "5px 7px", border: "1px solid var(--border-color)", borderRadius: 3, background: "var(--bg-secondary)" }}>
                  <div style={{ display: "flex", gap: 8, alignItems: "center", flexWrap: "wrap" }}>
                    <strong>条件状态 {candidate.conditionStateProfile.sourceRegister}</strong>
                    <span>{candidate.conditionStateProfile.capturedObservationCount} 条已捕获 / {candidate.conditionStateProfile.missingObservationCount} 条缺失</span>
                    <span>{candidate.conditionStateProfile.distinctValueCount} 个不同值</span>
                    {candidate.conditionStateProfile.incomplete && <span style={{ color: "#d29922" }}>配置不完整</span>}
                    {candidate.conditionStateProfile.flagBits.map(flag => (
                      <code key={`${candidate.branchOffset}-flag-${flag.flag}`}>{flag.flag}=1:{flag.setCount} / 0:{flag.clearCount}</code>
                    ))}
                  </div>
                  <div style={{ marginTop: 4, display: "flex", gap: 6, flexWrap: "wrap", color: "var(--text-tertiary)" }}>
                    {candidate.conditionStateProfile.values.map(value => <code key={`${candidate.branchOffset}-condition-${value.value}`}>{value.value} ×{value.count}</code>)}
                    {candidate.conditionStateProfile.outcomes.map(outcome => (
                      <span key={`${candidate.branchOffset}-outcome-${outcome.outcome}`}>
                        {outcome.outcome}: {outcome.values.map(value => `${value.value}×${value.count}`).join(", ") || `${outcome.observationCount} observations`}
                      </span>
                    ))}
                  </div>
                </div>
              )}
              {candidate.conditionSourceOffsets.length > 0 && (
                <div style={{ marginTop: 5, paddingLeft: 88, display: "flex", gap: 6, alignItems: "center", flexWrap: "wrap" }}>
                  <span style={{ color: "var(--text-tertiary)" }}>条件来源</span>
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
          {report.opaqueBranchCandidates.length === 0 && <div style={{ padding: 14, color: "var(--text-secondary)", fontSize: 11 }}>未观察到重复且结果单一的条件分支。</div>}
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
            <span /><strong>打开的 trace</strong><strong>案例标签</strong><strong>节点 ID</strong><strong>起始序号</strong><strong>结束序号</strong><strong>精确 ELF</strong>
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
            <button type="button" style={buttonStyle} onClick={refreshCompareSessions}>刷新会话</button>
            <button type="button" style={buttonStyle} disabled={selectedCompareCases.length === 0} onClick={selectElfForSelectedCases}>为选中项设置 ELF</button>
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
              <h4 style={{ margin: "8px 0" }}>Dispatcher 稳定性</h4>
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
              <h4 style={{ margin: "12px 0 8px" }}>分支结果稳定性</h4>
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
            <span /><strong>打开的 trace</strong><strong>版本 ID</strong><strong>模块</strong><strong>节点 ID</strong><strong>起始</strong><strong>结束</strong><strong>精确 ELF</strong><span />
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
                <button type="button" style={buttonStyle} onClick={() => selectVersionElf(index)}>浏览</button>
              </React.Fragment>
            ))}
          </div>
          <div style={{ display: "flex", gap: 6, alignItems: "center", marginTop: 9 }}>
            <button type="button" style={buttonStyle} onClick={refreshCompareSessions}>刷新会话</button>
            <label htmlFor="ollvm-baseline-version">基准版本</label>
            <select id="ollvm-baseline-version" style={{ ...inputStyle, minWidth: 150 }} value={baselineVersionId} onChange={event => { setBaselineVersionId(event.target.value); setVersionMap(null); }}>
              <option value="">第一个选中版本</option>
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
                <strong>版本</strong><strong>模块</strong><strong>动态 CFG</strong><strong>精确 ELF 身份</strong>
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
                    <strong>基准 dispatcher</strong>
                    <code>{mapping.sourceBlock.moduleName}+{mapping.sourceBlock.startOffset}</code>
                    <span>{mapping.sourceBlock.instructionCount} instructions</span>
                    <code>{mapping.sourceBlock.normalizedOperations.join(" · ")}</code>
                  </div>
                  {mapping.targets.map(target => (
                    <div key={target.targetVersionId} style={{ marginTop: 7, paddingTop: 7, borderTop: "1px solid var(--border-color)" }}>
                      <div style={{ display: "flex", gap: 8, alignItems: "center" }}>
                        <strong>{target.targetVersionId}</strong>
                        {target.ambiguous && <span style={{ color: "#d29922" }}>最高分候选存在歧义</span>}
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

      {report && section === "atlas" && (
        <div style={{ flex: 1, minHeight: 0, display: "flex", overflow: "hidden" }}>
          <div style={{ width: 430, padding: 10, borderRight: "1px solid var(--border-color)", overflow: "auto", fontSize: 11 }}>
            <div style={{ color: "var(--text-secondary)", lineHeight: 1.5 }}>
              Generate one bounded Frida 16 script for several exact dispatcher startOffsets. Run it manually, import the captured JSON/NDJSON, then reconstruct per-thread candidate dispatcher flows and state changes. Trace UI never attaches, spawns, loads, or runs Frida.
            </div>
            <div style={{ display: "grid", gridTemplateColumns: "150px minmax(0, 1fr)", gap: 7, alignItems: "center", marginTop: 10 }}>
              <label htmlFor="atlas-dispatchers">Dispatcher 目标数</label>
              <input id="atlas-dispatchers" style={inputStyle} value={atlasMaxDispatchers} onChange={event => { setAtlasMaxDispatchers(event.target.value); setAtlasScript(null); }} />
              <label htmlFor="atlas-idle-gap">Flow 空闲间隔（毫秒）</label>
              <input id="atlas-idle-gap" style={inputStyle} value={atlasIdleGapMs} onChange={event => { setAtlasIdleGapMs(event.target.value); setAtlasScript(null); setAtlasResult(null); }} />
              <label htmlFor="atlas-max-events">最大命中事件数</label>
              <input id="atlas-max-events" style={inputStyle} value={atlasMaxEvents} onChange={event => { setAtlasMaxEvents(event.target.value); setAtlasScript(null); setAtlasResult(null); }} />
              <label htmlFor="atlas-pointer-registers">指针内存（可选）</label>
              <input id="atlas-pointer-registers" placeholder="X0,X1" style={inputStyle} value={atlasPointerRegisters} onChange={event => { setAtlasPointerRegisters(event.target.value); setAtlasScript(null); }} />
              <label htmlFor="atlas-pointer-bytes">每个指针读取字节数</label>
              <input id="atlas-pointer-bytes" type="number" min={1} max={4096} style={inputStyle} value={atlasPointerBytes} onChange={event => { setAtlasPointerBytes(event.target.value); setAtlasScript(null); }} />
              <label htmlFor="atlas-stack-bytes">SP 栈捕获字节数</label>
              <input id="atlas-stack-bytes" type="number" min={0} max={16384} style={inputStyle} value={atlasStackBytes} onChange={event => { setAtlasStackBytes(event.target.value); setAtlasScript(null); }} />
            </div>
            <div style={{ marginTop: 6, color: "var(--text-tertiary)", lineHeight: 1.4 }}>
              Optional X0-X28 pointer snapshots and the bounded SP stack window become byteArray regions for later angr/Unicorn seeds. Invalid or unreadable ranges emit readError; no automatic retry or process control is performed.
            </div>
            <div style={{ display: "flex", gap: 6, flexWrap: "wrap", marginTop: 10 }}>
              <button type="button" style={{ ...buttonStyle, background: "var(--btn-primary)", color: "#fff", border: "none", opacity: atlasBusy ? 0.6 : 1 }} disabled={atlasBusy} onClick={generateAtlasHook}>{atlasBusy ? "处理中…" : "生成 Frida 16 脚本"}</button>
              <button type="button" style={buttonStyle} onClick={saveAtlasHook}>保存 .js</button>
              <button type="button" style={buttonStyle} onClick={importAtlasCapture}>导入捕获</button>
              <button type="button" style={{ ...buttonStyle, opacity: atlasBundle && !atlasBusy ? 1 : 0.5 }} disabled={!atlasBundle || atlasBusy} onClick={analyzeAtlasCapture}>构建 Atlas</button>
              <button type="button" style={{ ...buttonStyle, opacity: atlasBundle ? 1 : 0.5 }} disabled={!atlasBundle} onClick={saveAtlasResult}>保存 Atlas JSON</button>
            </div>
            <div style={{ display: "flex", gap: 6, marginTop: 8 }}>
              <button type="button" style={{ ...buttonStyle, background: atlasDisplay === "script" ? "var(--bg-selected)" : "var(--bg-input)", opacity: atlasScript ? 1 : 0.5 }} disabled={!atlasScript} onClick={() => setAtlasDisplay("script")}>生成脚本</button>
              <button type="button" style={{ ...buttonStyle, background: atlasDisplay === "result" ? "var(--bg-selected)" : "var(--bg-input)", opacity: atlasResult ? 1 : 0.5 }} disabled={!atlasResult} onClick={() => setAtlasDisplay("result")}>捕获 Atlas</button>
              <span style={{ flex: 1 }} />
              <button type="button" style={{ ...buttonStyle, opacity: atlasBundle ? 1 : 0.5 }} disabled={!atlasBundle} onClick={clearAtlasCapture}>清除捕获</button>
            </div>
            {atlasSavedPath && <div title={atlasSavedPath} style={{ marginTop: 8, color: "#3fb950", overflow: "hidden", textOverflow: "ellipsis" }}>Hook saved: {atlasSavedPath}</div>}
            {atlasResultSavedPath && <div title={atlasResultSavedPath} style={{ marginTop: 5, color: "#3fb950", overflow: "hidden", textOverflow: "ellipsis" }}>Atlas saved: {atlasResultSavedPath}</div>}
            {atlasBundle && (
              <div style={{ marginTop: 10, padding: 8, border: "1px solid var(--border-color)", borderRadius: 4, background: "var(--bg-secondary)", lineHeight: 1.5 }}>
                <strong>用户捕获文件</strong>
                <div title={atlasCapturePath || ""} style={{ overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{atlasCapturePath?.split(/[\\/]/).pop()}</div>
                <div>{atlasBundle.events.filter(event => event.event === "ollvm-dispatcher-hit").length} dedicated hits · {atlasBundle.enterEventCount} hook-enter events · {atlasBundle.hookIds.length} hooks</div>
              </div>
            )}
            {atlasScript && (
              <div style={{ marginTop: 10, lineHeight: 1.5 }}>
                <strong>{atlasScript.targets.length} dispatcher targets</strong>
                <div>{atlasScript.fridaApiVersion} · idle {atlasScript.idleGapMs} ms · limit {atlasScript.maxEvents.toLocaleString()}</div>
                <div>{atlasScript.capturePointerRegisters.length > 0 ? `${atlasScript.capturePointerRegisters.map(index => `X${index}`).join(", ")} · ${atlasScript.pointerCaptureBytes} bytes each` : "pointer memory capture disabled"}</div>
                <div>{atlasScript.stackCaptureBytes > 0 ? `SP stack · ${atlasScript.stackCaptureBytes} bytes` : "stack capture disabled"}</div>
                <div style={{ marginTop: 4, display: "flex", gap: 4, flexWrap: "wrap" }}>
                  {atlasScript.targets.map(target => <button key={target.offset} type="button" style={buttonStyle} onClick={() => jumpOffset(target.offset)}>{target.offset} · {target.score}</button>)}
                </div>
              </div>
            )}
            {atlasResult && (
              <div style={{ marginTop: 10, lineHeight: 1.5 }}>
                <strong>{atlasResult.nodes.length} nodes · {atlasResult.transitions.length} transitions</strong>
                <div>{atlasResult.matchedEventCount} matched / {atlasResult.skippedEventCount} skipped · {atlasResult.threadCount} threads · {atlasResult.flowCount} flows</div>
                <div>{atlasResult.explicitFlowCount} explicit / {atlasResult.derivedFlowCount} derived flows</div>
              </div>
            )}
            {atlasScript?.warnings.map((warning, index) => <div key={`atlas-script-${index}`} style={{ marginTop: 5, color: "#d29922" }}>{warning}</div>)}
            {atlasResult?.warnings.map((warning, index) => <div key={`atlas-warning-${index}`} style={{ marginTop: 5, color: "#d29922" }}>{warning}</div>)}
            {atlasResult?.limitations.map((limitation, index) => <div key={`atlas-limit-${index}`} style={{ marginTop: 5, color: "var(--text-tertiary)" }}>{limitation}</div>)}
          </div>
          {atlasDisplay === "script" ? (
            <pre style={{ flex: 1, minWidth: 0, margin: 0, padding: 10, overflow: "auto", background: "var(--bg-primary)", color: "var(--text-primary)", fontSize: 10, lineHeight: 1.45, whiteSpace: "pre" }}>{atlasScript?.script || ""}</pre>
          ) : (
            <div style={{ flex: 1, minWidth: 0, overflow: "auto", fontSize: 11 }}>
              {atlasResult?.transitions.map((transition, index) => (
                <div key={`${transition.fromOffset}-${transition.toOffset}-${index}`} style={{ padding: "7px 8px", borderBottom: "1px solid var(--border-color)" }}>
                  <div style={{ display: "flex", alignItems: "center", gap: 7, flexWrap: "wrap" }}>
                    <button type="button" style={buttonStyle} onClick={() => jumpOffset(transition.fromOffset)}>{transition.fromOffset}</button>
                    <span>→</span>
                    <button type="button" style={buttonStyle} onClick={() => jumpOffset(transition.toOffset)}>{transition.toOffset}</button>
                    <strong>{transition.executionCount} hits</strong>
                    <span>{transition.threadCount} threads / {transition.flowCount} flows</span>
                    <span style={{ color: "var(--text-tertiary)" }}>events #{transition.sampleFromEventIndex} → #{transition.sampleToEventIndex}</span>
                  </div>
                  {transition.stateChanges.length > 0 && (
                    <div style={{ marginTop: 5, paddingLeft: 12, display: "flex", gap: 5, flexWrap: "wrap" }}>
                      {transition.stateChanges.slice(0, 24).map(change => (
                        <code key={`${change.register}-${change.fromValue}-${change.toValue}`} title={`events #${change.sampleFromEventIndex} → #${change.sampleToEventIndex}`}>
                          {change.register}:{change.fromValue}→{change.toValue} ×{change.executionCount}
                        </code>
                      ))}
                      {(transition.stateChanges.length > 24 || transition.stateChangesTruncated) && <span style={{ color: "#d29922" }}>状态变化已截断</span>}
                    </div>
                  )}
                </div>
              ))}
              {atlasResult && atlasResult.transitions.length === 0 && <div style={{ padding: 14, color: "var(--text-secondary)" }}>No adjacent exact dispatcher transitions survived the thread/flow checks.</div>}
              {atlasResult?.nodes.map(node => (
                <details key={`atlas-node-${node.offset}`} style={{ padding: "7px 8px", borderBottom: "1px solid var(--border-color)" }}>
                  <summary style={{ cursor: "pointer" }}>
                    <button type="button" style={buttonStyle} onClick={event => { event.preventDefault(); jumpOffset(node.offset); }}>{node.offset}</button>
                    <span style={{ marginLeft: 8 }}>{node.eventCount} hits · {node.threadCount} threads · {node.flowCount} flows · {node.stateRegisters.join(", ") || "no ranked state register"}</span>
                  </summary>
                  <div style={{ marginTop: 6, paddingLeft: 12 }}>
                    {node.registerValues.map(register => (
                      <div key={`${node.offset}-${register.register}`} style={{ marginTop: 4 }}>
                        <code>{register.register}</code> {register.observedCount} observed / {register.missingCount} missing
                        <span style={{ marginLeft: 8 }}>{register.values.slice(0, 16).map(value => `${value.value}×${value.executionCount}`).join(", ") || "no value"}</span>
                        {(register.values.length > 16 || register.valuesTruncated) && <span style={{ marginLeft: 6, color: "#d29922" }}>已截断</span>}
                      </div>
                    ))}
                  </div>
                </details>
              ))}
              {atlasResult?.flows.slice(0, 256).map(flow => (
                <div key={`${flow.captureSessionId}-${flow.threadId}-${flow.flowId}`} style={{ padding: "5px 8px", borderBottom: "1px solid var(--border-color)", color: "var(--text-secondary)" }}>
                  <code>{flow.explicitFlowId ? "explicit" : "derived"} · T{flow.threadId} · {flow.eventCount} hits</code>
                  <span title={flow.offsets.join(" → ")} style={{ marginLeft: 8 }}>{flow.offsets.join(" → ")}{flow.offsetsTruncated ? " → …" : ""}</span>
                </div>
              ))}
              {atlasResult && (atlasResult.flows.length > 256 || atlasResult.flowsTruncated) && <div style={{ padding: 8, color: "#d29922" }}>Flow list truncated; aggregate node/transition counts are retained.</div>}
            </div>
          )}
        </div>
      )}

      {report && section === "ida" && (
        <div style={{ flex: 1, minHeight: 0, display: "flex", overflow: "hidden" }}>
          <div style={{ width: 360, padding: 10, borderRight: "1px solid var(--border-color)", overflow: "auto", fontSize: 11 }}>
            <div style={{ display: "grid", gridTemplateColumns: "110px minmax(0, 1fr)", gap: 7, alignItems: "center" }}>
              <label htmlFor="ida-image-base">IDA 镜像基址</label>
              <input id="ida-image-base" style={inputStyle} value={idaImageBase} onChange={event => { setIdaImageBase(event.target.value); setIdaScript(null); }} placeholder="use idaapi.get_imagebase()" />
              <span>用户交叉引用</span>
              <label style={{ display: "flex", alignItems: "center", gap: 5 }}>
                <input type="checkbox" checked={addUserXrefs} onChange={event => { setAddUserXrefs(event.target.checked); setIdaScript(null); }} />
                添加观测到的 CFG 边
              </label>
            </div>
            <div style={{ display: "flex", gap: 6, flexWrap: "wrap", marginTop: 10 }}>
              <button type="button" style={{ ...buttonStyle, background: "var(--btn-primary)", color: "#fff", border: "none" }} onClick={generateIdaScript}>生成 IDAPython</button>
              <button type="button" style={buttonStyle} onClick={saveIdaScript}>保存 .py</button>
              <button type="button" style={buttonStyle} onClick={importIdaAnnotations}>导入 IDA JSON</button>
              <button type="button" style={{ ...buttonStyle, opacity: idaScript ? 1 : 0.5 }} disabled={!idaScript} onClick={() => idaScript && navigator.clipboard.writeText(idaScript.script)}>复制脚本</button>
            </div>
            {savedPath && <div title={savedPath} style={{ marginTop: 8, color: "#3fb950", overflow: "hidden", textOverflow: "ellipsis" }}>已保存：{savedPath}</div>}
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
              <span>Opaque 分支探针</span>
              <label style={{ display: "flex", alignItems: "center", gap: 5 }}>
                <input type="checkbox" checked={angrProbeOpaque} onChange={event => { setAngrProbeOpaque(event.target.checked); setAngrScript(null); }} />
                无约束候选探针
              </label>
              <span>CFG 策略</span>
              <label style={{ display: "flex", alignItems: "center", gap: 5 }}>
                <input type="checkbox" checked={angrCfgEmulated} onChange={event => { setAngrCfgEmulated(event.target.checked); setAngrScript(null); }} />
                优先使用 CFGEmulated
              </label>
              <span>种子 Flow</span>
              <label style={{ display: "flex", alignItems: "center", gap: 5 }}>
                <input type="checkbox" disabled={!angrProbeOpaque} checked={angrExploreFlows && angrProbeOpaque} onChange={event => { setAngrExploreFlows(event.target.checked); setAngrScript(null); }} />
                有界延续
              </label>
              <span>Flow 边界</span>
              <div style={{ display: "flex", alignItems: "center", gap: 5 }}>
                <input aria-label="Seeded flow depth" title="Maximum symbolic flow depth" type="number" min={1} max={64} disabled={!angrProbeOpaque || !angrExploreFlows} style={{ ...inputStyle, width: 58 }} value={angrFlowDepth} onChange={event => { setAngrFlowDepth(event.target.value); setAngrScript(null); }} />
                <span>深度 /</span>
                <input aria-label="Seeded flow states" title="Maximum symbolic states per probe" type="number" min={1} max={256} disabled={!angrProbeOpaque || !angrExploreFlows} style={{ ...inputStyle, width: 64 }} value={angrFlowStates} onChange={event => { setAngrFlowStates(event.target.value); setAngrScript(null); }} />
                <span>状态数</span>
              </div>
            </div>
            <div style={{ marginTop: 6, color: "var(--text-tertiary)", lineHeight: 1.4 }}>
              Branch continuation applies to the first trace-register seed and every selected exact branch/condition Frida seed. Exact dispatcher-entry seeds explore independently until another dispatcher, loop, exit, or configured limit. Blank-state probes remain single-step.
            </div>
            <div style={{ marginTop: 10, paddingTop: 9, borderTop: "1px solid var(--border-color)" }}>
              <div style={{ display: "flex", alignItems: "center", gap: 6 }}>
                <strong>精确 ELF 身份校验</strong>
                <span style={{ flex: 1 }} />
                <button type="button" style={buttonStyle} onClick={selectAngrStaticBinary}>选择 ELF</button>
                <button type="button" style={{ ...buttonStyle, opacity: angrStaticBinaryPath ? 1 : 0.5 }} disabled={!angrStaticBinaryPath} onClick={() => { setAngrStaticBinaryPath(null); setAngrScript(null); }}>清除</button>
              </div>
              <div style={{ marginTop: 5, color: "var(--text-tertiary)", lineHeight: 1.4 }}>
                Trace UI hashes the selected AArch64 ELF and embeds its SHA-256. The manual Python bridge refuses a different file before CFG or symbolic analysis starts.
              </div>
              {angrStaticBinaryPath && <div title={angrStaticBinaryPath} style={{ marginTop: 5, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap", color: "var(--text-secondary)" }}>{angrStaticBinaryPath}</div>}
              {angrScript?.expectedBinaryIdentity && (
                <div style={{ marginTop: 5, color: "#3fb950", overflowWrap: "anywhere" }}>
                  SHA-256 guard: <code>{angrScript.expectedBinaryIdentity.binarySha256}</code>
                </div>
              )}
            </div>
            <div style={{ marginTop: 10, paddingTop: 9, borderTop: "1px solid var(--border-color)" }}>
              <div style={{ display: "flex", alignItems: "center", gap: 6 }}>
                <strong>精确偏移 Frida 种子</strong>
                <span style={{ flex: 1 }} />
                <button type="button" style={buttonStyle} onClick={importAngrFridaCapture}>导入捕获</button>
                <button type="button" style={{ ...buttonStyle, opacity: angrFridaBundle ? 1 : 0.5 }} disabled={!angrFridaBundle} onClick={clearAngrFridaCapture}>清除</button>
              </div>
              <div style={{ marginTop: 5, color: "var(--text-tertiary)", lineHeight: 1.4 }}>
                Select up to 32 events. Every hook-enter/dispatcher-hit target must exactly match an opaque branch, recorded condition-source, or dispatcher-entry module offset. Trace UI embeds the seeds but never runs Frida or angr.
              </div>
              {angrFridaBundle && (
                <div style={{ marginTop: 7 }}>
                  <div title={angrFridaPath || ""} style={{ overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap", color: "var(--text-secondary)" }}>{angrFridaPath?.split(/[\\/]/).pop()}</div>
                  <div style={{ maxHeight: 180, marginTop: 5, overflow: "auto", border: "1px solid var(--border-color)", borderRadius: 3 }}>
                    {angrFridaEvents.map(event => (
                      <label key={event.index} style={{ display: "grid", gridTemplateColumns: "20px minmax(0, 1fr)", gap: 5, alignItems: "start", padding: "5px 6px", borderBottom: "1px solid var(--border-color)", cursor: "pointer" }}>
                        <input type="checkbox" checked={angrFridaEventIndices.includes(event.index)} onChange={() => toggleAngrFridaEvent(event.index)} />
                        <span>
                          <span style={{ display: "block" }}>#{event.index} · {event.functionName} · {event.moduleName || "unknown module"} · {event.target || "no target"}</span>
                          <span style={{ display: "block", color: "var(--text-tertiary)" }}>{Object.keys(event.registers).length} registers · {event.captures.length} buffers · thread {event.threadId}</span>
                        </span>
                      </label>
                    ))}
                  </div>
                  <div style={{ marginTop: 5, color: "var(--text-secondary)" }}>{selectedAngrFridaEvents.length} selected / 32 maximum</div>
                  <div style={{ display: "flex", gap: 12, marginTop: 5 }}>
                    <label style={{ display: "flex", alignItems: "center", gap: 4 }}><input type="checkbox" checked={angrFridaIncludeLr} onChange={event => { setAngrFridaIncludeLr(event.target.checked); setAngrScript(null); }} />包含 LR</label>
                    <label style={{ display: "flex", alignItems: "center", gap: 4 }}><input type="checkbox" checked={angrFridaIncludeSp} onChange={event => { setAngrFridaIncludeSp(event.target.checked); setAngrScript(null); }} />包含 SP</label>
                  </div>
                </div>
              )}
              {angrScript && angrScript.fridaSeeds.length > 0 && (
                <div style={{ marginTop: 7, padding: 7, border: "1px solid #d29922", borderRadius: 4, background: "var(--bg-secondary)", lineHeight: 1.4 }}>
                  <strong>{angrScript.fridaSeeds.length} embedded Candidate seed{angrScript.fridaSeeds.length === 1 ? "" : "s"}</strong>
                  {angrScript.fridaSeeds.map(seed => (
                    <div key={seed.sourceEventIndex} style={{ marginTop: 4 }}>
                      event #{seed.sourceEventIndex} · <code>{seed.captureOffset}</code> → {seed.matchedProbeOffsets.join(", ")} · {seed.registersSeeded.length} registers · {seed.memoryRegionCount} memory regions
                    </div>
                  ))}
                </div>
              )}
            </div>
            <div style={{ display: "flex", gap: 6, flexWrap: "wrap", marginTop: 10 }}>
              <button type="button" style={{ ...buttonStyle, background: "var(--btn-primary)", color: "#fff", border: "none" }} onClick={generateAngrScript}>生成 Python</button>
              <button type="button" style={buttonStyle} onClick={saveAngrScript}>保存 .py</button>
              <button type="button" style={buttonStyle} onClick={importAngrResults}>导入 angr JSON</button>
              <button type="button" style={{ ...buttonStyle, opacity: angrScript ? 1 : 0.5 }} disabled={!angrScript} onClick={() => angrScript && navigator.clipboard.writeText(angrScript.script)}>复制脚本</button>
            </div>
            <div style={{ display: "flex", gap: 6, marginTop: 8 }}>
              <button type="button" style={{ ...buttonStyle, background: angrDisplay === "script" ? "var(--bg-selected)" : "var(--bg-input)" }} onClick={() => setAngrDisplay("script")}>脚本</button>
              <button type="button" style={{ ...buttonStyle, background: angrDisplay === "results" ? "var(--bg-selected)" : "var(--bg-input)", opacity: angrResults ? 1 : 0.5 }} disabled={!angrResults} onClick={() => setAngrDisplay("results")}>导入结果</button>
            </div>
            {angrSavedPath && <div title={angrSavedPath} style={{ marginTop: 8, color: "#3fb950", overflow: "hidden", textOverflow: "ellipsis" }}>已保存：{angrSavedPath}</div>}
            {angrResults && (
              <div style={{ marginTop: 10, paddingTop: 8, borderTop: "1px solid var(--border-color)", lineHeight: 1.5 }}>
                <strong>{angrResults.cfgKind} / angr {angrResults.angrVersion}</strong>
                <div>{angrResults.architecture} mapped at {angrResults.mappedBase}</div>
                <div title={angrResults.binarySha256} style={{ overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>SHA-256 {angrResults.binarySha256}</div>
                {angrResults.expectedBinarySha256 && (
                  <div style={{ color: angrResults.binaryIdentityMatched ? "#3fb950" : "#e5484d" }}>
                    Exact ELF guard {angrResults.binaryIdentityMatched ? "matched" : "mismatch"}
                  </div>
                )}
                <div>{angrResults.blocks.length} blocks / {angrResults.branchProbes.length} branch probes / {angrResults.dispatcherProbes.length} dispatcher probes</div>
                {angrResults.flowConfig?.enabled && <div>{angrResults.branchProbes.filter(probe => probe.flowExploration).length + angrResults.dispatcherProbes.filter(probe => probe.flowExploration).length} bounded flows / depth {angrResults.flowConfig.maxDepth} / {angrResults.flowConfig.maxStatesPerProbe} states each</div>}
                {angrResults.fridaSeeds.length > 0 && <div>{angrResults.fridaSeeds.length} Frida seeds: {angrResults.fridaSeeds.map(seed => `#${seed.sourceEventIndex}@${seed.captureOffset}`).join(", ")}</div>}
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
              {angrResults.dispatcherProbes.length > 0 && (
                <div style={{ padding: "9px 10px", borderBottom: "1px solid var(--border-color)", fontWeight: 600 }}>精确 dispatcher 入口 Frida 探针</div>
              )}
              {angrResults.dispatcherProbes.map(probe => (
                <div key={`dispatcher-${probe.offset}-${probe.sourceEventIndex}`} style={{ padding: "7px 8px", borderBottom: "1px solid var(--border-color)" }}>
                  <div style={{ display: "flex", alignItems: "center", gap: 8, flexWrap: "wrap" }}>
                    <button type="button" style={buttonStyle} onClick={() => jumpOffset(probe.offset)}>{probe.offset}</button>
                    <code>{probe.status}</code>
                    <span>Frida event #{probe.sourceEventIndex}</span>
                    {probe.seededRegisters.length > 0 && <code>{probe.seededRegisters.join(", ")}</code>}
                    {probe.seededMemoryRegions.length > 0 && <span>{probe.seededMemoryRegions.length} memory regions</span>}
                    {probe.sourceStateValues.map(value => (
                      <code key={`${probe.offset}-source-${value.register}`} title={value.alternatives.join(", ")}>
                        {value.register}={value.value || value.status}
                      </code>
                    ))}
                    {probe.error && <span style={{ color: "#e5484d" }}>{probe.error}</span>}
                  </div>
                  <div style={{ marginTop: 4, paddingLeft: 108, color: "var(--text-secondary)" }}>{probe.limitation}</div>
                  {probe.flowExploration && (
                    <details style={{ marginTop: 6, marginLeft: 108 }} open>
                      <summary style={{ cursor: "pointer", color: probe.flowExploration.truncated ? "#d29922" : "#3fb950" }}>
                        {probe.flowExploration.paths.length} bounded paths / {probe.flowExploration.exploredStates} states{probe.flowExploration.truncated ? " / truncated" : ""}
                      </summary>
                      <div style={{ marginTop: 5, color: "var(--text-tertiary)" }}>{probe.flowExploration.limitation}</div>
                      {probe.flowExploration.paths.map((path, pathIndex) => (
                        <div key={`${probe.offset}-dispatcher-flow-${pathIndex}`} style={{ display: "grid", gridTemplateColumns: "120px minmax(180px, 1fr) minmax(160px, 0.8fr) 90px", gap: 7, alignItems: "center", marginTop: 5, padding: "4px 6px", background: "var(--bg-secondary)", borderRadius: 3 }}>
                          <code title={path.constraints.join("\n")}>{path.status} · {path.constraintCount}c</code>
                          <span title={path.offsets.join(" -> ")} style={{ overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{path.offsets.join(" -> ") || path.terminalAddress}</span>
                          <span style={{ overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
                            {path.dispatcherStateValues.map(value => `${value.register}=${value.value || value.status}${value.alternatives.length ? `(${value.alternatives.join("|")})` : ""}`).join(", ") || "no concrete target state"}
                          </span>
                          {path.matchedDispatcherOffset
                            ? <button type="button" style={buttonStyle} onClick={() => jumpOffset(path.matchedDispatcherOffset!)}>{path.matchedDispatcherOffset}</button>
                            : path.terminalOffset
                              ? <button type="button" style={buttonStyle} onClick={() => jumpOffset(path.terminalOffset!)}>{path.terminalOffset}</button>
                              : <code>{path.terminalAddress}</code>}
                          {path.error && <span style={{ gridColumn: "1 / -1", color: "#e5484d" }}>{path.error}</span>}
                        </div>
                      ))}
                    </details>
                  )}
                </div>
              ))}
              {angrResults.branchProbes.length > 0 && (
                <div style={{ padding: "9px 10px", borderBottom: "1px solid var(--border-color)", fontWeight: 600 }}>Opaque 分支探针</div>
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
      {report && section === "unicorn" && <OllvmUnicornPanel report={report} />}
    </div>
  );
}
