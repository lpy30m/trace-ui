import { useMemo, useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import type {
  AngrOllvmResultBundle,
  AngrOllvmScript,
  FridaCaptureBundle,
  FridaCaptureEvent,
  FridaUnicornCheckpointHookScript,
  FridaUnicornRecaptureHookScript,
  OllvmReport,
  UnicornOllvmRoundComparisonReport,
  UnicornOllvmResultBundle,
  UnicornRecaptureSuggestion,
  UnicornOllvmScript,
} from "../types/trace";

interface Props {
  report: OllvmReport;
}

const buttonStyle: React.CSSProperties = {
  padding: "4px 9px",
  border: "1px solid var(--border-color)",
  borderRadius: 4,
  background: "var(--bg-input)",
  color: "var(--text-primary)",
  cursor: "pointer",
  fontSize: 11,
};

const inputStyle: React.CSSProperties = {
  width: "100%",
  boxSizing: "border-box",
  padding: "4px 6px",
  border: "1px solid var(--border-color)",
  borderRadius: 3,
  background: "var(--bg-input)",
  color: "var(--text-primary)",
  fontSize: 11,
};

function positiveInteger(value: string, fallback: number): number {
  const parsed = Number(value);
  return Number.isInteger(parsed) && parsed > 0 ? parsed : fallback;
}

function eventOffset(event: FridaCaptureEvent): string {
  if (event.dispatcherOffset) return event.dispatcherOffset;
  if (event.target && event.moduleBase) {
    try {
      return `0x${(BigInt(event.target) - BigInt(event.moduleBase)).toString(16)}`;
    } catch {
      return event.target;
    }
  }
  return event.target || "unknown-offset";
}

function stateText(values: Array<{ register: string; status: string; value: string | null }>): string {
  return values.map(value => `${value.register}=${value.value || value.status}`).join(", ") || "no state register";
}

function automaticRecaptureSupported(suggestion: UnicornRecaptureSuggestion): boolean {
  if (!suggestion.baseRegister) return false;
  if (!/^(?:X(?:[0-9]|1[0-9]|2[0-8])|SP)$/i.test(suggestion.baseRegister)) return false;
  const displacement = suggestion.displacement || "0";
  return /^[+-]?(?:0x[0-9a-f]+|[0-9]+)$/i.test(displacement);
}

const checkpointStopReasons = new Set([
  "missing-memory",
  "missing-register",
  "call-boundary",
  "loop-detected",
  "instruction-limit",
  "timeout",
]);

function checkpointSeedOffsets(bundle: UnicornOllvmResultBundle): string[] {
  const seedsByEvent = new Map(bundle.seeds.map(seed => [seed.sourceEventIndex, seed.captureOffset]));
  return Array.from(new Set(bundle.runs
    .filter(run => {
      if (!checkpointStopReasons.has(run.stopReason)) return false;
      const start = run.startOffset.toLowerCase();
      const missingOffsets = run.stopReason === "missing-memory"
        ? run.missingMemory.map(missing => missing.pcOffset).filter((offset): offset is string => Boolean(offset))
        : [];
      if (missingOffsets.length > 0) return missingOffsets.some(offset => offset.toLowerCase() !== start);
      if (run.stopReason === "call-boundary") {
        return (run.callBoundaries || []).some(boundary => Boolean(boundary.returnOffset && boundary.returnOffset.toLowerCase() !== start));
      }
      return Boolean(run.terminalOffset && run.terminalOffset.toLowerCase() !== start);
    })
    .map(run => seedsByEvent.get(run.sourceEventIndex))
    .filter((offset): offset is string => Boolean(offset))))
    .slice(0, 32);
}

function comparisonCheckpointSeedOffsets(report: UnicornOllvmRoundComparisonReport): string[] {
  const latestRoundId = report.rounds[report.rounds.length - 1]?.roundId;
  if (!latestRoundId) return [];
  return report.seeds.filter(seed => {
    const observation = seed.observations.find(value => value.roundId === latestRoundId);
    if (!observation?.present || !observation.stopReasons.some(reason => checkpointStopReasons.has(reason))) return false;
    const start = seed.captureOffset.toLowerCase();
    if (observation.stopReasons.includes("missing-memory") && observation.missingPcOffsets.length > 0) {
      return observation.missingPcOffsets.some(offset => offset.toLowerCase() !== start);
    }
    if (observation.stopReasons.includes("call-boundary")) return observation.terminalOffsets.some(offset => offset.toLowerCase() !== start);
    return observation.terminalOffsets.some(offset => offset.toLowerCase() !== start);
  }).map(seed => seed.captureOffset).slice(0, 32);
}

function roundStatusColor(status: string): string {
  if (["reached-new-dispatcher", "resolved-prior-stop", "missing-memory-moved-forward", "advanced-coverage", "candidate-progress-observed"].includes(status)) return "#3fb950";
  if (["stalled-same-missing-memory", "stalled-same-terminal", "longer-same-coverage", "unchanged", "stalled-seeds-present"].includes(status)) return "#d29922";
  if (["regressed-coverage", "regression-present"].includes(status)) return "#e5484d";
  return "var(--text-secondary)";
}

function countMapText(values: Record<string, number>): string {
  return Object.entries(values)
    .sort(([left], [right]) => left.localeCompare(right))
    .map(([name, count]) => `${name}=${count}`)
    .join(" · ") || "none";
}

function offsetList(values: string[], truncated = false): string {
  if (values.length === 0) return "none";
  return `${values.join(", ")}${truncated ? ", …" : ""}`;
}

export default function OllvmUnicornPanel({ report }: Props) {
  const [binaryPath, setBinaryPath] = useState<string | null>(null);
  const [capturePath, setCapturePath] = useState<string | null>(null);
  const [capture, setCapture] = useState<FridaCaptureBundle | null>(null);
  const [selectedEvents, setSelectedEvents] = useState<number[]>([]);
  const [maxInstructions, setMaxInstructions] = useState("50000");
  const [timeoutMs, setTimeoutMs] = useState("5000");
  const [maxMemoryWrites, setMaxMemoryWrites] = useState("4096");
  const [maxRecordedOffsets, setMaxRecordedOffsets] = useState("50000");
  const [loopVisitLimit, setLoopVisitLimit] = useState("2");
  const [stopOnCall, setStopOnCall] = useState(true);
  const [generated, setGenerated] = useState<UnicornOllvmScript | null>(null);
  const [results, setResults] = useState<UnicornOllvmResultBundle | null>(null);
  const [resultsPath, setResultsPath] = useState<string | null>(null);
  const [roundComparison, setRoundComparison] = useState<UnicornOllvmRoundComparisonReport | null>(null);
  const [roundComparisonPaths, setRoundComparisonPaths] = useState<string[]>([]);
  const [selectedRecaptureSuggestions, setSelectedRecaptureSuggestions] = useState<number[]>([]);
  const [recaptureMaxEvents, setRecaptureMaxEvents] = useState("5000");
  const [recaptureHook, setRecaptureHook] = useState<FridaUnicornRecaptureHookScript | null>(null);
  const [recaptureSavedPath, setRecaptureSavedPath] = useState<string | null>(null);
  const [checkpointResultPath, setCheckpointResultPath] = useState<string | null>(null);
  const [selectedCheckpointSeedOffsets, setSelectedCheckpointSeedOffsets] = useState<string[]>([]);
  const [checkpointMaxEvents, setCheckpointMaxEvents] = useState("5000");
  const [checkpointHook, setCheckpointHook] = useState<FridaUnicornCheckpointHookScript | null>(null);
  const [checkpointSavedPath, setCheckpointSavedPath] = useState<string | null>(null);
  const [angrFlowDepth, setAngrFlowDepth] = useState("8");
  const [angrFlowStates, setAngrFlowStates] = useState("32");
  const [angrFallbackScript, setAngrFallbackScript] = useState<AngrOllvmScript | null>(null);
  const [angrFallbackSavedPath, setAngrFallbackSavedPath] = useState<string | null>(null);
  const [angrFallbackResults, setAngrFallbackResults] = useState<AngrOllvmResultBundle | null>(null);
  const [angrFallbackResultsPath, setAngrFallbackResultsPath] = useState<string | null>(null);
  const [savedPath, setSavedPath] = useState<string | null>(null);
  const [display, setDisplay] = useState<"script" | "results" | "recapture" | "checkpoint" | "comparison" | "angr" | "angr-results">("script");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const eligibleEvents = useMemo(() => capture?.events.filter(event => (
    (event.event === "hook-enter" || event.event === "ollvm-dispatcher-hit")
      && Object.keys(event.registers).length > 0
  )) || [], [capture]);

  const selectedEventSet = useMemo(() => new Set(selectedEvents), [selectedEvents]);
  const replayCommand = useMemo(() => (
    savedPath && binaryPath
      ? `python "${savedPath}" "${binaryPath}" -o "trace-ui-unicorn-ollvm.json"`
      : null
  ), [binaryPath, savedPath]);
  const angrFallbackCommand = useMemo(() => (
    angrFallbackSavedPath && binaryPath
      ? `python "${angrFallbackSavedPath}" "${binaryPath}" -o "trace-ui-angr-ollvm.json"`
      : null
  ), [angrFallbackSavedPath, binaryPath]);
  const generatedRecaptureSummary = useMemo(() => {
    const plans = generated?.seedRecapturePlans || [];
    return {
      windows: plans.reduce((count, plan) => count + plan.windows.length, 0),
      bytes: plans.reduce((count, plan) => count + plan.carryForwardBytes, 0),
      unsupported: plans.reduce((count, plan) => count + plan.unsupportedMemoryRegionCount, 0),
      truncated: plans.some(plan => plan.windowsTruncated),
    };
  }, [generated]);
  const resultRecaptureSummary = useMemo(() => {
    const plans = results?.seedRecapturePlans || [];
    return {
      windows: plans.reduce((count, plan) => count + plan.windows.length, 0),
      bytes: plans.reduce((count, plan) => count + plan.carryForwardBytes, 0),
      unsupported: plans.reduce((count, plan) => count + plan.unsupportedMemoryRegionCount, 0),
      truncated: plans.some(plan => plan.windowsTruncated),
    };
  }, [results]);

  const resetAngrFallback = () => {
    setAngrFallbackScript(null);
    setAngrFallbackSavedPath(null);
    setAngrFallbackResults(null);
    setAngrFallbackResultsPath(null);
  };

  const requestArgs = () => ({
    report,
    maxInstructions: positiveInteger(maxInstructions, 50_000),
    timeoutMs: positiveInteger(timeoutMs, 5_000),
    maxMemoryWrites: positiveInteger(maxMemoryWrites, 4_096),
    maxRecordedOffsets: positiveInteger(maxRecordedOffsets, 50_000),
    stopOnCall,
    loopVisitLimit: positiveInteger(loopVisitLimit, 2),
    fridaBundle: capture,
    fridaEventIndex: null,
    fridaEventIndices: selectedEvents,
    staticBinaryPath: binaryPath || "",
    checkpointResultPath,
  });

  const selectBinary = async () => {
    const { open } = await import("@tauri-apps/plugin-dialog");
    const path = await open({
      multiple: false,
      directory: false,
      title: "Select exact AArch64 ELF/shared object",
    });
    if (typeof path === "string") {
      setBinaryPath(path);
      setGenerated(null);
      setResults(null);
      setResultsPath(null);
      setSelectedRecaptureSuggestions([]);
      setRecaptureHook(null);
      setCheckpointResultPath(null);
      setSelectedCheckpointSeedOffsets([]);
      setCheckpointHook(null);
      setCheckpointSavedPath(null);
      resetAngrFallback();
    }
  };

  const importCapture = async () => {
    const { open } = await import("@tauri-apps/plugin-dialog");
    const path = await open({
      multiple: false,
      directory: false,
      title: "Select exact-offset Frida capture",
      filters: [{ name: "Frida capture", extensions: ["json", "jsonl", "ndjson", "log", "txt"] }],
    });
    if (typeof path !== "string") return;
    setBusy(true);
    setError(null);
    try {
      const bundle = await invoke<FridaCaptureBundle>("load_frida_capture", { path });
      const eligible = bundle.events.filter(event => (
        (event.event === "hook-enter" || event.event === "ollvm-dispatcher-hit")
          && Object.keys(event.registers).length > 0
      ));
      if (eligible.length === 0) throw new Error("capture has no hook-enter or dispatcher-hit event with registers");
      setCapture(bundle);
      setCapturePath(path);
      setSelectedEvents(eligible.slice(0, 1).map(event => event.index));
      setGenerated(null);
      setResults(null);
      setResultsPath(null);
      setSelectedRecaptureSuggestions([]);
      setRecaptureHook(null);
      resetAngrFallback();
    } catch (reason) {
      setError(String(reason));
    } finally {
      setBusy(false);
    }
  };

  const toggleEvent = (index: number) => {
    setSelectedEvents(current => {
      if (current.includes(index)) return current.filter(value => value !== index);
      if (current.length >= 32) return current;
      return [...current, index].sort((left, right) => left - right);
    });
    setGenerated(null);
    setResults(null);
    setResultsPath(null);
    setSelectedRecaptureSuggestions([]);
    setRecaptureHook(null);
    resetAngrFallback();
  };

  const generateScript = async (): Promise<UnicornOllvmScript | null> => {
    if (!binaryPath) {
      setError("请先选择精确 AArch64 ELF/shared object。");
      return null;
    }
    if (!capture || selectedEvents.length === 0) {
      setError("请导入 Frida 捕获并选择至少一个精确事件。");
      return null;
    }
    setBusy(true);
    setError(null);
    try {
      const value = await invoke<UnicornOllvmScript>("generate_unicorn_ollvm_script", requestArgs());
      setGenerated(value);
      setDisplay("script");
      return value;
    } catch (reason) {
      setError(String(reason));
      return null;
    } finally {
      setBusy(false);
    }
  };

  const saveScript = async () => {
    const value = generated || await generateScript();
    if (!value) return;
    const { save } = await import("@tauri-apps/plugin-dialog");
    const path = await save({
      defaultPath: value.fileName,
      filters: [{ name: "Python", extensions: ["py"] }],
    });
    if (typeof path !== "string") return;
    setBusy(true);
    setError(null);
    try {
      const written = await invoke<string>("save_unicorn_ollvm_script", { path, ...requestArgs() });
      setSavedPath(written);
    } catch (reason) {
      setError(String(reason));
    } finally {
      setBusy(false);
    }
  };

  const importResults = async () => {
    const { open } = await import("@tauri-apps/plugin-dialog");
    const path = await open({
      multiple: false,
      directory: false,
      title: "Select Trace UI Unicorn result JSON",
      filters: [{ name: "Trace UI Unicorn results", extensions: ["json"] }],
    });
    if (typeof path !== "string") return;
    setBusy(true);
    setError(null);
    try {
      const bundle = await invoke<UnicornOllvmResultBundle>("load_unicorn_ollvm_results", { path });
      if (bundle.moduleName !== report.scope.moduleName) {
        throw new Error(`Unicorn result module ${bundle.moduleName} does not match ${report.scope.moduleName}`);
      }
      setResults(bundle);
      setResultsPath(path);
      setCheckpointResultPath(path);
      setSelectedCheckpointSeedOffsets(checkpointSeedOffsets(bundle).slice(0, 1));
      setSelectedRecaptureSuggestions(bundle.recaptureSuggestions
        .map((suggestion, index) => automaticRecaptureSupported(suggestion) ? index : -1)
        .filter(index => index >= 0)
        .slice(0, 1));
      setRecaptureHook(null);
      setRecaptureSavedPath(null);
      setCheckpointHook(null);
      setCheckpointSavedPath(null);
      resetAngrFallback();
      setDisplay("results");
    } catch (reason) {
      setError(String(reason));
    } finally {
      setBusy(false);
    }
  };

  const compareRoundResults = async () => {
    const { open } = await import("@tauri-apps/plugin-dialog");
    const selected = await open({
      multiple: true,
      directory: false,
      title: "选择按时间顺序排列的 2–16 轮 Unicorn 结果",
      filters: [{ name: "Trace UI Unicorn results", extensions: ["json"] }],
    });
    const paths = Array.isArray(selected)
      ? selected
      : typeof selected === "string"
        ? [selected]
        : [];
    if (paths.length === 0) return;
    if (paths.length < 2 || paths.length > 16) {
      setError(`多轮比较需要选择 2–16 个结果 JSON，当前选择了 ${paths.length} 个。`);
      return;
    }
    setBusy(true);
    setError(null);
    try {
      const roundIds = paths.map((_, index) => `round-${index + 1}`);
      const value = await invoke<UnicornOllvmRoundComparisonReport>(
        "compare_unicorn_ollvm_rounds",
        { paths, roundIds },
      );
      if (value.moduleName !== report.scope.moduleName) {
        throw new Error(`Unicorn comparison module ${value.moduleName} does not match ${report.scope.moduleName}`);
      }
      setRoundComparison(value);
      setRoundComparisonPaths(paths);
      setCheckpointResultPath(paths[paths.length - 1]);
      const supportedCheckpointOffsets = new Set(comparisonCheckpointSeedOffsets(value));
      setSelectedCheckpointSeedOffsets(value.seeds
        .filter(seed => supportedCheckpointOffsets.has(seed.captureOffset)
          && (seed.latestStatus.includes("stalled") || seed.latestStatus.includes("regressed")))
        .map(seed => seed.captureOffset)
        .slice(0, 1));
      setCheckpointHook(null);
      setCheckpointSavedPath(null);
      resetAngrFallback();
      setDisplay("comparison");
    } catch (reason) {
      setError(String(reason));
    } finally {
      setBusy(false);
    }
  };

  const toggleRecaptureSuggestion = (index: number) => {
    setSelectedRecaptureSuggestions(current => {
      if (current.includes(index)) return current.filter(value => value !== index);
      if (current.length >= 64) return current;
      return [...current, index].sort((left, right) => left - right);
    });
    setRecaptureHook(null);
    setRecaptureSavedPath(null);
  };

  const selectSupportedRecaptureSuggestions = () => {
    if (!results) return;
    setSelectedRecaptureSuggestions(results.recaptureSuggestions
      .map((suggestion, index) => automaticRecaptureSupported(suggestion) ? index : -1)
      .filter(index => index >= 0)
      .slice(0, 64));
    setRecaptureHook(null);
    setRecaptureSavedPath(null);
  };

  const recaptureRequestArgs = () => ({
    unicornResultPath: resultsPath || "",
    suggestionIndices: selectedRecaptureSuggestions,
    maxEvents: positiveInteger(recaptureMaxEvents, 5_000),
  });

  const generateRecaptureHook = async (): Promise<FridaUnicornRecaptureHookScript | null> => {
    if (!results || !resultsPath) {
      setError("请先导入 Unicorn 结果 JSON。");
      return null;
    }
    if (selectedRecaptureSuggestions.length === 0) {
      setError("请选择至少一条支持自动生成的 register-relative 重捕获建议。");
      return null;
    }
    setBusy(true);
    setError(null);
    try {
      const value = await invoke<FridaUnicornRecaptureHookScript>(
        "generate_frida_unicorn_recapture_hook",
        recaptureRequestArgs(),
      );
      setRecaptureHook(value);
      setDisplay("recapture");
      return value;
    } catch (reason) {
      setError(String(reason));
      return null;
    } finally {
      setBusy(false);
    }
  };

  const saveRecaptureHook = async () => {
    const value = recaptureHook || await generateRecaptureHook();
    if (!value) return;
    const { save } = await import("@tauri-apps/plugin-dialog");
    const path = await save({
      defaultPath: value.fileName,
      filters: [{ name: "Frida JavaScript", extensions: ["js"] }],
    });
    if (typeof path !== "string") return;
    setBusy(true);
    setError(null);
    try {
      const written = await invoke<string>("save_frida_unicorn_recapture_hook", {
        path,
        ...recaptureRequestArgs(),
      });
      setRecaptureSavedPath(written);
    } catch (reason) {
      setError(String(reason));
    } finally {
      setBusy(false);
    }
  };

  const checkpointSeedChoices = useMemo(() => {
    if (results && resultsPath === checkpointResultPath) return checkpointSeedOffsets(results);
    if (roundComparison && roundComparisonPaths[roundComparisonPaths.length - 1] === checkpointResultPath) {
      return comparisonCheckpointSeedOffsets(roundComparison);
    }
    return selectedCheckpointSeedOffsets;
  }, [checkpointResultPath, results, resultsPath, roundComparison, roundComparisonPaths, selectedCheckpointSeedOffsets]);

  const toggleCheckpointSeed = (offset: string) => {
    setSelectedCheckpointSeedOffsets(current => {
      if (current.includes(offset)) return current.filter(value => value !== offset);
      if (current.length >= 32) return current;
      return [...current, offset];
    });
    setCheckpointHook(null);
    setCheckpointSavedPath(null);
  };

  const checkpointRequestArgs = () => ({
    unicornResultPath: checkpointResultPath || "",
    seedCaptureOffsets: selectedCheckpointSeedOffsets,
    maxEvents: positiveInteger(checkpointMaxEvents, 5_000),
  });

  const generateCheckpointHook = async (): Promise<FridaUnicornCheckpointHookScript | null> => {
    if (!checkpointResultPath) {
      setError("请先导入一轮 Unicorn 结果，或完成多轮结果比较。");
      return null;
    }
    if (selectedCheckpointSeedOffsets.length === 0) {
      setError("请选择至少一个停滞或回退的原 seed offset。");
      return null;
    }
    setBusy(true);
    setError(null);
    try {
      const value = await invoke<FridaUnicornCheckpointHookScript>(
        "generate_frida_unicorn_checkpoint_hook",
        checkpointRequestArgs(),
      );
      setCheckpointHook(value);
      setDisplay("checkpoint");
      return value;
    } catch (reason) {
      setError(String(reason));
      return null;
    } finally {
      setBusy(false);
    }
  };

  const saveCheckpointHook = async () => {
    const value = checkpointHook || await generateCheckpointHook();
    if (!value) return;
    const { save } = await import("@tauri-apps/plugin-dialog");
    const path = await save({
      defaultPath: value.fileName,
      filters: [{ name: "Frida JavaScript", extensions: ["js"] }],
    });
    if (typeof path !== "string") return;
    setBusy(true);
    setError(null);
    try {
      const written = await invoke<string>("save_frida_unicorn_checkpoint_hook", {
        path,
        ...checkpointRequestArgs(),
      });
      setCheckpointSavedPath(written);
    } catch (reason) {
      setError(String(reason));
    } finally {
      setBusy(false);
    }
  };

  const angrFallbackRequestArgs = () => ({
    report,
    probeOpaqueBranches: false,
    useCfgEmulated: false,
    exploreSeededFlows: true,
    flowMaxDepth: positiveInteger(angrFlowDepth, 8),
    flowMaxStatesPerProbe: positiveInteger(angrFlowStates, 32),
    fridaBundle: capture,
    fridaEventIndex: null,
    fridaEventIndices: selectedEvents,
    fridaIncludeSp: true,
    fridaIncludeLr: true,
    staticBinaryPath: binaryPath || "",
    checkpointResultPath,
  });

  const generateAngrFallback = async (): Promise<AngrOllvmScript | null> => {
    if (!binaryPath) {
      setError("请先选择与上一轮结果一致的精确 AArch64 ELF/shared object。");
      return null;
    }
    if (!checkpointResultPath) {
      setError("请先导入授权更近 checkpoint 的上一轮 Unicorn 结果 JSON。");
      return null;
    }
    if (!capture || selectedEvents.length === 0) {
      setError("请导入更近 checkpoint Hook 的 Frida 捕获，并选择至少一个带寄存器的精确事件。");
      return null;
    }
    setBusy(true);
    setError(null);
    try {
      const value = await invoke<AngrOllvmScript>("generate_angr_ollvm_script", angrFallbackRequestArgs());
      setAngrFallbackScript(value);
      setAngrFallbackResults(null);
      setAngrFallbackResultsPath(null);
      setDisplay("angr");
      return value;
    } catch (reason) {
      setError(String(reason));
      return null;
    } finally {
      setBusy(false);
    }
  };

  const saveAngrFallback = async () => {
    const value = angrFallbackScript || await generateAngrFallback();
    if (!value) return;
    const { save } = await import("@tauri-apps/plugin-dialog");
    const path = await save({
      defaultPath: value.fileName,
      filters: [{ name: "Python", extensions: ["py"] }],
    });
    if (typeof path !== "string") return;
    setBusy(true);
    setError(null);
    try {
      const written = await invoke<string>("save_angr_ollvm_script", {
        path,
        ...angrFallbackRequestArgs(),
      });
      setAngrFallbackSavedPath(written);
    } catch (reason) {
      setError(String(reason));
    } finally {
      setBusy(false);
    }
  };

  const importAngrFallbackResults = async () => {
    const { open } = await import("@tauri-apps/plugin-dialog");
    const path = await open({
      multiple: false,
      directory: false,
      title: "Select Trace UI bounded angr result JSON",
      filters: [{ name: "Trace UI angr results", extensions: ["json"] }],
    });
    if (typeof path !== "string") return;
    setBusy(true);
    setError(null);
    try {
      const bundle = await invoke<AngrOllvmResultBundle>("load_angr_ollvm_results", { path });
      if (bundle.moduleName !== report.scope.moduleName) {
        throw new Error(`angr result module ${bundle.moduleName} does not match ${report.scope.moduleName}`);
      }
      setAngrFallbackResults(bundle);
      setAngrFallbackResultsPath(path);
      setDisplay("angr-results");
    } catch (reason) {
      setError(String(reason));
    } finally {
      setBusy(false);
    }
  };

  return (
    <div style={{ display: "flex", flex: 1, minHeight: 0, overflow: "hidden" }}>
      <div style={{ width: 440, padding: 10, borderRight: "1px solid var(--border-color)", overflow: "auto", fontSize: 11 }}>
        <div style={{ color: "var(--text-secondary)", lineHeight: 1.5 }}>
          用精确 Frida 状态进行有界 ARM64 具体重放。脚本由用户手动运行；下一 dispatcher、寄存器变化和缺失状态均为 Candidate/Related 证据。
        </div>

        <div style={{ marginTop: 10, fontWeight: 600 }}>1. 精确 ELF</div>
        <div style={{ display: "flex", gap: 6, marginTop: 5 }}>
          <button type="button" style={buttonStyle} onClick={selectBinary}>选择 ELF</button>
          {binaryPath && <button type="button" style={buttonStyle} onClick={() => { setBinaryPath(null); setGenerated(null); setResults(null); setResultsPath(null); setSelectedRecaptureSuggestions([]); setRecaptureHook(null); setCheckpointResultPath(null); setSelectedCheckpointSeedOffsets([]); setCheckpointHook(null); setCheckpointSavedPath(null); resetAngrFallback(); }}>清除</button>}
        </div>
        <div title={binaryPath || ""} style={{ marginTop: 5, color: binaryPath ? "var(--text-secondary)" : "#d29922", overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
          {binaryPath || "必须选择与 Frida 捕获相同构建的 AArch64 ELF"}
        </div>

        <div style={{ marginTop: 12, fontWeight: 600 }}>2. Frida 精确事件</div>
        <div style={{ display: "flex", gap: 6, marginTop: 5 }}>
          <button type="button" style={buttonStyle} onClick={importCapture}>导入捕获</button>
          {capture && <button type="button" style={buttonStyle} onClick={() => { setCapture(null); setCapturePath(null); setSelectedEvents([]); setGenerated(null); setResults(null); setResultsPath(null); setSelectedRecaptureSuggestions([]); setRecaptureHook(null); resetAngrFallback(); }}>清除</button>}
        </div>
        {capturePath && <div title={capturePath} style={{ marginTop: 5, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap", color: "var(--text-secondary)" }}>{capturePath.split(/[\\/]/).pop()}</div>}
        {capture && (
          <div style={{ maxHeight: 180, overflow: "auto", marginTop: 6, border: "1px solid var(--border-color)" }}>
            {eligibleEvents.map(event => (
              <label key={event.index} style={{ display: "grid", gridTemplateColumns: "20px 62px 82px minmax(0,1fr)", gap: 5, padding: "4px 5px", borderBottom: "1px solid var(--border-color)", alignItems: "center" }}>
                <input type="checkbox" checked={selectedEventSet.has(event.index)} onChange={() => toggleEvent(event.index)} />
                <span>#{event.index}</span>
                <code>{eventOffset(event)}</code>
                <span style={{ overflow: "hidden", textOverflow: "ellipsis" }}>{event.event} · {Object.keys(event.registers).length} regs · {event.captures.length} memory</span>
              </label>
            ))}
          </div>
        )}
        {capture && <div style={{ marginTop: 4, color: "var(--text-tertiary)" }}>{selectedEvents.length} selected / 32 maximum</div>}

        <div style={{ marginTop: 12, fontWeight: 600 }}>3. 有界执行</div>
        <div style={{ display: "grid", gridTemplateColumns: "165px minmax(0,1fr)", gap: 6, alignItems: "center", marginTop: 6 }}>
          <label>最大指令数</label><input style={inputStyle} value={maxInstructions} onChange={event => { setMaxInstructions(event.target.value); setGenerated(null); }} />
          <label>单 seed 超时（毫秒）</label><input style={inputStyle} value={timeoutMs} onChange={event => { setTimeoutMs(event.target.value); setGenerated(null); }} />
          <label>最大内存写记录</label><input style={inputStyle} value={maxMemoryWrites} onChange={event => { setMaxMemoryWrites(event.target.value); setGenerated(null); }} />
          <label>最大指令偏移记录</label><input style={inputStyle} value={maxRecordedOffsets} onChange={event => { setMaxRecordedOffsets(event.target.value); setGenerated(null); }} />
          <label>循环访问阈值</label><input style={inputStyle} value={loopVisitLimit} onChange={event => { setLoopVisitLimit(event.target.value); setGenerated(null); }} />
          <label style={{ display: "flex", gap: 5, alignItems: "center" }}><input type="checkbox" checked={stopOnCall} onChange={event => { setStopOnCall(event.target.checked); setGenerated(null); }} />调用前停止</label><span />
        </div>

        <div style={{ display: "flex", gap: 6, flexWrap: "wrap", marginTop: 12 }}>
          <button type="button" style={{ ...buttonStyle, background: "var(--btn-primary)", color: "#fff", border: "none", opacity: busy ? 0.6 : 1 }} disabled={busy} onClick={generateScript}>{busy ? "处理中…" : "生成 Unicorn Python"}</button>
          <button type="button" style={buttonStyle} disabled={busy} onClick={saveScript}>保存 .py</button>
          <button type="button" style={buttonStyle} disabled={busy} onClick={importResults}>导入结果 JSON</button>
          <button type="button" style={buttonStyle} disabled={busy} onClick={compareRoundResults}>对比多轮 JSON</button>
          <button type="button" style={{ ...buttonStyle, opacity: generated ? 1 : 0.5 }} disabled={!generated} onClick={() => generated && navigator.clipboard.writeText(generated.script)}>复制脚本</button>
        </div>
        {savedPath && <div title={savedPath} style={{ marginTop: 6, color: "#3fb950", overflow: "hidden", textOverflow: "ellipsis" }}>已保存：{savedPath}</div>}
        {generated && (
          <div style={{ marginTop: 8, padding: 7, background: "var(--bg-secondary)", borderRadius: 4, lineHeight: 1.5 }}>
            <strong>手动运行</strong>
            <div style={{ color: "var(--text-tertiary)" }}>Trace UI 不会自动执行模拟器。先在隔离的 Python 环境安装固定依赖：</div>
            <code style={{ display: "block", marginTop: 3, whiteSpace: "pre-wrap", userSelect: "text" }}>python -m pip install unicorn==2.1.4 capstone==5.0.6 pyelftools==0.32</code>
            {replayCommand
              ? <code style={{ display: "block", marginTop: 4, whiteSpace: "pre-wrap", userSelect: "text" }}>{replayCommand}</code>
              : <div style={{ marginTop: 3, color: "var(--text-tertiary)" }}>保存 .py 后运行脚本，再用“导入结果 JSON”载入输出。</div>}
          </div>
        )}
        {generated && (
          <div style={{ marginTop: 8, padding: 7, background: "var(--bg-secondary)", borderRadius: 4 }}>
            <strong>Seed 完整度</strong>
            {generated.seedQualities.map(quality => (
              <div key={quality.sourceEventIndex} style={{ marginTop: 5, color: quality.status === "ready" ? "#3fb950" : "#d29922" }}>
                #{quality.sourceEventIndex}@{quality.captureOffset} · {quality.status} · {quality.registerCount} regs · {quality.memoryRegionCount} regions / {quality.capturedMemoryBytes} bytes · stack {quality.stackMemoryCaptured ? "captured" : "missing"}
                {quality.missingRegisters.length > 0 && <div>缺失：{quality.missingRegisters.join(", ")}</div>}
              </div>
            ))}
            <div style={{ marginTop: 6, color: generatedRecaptureSummary.unsupported > 0 || generatedRecaptureSummary.truncated ? "#d29922" : "var(--text-secondary)" }}>
              可跨轮重读 {generatedRecaptureSummary.windows} 个寄存器相对窗口 / {generatedRecaptureSummary.bytes} bytes
              {generatedRecaptureSummary.unsupported > 0 && ` · ${generatedRecaptureSummary.unsupported} 个内存区域无法自动保留`}
              {generatedRecaptureSummary.truncated && " · 已达到窗口上限"}
            </div>
          </div>
        )}
        {generated?.warnings.map((warning, index) => <div key={`generated-${index}`} style={{ marginTop: 5, color: "#d29922" }}>{warning}</div>)}

        {results && results.recaptureSuggestions.length > 0 && (
          <div style={{ marginTop: 12, paddingTop: 10, borderTop: "1px solid var(--border-color)" }}>
            <div style={{ fontWeight: 600 }}>4. Frida 精确重捕获</div>
            <div style={{ marginTop: 4, color: "var(--text-secondary)", lineHeight: 1.5 }}>
              从下次捕获建议生成 X0-X28/SP 正负位移窗口。Hook 仍落在原 exact seed offset，捕获结果可以再次导入 Unicorn/angr。
            </div>
            <div style={{ marginTop: 4, color: "var(--text-tertiary)", lineHeight: 1.5 }}>
              新 Hook 会在当前进程重新读取上一轮 seed 的寄存器相对内存，再叠加本轮缺失窗口；不会复制上一轮的绝对地址或陈旧字节。
            </div>
            <div style={{ display: "grid", gridTemplateColumns: "165px minmax(0,1fr)", gap: 6, alignItems: "center", marginTop: 6 }}>
              <label>最大重捕获事件</label>
              <input style={inputStyle} value={recaptureMaxEvents} onChange={event => { setRecaptureMaxEvents(event.target.value); setRecaptureHook(null); }} />
            </div>
            <div style={{ marginTop: 5, color: "var(--text-tertiary)" }}>{selectedRecaptureSuggestions.length} selected / 64 maximum</div>
            <div style={{ display: "flex", gap: 6, flexWrap: "wrap", marginTop: 6 }}>
              <button type="button" style={buttonStyle} disabled={busy} onClick={selectSupportedRecaptureSuggestions}>全选可自动项</button>
              <button type="button" style={buttonStyle} disabled={busy} onClick={() => { setSelectedRecaptureSuggestions([]); setRecaptureHook(null); }}>清除选择</button>
              <button type="button" style={{ ...buttonStyle, background: "var(--btn-primary)", color: "#fff", border: "none", opacity: busy ? 0.6 : 1 }} disabled={busy} onClick={generateRecaptureHook}>生成重捕获 Hook</button>
              <button type="button" style={buttonStyle} disabled={busy} onClick={saveRecaptureHook}>保存 .js</button>
              <button type="button" style={{ ...buttonStyle, opacity: recaptureHook ? 1 : 0.5 }} disabled={!recaptureHook} onClick={() => recaptureHook && navigator.clipboard.writeText(recaptureHook.script)}>复制 Hook</button>
            </div>
            {recaptureSavedPath && <div title={recaptureSavedPath} style={{ marginTop: 5, color: "#3fb950", overflow: "hidden", textOverflow: "ellipsis" }}>已保存：{recaptureSavedPath}</div>}
            {recaptureHook && (
              <div style={{ marginTop: 6, padding: 6, background: "var(--bg-secondary)", borderRadius: 4 }}>
                {recaptureHook.targets.length} exact seed targets · {recaptureHook.targets.reduce((count, target) => count + target.captures.length, 0)} bounded windows · 保留旧窗口 {recaptureHook.carriedForwardWindowCount} · 新建议窗口 {recaptureHook.suggestedWindowCount} · max {recaptureHook.maxEvents} events
              </div>
            )}
            {recaptureHook && recaptureHook.unsupportedSeedRegionCount > 0 && (
              <div style={{ marginTop: 4, color: "#d29922" }}>
                {recaptureHook.unsupportedSeedRegionCount} 个旧 seed 内存区域缺少已验证的 X0-X28/SP 相对关系，未自动跨轮保留。
              </div>
            )}
            {recaptureHook?.warnings.map((warning, index) => <div key={`recapture-warning-${index}`} style={{ marginTop: 4, color: "#d29922" }}>{warning}</div>)}
          </div>
        )}
        {checkpointResultPath && (
          <div style={{ marginTop: 12, paddingTop: 10, borderTop: "1px solid var(--border-color)" }}>
            <div style={{ fontWeight: 600 }}>5. 更近 checkpoint 捕获</div>
            <div style={{ marginTop: 4, color: "var(--text-secondary)", lineHeight: 1.5 }}>
              当原 seed 在缺页、缺寄存器、循环、超时或指令上限处停滞时，把 Frida Hook 前移到实际 missing-memory PC 或 terminal PC，重新捕获完整 ARM64 状态后再继续 Unicorn。
            </div>
            <div style={{ marginTop: 4, color: "var(--text-tertiary)", lineHeight: 1.5 }}>
              上一轮结果只授权同模块、同 ELF SHA-256 的 checkpoint offset，不证明运行时就是该构建。Hook 和 Unicorn 都由用户手动执行，结果仍是 Candidate/Related。
            </div>
            <div title={checkpointResultPath} style={{ marginTop: 5, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap", color: "var(--text-secondary)" }}>
              授权结果：{checkpointResultPath.split(/[\\/]/).pop()}
            </div>
            <div style={{ maxHeight: 130, overflow: "auto", marginTop: 6, border: "1px solid var(--border-color)" }}>
              {checkpointSeedChoices.map(offset => (
                <label key={offset} style={{ display: "grid", gridTemplateColumns: "20px minmax(0,1fr)", gap: 5, padding: "4px 5px", borderBottom: "1px solid var(--border-color)", alignItems: "center" }}>
                  <input type="checkbox" checked={selectedCheckpointSeedOffsets.includes(offset)} onChange={() => toggleCheckpointSeed(offset)} />
                  <span>原 seed <code>{offset}</code></span>
                </label>
              ))}
              {checkpointSeedChoices.length === 0 && <div style={{ padding: 6, color: "#d29922" }}>当前结果没有支持自动前移的停滞 seed。</div>}
            </div>
            <div style={{ display: "grid", gridTemplateColumns: "165px minmax(0,1fr)", gap: 6, alignItems: "center", marginTop: 6 }}>
              <label>最大 checkpoint 事件</label>
              <input style={inputStyle} value={checkpointMaxEvents} onChange={event => { setCheckpointMaxEvents(event.target.value); setCheckpointHook(null); }} />
            </div>
            <div style={{ marginTop: 5, color: "var(--text-tertiary)" }}>{selectedCheckpointSeedOffsets.length} selected / 32 maximum</div>
            <div style={{ display: "flex", gap: 6, flexWrap: "wrap", marginTop: 6 }}>
              <button type="button" style={{ ...buttonStyle, background: "var(--btn-primary)", color: "#fff", border: "none", opacity: busy ? 0.6 : 1 }} disabled={busy} onClick={generateCheckpointHook}>生成更近 checkpoint Hook</button>
              <button type="button" style={buttonStyle} disabled={busy} onClick={saveCheckpointHook}>保存 checkpoint .js</button>
              <button type="button" style={{ ...buttonStyle, opacity: checkpointHook ? 1 : 0.5 }} disabled={!checkpointHook} onClick={() => checkpointHook && navigator.clipboard.writeText(checkpointHook.script)}>复制 checkpoint Hook</button>
            </div>
            {checkpointSavedPath && <div title={checkpointSavedPath} style={{ marginTop: 5, color: "#3fb950", overflow: "hidden", textOverflow: "ellipsis" }}>已保存：{checkpointSavedPath}</div>}
            {checkpointHook && (
              <div style={{ marginTop: 6, padding: 6, background: "var(--bg-secondary)", borderRadius: 4, lineHeight: 1.5 }}>
                {checkpointHook.targets.length} 个更近目标 · {checkpointHook.captureWindowCount} 个安全内存窗口 · max {checkpointHook.maxEvents} events
                <div style={{ color: "var(--text-tertiary)" }}>目标：{checkpointHook.targets.map(target => `${target.offset} (${target.stopReasons.join("/")})`).join(", ")}</div>
                <div style={{ marginTop: 3 }}>手动执行后，用上面的“导入捕获”载入新 hook-enter；生成 Unicorn Python 时会自动携带这份授权结果。</div>
              </div>
            )}
            {checkpointHook?.warnings.map((warning, index) => <div key={`checkpoint-warning-${index}`} style={{ marginTop: 4, color: "#d29922" }}>{warning}</div>)}
          </div>
        )}
        {checkpointResultPath && (
          <div style={{ marginTop: 12, paddingTop: 10, borderTop: "1px solid var(--border-color)" }}>
            <div style={{ fontWeight: 600 }}>6. checkpoint → bounded angr 接力</div>
            <div style={{ marginTop: 4, color: "var(--text-secondary)", lineHeight: 1.5 }}>
              当更近 checkpoint 的具体重放仍缺少状态时，使用同一 Frida 事件建立 blank state，并有界探索到下一 dispatcher、循环、外部目标、死路或配置上限。
            </div>
            <div style={{ marginTop: 4, color: "var(--text-tertiary)", lineHeight: 1.5 }}>
              Core 会严格校验同模块、上一轮 expected/actual SHA-256、当前精确 ELF SHA-256，以及捕获 offset 是否属于上一轮授权集合。路径只属于 Candidate/Related 证据。
            </div>
            <div style={{ display: "grid", gridTemplateColumns: "165px minmax(0,1fr)", gap: 6, alignItems: "center", marginTop: 6 }}>
              <label>最大 symbolic 深度</label>
              <input aria-label="Checkpoint angr flow depth" type="number" min={1} max={64} style={inputStyle} value={angrFlowDepth} onChange={event => { setAngrFlowDepth(event.target.value); resetAngrFallback(); }} />
              <label>每个 probe 最大状态</label>
              <input aria-label="Checkpoint angr flow states" type="number" min={1} max={256} style={inputStyle} value={angrFlowStates} onChange={event => { setAngrFlowStates(event.target.value); resetAngrFallback(); }} />
            </div>
            <div title={checkpointResultPath} style={{ marginTop: 5, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap", color: "var(--text-secondary)" }}>
              prior result：{checkpointResultPath.split(/[\\/]/).pop()} · selected events：{selectedEvents.length > 0 ? selectedEvents.map(index => `#${index}`).join(", ") : "none"}
            </div>
            <div style={{ display: "flex", gap: 6, flexWrap: "wrap", marginTop: 6 }}>
              <button type="button" style={{ ...buttonStyle, background: "var(--btn-primary)", color: "#fff", border: "none", opacity: busy ? 0.6 : 1 }} disabled={busy} onClick={generateAngrFallback}>生成 bounded angr</button>
              <button type="button" style={buttonStyle} disabled={busy} onClick={saveAngrFallback}>保存 angr .py</button>
              <button type="button" style={buttonStyle} disabled={busy} onClick={importAngrFallbackResults}>导入 angr JSON</button>
              <button type="button" style={{ ...buttonStyle, opacity: angrFallbackScript ? 1 : 0.5 }} disabled={!angrFallbackScript} onClick={() => angrFallbackScript && navigator.clipboard.writeText(angrFallbackScript.script)}>复制 angr 脚本</button>
            </div>
            {angrFallbackSavedPath && <div title={angrFallbackSavedPath} style={{ marginTop: 5, color: "#3fb950", overflow: "hidden", textOverflow: "ellipsis" }}>已保存：{angrFallbackSavedPath}</div>}
            {angrFallbackScript && (
              <div style={{ marginTop: 6, padding: 6, background: "var(--bg-secondary)", borderRadius: 4, lineHeight: 1.5 }}>
                已嵌入 {angrFallbackScript.fridaSeeds.length} 个 Frida seed · 授权 checkpoint：{angrFallbackScript.authorizedCheckpointOffsets.join(", ") || "none"}
                <div style={{ color: "var(--text-tertiary)" }}>bounded flow：depth {angrFallbackScript.flowConfig.maxDepth} / {angrFallbackScript.flowConfig.maxStatesPerProbe} states per probe</div>
                <div style={{ marginTop: 3 }}>Trace UI 不会安装或运行 angr。请在隔离 Python 环境手动执行，再导入生成的 JSON。</div>
                <code style={{ display: "block", marginTop: 3, whiteSpace: "pre-wrap", userSelect: "text" }}>python -m pip install angr</code>
                {angrFallbackCommand && <code style={{ display: "block", marginTop: 3, whiteSpace: "pre-wrap", userSelect: "text" }}>{angrFallbackCommand}</code>}
              </div>
            )}
            {angrFallbackScript?.warnings.map((warning, index) => <div key={`angr-fallback-warning-${index}`} style={{ marginTop: 4, color: "#d29922" }}>{warning}</div>)}
          </div>
        )}
        {error && <div style={{ marginTop: 8, color: "#e5484d", whiteSpace: "pre-wrap" }}>{error}</div>}
      </div>

      <div style={{ flex: 1, minWidth: 0, display: "flex", flexDirection: "column", overflow: "hidden" }}>
        <div style={{ display: "flex", gap: 5, padding: 7, borderBottom: "1px solid var(--border-color)" }}>
          <button type="button" style={{ ...buttonStyle, background: display === "script" ? "var(--bg-selected)" : "var(--bg-input)" }} onClick={() => setDisplay("script")}>脚本</button>
          <button type="button" style={{ ...buttonStyle, background: display === "results" ? "var(--bg-selected)" : "var(--bg-input)", opacity: results ? 1 : 0.5 }} disabled={!results} onClick={() => setDisplay("results")}>模拟结果</button>
          <button type="button" style={{ ...buttonStyle, background: display === "recapture" ? "var(--bg-selected)" : "var(--bg-input)", opacity: recaptureHook ? 1 : 0.5 }} disabled={!recaptureHook} onClick={() => setDisplay("recapture")}>重捕获 Hook</button>
          <button type="button" style={{ ...buttonStyle, background: display === "checkpoint" ? "var(--bg-selected)" : "var(--bg-input)", opacity: checkpointHook ? 1 : 0.5 }} disabled={!checkpointHook} onClick={() => setDisplay("checkpoint")}>Checkpoint Hook</button>
          <button type="button" style={{ ...buttonStyle, background: display === "comparison" ? "var(--bg-selected)" : "var(--bg-input)", opacity: roundComparison ? 1 : 0.5 }} disabled={!roundComparison} onClick={() => setDisplay("comparison")}>轮次对比</button>
          <button type="button" style={{ ...buttonStyle, background: display === "angr" ? "var(--bg-selected)" : "var(--bg-input)", opacity: angrFallbackScript ? 1 : 0.5 }} disabled={!angrFallbackScript} onClick={() => setDisplay("angr")}>angr 脚本</button>
          <button type="button" style={{ ...buttonStyle, background: display === "angr-results" ? "var(--bg-selected)" : "var(--bg-input)", opacity: angrFallbackResults ? 1 : 0.5 }} disabled={!angrFallbackResults} onClick={() => setDisplay("angr-results")}>angr 结果</button>
        </div>
        {display === "script" && (
          <pre style={{ flex: 1, margin: 0, padding: 10, overflow: "auto", background: "var(--bg-primary)", color: "var(--text-primary)", fontSize: 10, lineHeight: 1.45, whiteSpace: "pre" }}>{generated?.script || ""}</pre>
        )}
        {display === "recapture" && (
          <pre style={{ flex: 1, margin: 0, padding: 10, overflow: "auto", background: "var(--bg-primary)", color: "var(--text-primary)", fontSize: 10, lineHeight: 1.45, whiteSpace: "pre" }}>{recaptureHook?.script || ""}</pre>
        )}
        {display === "checkpoint" && (
          <pre style={{ flex: 1, margin: 0, padding: 10, overflow: "auto", background: "var(--bg-primary)", color: "var(--text-primary)", fontSize: 10, lineHeight: 1.45, whiteSpace: "pre" }}>{checkpointHook?.script || ""}</pre>
        )}
        {display === "angr" && (
          <pre style={{ flex: 1, margin: 0, padding: 10, overflow: "auto", background: "var(--bg-primary)", color: "var(--text-primary)", fontSize: 10, lineHeight: 1.45, whiteSpace: "pre" }}>{angrFallbackScript?.script || ""}</pre>
        )}
        {display === "angr-results" && angrFallbackResults && (
          <div style={{ flex: 1, overflow: "auto", fontSize: 11 }}>
            <div style={{ padding: 9, borderBottom: "1px solid var(--border-color)", background: "var(--bg-secondary)", lineHeight: 1.5 }}>
              <strong>{angrFallbackResults.cfgKind} / angr {angrFallbackResults.angrVersion}</strong>
              <div>{angrFallbackResults.checkpointProbes.length} checkpoint probes · {angrFallbackResults.checkpointProbes.filter(probe => probe.flowExploration).length} bounded flows</div>
              <div style={{ color: angrFallbackResults.binaryIdentityMatched === false ? "#e5484d" : "#3fb950" }}>Exact ELF guard {angrFallbackResults.binaryIdentityMatched === false ? "mismatch" : "matched"}</div>
              {angrFallbackResultsPath && <div title={angrFallbackResultsPath} style={{ color: "var(--text-tertiary)", overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{angrFallbackResultsPath}</div>}
              <div style={{ color: "var(--text-tertiary)" }}>这些路径不是已恢复 CFG，也不证明从真实入口可达。</div>
            </div>
            {angrFallbackResults.checkpointProbes.map(probe => (
              <div key={`angr-checkpoint-${probe.offset}-${probe.sourceEventIndex}`} style={{ padding: 9, borderBottom: "1px solid var(--border-color)", lineHeight: 1.5 }}>
                <div style={{ display: "flex", gap: 8, flexWrap: "wrap", alignItems: "center" }}>
                  <code>{probe.offset}</code>
                  <strong style={{ color: probe.status === "ok" ? "#3fb950" : "#d29922" }}>{probe.status}</strong>
                  <span>event #{probe.sourceEventIndex}</span>
                  <span>{probe.seededRegisters.length} regs / {probe.seededMemoryRegions.length} memory regions</span>
                </div>
                <div style={{ marginTop: 3 }}>source state：{stateText(probe.sourceStateValues)}</div>
                <div style={{ color: "var(--text-tertiary)" }}>{probe.limitation}</div>
                {probe.error && <div style={{ color: "#e5484d" }}>{probe.error}</div>}
                {probe.flowExploration && (
                  <div style={{ marginTop: 6 }}>
                    <div style={{ color: probe.flowExploration.truncated ? "#d29922" : "#3fb950" }}>
                      {probe.flowExploration.paths.length} paths / {probe.flowExploration.exploredStates} states{probe.flowExploration.truncated ? " / truncated" : ""}
                    </div>
                    {probe.flowExploration.paths.map((path, pathIndex) => (
                      <div key={`${probe.offset}-angr-path-${pathIndex}`} style={{ marginTop: 5, padding: 6, background: "var(--bg-secondary)", borderRadius: 4 }}>
                        <code>{path.status}</code> · {path.offsets.join(" → ") || path.terminalAddress}
                        <div>target：<code>{path.matchedDispatcherOffset || path.terminalOffset || path.terminalAddress}</code> · state {stateText(path.dispatcherStateValues)}</div>
                        <div style={{ color: "var(--text-tertiary)" }}>{path.constraintCount} constraints · {path.jumpKinds.join(", ") || "no jump kind"}</div>
                        {path.error && <div style={{ color: "#e5484d" }}>{path.error}</div>}
                      </div>
                    ))}
                  </div>
                )}
              </div>
            ))}
            {angrFallbackResults.checkpointProbes.length === 0 && <div style={{ padding: 10, color: "#d29922" }}>结果没有 checkpoint probe；请确认捕获 offset 确实由所选上一轮 Unicorn 结果授权。</div>}
            {angrFallbackResults.warnings.map((warning, index) => <div key={`angr-result-warning-${index}`} style={{ padding: "4px 9px", color: "#d29922" }}>{warning}</div>)}
          </div>
        )}
        {display === "results" && results && (
          <div style={{ flex: 1, overflow: "auto", fontSize: 11 }}>
            <div style={{ padding: 9, borderBottom: "1px solid var(--border-color)", background: "var(--bg-secondary)" }}>
              <strong>Unicorn {results.unicornVersion} / Capstone {results.capstoneVersion}</strong>
              <div>{results.runs.length} runs · {results.transitionMatrix.length} transition groups · {results.recaptureSuggestions.length} recapture suggestions</div>
              <div style={{ color: resultRecaptureSummary.unsupported > 0 || resultRecaptureSummary.truncated ? "#d29922" : "var(--text-secondary)" }}>
                Seed 跨轮保留计划：{resultRecaptureSummary.windows} windows / {resultRecaptureSummary.bytes} bytes
                {resultRecaptureSummary.unsupported > 0 && ` · ${resultRecaptureSummary.unsupported} unsupported regions`}
                {resultRecaptureSummary.truncated && " · window limit reached"}
              </div>
              <div style={{ color: results.binaryIdentityMatched ? "#3fb950" : "#e5484d" }}>Exact ELF SHA-256 {results.binaryIdentityMatched ? "matched" : "mismatch"}</div>
            </div>

            {results.transitionMatrix.length > 0 && <div style={{ padding: "8px 9px", fontWeight: 600, borderBottom: "1px solid var(--border-color)" }}>Dispatcher 转移矩阵</div>}
            {results.transitionMatrix.map((transition, index) => (
              <div key={`${transition.sourceOffset}-${transition.targetOffset}-${index}`} style={{ padding: 8, borderBottom: "1px solid var(--border-color)", display: "grid", gridTemplateColumns: "100px minmax(150px,1fr) 24px 100px minmax(150px,1fr) 85px", gap: 6, alignItems: "center" }}>
                <code>{transition.sourceOffset}</code><span>{transition.sourceState}</span><span>→</span><code>{transition.targetOffset}</code><span>{transition.targetState}</span><span>{transition.executionCount} run(s)</span>
              </div>
            ))}

            {results.recaptureSuggestions.length > 0 && <div style={{ padding: "8px 9px", fontWeight: 600, borderBottom: "1px solid var(--border-color)", color: "#d29922" }}>缺失状态 / 下次 Frida 捕获建议</div>}
            {results.recaptureSuggestions.map((suggestion, index) => {
              const supported = automaticRecaptureSupported(suggestion);
              return (
                <div key={`${suggestion.pcOffset}-${index}`} style={{ padding: 8, borderBottom: "1px solid var(--border-color)", display: "grid", gridTemplateColumns: "22px minmax(0,1fr)", gap: 6 }}>
                  <input type="checkbox" disabled={!supported} checked={selectedRecaptureSuggestions.includes(index)} onChange={() => toggleRecaptureSuggestion(index)} title={supported ? "加入重捕获 Hook" : "该建议需要手工验证/捕获"} />
                  <div>
                    <code>{suggestion.pcOffset}</code> · {suggestion.baseRegister || "absolute"}{suggestion.displacement || ""} · {suggestion.byteLength} bytes · <span style={{ color: supported ? "#3fb950" : "#d29922" }}>{supported ? "可自动生成" : "需手动捕获"}</span>
                    <div style={{ color: "var(--text-secondary)" }}>{suggestion.reason} Events: {suggestion.sourceEventIndices.join(", ")}</div>
                  </div>
                </div>
              );
            })}

            <div style={{ padding: "8px 9px", fontWeight: 600, borderBottom: "1px solid var(--border-color)" }}>具体重放</div>
            {results.runs.map(run => (
              <div key={run.sourceEventIndex} style={{ padding: 9, borderBottom: "1px solid var(--border-color)" }}>
                <div style={{ display: "flex", gap: 10, flexWrap: "wrap" }}>
                  <strong>Event #{run.sourceEventIndex}</strong>
                  <code>{run.startOffset}</code>
                  <span style={{ color: run.stopReason === "next-dispatcher" || run.stopReason === "return" ? "#3fb950" : "#d29922" }}>{run.stopReason}</span>
                  <span>{run.instructionCount} instructions / {run.elapsedMs} ms</span>
                  {run.matchedDispatcherOffset && <span>→ <code>{run.matchedDispatcherOffset}</code></span>}
                </div>
                <div style={{ marginTop: 5 }}>state: {stateText(run.sourceStateValues)} → {stateText(run.targetStateValues)}</div>
                <div style={{ marginTop: 4, color: "var(--text-secondary)" }}>{run.blockOffsets.length} block hits · {run.registerChanges.length} register changes · {run.memoryWrites.length} writes · {run.missingMemory.length} missing reads</div>
                {(run.callBoundaries || []).map((boundary, index) => (
                  <div key={`${run.sourceEventIndex}-call-${index}`} style={{ marginTop: 4, color: "#d29922" }}>
                    call {boundary.mnemonic} at <code>{boundary.pcOffset}</code>
                    {boundary.targetOffset ? ` → ${boundary.targetOffset}` : boundary.targetAddress ? ` → ${boundary.targetAddress}` : ""}
                    {boundary.returnOffset ? ` · post-call return checkpoint ${boundary.returnOffset}` : " · legacy result has no return checkpoint offset"}
                  </div>
                ))}
                {run.missingMemory.map((missing, index) => (
                  <div key={`${run.sourceEventIndex}-missing-${index}`} style={{ marginTop: 4, color: "#d29922" }}>
                    {missing.pcOffset || "outside"}: {missing.access} {missing.address} ({missing.size}) · {missing.instruction || "unknown instruction"}
                  </div>
                ))}
                {run.error && <div style={{ marginTop: 4, color: "#e5484d" }}>{run.error}</div>}
              </div>
            ))}
            {results.warnings.map((warning, index) => <div key={`result-warning-${index}`} style={{ padding: "4px 9px", color: "#d29922" }}>{warning}</div>)}
          </div>
        )}
        {display === "comparison" && roundComparison && (
          <div style={{ flex: 1, overflow: "auto", fontSize: 11 }}>
            <div style={{ padding: 10, borderBottom: "1px solid var(--border-color)", background: "var(--bg-secondary)", lineHeight: 1.55 }}>
              <div style={{ display: "flex", gap: 10, alignItems: "center", flexWrap: "wrap" }}>
                <strong style={{ color: roundStatusColor(roundComparison.overallStatus) }}>{roundComparison.overallStatus}</strong>
                <span>{roundComparison.roundCount} rounds</span>
                <span>{roundComparison.seedOffsetCount} exact seeds</span>
                <span>{roundComparison.totalUniqueExecutedOffsetCount} unique instructions</span>
                <span>{roundComparison.totalUniqueBlockOffsetCount} unique blocks</span>
              </div>
              <div style={{ marginTop: 4 }}>{roundComparison.overallRecommendation}</div>
              <div style={{ marginTop: 4, color: "var(--text-secondary)" }}>
                progress {roundComparison.progressedSeedCount} · stalled {roundComparison.stalledSeedCount} · regressed {roundComparison.regressedSeedCount} · changed {roundComparison.changedSeedCount} · incomplete {roundComparison.incompleteSeedCount}
              </div>
              <div style={{ marginTop: 4, color: "var(--text-tertiary)" }}>
                Module {roundComparison.moduleName} · exact ELF SHA-256 <code>{roundComparison.binarySha256}</code>
              </div>
            </div>

            <div style={{ padding: "8px 10px", fontWeight: 600, borderBottom: "1px solid var(--border-color)" }}>轮次覆盖趋势</div>
            {roundComparison.rounds.map((round, index) => (
              <div key={round.roundId} style={{ padding: 9, borderBottom: "1px solid var(--border-color)", lineHeight: 1.5 }}>
                <div style={{ display: "flex", gap: 9, flexWrap: "wrap", alignItems: "center" }}>
                  <strong>{index === 0 ? `基线 · ${round.roundId}` : round.roundId}</strong>
                  <span title={roundComparisonPaths[index] || round.sourceLabel || ""} style={{ color: "var(--text-secondary)" }}>{round.sourceLabel || roundComparisonPaths[index]?.split(/[\\/]/).pop()}</span>
                  <span>{round.runCount} runs / {round.seedOffsetCount} seeds</span>
                  <span>{round.totalInstructionCount} instructions</span>
                  <span>{round.uniqueExecutedOffsetCount} unique offsets / {round.uniqueBlockOffsetCount} blocks</span>
                </div>
                <div style={{ marginTop: 3, color: index === 0 ? "var(--text-secondary)" : round.newExecutedOffsetCount > 0 || round.newBlockOffsetCount > 0 ? "#3fb950" : "#d29922" }}>
                  {index === 0 ? "基线覆盖" : "相对之前全部轮次首次新增"}：{round.newExecutedOffsetCount} offsets / {round.newBlockOffsetCount} blocks
                </div>
                <div style={{ marginTop: 3, color: "var(--text-secondary)" }}>
                  stop reasons: {countMapText(round.stopReasonCounts)} · missing {round.missingMemoryCount} ({round.registerRelativeMissingCount} register-relative) · suggestions {round.recaptureSuggestionCount}
                </div>
                <div style={{ marginTop: 3, color: round.unsupportedSeedRegionCount > 0 ? "#d29922" : "var(--text-secondary)" }}>
                  carry-forward {round.carryForwardWindowCount} windows / {round.carryForwardBytes} bytes · unsupported regions {round.unsupportedSeedRegionCount} · dispatchers {offsetList(round.matchedDispatcherOffsets)}
                </div>
                {(round.newExecutedOffsets.length > 0 || round.newBlockOffsets.length > 0) && (
                  <div style={{ marginTop: 3, color: "var(--text-tertiary)" }}>
                    offsets: {offsetList(round.newExecutedOffsets, round.newExecutedOffsetsTruncated)}<br />
                    blocks: {offsetList(round.newBlockOffsets, round.newBlockOffsetsTruncated)}
                  </div>
                )}
                {!round.configMatchesBaseline && <div style={{ marginTop: 3, color: "#d29922" }}>本轮执行上限或配置与基线不同，差异不能只归因于重捕获状态。</div>}
                {round.executionDataTruncated && <div style={{ marginTop: 3, color: "#d29922" }}>执行偏移或重捕获计划已截断；没有看到新增不等于没有前进。</div>}
                {(round.errorRunCount > 0 || round.warningCount > 0) && <div style={{ marginTop: 3, color: "#d29922" }}>{round.errorRunCount} error runs · {round.warningCount} warnings</div>}
              </div>
            ))}

            <div style={{ padding: "8px 10px", fontWeight: 600, borderBottom: "1px solid var(--border-color)" }}>按 exact seed offset 诊断</div>
            {roundComparison.seeds.map(seed => (
              <details key={seed.captureOffset} style={{ borderBottom: "1px solid var(--border-color)" }}>
                <summary style={{ padding: 9, cursor: "pointer", display: "flex", gap: 10, flexWrap: "wrap", alignItems: "center" }}>
                  <code>{seed.captureOffset}</code>
                  <strong style={{ color: roundStatusColor(seed.latestStatus) }}>{seed.latestStatus}</strong>
                  <span style={{ color: "var(--text-secondary)" }}>{seed.latestRecommendation}</span>
                </summary>
                <div style={{ padding: "0 10px 10px" }}>
                  {seed.matchedProbeOffsets.length > 0 && <div style={{ color: "var(--text-tertiary)" }}>matched probes: {seed.matchedProbeOffsets.join(", ")}</div>}
                  <div style={{ marginTop: 7, fontWeight: 600 }}>轮次观测</div>
                  {seed.observations.map(observation => (
                    <div key={`${seed.captureOffset}-${observation.roundId}`} style={{ marginTop: 5, padding: 7, background: "var(--bg-secondary)", borderRadius: 4, lineHeight: 1.5, opacity: observation.present ? 1 : 0.65 }}>
                      <strong>{observation.roundId}</strong>
                      {!observation.present ? (
                        <span style={{ marginLeft: 7, color: "#d29922" }}>seed 不存在</span>
                      ) : (
                        <>
                          <span> · events {observation.sourceEventIndices.join(", ")} · {observation.runCount} runs · {observation.totalInstructionCount} instructions</span>
                          <div>stop: {observation.stopReasons.join(", ") || "none"} · terminal: {offsetList(observation.terminalOffsets)} · blocks {observation.blockOffsetCount} · offsets {observation.executedOffsetCount}</div>
                          <div style={{ color: observation.missingMemoryCount > 0 ? "#d29922" : "var(--text-secondary)" }}>missing {observation.missingMemoryCount} ({observation.registerRelativeMissingCount} register-relative) at {offsetList(observation.missingPcOffsets)} · dispatchers {offsetList(observation.matchedDispatcherOffsets)}</div>
                          <div style={{ color: "var(--text-secondary)" }}>carry-forward {observation.carryForwardWindowCount} windows / {observation.carryForwardBytes} bytes · unsupported {observation.unsupportedSeedRegionCount} · suggestions {observation.recaptureSuggestionCount}</div>
                          {observation.executionDataTruncated && <div style={{ color: "#d29922" }}>该轮观测数据已截断。</div>}
                          {observation.errorRunCount > 0 && <div style={{ color: "#e5484d" }}>{observation.errorRunCount} replay run(s) reported errors.</div>}
                        </>
                      )}
                    </div>
                  ))}

                  <div style={{ marginTop: 8, fontWeight: 600 }}>相邻轮次变化</div>
                  {seed.deltas.map(delta => (
                    <div key={`${seed.captureOffset}-${delta.fromRoundId}-${delta.toRoundId}`} style={{ marginTop: 5, padding: 7, border: "1px solid var(--border-color)", borderRadius: 4, lineHeight: 1.5 }}>
                      <div style={{ display: "flex", gap: 8, flexWrap: "wrap" }}>
                        <strong>{delta.fromRoundId} → {delta.toRoundId}</strong>
                        <span style={{ color: roundStatusColor(delta.status) }}>{delta.status}</span>
                        <span>{delta.evidenceLevel}</span>
                        <span>instructions {delta.instructionDelta >= 0 ? "+" : ""}{delta.instructionDelta}</span>
                      </div>
                      <div>{delta.detail}</div>
                      <div style={{ color: "var(--text-secondary)" }}>new offsets {delta.newExecutedOffsetCount} · lost offsets {delta.lostExecutedOffsetCount} · new blocks {delta.newBlockOffsetCount} · lost blocks {delta.lostBlockOffsetCount}</div>
                      {delta.newExecutedOffsets.length > 0 && <div style={{ color: "var(--text-tertiary)" }}>new offsets: {offsetList(delta.newExecutedOffsets, delta.newExecutedOffsetsTruncated)}</div>}
                      {delta.newBlockOffsets.length > 0 && <div style={{ color: "var(--text-tertiary)" }}>new blocks: {offsetList(delta.newBlockOffsets, delta.newBlockOffsetsTruncated)}</div>}
                      <div style={{ color: "var(--text-secondary)" }}>stop changed {delta.stopReasonChanged ? "yes" : "no"} · terminal changed {delta.terminalChanged ? "yes" : "no"} · missing changed {delta.missingMemoryChanged ? "yes" : "no"}</div>
                      <div style={{ marginTop: 2 }}>{delta.recommendation}</div>
                    </div>
                  ))}
                  {seed.warnings.map((warning, index) => <div key={`${seed.captureOffset}-warning-${index}`} style={{ marginTop: 4, color: "#d29922" }}>{warning}</div>)}
                </div>
              </details>
            ))}

            {roundComparison.warnings.length > 0 && <div style={{ padding: "8px 10px", fontWeight: 600 }}>比较警告</div>}
            {roundComparison.warnings.map((warning, index) => <div key={`comparison-warning-${index}`} style={{ padding: "3px 10px", color: "#d29922" }}>{warning}</div>)}
            <div style={{ padding: "8px 10px", fontWeight: 600 }}>限制</div>
            {roundComparison.limitations.map((limitation, index) => <div key={`comparison-limitation-${index}`} style={{ padding: "3px 10px", color: "var(--text-secondary)" }}>{limitation}</div>)}
            <div style={{ height: 10 }} />
          </div>
        )}
      </div>
    </div>
  );
}
