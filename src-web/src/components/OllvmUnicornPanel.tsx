import { useMemo, useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import type {
  FridaCaptureBundle,
  FridaCaptureEvent,
  FridaUnicornRecaptureHookScript,
  OllvmReport,
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
  const [selectedRecaptureSuggestions, setSelectedRecaptureSuggestions] = useState<number[]>([]);
  const [recaptureMaxEvents, setRecaptureMaxEvents] = useState("5000");
  const [recaptureHook, setRecaptureHook] = useState<FridaUnicornRecaptureHookScript | null>(null);
  const [recaptureSavedPath, setRecaptureSavedPath] = useState<string | null>(null);
  const [savedPath, setSavedPath] = useState<string | null>(null);
  const [display, setDisplay] = useState<"script" | "results" | "recapture">("script");
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
      setSelectedRecaptureSuggestions(bundle.recaptureSuggestions
        .map((suggestion, index) => automaticRecaptureSupported(suggestion) ? index : -1)
        .filter(index => index >= 0)
        .slice(0, 1));
      setRecaptureHook(null);
      setRecaptureSavedPath(null);
      setDisplay("results");
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

  return (
    <div style={{ display: "flex", flex: 1, minHeight: 0, overflow: "hidden" }}>
      <div style={{ width: 440, padding: 10, borderRight: "1px solid var(--border-color)", overflow: "auto", fontSize: 11 }}>
        <div style={{ color: "var(--text-secondary)", lineHeight: 1.5 }}>
          用精确 Frida 状态进行有界 ARM64 具体重放。脚本由用户手动运行；下一 dispatcher、寄存器变化和缺失状态均为 Candidate/Related 证据。
        </div>

        <div style={{ marginTop: 10, fontWeight: 600 }}>1. 精确 ELF</div>
        <div style={{ display: "flex", gap: 6, marginTop: 5 }}>
          <button type="button" style={buttonStyle} onClick={selectBinary}>选择 ELF</button>
          {binaryPath && <button type="button" style={buttonStyle} onClick={() => { setBinaryPath(null); setGenerated(null); setResults(null); setResultsPath(null); setSelectedRecaptureSuggestions([]); setRecaptureHook(null); }}>清除</button>}
        </div>
        <div title={binaryPath || ""} style={{ marginTop: 5, color: binaryPath ? "var(--text-secondary)" : "#d29922", overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
          {binaryPath || "必须选择与 Frida 捕获相同构建的 AArch64 ELF"}
        </div>

        <div style={{ marginTop: 12, fontWeight: 600 }}>2. Frida 精确事件</div>
        <div style={{ display: "flex", gap: 6, marginTop: 5 }}>
          <button type="button" style={buttonStyle} onClick={importCapture}>导入捕获</button>
          {capture && <button type="button" style={buttonStyle} onClick={() => { setCapture(null); setCapturePath(null); setSelectedEvents([]); setGenerated(null); setResults(null); setResultsPath(null); setSelectedRecaptureSuggestions([]); setRecaptureHook(null); }}>清除</button>}
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
          </div>
        )}
        {generated?.warnings.map((warning, index) => <div key={`generated-${index}`} style={{ marginTop: 5, color: "#d29922" }}>{warning}</div>)}

        {results && results.recaptureSuggestions.length > 0 && (
          <div style={{ marginTop: 12, paddingTop: 10, borderTop: "1px solid var(--border-color)" }}>
            <div style={{ fontWeight: 600 }}>4. Frida 精确重捕获</div>
            <div style={{ marginTop: 4, color: "var(--text-secondary)", lineHeight: 1.5 }}>
              从下次捕获建议生成 X0-X28/SP 正负位移窗口。Hook 仍落在原 exact seed offset，捕获结果可以再次导入 Unicorn/angr。
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
                {recaptureHook.targets.length} exact seed targets · {recaptureHook.targets.reduce((count, target) => count + target.captures.length, 0)} bounded windows · max {recaptureHook.maxEvents} events
              </div>
            )}
            {recaptureHook?.warnings.map((warning, index) => <div key={`recapture-warning-${index}`} style={{ marginTop: 4, color: "#d29922" }}>{warning}</div>)}
          </div>
        )}
        {error && <div style={{ marginTop: 8, color: "#e5484d", whiteSpace: "pre-wrap" }}>{error}</div>}
      </div>

      <div style={{ flex: 1, minWidth: 0, display: "flex", flexDirection: "column", overflow: "hidden" }}>
        <div style={{ display: "flex", gap: 5, padding: 7, borderBottom: "1px solid var(--border-color)" }}>
          <button type="button" style={{ ...buttonStyle, background: display === "script" ? "var(--bg-selected)" : "var(--bg-input)" }} onClick={() => setDisplay("script")}>脚本</button>
          <button type="button" style={{ ...buttonStyle, background: display === "results" ? "var(--bg-selected)" : "var(--bg-input)", opacity: results ? 1 : 0.5 }} disabled={!results} onClick={() => setDisplay("results")}>模拟结果</button>
          <button type="button" style={{ ...buttonStyle, background: display === "recapture" ? "var(--bg-selected)" : "var(--bg-input)", opacity: recaptureHook ? 1 : 0.5 }} disabled={!recaptureHook} onClick={() => setDisplay("recapture")}>重捕获 Hook</button>
        </div>
        {display === "script" && (
          <pre style={{ flex: 1, margin: 0, padding: 10, overflow: "auto", background: "var(--bg-primary)", color: "var(--text-primary)", fontSize: 10, lineHeight: 1.45, whiteSpace: "pre" }}>{generated?.script || ""}</pre>
        )}
        {display === "recapture" && (
          <pre style={{ flex: 1, margin: 0, padding: 10, overflow: "auto", background: "var(--bg-primary)", color: "var(--text-primary)", fontSize: 10, lineHeight: 1.45, whiteSpace: "pre" }}>{recaptureHook?.script || ""}</pre>
        )}
        {display === "results" && results && (
          <div style={{ flex: 1, overflow: "auto", fontSize: 11 }}>
            <div style={{ padding: 9, borderBottom: "1px solid var(--border-color)", background: "var(--bg-secondary)" }}>
              <strong>Unicorn {results.unicornVersion} / Capstone {results.capstoneVersion}</strong>
              <div>{results.runs.length} runs · {results.transitionMatrix.length} transition groups · {results.recaptureSuggestions.length} recapture suggestions</div>
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
      </div>
    </div>
  );
}
