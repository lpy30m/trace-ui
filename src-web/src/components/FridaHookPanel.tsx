import React, { useCallback, useEffect, useMemo, useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import type {
  FridaArgumentKind,
  FridaArgumentSpec,
  FridaCaptureDirection,
  FridaHookRequest,
  FridaHookScript,
  FridaHookSeed,
  FridaStalkerMode,
} from "../types/trace";

interface Props {
  seed: FridaHookSeed | null;
}

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

function newArgument(index: number): FridaArgumentSpec {
  return {
    index,
    label: `x${index}`,
    kind: "pointer",
    direction: "input",
    length: null,
    lengthArg: null,
  };
}

const initialRequest: FridaHookRequest = {
  moduleName: "",
  symbol: "",
  offset: null,
  functionName: "",
  arguments: [],
  captureRegisters: true,
  captureReturn: true,
  captureBacktrace: false,
  stalker: "off",
  stalkerDurationMs: 10_000,
  maxBytes: 256,
};

function optionalNumber(value: string): number | null {
  if (value.trim() === "") return null;
  const parsed = Number(value);
  return Number.isFinite(parsed) && parsed >= 0 ? Math.floor(parsed) : null;
}

export default function FridaHookPanel({ seed }: Props) {
  const [request, setRequest] = useState<FridaHookRequest>(initialRequest);
  const [targetMode, setTargetMode] = useState<"symbol" | "offset">("offset");
  const [generated, setGenerated] = useState<FridaHookScript | null>(null);
  const [generating, setGenerating] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [savedPath, setSavedPath] = useState<string | null>(null);
  const [seedLabel, setSeedLabel] = useState<string | null>(null);

  useEffect(() => {
    if (!seed) return;
    setTargetMode(seed.targetMode);
    setRequest(previous => ({
      ...previous,
      moduleName: seed.moduleName,
      symbol: seed.symbol,
      offset: seed.offset,
      functionName: seed.functionName,
      arguments: seed.arguments,
    }));
    setSeedLabel(seed.sourceLabel);
    setError(null);
  }, [seed]);

  useEffect(() => {
    setGenerated(null);
    setSavedPath(null);
  }, [request, targetMode]);

  const effectiveRequest = useMemo<FridaHookRequest>(() => ({
    ...request,
    moduleName: request.moduleName.trim(),
    symbol: targetMode === "symbol" ? request.symbol?.trim() || null : null,
    offset: targetMode === "offset" ? request.offset?.trim() || null : null,
    functionName: request.functionName?.trim() || null,
    stalkerDurationMs: Math.max(100, Math.min(600_000, request.stalkerDurationMs || 10_000)),
    maxBytes: Math.max(1, Math.min(1_048_576, request.maxBytes || 256)),
  }), [request, targetMode]);

  const updateArgument = useCallback((row: number, patch: Partial<FridaArgumentSpec>) => {
    setRequest(previous => ({
      ...previous,
      arguments: previous.arguments.map((argument, index) => index === row ? { ...argument, ...patch } : argument),
    }));
  }, []);

  const addArgument = useCallback(() => {
    setRequest(previous => {
      const used = new Set(previous.arguments.map(argument => argument.index));
      const index = Array.from({ length: 8 }, (_, value) => value).find(value => !used.has(value));
      if (index == null) return previous;
      return { ...previous, arguments: [...previous.arguments, newArgument(index)] };
    });
  }, []);

  const removeArgument = useCallback((row: number) => {
    setRequest(previous => ({
      ...previous,
      arguments: previous.arguments.filter((_, index) => index !== row),
    }));
  }, []);

  const generate = useCallback(async (): Promise<FridaHookScript | null> => {
    setGenerating(true);
    setError(null);
    try {
      const result = await invoke<FridaHookScript>("generate_frida_hook", { request: effectiveRequest });
      setGenerated(result);
      return result;
    } catch (reason) {
      setError(String(reason));
      return null;
    } finally {
      setGenerating(false);
    }
  }, [effectiveRequest]);

  const save = useCallback(async () => {
    const current = generated || await generate();
    if (!current) return;
    const { save: chooseSavePath } = await import("@tauri-apps/plugin-dialog");
    const selected = await chooseSavePath({
      defaultPath: current.fileName,
      filters: [{ name: "Frida JavaScript", extensions: ["js"] }],
    });
    if (typeof selected !== "string") return;
    setError(null);
    try {
      const path = await invoke<string>("save_frida_hook", {
        path: selected,
        request: effectiveRequest,
      });
      setSavedPath(path);
    } catch (reason) {
      setError(String(reason));
    }
  }, [effectiveRequest, generate, generated]);

  const copyScript = useCallback(async () => {
    if (!generated) return;
    await navigator.clipboard.writeText(generated.script);
  }, [generated]);

  const segmentStyle = (active: boolean): React.CSSProperties => ({
    ...buttonStyle,
    borderRadius: 0,
    border: "none",
    borderRight: "1px solid var(--border-color)",
    background: active ? "var(--bg-selected)" : "var(--bg-input)",
  });

  return (
    <div style={{ flex: 1, minWidth: 0, minHeight: 0, display: "flex", overflow: "hidden" }}>
      <div style={{ width: "min(580px, 48%)", minWidth: 430, display: "flex", flexDirection: "column", borderRight: "1px solid var(--border-color)", overflow: "auto" }}>
        <div style={{ display: "grid", gridTemplateColumns: "105px minmax(0, 1fr)", gap: 7, alignItems: "center", padding: 10, borderBottom: "1px solid var(--border-color)", fontSize: 11 }}>
          <label htmlFor="frida-module">Module</label>
          <input
            id="frida-module"
            style={inputStyle}
            value={request.moduleName}
            placeholder="libtarget.so"
            onChange={event => setRequest(previous => ({ ...previous, moduleName: event.target.value }))}
          />

          <span>Target</span>
          <div style={{ display: "flex", minWidth: 0, border: "1px solid var(--border-color)", borderRadius: 3, overflow: "hidden" }}>
            <button type="button" style={segmentStyle(targetMode === "symbol")} onClick={() => setTargetMode("symbol")}>Symbol</button>
            <button type="button" style={{ ...segmentStyle(targetMode === "offset"), borderRight: "none" }} onClick={() => setTargetMode("offset")}>Module offset</button>
          </div>

          <label htmlFor="frida-target">{targetMode === "symbol" ? "Symbol" : "Offset"}</label>
          <input
            id="frida-target"
            style={inputStyle}
            value={(targetMode === "symbol" ? request.symbol : request.offset) || ""}
            placeholder={targetMode === "symbol" ? "target_export" : "0x1234"}
            onChange={event => setRequest(previous => targetMode === "symbol"
              ? { ...previous, symbol: event.target.value }
              : { ...previous, offset: event.target.value })}
          />

          <label htmlFor="frida-label">Hook label</label>
          <input
            id="frida-label"
            style={inputStyle}
            value={request.functionName || ""}
            placeholder="target-function"
            onChange={event => setRequest(previous => ({ ...previous, functionName: event.target.value }))}
          />
        </div>

        <div style={{ padding: 10, borderBottom: "1px solid var(--border-color)", fontSize: 11 }}>
          <div style={{ display: "grid", gridTemplateColumns: "repeat(3, minmax(0, 1fr))", gap: 8, alignItems: "center" }}>
            <label style={{ display: "flex", alignItems: "center", gap: 5 }}>
              <input type="checkbox" checked={request.captureRegisters} onChange={event => setRequest(previous => ({ ...previous, captureRegisters: event.target.checked }))} />
              X0-X7 / SP / LR / PC
            </label>
            <label style={{ display: "flex", alignItems: "center", gap: 5 }}>
              <input type="checkbox" checked={request.captureReturn} onChange={event => setRequest(previous => ({ ...previous, captureReturn: event.target.checked }))} />
              Return value
            </label>
            <label style={{ display: "flex", alignItems: "center", gap: 5 }}>
              <input type="checkbox" checked={request.captureBacktrace} onChange={event => setRequest(previous => ({ ...previous, captureBacktrace: event.target.checked }))} />
              Backtrace
            </label>
          </div>
          <div style={{ display: "grid", gridTemplateColumns: "105px minmax(100px, 1fr) 92px minmax(70px, 1fr)", gap: 7, alignItems: "center", marginTop: 9 }}>
            <label htmlFor="frida-stalker">Stalker</label>
            <select id="frida-stalker" style={inputStyle} value={request.stalker} onChange={event => setRequest(previous => ({ ...previous, stalker: event.target.value as FridaStalkerMode }))}>
              <option value="off">Off</option>
              <option value="calls">Calls</option>
              <option value="blocks">Blocks</option>
              <option value="instructions">Instructions</option>
            </select>
            <label htmlFor="frida-duration">Duration ms</label>
            <input id="frida-duration" type="number" min={100} max={600000} style={inputStyle} value={request.stalkerDurationMs} onChange={event => setRequest(previous => ({ ...previous, stalkerDurationMs: Number(event.target.value) }))} />
            <label htmlFor="frida-max-bytes">Max bytes</label>
            <input id="frida-max-bytes" type="number" min={1} max={1048576} style={inputStyle} value={request.maxBytes} onChange={event => setRequest(previous => ({ ...previous, maxBytes: Number(event.target.value) }))} />
          </div>
        </div>

        <div style={{ display: "flex", alignItems: "center", padding: "7px 10px", borderBottom: "1px solid var(--border-color)" }}>
          <strong style={{ fontSize: 11 }}>Argument captures</strong>
          <span style={{ flex: 1 }} />
          <button type="button" style={{ ...buttonStyle, opacity: request.arguments.length >= 8 ? 0.5 : 1 }} disabled={request.arguments.length >= 8} onClick={addArgument}>Add capture</button>
        </div>
        <div style={{ padding: "6px 10px 10px" }}>
          <div style={{ display: "grid", gridTemplateColumns: "54px minmax(85px, 1fr) 104px 84px 72px 74px 26px", gap: 5, alignItems: "center", color: "var(--text-tertiary)", fontSize: 10, marginBottom: 4 }}>
            <span>Register</span><span>Label</span><span>Decoder</span><span>Phase</span><span>Length</span><span>Length reg</span><span />
          </div>
          {request.arguments.map((argument, row) => (
            <div key={`${row}-${argument.index}`} style={{ display: "grid", gridTemplateColumns: "54px minmax(85px, 1fr) 104px 84px 72px 74px 26px", gap: 5, alignItems: "center", marginBottom: 5 }}>
              <select style={inputStyle} value={argument.index} onChange={event => updateArgument(row, { index: Number(event.target.value) })}>
                {Array.from({ length: 8 }, (_, index) => <option key={index} value={index}>X{index}</option>)}
              </select>
              <input style={inputStyle} value={argument.label || ""} onChange={event => updateArgument(row, { label: event.target.value })} />
              <select style={inputStyle} value={argument.kind} onChange={event => updateArgument(row, { kind: event.target.value as FridaArgumentKind })}>
                <option value="integer">Integer</option>
                <option value="pointer">Pointer</option>
                <option value="utf8String">UTF-8</option>
                <option value="utf16String">UTF-16</option>
                <option value="byteArray">Byte array</option>
              </select>
              <select style={inputStyle} value={argument.direction} onChange={event => updateArgument(row, { direction: event.target.value as FridaCaptureDirection })}>
                <option value="input">Input</option>
                <option value="output">Output</option>
                <option value="inOut">In/out</option>
              </select>
              <input type="number" min={0} style={inputStyle} value={argument.length ?? ""} onChange={event => updateArgument(row, { length: optionalNumber(event.target.value) })} />
              <select style={inputStyle} value={argument.lengthArg ?? ""} onChange={event => updateArgument(row, { lengthArg: optionalNumber(event.target.value) })}>
                <option value="">None</option>
                {Array.from({ length: 8 }, (_, index) => <option key={index} value={index}>X{index}</option>)}
              </select>
              <button type="button" title="Remove capture" aria-label="Remove capture" onClick={() => removeArgument(row)} style={{ ...buttonStyle, width: 26, padding: 0 }}>x</button>
            </div>
          ))}
          {request.arguments.length === 0 && (
            <div style={{ color: "var(--text-tertiary)", fontSize: 11, padding: "5px 0" }}>No argument captures</div>
          )}
        </div>
      </div>

      <div style={{ flex: 1, minWidth: 0, display: "flex", flexDirection: "column", overflow: "hidden" }}>
        <div style={{ height: 38, display: "flex", alignItems: "center", gap: 6, padding: "6px 8px", borderBottom: "1px solid var(--border-color)", flexShrink: 0 }}>
          <button type="button" disabled={generating} onClick={generate} style={{ ...buttonStyle, background: "var(--btn-primary)", color: "#fff", border: "none", opacity: generating ? 0.6 : 1 }}>{generating ? "Generating..." : "Generate"}</button>
          <button type="button" onClick={save} style={buttonStyle}>Save .js</button>
          <button type="button" disabled={!generated} onClick={copyScript} style={{ ...buttonStyle, opacity: generated ? 1 : 0.5 }}>Copy script</button>
          <span style={{ flex: 1 }} />
          {seedLabel && <span title={seedLabel} style={{ maxWidth: 240, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap", color: "var(--text-tertiary)", fontSize: 10 }}>{seedLabel}</span>}
        </div>
        {error && <div style={{ padding: "7px 10px", color: "#e5484d", borderBottom: "1px solid var(--border-color)", fontSize: 11 }}>{error}</div>}
        {savedPath && <div title={savedPath} style={{ padding: "6px 10px", color: "#3fb950", borderBottom: "1px solid var(--border-color)", fontSize: 11, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>Saved: {savedPath}</div>}
        {generated && (
          <div style={{ padding: "7px 10px", borderBottom: "1px solid var(--border-color)", fontSize: 11 }}>
            <div style={{ display: "flex", gap: 10, marginBottom: generated.warnings.length ? 5 : 0 }}>
              <strong>{generated.targetExpression}</strong>
              <span style={{ color: "var(--text-tertiary)" }}>Frida {generated.fridaApiVersion}</span>
              <span style={{ color: "var(--text-tertiary)" }}>{generated.protocolVersion}</span>
            </div>
            {generated.warnings.map((warning, index) => <div key={index} style={{ color: "#d29922" }}>{warning}</div>)}
          </div>
        )}
        <pre style={{ flex: 1, minHeight: 0, margin: 0, padding: 10, overflow: "auto", background: "var(--bg-primary)", color: "var(--text-primary)", fontSize: 11, lineHeight: 1.45, whiteSpace: "pre" }}>
          {generated?.script || ""}
        </pre>
      </div>
    </div>
  );
}
