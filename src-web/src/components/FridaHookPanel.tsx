import React, { useCallback, useEffect, useMemo, useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import type {
  AngrStateSeed,
  CryptoMaterialReport,
  FridaArgumentKind,
  FridaArgumentSpec,
  FridaCaptureBundle,
  FridaCaptureEvent,
  FridaCaptureDirection,
  FridaHookRequest,
  FridaHookRecipe,
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
    lengthPointerArg: null,
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
  const [recipes, setRecipes] = useState<FridaHookRecipe[]>([]);
  const [selectedRecipeId, setSelectedRecipeId] = useState("");
  const [targetMode, setTargetMode] = useState<"symbol" | "offset">("offset");
  const [generated, setGenerated] = useState<FridaHookScript | null>(null);
  const [generating, setGenerating] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [savedPath, setSavedPath] = useState<string | null>(null);
  const [seedLabel, setSeedLabel] = useState<string | null>(null);
  const [captureBundle, setCaptureBundle] = useState<FridaCaptureBundle | null>(null);
  const [capturePath, setCapturePath] = useState<string | null>(null);
  const [selectedEventIndex, setSelectedEventIndex] = useState<number | null>(null);
  const [angrSeed, setAngrSeed] = useState<AngrStateSeed | null>(null);
  const [fridaMaterials, setFridaMaterials] = useState<CryptoMaterialReport | null>(null);
  const [includeUnknownMaterials, setIncludeUnknownMaterials] = useState(false);
  const [includeSp, setIncludeSp] = useState(false);
  const [includeLr, setIncludeLr] = useState(true);
  const [seedSavedPath, setSeedSavedPath] = useState<string | null>(null);
  const [outputView, setOutputView] = useState<"script" | "capture" | "materials" | "seed">("script");

  useEffect(() => {
    invoke<FridaHookRecipe[]>("list_frida_hook_recipes")
      .then(setRecipes)
      .catch(reason => setError(String(reason)));
  }, []);

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
      captureRegisters: true,
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

  const selectedRecipe = useMemo(
    () => recipes.find(recipe => recipe.recipeId === selectedRecipeId) || null,
    [recipes, selectedRecipeId],
  );

  const applySelectedRecipe = useCallback(() => {
    if (!selectedRecipe) return;
    const currentModule = request.moduleName.trim();
    setTargetMode("symbol");
    setRequest({
      ...selectedRecipe.request,
      moduleName: currentModule || selectedRecipe.request.moduleName,
      arguments: selectedRecipe.request.arguments.map(argument => ({ ...argument })),
    });
    setSeedLabel(`recipe:${selectedRecipe.recipeId}`);
    setError(null);
  }, [request.moduleName, selectedRecipe]);

  const updateArgument = useCallback((row: number, patch: Partial<FridaArgumentSpec>) => {
    setRequest(previous => ({
      ...previous,
      arguments: previous.arguments.map((argument, index) => {
        if (index !== row) return argument;
        const updated = { ...argument, ...patch };
        if (patch.length !== undefined && patch.length !== null) {
          updated.lengthArg = null;
          updated.lengthPointerArg = null;
        } else if (patch.lengthArg !== undefined && patch.lengthArg !== null) {
          updated.length = null;
          updated.lengthPointerArg = null;
        } else if (patch.lengthPointerArg !== undefined && patch.lengthPointerArg !== null) {
          updated.length = null;
          updated.lengthArg = null;
          updated.direction = "output";
        }
        if (patch.direction !== undefined && patch.direction !== "output") {
          updated.lengthPointerArg = null;
        }
        return updated;
      }),
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
      setOutputView("script");
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

  const selectedCaptureEvent = useMemo<FridaCaptureEvent | null>(() => (
    captureBundle?.events.find(event => event.index === selectedEventIndex) || null
  ), [captureBundle, selectedEventIndex]);

  const importCapture = useCallback(async () => {
    const { open } = await import("@tauri-apps/plugin-dialog");
    const selected = await open({
      multiple: false,
      directory: false,
      filters: [{ name: "Frida capture", extensions: ["json", "jsonl", "ndjson", "log", "txt"] }],
    });
    if (typeof selected !== "string") return;
    setError(null);
    try {
      const bundle = await invoke<FridaCaptureBundle>("load_frida_capture", { path: selected });
      const preferred = bundle.events.find(event => event.event === "hook-enter" && (Object.keys(event.registers).length > 0 || event.captures.length > 0))
        || bundle.events.find(event => Object.keys(event.registers).length > 0 || event.captures.length > 0)
        || bundle.events[0];
      setCaptureBundle(bundle);
      setCapturePath(selected);
      setSelectedEventIndex(preferred?.index ?? null);
      setAngrSeed(null);
      setFridaMaterials(null);
      setSeedSavedPath(null);
      setOutputView("capture");
    } catch (reason) {
      setError(String(reason));
    }
  }, []);

  const analyzeCaptureMaterials = useCallback(async (): Promise<CryptoMaterialReport | null> => {
    if (!captureBundle) return null;
    setError(null);
    try {
      const result = await invoke<CryptoMaterialReport>("analyze_frida_crypto_materials", {
        bundle: captureBundle,
        maxMaterials: 1_000,
        includeUnknown: includeUnknownMaterials,
      });
      setFridaMaterials(result);
      setOutputView("materials");
      return result;
    } catch (reason) {
      setError(String(reason));
      return null;
    }
  }, [captureBundle, includeUnknownMaterials]);

  const generateStateSeed = useCallback(async (): Promise<AngrStateSeed | null> => {
    if (!captureBundle || selectedEventIndex == null) return null;
    setError(null);
    try {
      const result = await invoke<AngrStateSeed>("generate_angr_state_seed", {
        bundle: captureBundle,
        eventIndex: selectedEventIndex,
        includeSp,
        includeLr,
      });
      setAngrSeed(result);
      setOutputView("seed");
      return result;
    } catch (reason) {
      setError(String(reason));
      return null;
    }
  }, [captureBundle, includeLr, includeSp, selectedEventIndex]);

  const saveStateSeed = useCallback(async () => {
    if (!captureBundle || selectedEventIndex == null) return;
    const current = angrSeed || await generateStateSeed();
    if (!current) return;
    const { save: chooseSavePath } = await import("@tauri-apps/plugin-dialog");
    const selected = await chooseSavePath({
      defaultPath: `${current.functionName || current.hookId}-angr-state-seed.py`,
      filters: [{ name: "Python", extensions: ["py"] }],
    });
    if (typeof selected !== "string") return;
    try {
      const path = await invoke<string>("save_angr_state_seed", {
        path: selected,
        bundle: captureBundle,
        eventIndex: selectedEventIndex,
        includeSp,
        includeLr,
      });
      setSeedSavedPath(path);
    } catch (reason) {
      setError(String(reason));
    }
  }, [angrSeed, captureBundle, generateStateSeed, includeLr, includeSp, selectedEventIndex]);

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
          <label htmlFor="frida-recipe">API recipe</label>
          <div style={{ display: "flex", gap: 5, minWidth: 0 }}>
            <select id="frida-recipe" style={{ ...inputStyle, flex: 1 }} value={selectedRecipeId} onChange={event => setSelectedRecipeId(event.target.value)}>
              <option value="">Manual configuration</option>
              {recipes.map(recipe => <option key={recipe.recipeId} value={recipe.recipeId}>{recipe.provider} · {recipe.displayName}</option>)}
            </select>
            <button type="button" style={{ ...buttonStyle, opacity: selectedRecipe ? 1 : 0.5 }} disabled={!selectedRecipe} onClick={applySelectedRecipe}>Apply</button>
          </div>
          {selectedRecipe && <>
            <span>Recipe scope</span>
            <div style={{ color: "var(--text-secondary)" }}>
              <div>{selectedRecipe.description}</div>
              <div style={{ marginTop: 3 }}>Roles: {selectedRecipe.evidenceRoles.join(", ")}</div>
              {selectedRecipe.warnings.map((warning, index) => <div key={index} style={{ marginTop: 3, color: "#d29922" }}>{warning}</div>)}
            </div>
          </>}
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
          <div style={{ display: "grid", gridTemplateColumns: "54px minmax(85px, 1fr) 104px 84px 68px 70px 70px 26px", gap: 5, alignItems: "center", color: "var(--text-tertiary)", fontSize: 10, marginBottom: 4 }}>
            <span>Register</span><span>Label</span><span>Decoder</span><span>Phase</span><span>Length</span><span>Length reg</span><span>Length *reg</span><span />
          </div>
          {request.arguments.map((argument, row) => (
            <div key={`${row}-${argument.index}`} style={{ display: "grid", gridTemplateColumns: "54px minmax(85px, 1fr) 104px 84px 68px 70px 70px 26px", gap: 5, alignItems: "center", marginBottom: 5 }}>
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
              <select style={inputStyle} value={argument.lengthPointerArg ?? ""} onChange={event => updateArgument(row, { lengthPointerArg: optionalNumber(event.target.value) })}>
                <option value="">None</option>
                {Array.from({ length: 8 }, (_, index) => <option key={index} value={index}>*X{index}</option>)}
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
        <div style={{ minHeight: 38, display: "flex", alignItems: "center", gap: 6, padding: "6px 8px", borderBottom: "1px solid var(--border-color)", flexShrink: 0, overflowX: "auto" }}>
          <button type="button" disabled={generating} onClick={generate} style={{ ...buttonStyle, background: "var(--btn-primary)", color: "#fff", border: "none", opacity: generating ? 0.6 : 1 }}>{generating ? "Generating..." : "Generate"}</button>
          <button type="button" onClick={save} style={buttonStyle}>Save .js</button>
          <button type="button" disabled={!generated} onClick={copyScript} style={{ ...buttonStyle, opacity: generated ? 1 : 0.5 }}>Copy script</button>
          <button type="button" onClick={importCapture} style={buttonStyle}>Import capture</button>
          <button type="button" onClick={() => setOutputView("script")} style={{ ...buttonStyle, background: outputView === "script" ? "var(--bg-selected)" : "var(--bg-input)" }}>Script</button>
          <button type="button" disabled={!captureBundle} onClick={() => setOutputView("capture")} style={{ ...buttonStyle, background: outputView === "capture" ? "var(--bg-selected)" : "var(--bg-input)", opacity: captureBundle ? 1 : 0.5 }}>Capture</button>
          <button type="button" disabled={!fridaMaterials} onClick={() => setOutputView("materials")} style={{ ...buttonStyle, background: outputView === "materials" ? "var(--bg-selected)" : "var(--bg-input)", opacity: fridaMaterials ? 1 : 0.5 }}>Materials</button>
          <button type="button" disabled={!angrSeed} onClick={() => setOutputView("seed")} style={{ ...buttonStyle, background: outputView === "seed" ? "var(--bg-selected)" : "var(--bg-input)", opacity: angrSeed ? 1 : 0.5 }}>angr seed</button>
          <span style={{ flex: 1 }} />
          {seedLabel && <span title={seedLabel} style={{ maxWidth: 240, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap", color: "var(--text-tertiary)", fontSize: 10 }}>{seedLabel}</span>}
        </div>
        {error && <div style={{ padding: "7px 10px", color: "#e5484d", borderBottom: "1px solid var(--border-color)", fontSize: 11 }}>{error}</div>}
        {outputView === "script" && (
          <>
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
          </>
        )}

        {outputView === "capture" && captureBundle && (
          <div style={{ flex: 1, minHeight: 0, display: "flex", flexDirection: "column", overflow: "hidden", fontSize: 11 }}>
            <div style={{ padding: "7px 9px", borderBottom: "1px solid var(--border-color)", flexShrink: 0 }}>
              <div style={{ display: "flex", gap: 10, alignItems: "center" }}>
                <strong>{captureBundle.events.length.toLocaleString()} events</strong>
                <span>{captureBundle.enterEventCount} enter / {captureBundle.leaveEventCount} leave / {captureBundle.stalkerEventCount} Stalker batches</span>
                <span>{captureBundle.hookIds.length} hooks</span>
                <span style={{ color: "var(--text-tertiary)" }}>{captureBundle.sourceFormat}</span>
              </div>
              {capturePath && <div title={capturePath} style={{ marginTop: 3, color: "var(--text-tertiary)", overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{capturePath}</div>}
              {captureBundle.warnings.map((warning, index) => <div key={index} style={{ color: "#d29922", marginTop: 3 }}>{warning}</div>)}
            </div>
            <div style={{ flex: 1, minHeight: 0, display: "flex", overflow: "hidden" }}>
              <div style={{ width: 330, minWidth: 260, overflow: "auto", borderRight: "1px solid var(--border-color)" }}>
                {captureBundle.events.slice(0, 5000).map(event => (
                  <button
                    type="button"
                    key={event.index}
                    onClick={() => { setSelectedEventIndex(event.index); setAngrSeed(null); setSeedSavedPath(null); }}
                    style={{ width: "100%", border: "none", borderBottom: "1px solid var(--border-color)", padding: "6px 8px", textAlign: "left", background: selectedEventIndex === event.index ? "var(--bg-selected)" : "transparent", color: "var(--text-primary)", cursor: "pointer", fontFamily: "inherit", fontSize: 10 }}
                  >
                    <div style={{ display: "flex", gap: 6 }}><strong>#{event.index} {event.event}</strong><span style={{ color: "var(--text-tertiary)" }}>T{event.threadId}</span></div>
                    <div style={{ marginTop: 2, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap", color: "var(--text-secondary)" }}>{event.functionName} · {event.callId || "no call id"}</div>
                    <div style={{ marginTop: 2, color: "var(--text-tertiary)" }}>{Object.keys(event.registers).length} regs · {event.captures.length} captures{event.stalkerEventCount != null ? ` · ${event.stalkerEventCount} Stalker events` : ""}</div>
                  </button>
                ))}
                {captureBundle.events.length > 5000 && <div style={{ padding: 8, color: "#d29922" }}>UI list limited to the first 5000 events.</div>}
              </div>
              <div style={{ flex: 1, minWidth: 0, overflow: "auto", padding: 10 }}>
                {selectedCaptureEvent ? (
                  <>
                    <div style={{ display: "flex", gap: 9, alignItems: "center", flexWrap: "wrap" }}>
                      <strong>#{selectedCaptureEvent.index} {selectedCaptureEvent.event}</strong>
                      <span>{selectedCaptureEvent.moduleName || "unknown module"}</span>
                      <code>{selectedCaptureEvent.target || "unknown target"}</code>
                      <span>{selectedCaptureEvent.callId || "no call id"}</span>
                    </div>
                    <div style={{ display: "grid", gridTemplateColumns: "70px minmax(0, 1fr)", gap: 5, marginTop: 9 }}>
                      {Object.entries(selectedCaptureEvent.registers).map(([name, value]) => <React.Fragment key={name}><strong>{name.toUpperCase()}</strong><code>{value}</code></React.Fragment>)}
                    </div>
                    {selectedCaptureEvent.captures.map((capture, index) => (
                      <div key={`${capture.index}-${capture.label}-${index}`} style={{ marginTop: 8, padding: 7, border: "1px solid var(--border-color)", borderRadius: 3 }}>
                        <div><strong>X{capture.index} {capture.label}</strong> · {capture.kind} · {capture.direction}/{capture.phase}</div>
                        <div style={{ marginTop: 3 }}><code>{capture.pointer || "null"}</code> · {capture.byteLength ?? capture.requestedLength ?? "?"} bytes</div>
                        <div style={{ marginTop: 3, overflowWrap: "anywhere", color: capture.readError ? "#e5484d" : "var(--text-secondary)" }}>{capture.readError || capture.value || "no value"}</div>
                      </div>
                    ))}
                    {selectedCaptureEvent.returnValue && <div style={{ marginTop: 8 }}><strong>Return:</strong> <code>{selectedCaptureEvent.returnValue}</code></div>}
                    {selectedCaptureEvent.error && <div style={{ marginTop: 8, color: "#e5484d" }}>{selectedCaptureEvent.error}</div>}
                    {selectedCaptureEvent.backtrace.length > 0 && <pre style={{ marginTop: 8, padding: 7, overflow: "auto", background: "var(--bg-secondary)", fontSize: 10 }}>{selectedCaptureEvent.backtrace.join("\n")}</pre>}
                    <div style={{ display: "flex", gap: 8, alignItems: "center", marginTop: 12, paddingTop: 9, borderTop: "1px solid var(--border-color)" }}>
                      <label style={{ display: "flex", alignItems: "center", gap: 4 }}><input type="checkbox" checked={includeUnknownMaterials} onChange={event => { setIncludeUnknownMaterials(event.target.checked); setFridaMaterials(null); }} />Include weak material roles</label>
                      <button type="button" style={buttonStyle} onClick={analyzeCaptureMaterials}>Index crypto materials</button>
                      <label style={{ display: "flex", alignItems: "center", gap: 4 }}><input type="checkbox" checked={includeSp} onChange={event => { setIncludeSp(event.target.checked); setAngrSeed(null); }} />Seed SP</label>
                      <label style={{ display: "flex", alignItems: "center", gap: 4 }}><input type="checkbox" checked={includeLr} onChange={event => { setIncludeLr(event.target.checked); setAngrSeed(null); }} />Seed LR/X30</label>
                      <button type="button" style={{ ...buttonStyle, background: "var(--btn-primary)", color: "#fff", border: "none" }} onClick={generateStateSeed}>Generate angr seed</button>
                    </div>
                  </>
                ) : <div style={{ color: "var(--text-secondary)" }}>Select a capture event.</div>}
              </div>
            </div>
          </div>
        )}

        {outputView === "materials" && fridaMaterials && (
          <div style={{ flex: 1, minHeight: 0, display: "flex", flexDirection: "column", overflow: "hidden", fontSize: 11 }}>
            <div style={{ padding: "7px 9px", borderBottom: "1px solid var(--border-color)", flexShrink: 0 }}>
              <div style={{ display: "flex", gap: 10, alignItems: "center", flexWrap: "wrap" }}>
                <strong>{fridaMaterials.materials.length} materials</strong>
                <span>{fridaMaterials.verifiedMaterials} verified</span>
                <span>{fridaMaterials.formulas.length} formulas / {fridaMaterials.verifiedFormulas} verified</span>
                {fridaMaterials.materialsTruncated && <span style={{ color: "#d29922" }}>truncated</span>}
                <button type="button" style={buttonStyle} onClick={analyzeCaptureMaterials}>Re-index</button>
              </div>
              <div style={{ marginTop: 4, color: "var(--text-secondary)" }}>Label/phase classifications remain Related unless exact MD5/SHA/HMAC/PBKDF2 recomputation opens the verification gate.</div>
            </div>
            <div style={{ flex: 1, minHeight: 0, overflow: "auto" }}>
              {fridaMaterials.materials.map(material => (
                <div key={material.materialId} style={{ padding: "7px 9px", borderBottom: "1px solid var(--border-color)" }}>
                  <div style={{ display: "flex", gap: 8, alignItems: "center", flexWrap: "wrap" }}>
                    <span style={{ minWidth: 76, padding: "1px 6px", textAlign: "center", borderRadius: 3, background: material.assessment.verificationGateMet ? "#238636" : "#9e6a03", color: "#fff", textTransform: "uppercase", fontSize: 10 }}>{material.assessment.grade} {material.assessment.score}</span>
                    <strong>{material.kind}</strong>
                    <span>{material.role}</span>
                    {material.algorithm && <code>{material.algorithm}</code>}
                    <span>{material.byteLen ?? "?"} bytes</span>
                    <span>{material.functionName || "unknown function"}</span>
                    <code>{material.register || ""}</code>
                  </div>
                  <div title={material.bytesHex || ""} style={{ marginTop: 4, overflowWrap: "anywhere", color: "var(--text-secondary)", fontFamily: "monospace" }}>{material.bytesHex || "no bytes"}</div>
                  <div style={{ marginTop: 3, color: "var(--text-tertiary)" }}>{material.evidence.join(" · ")}</div>
                </div>
              ))}
              {fridaMaterials.formulas.length > 0 && <div style={{ padding: "9px", fontWeight: 600, borderBottom: "1px solid var(--border-color)" }}>Verified/reconstructed formulas</div>}
              {fridaMaterials.formulas.map(formula => (
                <div key={formula.formulaId} style={{ padding: "7px 9px", borderBottom: "1px solid var(--border-color)", background: "var(--bg-secondary)" }}>
                  <div style={{ display: "flex", gap: 8, alignItems: "center" }}>
                    <strong>{formula.operation}</strong><code>{formula.algorithm}</code><span>{formula.assessment.grade} {formula.assessment.score}</span>
                  </div>
                  <code style={{ display: "block", marginTop: 4, overflowWrap: "anywhere" }}>{formula.expression}</code>
                </div>
              ))}
              {fridaMaterials.materials.length === 0 && <div style={{ padding: 14, color: "var(--text-secondary)" }}>No byte-bearing crypto material was classified from this capture.</div>}
            </div>
          </div>
        )}

        {outputView === "seed" && angrSeed && (
          <div style={{ flex: 1, minHeight: 0, display: "flex", flexDirection: "column", overflow: "hidden" }}>
            <div style={{ padding: "7px 9px", borderBottom: "1px solid var(--border-color)", fontSize: 11 }}>
              <div style={{ display: "flex", gap: 8, alignItems: "center", flexWrap: "wrap" }}>
                <strong>{angrSeed.schemaVersion}</strong>
                <span>{angrSeed.registersSeeded.length} registers</span>
                <span>{angrSeed.memoryRegions.length} memory regions</span>
                <button type="button" style={buttonStyle} onClick={() => navigator.clipboard.writeText(angrSeed.script)}>Copy seed</button>
                <button type="button" style={buttonStyle} onClick={saveStateSeed}>Save .py</button>
              </div>
              {seedSavedPath && <div title={seedSavedPath} style={{ marginTop: 4, color: "#3fb950", overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>Saved: {seedSavedPath}</div>}
              {angrSeed.warnings.map((warning, index) => <div key={index} style={{ marginTop: 3, color: "#d29922" }}>{warning}</div>)}
            </div>
            <pre style={{ flex: 1, minHeight: 0, margin: 0, padding: 10, overflow: "auto", background: "var(--bg-primary)", color: "var(--text-primary)", fontSize: 11, lineHeight: 1.45, whiteSpace: "pre" }}>{angrSeed.script}</pre>
          </div>
        )}
      </div>
    </div>
  );
}
