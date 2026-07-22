import React, { useState, useCallback, useMemo, useRef } from "react";
import { createPortal } from "react-dom";

interface TaintSource {
  id: number;
  type: "register" | "memory";
  register: string;
  memAddr: string;
  memSize: string;
}

interface Props {
  seq: number;
  totalLines: number;
  defaultDefs?: string[];
  defaultMemAddr?: string;
  onExecute: (fromSpecs: string[], startSeq?: number, endSeq?: number, dataOnly?: boolean) => void;
  onClose: () => void;
}

const REGISTERS = [
  "x0", "x1", "x2", "x3", "x4", "x5", "x6", "x7",
  "x8", "x9", "x10", "x11", "x12", "x13", "x14", "x15",
  "x16", "x17", "x18", "x19", "x20", "x21", "x22", "x23",
  "x24", "x25", "x26", "x27", "x28", "x29", "x30", "sp",
];

const MEM_SIZES = ["1", "2", "4", "8", "16", "20", "32", "48", "64"];

function normalizeReg(token: string): string {
  const t = token.toLowerCase();
  const wMatch = t.match(/^w(\d+)$/);
  if (wMatch) return `x${wMatch[1]}`;
  return t;
}

function formatMemoryRange(address: string, sizeText: string): string {
  const normalized = address.trim();
  const size = Number.parseInt(sizeText, 10);
  if (!normalized || !Number.isInteger(size) || size < 1) {
    return `${normalized || "Memory address required"} (${sizeText || "?"} bytes)`;
  }
  try {
    const start = BigInt(normalized.toLowerCase().startsWith("0x") ? normalized : `0x${normalized}`);
    const end = start + BigInt(size) - 1n;
    return `0x${start.toString(16)}..0x${end.toString(16)} (${size} bytes)`;
  } catch {
    return `${normalized} (${size} bytes)`;
  }
}

function createDefaultSources(
  nextIdRef: React.MutableRefObject<number>,
  defaultDefs?: string[],
  defaultMemAddr?: string,
): TaintSource[] {
  const sources: TaintSource[] = [];
  if (defaultDefs && defaultDefs.length > 0) {
    for (const reg of defaultDefs) {
      const normalized = normalizeReg(reg);
      if (!REGISTERS.includes(normalized)) continue;
      sources.push({
        id: nextIdRef.current++,
        type: "register",
        register: normalized,
        memAddr: "",
        memSize: "4",
      });
    }
  }
  if (defaultMemAddr) {
    sources.push({
      id: nextIdRef.current++,
      type: "memory",
      register: "x0",
      memAddr: defaultMemAddr,
      memSize: "4",
    });
  }
  if (sources.length === 0) {
    sources.push({
      id: nextIdRef.current++,
      type: "register",
      register: "x0",
      memAddr: "",
      memSize: "4",
    });
  }
  return sources;
}

// ── Shared styles ──

const cardStyle: React.CSSProperties = {
  background: "var(--bg-input)",
  border: "1px solid var(--border-color)",
  borderRadius: 8,
  padding: "10px 14px",
};

const labelStyle: React.CSSProperties = {
  fontSize: 11,
  color: "var(--text-secondary)",
  marginBottom: 4,
  display: "block",
};

const fieldInputStyle: React.CSSProperties = {
  background: "transparent",
  border: "none",
  color: "var(--text-primary)",
  fontSize: 14,
  outline: "none",
  width: "100%",
  padding: 0,
  fontFamily: "var(--font-mono)",
};

const fieldSelectStyle: React.CSSProperties = {
  ...fieldInputStyle,
  cursor: "pointer",
  appearance: "auto" as React.CSSProperties["appearance"],
};

export default function TaintConfigDialog({
  seq,
  totalLines,
  defaultDefs,
  defaultMemAddr,
  onExecute,
  onClose,
}: Props) {
  const nextIdRef = useRef(1);
  const [mode, setMode] = useState<"simple" | "advanced">("simple");
  const [simpleRange, setSimpleRange] = useState<"full" | "recent">("full");
  const [simpleScope, setSimpleScope] = useState<"focused" | "broad">("focused");
  const [startSeq, setStartSeq] = useState("1");
  const [endSeq, setEndSeq] = useState(String(seq + 1));
  const [controlDep, setControlDep] = useState(true);
  const [configError, setConfigError] = useState<string | null>(null);
  const [controlTip, setControlTip] = useState<{ x: number; y: number } | null>(null);
  const controlTipTimer = useRef<ReturnType<typeof setTimeout> | null>(null);
  const [sources, setSources] = useState<TaintSource[]>(() =>
    createDefaultSources(nextIdRef, defaultDefs, defaultMemAddr)
  );

  const sourceSummaries = useMemo(() => sources.map((source) => {
    if (source.type === "register") {
      return `第 ${(seq + 1).toLocaleString()} 行的寄存器 ${source.register.toUpperCase()}`;
    }
    return `第 ${(seq + 1).toLocaleString()} 行的内存 ${formatMemoryRange(source.memAddr, source.memSize)}`;
  }), [seq, sources]);

  const addSource = useCallback(() => {
    setSources(prev => [
      ...prev,
      {
        id: nextIdRef.current++,
        type: "register",
        register: "x0",
        memAddr: "",
        memSize: "4",
      },
    ]);
  }, []);

  const removeSource = useCallback((id: number) => {
    setSources(prev => prev.length > 1 ? prev.filter(s => s.id !== id) : prev);
  }, []);

  const updateSource = useCallback((id: number, updates: Partial<TaintSource>) => {
    setSources(prev =>
      prev.map(s => (s.id === id ? { ...s, ...updates } : s))
    );
  }, []);

  const handleExecute = useCallback(() => {
    // sourceLineNum: 污点源所在行号（1-based），来自右键点击的行
    const sourceLineNum = seq + 1;

    const specs: string[] = [];
    for (const src of sources) {
      if (src.type === "register") {
        specs.push(`reg:${src.register}@${sourceLineNum}`);
      } else {
        const addr = src.memAddr.trim();
        if (!addr) {
          setConfigError("每个内存来源都必须填写地址。");
          return;
        }
        const sizeNum = Number.parseInt(src.memSize, 10);
        if (!Number.isInteger(sizeNum) || sizeNum < 1 || sizeNum > 4096) {
          setConfigError("内存大小必须是 1–4096 字节的整数。");
          return;
        }
        specs.push(`mem:${addr}:${sizeNum}@${sourceLineNum}`);
      }
    }

    if (specs.length === 0) {
      setConfigError("请至少添加一个分析目标。");
      return;
    }

    let validStartSeq: number | undefined;
    let validEndSeq: number | undefined;
    let dataOnly: boolean;
    if (mode === "simple") {
      const startLine = simpleRange === "recent" ? Math.max(1, sourceLineNum - 99_999) : 1;
      validStartSeq = startLine - 1;
      validEndSeq = seq;
      dataOnly = simpleScope === "focused";
    } else {
      const parsedStartSeq = startSeq.trim() ? Number.parseInt(startSeq.trim(), 10) : undefined;
      const parsedEndSeq = endSeq.trim() ? Number.parseInt(endSeq.trim(), 10) : undefined;
      if (parsedStartSeq !== undefined && (!Number.isInteger(parsedStartSeq) || parsedStartSeq < 1 || parsedStartSeq > totalLines)) {
        setConfigError(`起始行必须在 1–${totalLines.toLocaleString()} 之间。`);
        return;
      }
      if (parsedEndSeq !== undefined && (!Number.isInteger(parsedEndSeq) || parsedEndSeq < 1 || parsedEndSeq > totalLines)) {
        setConfigError(`结束行必须在 1–${totalLines.toLocaleString()} 之间。`);
        return;
      }
      if (parsedStartSeq !== undefined && parsedEndSeq !== undefined && parsedStartSeq > parsedEndSeq) {
        setConfigError("起始行不能晚于结束行。");
        return;
      }
      validStartSeq = parsedStartSeq !== undefined ? parsedStartSeq - 1 : undefined;
      validEndSeq = parsedEndSeq !== undefined ? parsedEndSeq - 1 : undefined;
      dataOnly = !controlDep;
    }

    setConfigError(null);
    onExecute(specs, validStartSeq, validEndSeq, dataOnly);
  }, [seq, startSeq, endSeq, sources, controlDep, mode, simpleRange, simpleScope, totalLines, onExecute]);

  const handleKeyDown = useCallback((e: React.KeyboardEvent) => {
    if (e.key === "Escape") {
      onClose();
    } else if (e.key === "Enter" && (e.ctrlKey || e.metaKey)) {
      handleExecute();
    }
  }, [onClose, handleExecute]);

  return (
    <>
    <div
      style={{
        position: "fixed",
        top: 0, left: 0, right: 0, bottom: 0,
        background: "rgba(0,0,0,0.6)",
        display: "flex",
        alignItems: "center",
        justifyContent: "center",
        zIndex: 10000,
      }}
      onClick={(e) => { if (e.target === e.currentTarget) onClose(); }}
      onKeyDown={handleKeyDown}
    >
      <div
        style={{
          background: "var(--bg-dialog)",
          border: "1px solid var(--border-color)",
          borderRadius: 8,
          boxShadow: "0 12px 40px rgba(0,0,0,0.5)",
          padding: "22px 26px",
          width: Math.min(560, window.innerWidth - 40),
          maxHeight: "calc(100vh - 40px)",
          overflowY: "auto",
        }}
        onClick={(e) => e.stopPropagation()}
      >
        {/* ── Title + Close ── */}
        <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: 16 }}>
          <div style={{ fontSize: 16, fontWeight: 700, color: "var(--text-primary)" }}>
            向后污点分析
          </div>
          <button
            onClick={onClose}
            style={{
              background: "transparent", border: "none",
              color: "var(--text-secondary)", fontSize: 18,
              cursor: "pointer", padding: "0 2px", lineHeight: 1,
            }}
            onMouseEnter={(e) => { e.currentTarget.style.color = "var(--text-primary)"; }}
            onMouseLeave={(e) => { e.currentTarget.style.color = "var(--text-secondary)"; }}
          >
            ×
          </button>
        </div>

        <div style={{ display: "flex", marginBottom: 18, border: "1px solid var(--border-color)", borderRadius: 4, overflow: "hidden" }}>
          {(["simple", "advanced"] as const).map((item) => (
            <button
              key={item}
              type="button"
              onClick={() => { setMode(item); setConfigError(null); }}
              style={{
                flex: 1, height: 30, border: "none",
                borderRight: item === "simple" ? "1px solid var(--border-color)" : "none",
                background: mode === item ? "var(--bg-selected)" : "var(--bg-input)",
                color: mode === item ? "var(--text-primary)" : "var(--text-secondary)",
                cursor: "pointer", fontSize: 12, fontFamily: "inherit", textTransform: "capitalize",
              }}
            >
              {item === "simple" ? "快速模式" : "高级模式"}
            </button>
          ))}
        </div>

        {mode === "simple" ? (
          <>
            <div style={{ ...cardStyle, marginBottom: 12 }}>
              <label style={labelStyle}>分析目标</label>
              <div style={{ display: "flex", flexDirection: "column", gap: 5, color: "var(--text-primary)", fontSize: 13 }}>
                {sourceSummaries.map((summary, index) => <div key={`${summary}-${index}`}>{summary}</div>)}
              </div>
              <button
                type="button"
                onClick={() => setMode("advanced")}
                style={{ marginTop: 8, padding: 0, border: "none", background: "transparent", color: "var(--text-address)", cursor: "pointer", fontSize: 11, fontFamily: "inherit" }}
              >
                编辑目标
              </button>
            </div>

            <div style={{ ...cardStyle, marginBottom: 12 }}>
              <label style={labelStyle}>历史范围</label>
              <select
                value={simpleRange}
                onChange={(event) => setSimpleRange(event.target.value as "full" | "recent")}
                style={{ ...fieldSelectStyle, fontSize: 13 }}
              >
                <option value="full">从 trace 开始到第 {(seq + 1).toLocaleString()} 行</option>
                <option value="recent">最近 {Math.min(100_000, seq + 1).toLocaleString()} 行</option>
              </select>
            </div>

            <div style={{ ...cardStyle, marginBottom: 22 }}>
              <label style={labelStyle}>结果范围</label>
              <div style={{ display: "flex", border: "1px solid var(--border-color)", borderRadius: 4, overflow: "hidden" }}>
                {(["focused", "broad"] as const).map((scope) => (
                  <button
                    key={scope}
                    type="button"
                    onClick={() => setSimpleScope(scope)}
                    style={{
                      flex: 1, height: 32, border: "none",
                      borderRight: scope === "focused" ? "1px solid var(--border-color)" : "none",
                      background: simpleScope === scope ? "var(--bg-selected)" : "transparent",
                      color: simpleScope === scope ? "var(--text-primary)" : "var(--text-secondary)",
                      cursor: "pointer", fontFamily: "inherit", fontSize: 12, textTransform: "capitalize",
                    }}
                    title={scope === "focused" ? "仅跟随数据依赖" : "同时包含分支和控制流影响"}
                  >
                    {scope === "focused" ? "聚焦" : "广泛"}
                  </button>
                ))}
              </div>
            </div>
          </>
        ) : (
        <>
        {/* ── Start Seq / End Seq ── */}
        <div style={{ display: "flex", gap: 12, marginBottom: 24 }}>
          <div style={{ ...cardStyle, flex: 1 }}>
            <label style={labelStyle}>起始行</label>
            <input
              type="text"
              value={startSeq}
              onChange={(e) => setStartSeq(e.target.value)}
              style={fieldInputStyle}
            />
          </div>
          <div style={{ ...cardStyle, flex: 1 }}>
            <label style={labelStyle}>结束行</label>
            <input
              type="text"
              value={endSeq}
              onChange={(e) => setEndSeq(e.target.value)}
              placeholder="留空表示到末尾"
              style={fieldInputStyle}
            />
          </div>
        </div>

        {/* ── Dependency Options ── */}
        <div style={{ ...cardStyle, marginBottom: 24, display: "flex", alignItems: "center", gap: 16 }}>
          <div style={{ fontSize: 14, fontWeight: 600, color: "var(--text-primary)", flexShrink: 0 }}>
            依赖范围
          </div>
          <label
            style={{ display: "flex", alignItems: "center", gap: 6, cursor: "pointer", fontSize: 13, color: "var(--text-primary)" }}
            onMouseEnter={(e) => {
              const mx = e.clientX, my = e.clientY;
              controlTipTimer.current = setTimeout(() => setControlTip({ x: mx, y: my + 16 }), 100);
            }}
            onMouseLeave={() => {
              if (controlTipTimer.current) { clearTimeout(controlTipTimer.current); controlTipTimer.current = null; }
              setControlTip(null);
            }}
          >
            <input
              type="checkbox"
              checked={controlDep}
              onChange={(e) => setControlDep(e.target.checked)}
              style={{ accentColor: "var(--btn-primary)" }}
            />
            包含控制流
          </label>
        </div>

        {/* ── Taint Sources Header ── */}
        <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: 12 }}>
          <div style={{ fontSize: 14, fontWeight: 600, color: "var(--text-primary)" }}>
            分析来源
          </div>
          <button
            onClick={addSource}
            onMouseEnter={(e) => { e.currentTarget.style.background = "var(--bg-secondary)"; }}
            onMouseLeave={(e) => { e.currentTarget.style.background = "transparent"; }}
            style={{
              background: "transparent",
              border: "1px solid var(--border-color)",
              borderRadius: 6,
              color: "var(--text-primary)",
              padding: "5px 14px",
              fontSize: 12,
              cursor: "pointer",
            }}
          >
            + 添加来源
          </button>
        </div>

        {/* ── Sources List ── */}
        <div style={{ display: "flex", flexDirection: "column", gap: 10, marginBottom: 28 }}>
          {sources.map((src) => (
            <div key={src.id} style={{ ...cardStyle, display: "flex", alignItems: "flex-end", gap: 12 }}>
              {/* Type */}
              <div style={{ width: 110, flexShrink: 0 }}>
                <label style={labelStyle}>类型</label>
                <select
                  value={src.type}
                  onChange={(e) => updateSource(src.id, { type: e.target.value as "register" | "memory" })}
                  style={{ ...fieldSelectStyle, fontSize: 14 }}
                >
                  <option value="register">寄存器</option>
                  <option value="memory">内存</option>
                </select>
              </div>

              {/* Value field */}
              {src.type === "register" ? (
                <div style={{ flex: 1 }}>
                  <label style={labelStyle}>寄存器</label>
                  <select
                    value={src.register}
                    onChange={(e) => updateSource(src.id, { register: e.target.value })}
                    style={{ ...fieldSelectStyle, fontSize: 14, textTransform: "uppercase" }}
                  >
                    {REGISTERS.map((r) => (
                      <option key={r} value={r}>{r.toUpperCase()}</option>
                    ))}
                  </select>
                </div>
              ) : (
                <>
                  <div style={{ flex: 1 }}>
                    <label style={labelStyle}>地址</label>
                    <input
                      type="text"
                      value={src.memAddr}
                      onChange={(e) => updateSource(src.id, { memAddr: e.target.value })}
                      placeholder="0x..."
                      style={{ ...fieldInputStyle, fontSize: 14 }}
                    />
                    <div style={{ marginTop: 4, color: "var(--text-secondary)", fontSize: 10, whiteSpace: "nowrap" }}>
                      {formatMemoryRange(src.memAddr, src.memSize)}
                    </div>
                  </div>
                  <div style={{ width: 76, flexShrink: 0 }}>
                    <label style={labelStyle}>字节数</label>
                    <input
                      type="number"
                      min={1}
                      max={4096}
                      list="taint-memory-sizes"
                      value={src.memSize}
                      onChange={(e) => updateSource(src.id, { memSize: e.target.value })}
                      style={{ ...fieldInputStyle, fontSize: 14 }}
                    />
                  </div>
                </>
              )}

              {/* Delete */}
              <button
                onClick={() => removeSource(src.id)}
                style={{
                  background: "transparent",
                  border: "none",
                  color: sources.length > 1 ? "var(--reg-changed)" : "var(--text-secondary)",
                  cursor: sources.length > 1 ? "pointer" : "default",
                  fontSize: 16,
                  padding: "0 2px",
                  lineHeight: 1,
                  flexShrink: 0,
                  opacity: sources.length > 1 ? 1 : 0.3,
                }}
                disabled={sources.length <= 1}
              >
                ×
              </button>
            </div>
          ))}
          <datalist id="taint-memory-sizes">
            {MEM_SIZES.map((size) => <option key={size} value={size} />)}
          </datalist>
        </div>
        </>
        )}

        {configError && (
          <div style={{ marginBottom: 12, color: "var(--reg-changed)", fontSize: 11, lineHeight: 1.5 }}>
            {configError}
          </div>
        )}

        {/* ── Buttons ── */}
        <div style={{ display: "flex", justifyContent: "center", gap: 10 }}>
          <button
            onClick={onClose}
            onMouseEnter={(e) => { e.currentTarget.style.background = "var(--bg-secondary)"; }}
            onMouseLeave={(e) => { e.currentTarget.style.background = "var(--bg-input)"; }}
            style={{
              padding: "6px 16px",
              background: "var(--bg-input)",
              color: "var(--text-primary)",
              border: "1px solid var(--border-color)",
              borderRadius: 4,
              cursor: "pointer",
              fontSize: 13,
            }}
          >
            取消
          </button>
          <button
            onClick={handleExecute}
            onMouseEnter={(e) => { e.currentTarget.style.opacity = "0.85"; }}
            onMouseLeave={(e) => { e.currentTarget.style.opacity = "1"; }}
            style={{
              padding: "6px 16px",
              background: "var(--btn-primary)",
              color: "#fff",
              border: "none",
              borderRadius: 4,
              cursor: "pointer",
              fontSize: 13,
              fontWeight: 600,
            }}
          >
            执行分析
          </button>
        </div>
      </div>
    </div>
    {controlTip && createPortal(
      <div style={{
        position: "fixed", left: controlTip.x, top: controlTip.y,
        background: "var(--bg-dialog)", color: "var(--text-primary)",
        border: "1px solid var(--border-color)", borderRadius: 4,
        padding: "4px 8px", fontSize: 11, maxWidth: 320, lineHeight: 1.5,
        pointerEvents: "none", zIndex: 10002,
        boxShadow: "0 2px 8px rgba(0,0,0,0.3)",
      }}>
        打开后，污点会沿控制流依赖传播（例如条件分支），而不只是数据流；污点指令数量可能增加。
      </div>,
      document.body,
    )}
    </>
  );
}
