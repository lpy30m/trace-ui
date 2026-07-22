import React, { useState, useEffect, useRef } from "react";
import { invoke } from "@tauri-apps/api/core";
import { useSelectedSeq } from "../stores/selectedSeqStore";
import type { FunctionInspection, FunctionRef, MemTouch, RegValue } from "../types/trace";

interface Props {
  sessionId: string | null;
  onJumpToSeq: (seq: number) => void;
  active: boolean;
}

const chip: React.CSSProperties = {
  padding: "0 5px", borderRadius: 3, fontSize: 10,
  background: "var(--bg-secondary)", color: "var(--text-secondary)",
  border: "1px solid var(--border-color)",
  maxWidth: 240, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap",
};

function Row({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <div style={{ display: "flex", gap: 6, alignItems: "baseline", marginTop: 3 }}>
      <span style={{ width: 60, flexShrink: 0, color: "var(--text-tertiary)", fontSize: 10, textAlign: "right" }}>
        {label}
      </span>
      <div style={{ display: "flex", flexWrap: "wrap", gap: 3, minWidth: 0 }}>{children}</div>
    </div>
  );
}

function RegList({ regs }: { regs: RegValue[] }) {
  if (regs.length === 0) return <span style={{ color: "var(--text-tertiary)", fontSize: 10 }}>—</span>;
  return (
    <>
      {regs.map(r => (
        <span key={r.reg} style={chip} title={`${r.reg}=${r.value}`}>
          <span style={{ color: "var(--syntax-keyword)" }}>{r.reg}</span>={r.value}
        </span>
      ))}
    </>
  );
}

function FuncLink({ fn, onJump }: { fn: FunctionRef; onJump: (s: number) => void }) {
  return (
    <span
      onClick={() => onJump(fn.entrySeq)}
      style={{ ...chip, cursor: "pointer", color: "var(--syntax-literal)", textDecoration: "underline" }}
      title={`${fn.funcAddr} · entry seq ${fn.entrySeq + 1} · ${fn.lineCount} ln`}
    >{fn.funcName || fn.funcAddr}</span>
  );
}

function MemList({ title, items, truncated }: { title: string; items: MemTouch[]; truncated: boolean }) {
  if (items.length === 0) return null;
  return (
    <Row label={title}>
      {items.map((m, i) => (
        <span key={i} style={chip} title={`${m.count}× · width ${m.size}B`}>
          {m.addr}{m.count > 1 ? ` ×${m.count}` : ""}
        </span>
      ))}
      {truncated && <span style={{ color: "var(--text-changes)", fontSize: 10 }}>（扫描已限制）</span>}
    </Row>
  );
}

export default function FunctionInspectorPanel({ sessionId, onJumpToSeq, active }: Props) {
  const seq = useSelectedSeq();
  const [insp, setInsp] = useState<FunctionInspection | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const genRef = useRef(0);

  useEffect(() => {
    if (!active || !sessionId || seq == null) {
      genRef.current++;
      setLoading(false);
      if (!sessionId || seq == null) { setInsp(null); setError(null); }
      return;
    }
    const gen = ++genRef.current;
    setLoading(true);
    const t = setTimeout(() => {
      invoke<FunctionInspection>("inspect_function_at_seq", { sessionId, seq })
        .then(r => { if (gen === genRef.current) { setInsp(r); setError(null); } })
        .catch(e => { if (gen === genRef.current) { setError(String(e)); setInsp(null); } })
        .finally(() => { if (gen === genRef.current) setLoading(false); });
    }, 250);
    return () => clearTimeout(t);
  }, [sessionId, seq, active]);

  if (!sessionId) {
    return <div style={{ padding: 16, color: "var(--text-secondary)", fontSize: 12 }}>请先打开 trace。</div>;
  }
  if (seq == null) {
    return <div style={{ padding: 16, color: "var(--text-secondary)", fontSize: 12 }}>
      请选择一行 trace，这里会检查其所属函数。
    </div>;
  }

  return (
    <div style={{ flex: 1, overflow: "auto", padding: "8px 10px", fontSize: 12 }}>
      {error && <div style={{ color: "#e5484d", fontSize: 11 }}>{error}</div>}
      {loading && !insp && <div style={{ color: "var(--text-secondary)", fontSize: 11 }}>检查中…</div>}
      {insp && (
        <>
          <div style={{ display: "flex", alignItems: "baseline", gap: 6, flexWrap: "wrap" }}>
            <span
              onClick={() => onJumpToSeq(insp.entrySeq)}
              style={{ color: "var(--syntax-keyword)", fontWeight: 600, cursor: "pointer", textDecoration: "underline" }}
              title="跳转到函数入口"
            >{insp.funcName || insp.funcAddr}</span>
            <span style={{ color: "var(--text-tertiary)", fontSize: 10 }}>{insp.funcAddr}</span>
            {loading && <span style={{ color: "var(--text-tertiary)", fontSize: 10 }}>· 更新中…</span>}
          </div>
          <div style={{ color: "var(--text-tertiary)", fontSize: 10, marginTop: 2 }}>
            入口序号 {insp.entrySeq + 1} · 退出序号 {insp.exitSeq + 1} · {insp.lineCount.toLocaleString()} 行 · {insp.childCount} 个子调用
          </div>

          {insp.parent && (
            <Row label="父函数"><FuncLink fn={insp.parent} onJump={onJumpToSeq} /></Row>
          )}
          <Row label="入口参数 X0–X7"><RegList regs={insp.entryArgs} /></Row>
          {insp.returnValue && (
            <Row label="返回值 X0"><span style={chip}>{insp.returnValue}</span></Row>
          )}
          {insp.callAnnotation && (
            <Row label="调用">
              <span style={{ ...chip, color: "var(--syntax-comment)" }}>
                {insp.callAnnotation.funcName}
                {insp.callAnnotation.retValue ? ` → ${insp.callAnnotation.retValue}` : ""}
              </span>
            </Row>
          )}
          {insp.children.length > 0 && (
            <Row label="子调用">
              {insp.children.slice(0, 40).map(c => <FuncLink key={c.funcId} fn={c} onJump={onJumpToSeq} />)}
              {insp.children.length > 40 && (
                <span style={{ color: "var(--text-tertiary)", fontSize: 10 }}>另有 {insp.children.length - 40} 项</span>
              )}
            </Row>
          )}

          <MemList title="内存读取" items={insp.memoryReads} truncated={insp.ioTruncated} />
          <MemList title="内存写入" items={insp.memoryWrites} truncated={insp.ioTruncated} />
        </>
      )}
    </div>
  );
}
