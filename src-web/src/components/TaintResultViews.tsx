import { useCallback, useEffect, useMemo, useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import type { DependencyGraph, NodeInfo, SliceResult, StringRecordDto, StringsResult } from "../types/trace";

type ViewMode = "summary" | "steps" | "all";

interface Props {
  sessionId: string;
  sources: string[];
  sliceInfo: SliceResult;
  onJumpToSeq: (seq: number) => void;
}

interface KeyStep {
  seq: number;
  endSeq: number;
  operation: string;
  expression: string;
  transportCount: number;
}

const TRANSPORT_OPS = /^(mov|mvn|fmov|ldr|ldur|ldp|str|stur|stp|load|store)/i;

function buildKeySteps(nodes: NodeInfo[]): KeyStep[] {
  const ordered = [...nodes].sort((a, b) => a.seq - b.seq);
  const steps: KeyStep[] = [];

  for (let index = 0; index < ordered.length;) {
    const node = ordered[index];
    if (!TRANSPORT_OPS.test(node.operation)) {
      steps.push({
        seq: node.seq,
        endSeq: node.seq,
        operation: node.operation || "unknown",
        expression: node.expression || node.asm,
        transportCount: 0,
      });
      index += 1;
      continue;
    }

    const chain = [node];
    let cursor = index + 1;
    while (
      cursor < ordered.length
      && TRANSPORT_OPS.test(ordered[cursor].operation)
      && ordered[cursor].seq <= chain[chain.length - 1].seq + 2
    ) {
      chain.push(ordered[cursor]);
      cursor += 1;
    }

    const first = chain[0];
    const last = chain[chain.length - 1];
    steps.push({
      seq: first.seq,
      endSeq: last.seq,
      operation: chain.length === 1 ? first.operation : "Data movement",
      expression: chain.length === 1
        ? (first.expression || first.asm)
        : `${first.expression || first.asm}  ->  ${last.expression || last.asm}`,
      transportCount: chain.length,
    });
    index = cursor;
  }

  return steps;
}

function sourceLabel(source: string): string {
  if (source.startsWith("mem:")) return `Memory ${source.slice(4).split("@")[0]}`;
  if (source.startsWith("reg:")) return `Register ${source.slice(4).split("@")[0]}`;
  return source;
}

function parseAddress(value: string | null): bigint | null {
  if (!value || !/^0x[0-9a-f]+$/i.test(value)) return null;
  try { return BigInt(value); } catch { return null; }
}

function relatedStrings(nodes: NodeInfo[], strings: StringRecordDto[]): StringRecordDto[] {
  const addresses = nodes.map(node => parseAddress(node.memAddr)).filter((addr): addr is bigint => addr !== null);
  return strings.filter((record) => {
    const start = parseAddress(record.addr);
    if (start === null) return false;
    const end = start + BigInt(record.byte_len);
    return addresses.some(address => address >= start && address < end);
  }).slice(0, 8);
}

export default function TaintResultViews({ sessionId, sources, sliceInfo, onJumpToSeq }: Props) {
  const [mode, setMode] = useState<ViewMode>("summary");
  const [graph, setGraph] = useState<DependencyGraph | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [strings, setStrings] = useState<StringRecordDto[]>([]);

  const loadGraph = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const result = await invoke<DependencyGraph>("build_dependency_tree_from_slice", {
        sessionId,
        maxNodes: 1000,
        dataOnly: true,
      });
      setGraph(result);
      try {
        const stringResult = await invoke<StringsResult>("get_strings", {
          sessionId, minLen: 4, offset: 0, limit: 5000, search: null,
        });
        setStrings(relatedStrings(result.nodes, stringResult.strings));
      } catch {
        setStrings([]);
      }
    } catch (reason) {
      setError(String(reason));
    } finally {
      setLoading(false);
    }
  }, [sessionId]);

  useEffect(() => {
    setMode("summary");
    setGraph(null);
    loadGraph();
  }, [loadGraph, sliceInfo.markedCount]);

  const keySteps = useMemo(() => buildKeySteps(graph?.nodes ?? []), [graph]);
  const operationSummary = useMemo(() => {
    const counts = new Map<string, number>();
    for (const node of graph?.nodes ?? []) {
      const operation = node.operation || "unknown";
      counts.set(operation, (counts.get(operation) ?? 0) + 1);
    }
    return [...counts.entries()].sort((a, b) => b[1] - a[1]).slice(0, 6);
  }, [graph]);
  const summary = useMemo(() => {
    const nodes = graph?.nodes ?? [];
    const unique = (values: Array<string | null>) => [...new Set(values.filter((value): value is string => !!value))];
    return {
      functions: unique(nodes.map(node => node.functionName)).slice(0, 8),
      modules: unique(nodes.map(node => node.module)).slice(0, 6),
      reads: unique(nodes.filter(node => node.memRw?.includes("R")).map(node => node.memAddr)).slice(0, 8),
      writes: unique(nodes.filter(node => node.memRw?.includes("W")).map(node => node.memAddr)).slice(0, 8),
    };
  }, [graph]);

  const tabButton = (key: ViewMode, label: string) => (
    <button
      type="button"
      onClick={() => setMode(key)}
      style={{
        padding: "4px 10px",
        border: "none",
        borderRight: key === "all" ? "none" : "1px solid var(--border-color)",
        background: mode === key ? "var(--btn-primary)" : "var(--bg-secondary)",
        color: mode === key ? "var(--btn-primary-text, #fff)" : "var(--text-secondary)",
        cursor: "pointer",
        fontSize: 11,
      }}
    >
      {label}
    </button>
  );

  return (
    <div style={{ width: "100%", minHeight: 0, display: "flex", flexDirection: "column", gap: 10 }}>
      <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", gap: 12 }}>
        <div style={{ display: "inline-flex", border: "1px solid var(--border-color)", borderRadius: 4, overflow: "hidden" }}>
          {tabButton("summary", "Summary")}
          {tabButton("steps", "Key Steps")}
          {tabButton("all", "All Instructions")}
        </div>
        <button
          type="button"
          onClick={loadGraph}
          disabled={loading}
          style={{
            padding: "4px 9px", border: "1px solid var(--border-color)", borderRadius: 4,
            background: "var(--bg-secondary)", color: "var(--text-secondary)", cursor: loading ? "default" : "pointer",
            fontSize: 11,
          }}
        >
          {loading ? "Loading" : "Reload"}
        </button>
      </div>

      {error ? (
        <div style={{ color: "var(--text-error)", lineHeight: 1.5 }}>{error}</div>
      ) : mode === "summary" ? (
        <div style={{ display: "grid", gridTemplateColumns: "minmax(160px, 1fr) minmax(160px, 1fr)", gap: "8px 24px" }}>
          <div><span style={{ color: "var(--text-secondary)" }}>来源：</span><span style={{ color: "var(--text-primary)" }}>{sources.map(sourceLabel).join(", ")}</span></div>
          <div><span style={{ color: "var(--text-secondary)" }}>匹配：</span><span style={{ color: "var(--text-primary)" }}>{sliceInfo.markedCount.toLocaleString()} 条指令</span></div>
          <div><span style={{ color: "var(--text-secondary)" }}>依赖节点：</span><span style={{ color: "var(--text-primary)" }}>{graph ? graph.totalReachable.toLocaleString() : "-"}</span></div>
          <div><span style={{ color: "var(--text-secondary)" }}>输入：</span><span style={{ color: "var(--text-primary)" }}>{graph ? graph.nodes.filter(node => node.isLeaf).length.toLocaleString() : "-"} 个叶值</span></div>
          <div><span style={{ color: "var(--text-secondary)" }}>根节点：</span><button type="button" onClick={() => graph && onJumpToSeq(graph.rootSeq)} style={{ padding: 0, border: "none", background: "transparent", color: "var(--accent, #61afef)", cursor: graph ? "pointer" : "default" }}>{graph ? `#${graph.rootSeq + 1}` : "-"}</button></div>
          <div><span style={{ color: "var(--text-secondary)" }}>操作：</span><span style={{ color: "var(--text-primary)" }}>{operationSummary.map(([name, count]) => `${name} ${count}`).join(" · ") || "-"}</span></div>
          <div style={{ gridColumn: "1 / -1" }}><span style={{ color: "var(--text-secondary)" }}>函数：</span><span style={{ color: "var(--text-primary)" }}>{summary.functions.join(", ") || "-"}</span></div>
          <div style={{ gridColumn: "1 / -1" }}><span style={{ color: "var(--text-secondary)" }}>模块：</span><span style={{ color: "var(--text-primary)" }}>{summary.modules.join(", ") || "-"}</span></div>
          <div style={{ gridColumn: "1 / -1" }}><span style={{ color: "var(--text-secondary)" }}>内存输入：</span><span style={{ color: "var(--text-primary)", fontFamily: "monospace" }}>{summary.reads.join(", ") || "-"}</span></div>
          <div style={{ gridColumn: "1 / -1" }}><span style={{ color: "var(--text-secondary)" }}>内存输出：</span><span style={{ color: "var(--text-primary)", fontFamily: "monospace" }}>{summary.writes.join(", ") || "-"}</span></div>
          <div style={{ gridColumn: "1 / -1" }}><span style={{ color: "var(--text-secondary)" }}>关键字符串：</span><span style={{ color: "var(--syntax-string)" }}>{strings.map(record => `"${record.content}"`).join(", ") || "-"}</span></div>
          {graph?.truncated && <div style={{ gridColumn: "1 / -1", color: "var(--text-changes)" }}>依赖预览最多显示 1,000 个节点。</div>}
        </div>
      ) : mode === "steps" ? (
        <div style={{ overflow: "auto", minHeight: 0 }}>
          {keySteps.map((step) => (
            <button
              type="button"
              key={`${step.seq}-${step.endSeq}`}
              onClick={() => onJumpToSeq(step.seq)}
              style={{
                width: "100%", display: "grid", gridTemplateColumns: "90px minmax(110px, 150px) 1fr",
                gap: 10, padding: "6px 4px", border: "none", borderBottom: "1px solid var(--border-color)",
                background: "transparent", color: "var(--text-primary)", cursor: "pointer", textAlign: "left", fontSize: 11,
              }}
            >
              <span style={{ color: "var(--accent, #61afef)" }}>{step.seq === step.endSeq ? `#${step.seq + 1}` : `#${step.seq + 1}-${step.endSeq + 1}`}</span>
              <span>{step.operation}{step.transportCount > 1 ? ` (${step.transportCount})` : ""}</span>
              <span style={{ overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap", fontFamily: "monospace" }}>{step.expression}</span>
            </button>
          ))}
        </div>
      ) : (
        <div style={{ overflow: "auto", minHeight: 0 }}>
          {[...(graph?.nodes ?? [])].sort((a, b) => a.seq - b.seq).map((node) => (
            <button
              type="button"
              key={node.seq}
              onClick={() => onJumpToSeq(node.seq)}
              style={{
                width: "100%", display: "grid", gridTemplateColumns: "70px 90px minmax(100px, 160px) 1fr", gap: 10,
                padding: "5px 4px", border: "none", borderBottom: "1px solid var(--border-color)",
                background: "transparent", color: "var(--text-primary)", cursor: "pointer", textAlign: "left", fontSize: 11,
              }}
            >
              <span style={{ color: "var(--accent, #61afef)" }}>#{node.seq + 1}</span>
              <span style={{ color: "var(--text-secondary)" }}>{node.operation}</span>
              <span style={{ color: "var(--text-secondary)", overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{node.functionName || node.module || node.address}</span>
              <span style={{ overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap", fontFamily: "monospace" }}>{node.expression || node.asm}</span>
            </button>
          ))}
        </div>
      )}
    </div>
  );
}
