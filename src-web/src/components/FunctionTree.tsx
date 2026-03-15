import { useState, useMemo, useCallback, useRef } from "react";
import { useVirtualizerNoSync } from "../hooks/useVirtualizerNoSync";
import type { CallTreeNodeDto } from "../types/trace";

interface FlatRow {
  id: number;
  func_addr: string;
  entry_seq: number;
  line_count: number;
  depth: number;
  hasChildren: boolean;
  isExpanded: boolean;
  isChildrenLoaded: boolean;
}

interface Props {
  isPhase2Ready: boolean;
  onJumpToSeq: (seq: number) => void;
  nodeMap: Map<number, CallTreeNodeDto>;
  nodeCount: number;
  loading: boolean;
  error: string | null;
  lazyMode?: boolean;
  loadedNodes?: Set<number>;
  onLoadChildren?: (nodeId: number) => Promise<void>;
}

function formatLineCount(count: number): string {
  if (count >= 1_000_000) return `${(count / 1_000_000).toFixed(1)}M`;
  if (count >= 1_000) return `${(count / 1_000).toFixed(1)}K`;
  return String(count);
}

export default function FunctionTree({
  isPhase2Ready, onJumpToSeq, nodeMap, nodeCount, loading, error,
  lazyMode = false, loadedNodes, onLoadChildren,
}: Props) {
  const [expanded, setExpanded] = useState<Set<number>>(new Set([0]));
  const [selectedId, setSelectedId] = useState<number | null>(null);
  const [loadingNodes, setLoadingNodes] = useState<Set<number>>(new Set());
  const parentRef = useRef<HTMLDivElement>(null);

  const rows = useMemo(() => {
    if (nodeMap.size === 0) return [];
    const result: FlatRow[] = [];
    function walk(id: number, depth: number) {
      const dto = nodeMap.get(id);
      if (!dto) return;
      const hasChildren = dto.children_ids.length > 0;
      const isExp = expanded.has(id);
      const isChildrenLoaded = !lazyMode || (loadedNodes?.has(id) ?? false);
      result.push({
        id: dto.id, func_addr: dto.func_addr, entry_seq: dto.entry_seq,
        line_count: dto.exit_seq - dto.entry_seq + 1,
        depth, hasChildren, isExpanded: isExp, isChildrenLoaded,
      });
      if (hasChildren && isExp && isChildrenLoaded) {
        for (const cid of dto.children_ids) walk(cid, depth + 1);
      }
    }
    walk(0, 0);
    return result;
  }, [nodeMap, expanded, lazyMode, loadedNodes]);

  const virtualizer = useVirtualizerNoSync({
    count: rows.length,
    getScrollElement: () => parentRef.current,
    estimateSize: () => 22,
    overscan: 20,
  });

  const toggleExpand = useCallback(async (id: number) => {
    if (expanded.has(id)) {
      setExpanded((prev) => {
        const next = new Set(prev);
        next.delete(id);
        return next;
      });
    } else {
      // 懒加载模式：展开前先加载子节点
      if (lazyMode && onLoadChildren && !(loadedNodes?.has(id))) {
        setLoadingNodes(prev => { const n = new Set(prev); n.add(id); return n; });
        try {
          await onLoadChildren(id);
        } finally {
          setLoadingNodes(prev => { const n = new Set(prev); n.delete(id); return n; });
        }
      }
      setExpanded((prev) => {
        const next = new Set(prev);
        next.add(id);
        return next;
      });
    }
  }, [expanded, lazyMode, onLoadChildren, loadedNodes]);

  const handleClick = useCallback((row: FlatRow) => {
    setSelectedId(row.id);
    if (row.hasChildren) toggleExpand(row.id);
  }, [toggleExpand]);

  const handleDoubleClick = useCallback((row: FlatRow) => {
    onJumpToSeq(row.entry_seq);
  }, [onJumpToSeq]);

  if (!isPhase2Ready) {
    return (
      <div style={{ height: "100%", display: "flex", alignItems: "center", justifyContent: "center", background: "var(--bg-primary)" }}>
        <div style={{ color: "var(--text-secondary)", fontSize: 12 }}></div>
      </div>
    );
  }
  if (loading) {
    return (
      <div style={{ height: "100%", display: "flex", alignItems: "center", justifyContent: "center", background: "var(--bg-primary)" }}>
        <div style={{ color: "var(--text-secondary)", fontSize: 12 }}>Loading function call tree...</div>
      </div>
    );
  }
  if (error) {
    return (
      <div style={{ height: "100%", display: "flex", alignItems: "center", justifyContent: "center", background: "var(--bg-primary)" }}>
        <div style={{ color: "var(--reg-changed)", fontSize: 12 }}>Failed to load: {error}</div>
      </div>
    );
  }

  const virtualItems = virtualizer.getVirtualItems();

  return (
    <div style={{ height: "100%", display: "flex", flexDirection: "column", background: "var(--bg-primary)" }}>
      <div style={{
        color: "var(--text-secondary)", fontSize: 11,
        padding: "6px 8px 4px", borderBottom: "1px solid var(--border-color)", flexShrink: 0,
      }}>
        Functions ({nodeCount.toLocaleString()})
      </div>
      <div ref={parentRef} style={{ flex: 1, overflow: "auto" }}>
        <div style={{ height: virtualizer.getTotalSize(), width: "100%", position: "relative" }}>
          {virtualItems.map((virtualRow) => {
            const row = rows[virtualRow.index];
            if (!row) return null;
            const isNodeLoading = loadingNodes.has(row.id);
            return (
              <div
                key={row.id}
                onClick={() => handleClick(row)}
                onDoubleClick={() => handleDoubleClick(row)}
                style={{
                  position: "absolute", top: 0, left: 0, width: "100%", height: 22,
                  transform: `translateY(${virtualRow.start}px)`,
                  paddingLeft: row.depth * 16 + 4, paddingRight: 8,
                  cursor: "pointer", fontSize: 12, lineHeight: "22px",
                  whiteSpace: "nowrap",
                  background: selectedId === row.id ? "var(--bg-selected)" : "transparent",
                  display: "flex", alignItems: "center", gap: 4,
                }}
                onMouseEnter={(e) => { if (selectedId !== row.id) e.currentTarget.style.background = "var(--bg-row-odd)"; }}
                onMouseLeave={(e) => { if (selectedId !== row.id) e.currentTarget.style.background = "transparent"; }}
              >
                <span style={{ width: 12, textAlign: "center", color: "var(--text-secondary)", fontSize: 10, flexShrink: 0 }}>
                  {row.hasChildren
                    ? (isNodeLoading ? "\u23F3" : (row.isExpanded && row.isChildrenLoaded ? "\u25BC" : "\u25B6"))
                    : ""}
                </span>
                <span style={{ color: "var(--text-address)", flexShrink: 0 }}>{row.func_addr}</span>
                <span style={{ color: "var(--text-secondary)", fontSize: 11, marginLeft: "auto", flexShrink: 0 }}>
                  {formatLineCount(row.line_count)}
                </span>
              </div>
            );
          })}
        </div>
      </div>
    </div>
  );
}
