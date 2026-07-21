import { useRef, useCallback, useEffect, useState } from "react";

const DEFAULT_OVERSCAN = 12;
const DEFAULT_WHEEL_SPEED = 3;

export interface UseVirtualScrollOptions {
  /** 总行数 */
  totalCount: number;
  /** 固定行高（px） */
  rowHeight: number;
  /** 上下额外渲染行数 */
  overscan?: number;
  /** 滚轮速度倍数 */
  wheelSpeed?: number;
}

export interface ScrollbarProps {
  currentRow: number;
  maxRow: number;
  visibleRows: number;
  virtualTotalRows: number;
  trackHeight: number;
  onScroll: (row: number) => void;
}

export interface UseVirtualScrollReturn {
  /** 当前滚动行（钳位后） */
  currentRow: number;
  /** 容器可见行数 */
  visibleRows: number;
  /** 最大可滚动行 */
  maxRow: number;
  /** 可见范围起始索引（含 overscan） */
  startIdx: number;
  /** 可见范围结束索引（含 overscan） */
  endIdx: number;
  /** 跳转到指定行 */
  scrollToRow: (row: number) => void;
  /** 绑定到容器 div 的 ref */
  containerRef: React.RefObject<HTMLDivElement | null>;
  /** 容器测量高度 */
  containerHeight: number;
  /** 容器测量宽度 */
  containerWidth: number;
  /** 容器 div 应使用的 style */
  containerStyle: React.CSSProperties;
  /** 计算指定索引行的 Y 坐标（相对于可视区域顶部） */
  getItemY: (index: number) => number;
  /** 直接传给 CustomScrollbar 的 props */
  scrollbarProps: ScrollbarProps;
}

export function useVirtualScroll({
  totalCount,
  rowHeight,
  overscan = DEFAULT_OVERSCAN,
  wheelSpeed = DEFAULT_WHEEL_SPEED,
}: UseVirtualScrollOptions): UseVirtualScrollReturn {
  const containerRef = useRef<HTMLDivElement>(null);
  const [containerEl, setContainerEl] = useState<HTMLDivElement | null>(null);
  const [currentRow, setCurrentRow] = useState(0);
  const [containerHeight, setContainerHeight] = useState(0);
  const [containerWidth, setContainerWidth] = useState(0);
  const scrollPosRef = useRef(0);
  const wheelTimerRef = useRef(0);

  const visibleRows = Math.max(1, Math.floor(containerHeight / rowHeight));
  const maxRow = Math.max(0, totalCount - visibleRows);

  // currentRow 钳位
  const clampedRow = Math.max(0, Math.min(currentRow, maxRow));
  useEffect(() => {
    if (currentRow > maxRow && maxRow >= 0) {
      scrollPosRef.current = maxRow;
      setCurrentRow(maxRow);
    }
  }, [currentRow, maxRow]);

  // totalCount 变化时重置滚动位置
  useEffect(() => {
    scrollPosRef.current = 0;
    setCurrentRow(0);
  }, [totalCount]);

  // scrollTo helper
  const scrollToRow = useCallback((row: number) => {
    const clamped = Math.max(0, Math.min(row, maxRow));
    scrollPosRef.current = clamped;
    setCurrentRow(clamped);
  }, [maxRow]);

  // wheel handler
  useEffect(() => {
    const el = containerRef.current;
    if (!el) return;
    const handler = (e: WheelEvent) => {
      e.preventDefault();
      scrollPosRef.current += (e.deltaY / rowHeight) * wheelSpeed;
      if (scrollPosRef.current < 0) scrollPosRef.current = 0;
      if (scrollPosRef.current > maxRow) scrollPosRef.current = maxRow;

      if (wheelTimerRef.current) clearTimeout(wheelTimerRef.current);
      wheelTimerRef.current = window.setTimeout(() => {
        const newRow = Math.floor(scrollPosRef.current);
        setCurrentRow(prev => prev !== newRow ? newRow : prev);
      }, 16);
    };
    el.addEventListener("wheel", handler, { passive: false });
    return () => {
      el.removeEventListener("wheel", handler);
      if (wheelTimerRef.current) clearTimeout(wheelTimerRef.current);
    };
  }, [maxRow, rowHeight, wheelSpeed]);

  // 通过 MutationObserver-like 轮询检测 containerRef 挂载，触发 ResizeObserver 重建
  useEffect(() => {
    const el = containerRef.current;
    if (el !== containerEl) setContainerEl(el);
  });

  // ResizeObserver — 依赖 containerEl 而非空数组，确保条件渲染延迟挂载时也能正确建立
  useEffect(() => {
    if (!containerEl) return;
    let timer = 0;
    const ro = new ResizeObserver((entries) => {
      clearTimeout(timer);
      const { height: h, width: w } = entries[0].contentRect;
      timer = window.setTimeout(() => {
        setContainerHeight(h);
        setContainerWidth(w);
      }, document.documentElement.dataset.separatorDrag ? 300 : 0);
    });
    ro.observe(containerEl);
    return () => { clearTimeout(timer); ro.disconnect(); };
  }, [containerEl]);

  // 可见范围
  const startIdx = Math.max(0, clampedRow - overscan);
  const endIdx = totalCount > 0 ? Math.min(totalCount - 1, clampedRow + visibleRows + overscan) : -1;

  // 计算行 Y 坐标
  const getItemY = useCallback((index: number): number => {
    return (index - clampedRow) * rowHeight;
  }, [clampedRow, rowHeight]);

  const containerStyle: React.CSSProperties = {
    overflow: "hidden",
    position: "relative",
  };

  const scrollbarProps: ScrollbarProps = {
    currentRow: clampedRow,
    maxRow,
    visibleRows,
    virtualTotalRows: totalCount,
    trackHeight: containerHeight,
    onScroll: scrollToRow,
  };

  return {
    currentRow: clampedRow,
    visibleRows,
    maxRow,
    startIdx,
    endIdx,
    scrollToRow,
    containerRef,
    containerHeight,
    containerWidth,
    containerStyle,
    getItemY,
    scrollbarProps,
  };
}
