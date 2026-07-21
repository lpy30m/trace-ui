import { useRef, useEffect, useCallback } from "react";
import { highlightHexdumpHTML } from "../utils/highlightText";

interface Props {
  text: string;
  query: string;
  caseSensitive: boolean;
  fuzzy: boolean;
  useRegex: boolean;
  isHex: boolean;
  lineHeight: number;
  maxVisibleLines: number;
  verticalPadding: number;
}

/**
 * 大文本高亮渲染组件（虚拟化）。
 *
 * 一次性预计算全部高亮 HTML（纯字符串，不创建 DOM），
 * 然后只将可见的 ~maxVisibleLines 行放入 DOM，
 * 滚动时通过 ref 直接替换 innerHTML，不触发 React 重渲染。
 */
export default function VirtualizedHighlight({
  text, query, caseSensitive, fuzzy, useRegex,
  isHex, lineHeight, maxVisibleLines, verticalPadding,
}: Props) {
  const containerRef = useRef<HTMLDivElement>(null);
  const contentRef = useRef<HTMLDivElement>(null);
  const htmlLinesRef = useRef<string[]>([]);
  const totalLinesRef = useRef(0);
  const firstMatchLineRef = useRef(-1);

  const renderVisible = useCallback((scrollTop: number) => {
    const content = contentRef.current;
    if (!content) return;

    const lines = htmlLinesRef.current;
    const total = totalLinesRef.current;
    if (total === 0) return;

    const visibleStart = Math.max(0, Math.floor(scrollTop / lineHeight));
    const visibleEnd = Math.min(total, visibleStart + maxVisibleLines + 2); // +2 overscan

    const beforeH = visibleStart * lineHeight;
    const afterH = Math.max(0, (total - visibleEnd) * lineHeight);
    const visibleHTML = lines.slice(visibleStart, visibleEnd).join("\n");

    content.innerHTML =
      `<div style="height:${beforeH}px"></div>` +
      `<div>${visibleHTML}</div>` +
      `<div style="height:${afterH}px"></div>`;
  }, [lineHeight, maxVisibleLines]);

  // 一次性预计算全部高亮 HTML 并按行拆分
  useEffect(() => {
    const fullHTML = highlightHexdumpHTML(text, query, caseSensitive, fuzzy, useRegex);
    const lines = fullHTML.split("\n");
    htmlLinesRef.current = lines;
    totalLinesRef.current = lines.length;

    // 找到第一个含 <mark 的行，用于自动滚动
    firstMatchLineRef.current = lines.findIndex(l => l.includes("<mark"));

    // 初始渲染
    renderVisible(0);

    // 自动滚动到第一个匹配行
    if (firstMatchLineRef.current >= 0 && containerRef.current) {
      const targetScroll = Math.max(0, (firstMatchLineRef.current - Math.floor(maxVisibleLines / 2)) * lineHeight);
      containerRef.current.scrollTop = targetScroll;
    }
  }, [text, query, caseSensitive, fuzzy, useRegex, lineHeight, maxVisibleLines, renderVisible]);

  // 滚动监听（ref-based，不触发 React 重渲染）
  useEffect(() => {
    const el = containerRef.current;
    if (!el) return;
    const onScroll = () => renderVisible(el.scrollTop);
    el.addEventListener("scroll", onScroll, { passive: true });
    return () => el.removeEventListener("scroll", onScroll);
  }, [renderVisible]);

  const containerHeight = maxVisibleLines * lineHeight + verticalPadding * 2;

  return (
    <div
      ref={containerRef}
      style={{
        border: "1px solid rgba(255,255,255,0.08)",
        background: "rgba(255,255,255,0.03)",
        borderRadius: 6,
        padding: `${verticalPadding}px 8px`,
        color: "var(--text-secondary)",
        fontFamily: "var(--font-mono)",
        fontSize: 11,
        lineHeight: `${lineHeight}px`,
        whiteSpace: isHex ? "pre" : "pre-wrap",
        wordBreak: isHex ? undefined : "break-all",
        overflowX: isHex ? "auto" : "hidden",
        overflowY: "auto",
        maxHeight: containerHeight,
        boxShadow: "inset 0 1px 0 rgba(255,255,255,0.03)",
      }}
    >
      <div ref={contentRef} />
    </div>
  );
}
