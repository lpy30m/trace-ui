import React from "react";

const MARK_STYLE: React.CSSProperties = {
  background: "rgba(255,210,0,0.45)",
  color: "inherit",
  borderRadius: 2,
  padding: 0,
};

/**
 * 将文本中匹配 query 的子串用 <mark> 高亮包裹。
 * 支持普通文本、FuzzyText（空格分隔多关键词）和 /regex/ 模式。
 * 无匹配时返回原始字符串。
 */
export function highlightText(
  text: string,
  query: string,
  caseSensitive: boolean = false,
): React.ReactNode {
  if (!text || !query) return text;

  // 构建匹配正则
  let regex: RegExp;
  try {
    if (query.startsWith("/") && query.endsWith("/") && query.length > 2) {
      // /regex/ 模式
      const pattern = query.slice(1, -1);
      regex = new RegExp(pattern, caseSensitive ? "g" : "gi");
    } else if (!caseSensitive && query.includes(" ")) {
      // FuzzyText：空格分隔多关键词，每个独立高亮
      const tokens = query.split(/\s+/).filter(Boolean);
      if (tokens.length === 0) return text;
      const escaped = tokens.map(t => t.replace(/[.*+?^${}()|[\]\\]/g, "\\$&"));
      regex = new RegExp(`(${escaped.join("|")})`, "gi");
    } else {
      // 普通文本匹配
      const escaped = query.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
      regex = new RegExp(escaped, caseSensitive ? "g" : "gi");
    }
  } catch {
    // 无效正则，不高亮
    return text;
  }

  const parts: React.ReactNode[] = [];
  let lastIndex = 0;
  let match: RegExpExecArray | null;
  let key = 0;

  regex.lastIndex = 0;
  while ((match = regex.exec(text)) !== null) {
    if (match[0].length === 0) {
      regex.lastIndex++;
      continue;
    }
    if (match.index > lastIndex) {
      parts.push(text.slice(lastIndex, match.index));
    }
    parts.push(
      <mark key={key++} style={MARK_STYLE}>{match[0]}</mark>
    );
    lastIndex = regex.lastIndex;
  }

  if (parts.length === 0) return text;
  if (lastIndex < text.length) {
    parts.push(text.slice(lastIndex));
  }
  return <>{parts}</>;
}
