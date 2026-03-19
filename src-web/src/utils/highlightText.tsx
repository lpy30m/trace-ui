import React from "react";

const MARK_STYLE: React.CSSProperties = {
  background: "transparent",
  color: "rgba(255,210,0,1)",
  borderRadius: 0,
  padding: 0,
};

/**
 * 将匹配片段中的非空格字符用 <mark> 高亮，空格保持原样。
 */
function highlightNonSpaces(matched: string, keyStart: number): React.ReactNode[] {
  const result: React.ReactNode[] = [];
  let k = keyStart;
  // 按空格/非空格交替拆分
  const segments = matched.split(/( +)/);
  for (const seg of segments) {
    if (!seg) continue;
    if (/^ +$/.test(seg)) {
      result.push(seg);
    } else {
      result.push(<mark key={k++} style={MARK_STYLE}>{seg}</mark>);
    }
  }
  return result;
}

/**
 * 将文本中匹配 query 的子串高亮（字体颜色变黄）。
 * 含空格的 query 作为整体匹配，但空格本身不高亮。
 * 支持普通文本和 /regex/ 模式。
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
    } else {
      // 普通文本匹配（含空格时作为整体匹配）
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
    // 高亮匹配部分，但跳过空格
    const highlighted = highlightNonSpaces(match[0], key);
    key += highlighted.filter(n => typeof n !== "string").length;
    parts.push(...highlighted);
    lastIndex = regex.lastIndex;
  }

  if (parts.length === 0) return text;
  if (lastIndex < text.length) {
    parts.push(text.slice(lastIndex));
  }
  return <>{parts}</>;
}
