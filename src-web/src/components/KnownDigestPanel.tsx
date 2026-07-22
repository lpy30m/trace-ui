import React, { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import { emit, emitTo, listen } from "@tauri-apps/api/event";
import { WebviewWindow } from "@tauri-apps/api/webviewWindow";
import type {
  HashAlgorithm,
  HashMatchRequest,
  HashMatchResponse,
  HashMatchResult,
  HashMemoryMatchResponse,
  HashTransform,
  StringRecordDto,
  StringXRef,
} from "../types/trace";

interface Props {
  sessionId: string | null;
  hasStringIndex: boolean;
  onJumpToSeq: (seq: number) => void;
  onScanStrings?: () => Promise<void> | void;
  onTraceInput?: (match: HashMatchResult) => Promise<void> | void;
}

interface DigestPanelState {
  input: string;
  algorithm: "auto" | HashAlgorithm;
  advancedOpen: boolean;
  utf8Nul: boolean;
  utf16le: boolean;
  utf16leNul: boolean;
  searchMemory: boolean;
  response: HashMatchResponse | null;
  memoryResponse: HashMemoryMatchResponse | null;
  error: string | null;
  loading: boolean;
}

const sessionStates = new Map<string, DigestPanelState>();

function defaultState(): DigestPanelState {
  return {
    input: "",
    algorithm: "auto",
    advancedOpen: false,
    utf8Nul: false,
    utf16le: false,
    utf16leNul: false,
    searchMemory: false,
    response: null,
    memoryResponse: null,
    error: null,
    loading: false,
  };
}

const buttonStyle: React.CSSProperties = {
  height: 26,
  padding: "0 10px",
  border: "1px solid var(--border-color)",
  borderRadius: 4,
  background: "var(--bg-input)",
  color: "var(--text-primary)",
  cursor: "pointer",
  fontSize: 11,
  fontFamily: "inherit",
  whiteSpace: "nowrap",
};

const transformLabels: Record<HashTransform, string> = {
  utf8: "UTF-8 bytes",
  utf8Nul: "UTF-8 + NUL",
  utf16le: "UTF-16LE",
  utf16leNul: "UTF-16LE + NUL",
};

const algorithmLabels: Record<HashAlgorithm, string> = {
  crc32: "CRC32",
  md5: "MD5",
  sha1: "SHA-1",
  sha256: "SHA-256",
  sha384: "SHA-384",
  sha512: "SHA-512",
};

function makeStringRecord(match: HashMatchResult): StringRecordDto {
  return {
    idx: match.stringIndex,
    addr: match.addr,
    content: match.content,
    encoding: match.encoding,
    byte_len: match.byteLen,
    seq: match.seq,
    xref_count: match.xrefCount,
    rw: match.rw,
  };
}

export default function KnownDigestPanel({
  sessionId,
  hasStringIndex,
  onJumpToSeq,
  onScanStrings,
  onTraceInput,
}: Props) {
  const [state, setState] = useState<DigestPanelState>(() =>
    sessionId ? sessionStates.get(sessionId) ?? defaultState() : defaultState()
  );
  const currentSessionRef = useRef(sessionId);
  const mountedRef = useRef(true);

  useEffect(() => {
    return () => {
      mountedRef.current = false;
    };
  }, []);

  useEffect(() => {
    currentSessionRef.current = sessionId;
    setState(sessionId ? sessionStates.get(sessionId) ?? defaultState() : defaultState());
  }, [sessionId]);

  const update = useCallback((changes: Partial<DigestPanelState>) => {
    setState((previous) => {
      const next = { ...previous, ...changes };
      const activeSession = currentSessionRef.current;
      if (activeSession) sessionStates.set(activeSession, next);
      return next;
    });
  }, []);

  const digests = useMemo(
    () => state.input.split(/\r?\n/).map((line) => line.trim()).filter(Boolean),
    [state.input],
  );

  const runMatch = useCallback(async () => {
    if (!sessionId) {
      update({ error: "Open a trace before matching a digest." });
      return;
    }
    if (!hasStringIndex && !state.searchMemory) {
      update({ error: "String index is not ready. Run String Scan or enable Binary memory writes." });
      return;
    }
    if (digests.length === 0) {
      update({ error: "Enter at least one digest." });
      return;
    }

    const request: HashMatchRequest = {
      digests,
      algorithm: state.algorithm === "auto" ? null : state.algorithm,
      transforms: {
        utf8Nul: state.utf8Nul,
        utf16le: state.utf16le,
        utf16leNul: state.utf16leNul,
      },
      maxResults: 500,
    };
    const querySession = sessionId;
    const pending = { ...state, loading: true, error: null };
    sessionStates.set(querySession, pending);
    setState(pending);

    try {
      const [response, memoryResponse] = await Promise.all([
        hasStringIndex
          ? invoke<HashMatchResponse>("match_known_digests", { sessionId: querySession, request })
          : Promise.resolve(null),
        state.searchMemory
          ? invoke<HashMemoryMatchResponse>("find_digest_memory", { sessionId: querySession, request })
          : Promise.resolve(null),
      ]);
      const completed = { ...pending, response, memoryResponse, loading: false, error: null };
      sessionStates.set(querySession, completed);
      if (mountedRef.current && currentSessionRef.current === querySession) setState(completed);
    } catch (error) {
      const failed = { ...pending, loading: false, error: String(error) };
      sessionStates.set(querySession, failed);
      if (mountedRef.current && currentSessionRef.current === querySession) setState(failed);
    }
  }, [digests, hasStringIndex, sessionId, state, update]);

  const showXRefs = useCallback(async (match: HashMatchResult) => {
    if (!sessionId) return;
    try {
      const record = makeStringRecord(match);
      const items = await invoke<StringXRef[]>("get_string_xrefs", {
        sessionId,
        addr: match.addr,
        byteLen: match.byteLen,
      });
      const winLabel = `panel-string-xrefs-${Date.now()}`;
      const unlisten = await listen(`xrefs:ready:${winLabel}`, () => {
        emitTo(winLabel, "xrefs:init-data", { record, items });
        unlisten();
      });
      new WebviewWindow(winLabel, {
        url: "index.html?panel=string-xrefs",
        title: `XRefs: ${match.content.slice(0, 30)}`,
        width: 520,
        height: 400,
        decorations: false,
        transparent: true,
      });
    } catch (error) {
      update({ error: `Unable to load XRefs: ${String(error)}` });
    }
  }, [sessionId, update]);

  const queryResults = state.response?.queries ?? state.memoryResponse?.queries ?? [];
  const invalidQueries = queryResults.filter((query) => query.error);
  const validQueries = queryResults.filter((query) => !query.error);

  return (
    <div style={{ flex: 1, minWidth: 0, minHeight: 0, display: "flex", flexDirection: "column", overflow: "hidden" }}>
      <div style={{ padding: "8px", borderBottom: "1px solid var(--border-color)", flexShrink: 0 }}>
        <div style={{ display: "flex", gap: 8, alignItems: "stretch" }}>
          <textarea
            value={state.input}
            onChange={(event) => update({ input: event.target.value, response: null, memoryResponse: null, error: null })}
            onKeyDown={(event) => {
              if (event.key === "Enter" && (event.ctrlKey || event.metaKey)) {
                event.preventDefault();
                void runMatch();
              }
            }}
            placeholder={"每行一个摘要\n5d41402abc4b2a76b9719d911017c592"}
            spellCheck={false}
            style={{
              flex: 1, minWidth: 180, height: 68, resize: "vertical", padding: "6px 8px",
              background: "var(--bg-input)", color: "var(--text-primary)",
              border: "1px solid var(--border-color)", borderRadius: 4,
              outline: "none", fontSize: 12, lineHeight: 1.5, fontFamily: "var(--font-mono)",
            }}
          />
          <div style={{ width: 142, display: "flex", flexDirection: "column", gap: 6, flexShrink: 0 }}>
            <select
              value={state.algorithm}
              onChange={(event) => update({ algorithm: event.target.value as DigestPanelState["algorithm"], response: null, memoryResponse: null, error: null })}
              style={{
                height: 28, padding: "0 7px", background: "var(--bg-input)", color: "var(--text-primary)",
                border: "1px solid var(--border-color)", borderRadius: 4, fontSize: 11, fontFamily: "inherit",
              }}
            >
              <option value="auto">自动识别</option>
              <option value="crc32">CRC32</option>
              <option value="md5">MD5</option>
              <option value="sha1">SHA-1</option>
              <option value="sha256">SHA-256</option>
              <option value="sha384">SHA-384</option>
              <option value="sha512">SHA-512</option>
            </select>
            <button
              type="button"
              onClick={() => void runMatch()}
              disabled={state.loading || !sessionId}
              style={{
                ...buttonStyle, flex: 1, background: "var(--btn-primary)", color: "#fff", borderColor: "var(--btn-primary)",
                cursor: state.loading || !sessionId ? "default" : "pointer",
                opacity: state.loading || !sessionId ? 0.55 : 1,
              }}
            >
              {state.loading ? "匹配中…" : "匹配摘要"}
            </button>
          </div>
        </div>

        <button
          type="button"
          onClick={() => update({ advancedOpen: !state.advancedOpen })}
          style={{
            marginTop: 6, border: "none", background: "transparent", color: "var(--text-secondary)",
            cursor: "pointer", fontSize: 11, fontFamily: "inherit", padding: 0,
          }}
        >
          {state.advancedOpen ? "▾" : "▸"} Byte transforms
        </button>
        {state.advancedOpen && (
          <div style={{ marginTop: 6, display: "flex", flexWrap: "wrap", gap: "6px 16px", fontSize: 11 }}>
              <span style={{ color: "var(--text-primary)" }}>UTF-8 字节（始终启用）</span>
            {([
              ["utf8Nul", "UTF-8 + NUL"],
              ["utf16le", "UTF-16LE"],
              ["utf16leNul", "UTF-16LE + NUL"],
            ] as const).map(([key, label]) => (
              <label key={key} style={{ display: "flex", alignItems: "center", gap: 5, cursor: "pointer", color: "var(--text-primary)" }}>
                <input
                  type="checkbox"
                  checked={state[key]}
                  onChange={(event) => update({ [key]: event.target.checked, response: null, error: null })}
                  style={{ accentColor: "var(--btn-primary)" }}
                />
                {label}
              </label>
            ))}
            <label style={{ display: "flex", alignItems: "center", gap: 5, cursor: "pointer", color: "var(--text-primary)" }}>
              <input
                type="checkbox"
                checked={state.searchMemory}
                onChange={(event) => update({ searchMemory: event.target.checked, memoryResponse: null, error: null })}
                style={{ accentColor: "var(--btn-primary)" }}
              />
              Binary memory writes
            </label>
          </div>
        )}
      </div>

      {!hasStringIndex && sessionId && (
        <div style={{
          padding: "8px 10px", display: "flex", alignItems: "center", gap: 10,
          borderBottom: "1px solid var(--border-color)", color: "var(--text-changes)", fontSize: 11,
        }}>
          <span>{state.searchMemory ? "String results require String Scan; memory search is available." : "String index is required."}</span>
          {onScanStrings && (
            <button type="button" style={buttonStyle} onClick={() => void onScanStrings()}>
              Run String Scan
            </button>
          )}
        </div>
      )}

      {state.error && (
        <div style={{ padding: "7px 10px", color: "var(--reg-changed)", borderBottom: "1px solid var(--border-color)", fontSize: 11 }}>
          {state.error}
        </div>
      )}

      {state.response && (
        <div style={{
          padding: "5px 8px", display: "flex", gap: 14, flexWrap: "wrap",
          borderBottom: "1px solid var(--border-color)", background: "var(--bg-secondary)",
          color: "var(--text-secondary)", fontSize: 11, flexShrink: 0,
        }}>
          <span>{state.response.totalMatches.toLocaleString()} matches</span>
          <span>{state.response.candidateCount.toLocaleString()} strings checked</span>
          <span>{validQueries.length} valid digests</span>
          {invalidQueries.length > 0 && <span style={{ color: "var(--reg-changed)" }}>{invalidQueries.length} invalid</span>}
          {state.response.truncated && <span style={{ color: "var(--text-changes)" }}>仅显示前 500 条结果</span>}
        </div>
      )}

      {invalidQueries.length > 0 && (
        <details style={{ borderBottom: "1px solid var(--border-color)", padding: "5px 8px", fontSize: 11, flexShrink: 0 }}>
          <summary style={{ cursor: "pointer", color: "var(--reg-changed)" }}>无效的摘要输入</summary>
          <div style={{ marginTop: 5, display: "flex", flexDirection: "column", gap: 3 }}>
            {invalidQueries.map((query, index) => (
              <div key={`${query.input}-${index}`} style={{ display: "flex", gap: 8 }}>
                <code style={{ color: "var(--text-primary)", overflowWrap: "anywhere" }}>{query.input || "(empty)"}</code>
                <span style={{ color: "var(--reg-changed)" }}>{query.error}</span>
              </div>
            ))}
          </div>
        </details>
      )}

      {state.memoryResponse && (
        <div style={{ flexShrink: 0, maxHeight: "42%", overflow: "auto", borderBottom: "1px solid var(--border-color)" }}>
          <div style={{
            position: "sticky", top: 0, zIndex: 2, height: 27, display: "grid",
            gridTemplateColumns: "76px 112px 95px 74px 110px 1fr 250px", alignItems: "center",
            padding: "0 8px", background: "var(--bg-secondary)", color: "var(--text-secondary)", fontSize: 11,
          }}>
            <span>最后写入</span><span>地址</span><span>算法</span><span>长度</span><span>写入次数</span><span>摘要</span><span>操作</span>
          </div>
          {state.memoryResponse.matches.length === 0 ? (
            <div style={{ padding: "12px", color: "var(--text-secondary)", fontSize: 11, textAlign: "center" }}>
              扫描 {state.memoryResponse.writesScanned.toLocaleString()} 次写入后，未找到匹配的二进制内存缓冲区。
            </div>
          ) : state.memoryResponse.matches.map((match, index) => (
            <div key={`${match.queryIndex}-${match.addr}-${match.lastWriteSeq}-${index}`} style={{
              minHeight: 38, display: "grid", gridTemplateColumns: "76px 112px 95px 74px 110px 1fr 250px",
              alignItems: "center", padding: "4px 8px", fontSize: 11,
              background: index % 2 === 0 ? "var(--bg-row-even)" : "var(--bg-row-odd)",
              borderTop: "1px solid var(--border-color)",
            }}>
              <button type="button" onClick={() => onJumpToSeq(match.lastWriteSeq)} style={{ border: "none", padding: 0, background: "transparent", color: "var(--text-address)", cursor: "pointer", textAlign: "left" }}>
                {match.lastWriteSeq + 1}
              </button>
              <span style={{ color: "var(--text-address)" }}>{match.addr}</span>
              <span style={{ color: "var(--asm-mnemonic)" }}>{algorithmLabels[match.algorithm]}</span>
              <span>{match.byteLen} bytes</span>
              <span title={match.writeSeqs.map(seq => `#${seq + 1}`).join(", ")}>{match.writeSeqs.length} instructions</span>
              <span title={match.normalizedDigest} style={{ overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap", fontFamily: "monospace" }}>{match.normalizedDigest}</span>
              <div style={{ display: "flex", gap: 5 }}>
                <button type="button" style={buttonStyle} onClick={() => onJumpToSeq(match.lastWriteSeq)}>跳转</button>
                <button type="button" style={buttonStyle} onClick={() => emit("action:view-in-memory", { addr: match.addr, seq: match.lastWriteSeq })}>查看内存</button>
                <button type="button" style={buttonStyle} onClick={() => emit("action:trace-memory-value", { addr: match.addr, size: match.byteLen, seq: match.lastWriteSeq })}>追踪输出</button>
              </div>
            </div>
          ))}
          <div style={{ padding: "4px 8px", background: "var(--bg-secondary)", color: "var(--text-secondary)", fontSize: 10 }}>
            {state.memoryResponse.totalMatches.toLocaleString()} memory matches · {state.memoryResponse.writesScanned.toLocaleString()} writes scanned
            {state.memoryResponse.truncated ? " · 仅显示前 500 条" : ""}
          </div>
        </div>
      )}

      <div style={{ flex: 1, minHeight: 0, overflow: "auto" }}>
        {!state.response && !state.memoryResponse && !state.loading ? (
          <div style={{ height: "100%", display: "flex", alignItems: "center", justifyContent: "center", color: "var(--text-secondary)", fontSize: 12 }}>
            请输入 CRC32、MD5、SHA-1、SHA-256、SHA-384 或 SHA-512 摘要。
          </div>
        ) : state.loading ? (
          <div style={{ height: "100%", display: "flex", alignItems: "center", justifyContent: "center", gap: 8, color: "var(--text-secondary)", fontSize: 12 }}>
            <span style={{
              display: "inline-block", width: 14, height: 14, border: "2px solid var(--border-color)",
              borderTopColor: "var(--btn-primary)", borderRadius: "50%", animation: "spin 1s linear infinite",
            }} />
            {state.searchMemory ? "正在匹配字符串与内存写入…" : "正在匹配已提取字符串…"}
          </div>
        ) : state.response && state.response.matches.length === 0 ? (
          <div style={{ height: "100%", display: "flex", alignItems: "center", justifyContent: "center", padding: 20 }}>
            <div style={{ maxWidth: 620, color: "var(--text-secondary)", fontSize: 12, lineHeight: 1.7, textAlign: "center" }}>
              未找到匹配的字符串。请检查字节变换，或为非文本输出缓冲区启用“二进制内存写入”。
            </div>
          </div>
        ) : state.response ? (
          <div style={{ minWidth: 820 }}>
            <div style={{
              height: 27, display: "grid", gridTemplateColumns: "70px minmax(180px, 1fr) 112px 95px 120px 64px 292px",
              alignItems: "center", padding: "0 8px", position: "sticky", top: 0, zIndex: 1,
              background: "var(--bg-secondary)", color: "var(--text-secondary)",
              borderBottom: "1px solid var(--border-color)", fontSize: 11,
            }}>
              <span>行号</span><span>字符串 / 摘要</span><span>地址</span><span>算法</span><span>字节数</span><span>交叉引用</span><span>操作</span>
            </div>
            {state.response?.matches.map((match, index) => (
              <div
                key={`${match.queryIndex}-${match.stringIndex}-${match.transform}-${index}`}
                style={{
                  minHeight: 48, display: "grid", gridTemplateColumns: "70px minmax(180px, 1fr) 112px 95px 120px 64px 292px",
                  alignItems: "center", padding: "5px 8px", fontSize: 11,
                  background: index % 2 === 0 ? "var(--bg-row-even)" : "var(--bg-row-odd)",
                  borderBottom: "1px solid var(--border-color)",
                }}
              >
                <button
                  type="button"
                  onClick={() => onJumpToSeq(match.seq)}
                  style={{ border: "none", padding: 0, background: "transparent", color: "var(--text-address)", cursor: "pointer", textAlign: "left", fontFamily: "inherit" }}
                >
                  {match.seq + 1}
                </button>
                <div style={{ minWidth: 0, paddingRight: 12 }}>
                  <div title={match.content} style={{ color: "var(--text-primary)", overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap", fontSize: 12 }}>
                    {match.content}
                  </div>
                  <div title={match.normalizedDigest} style={{ marginTop: 2, color: "var(--text-secondary)", overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
                    {match.normalizedDigest}
                  </div>
                </div>
                <span style={{ color: "var(--text-address)" }}>{match.addr}</span>
                <span style={{ color: "var(--asm-mnemonic)" }}>{algorithmLabels[match.algorithm]}</span>
                <div>
                  <div style={{ color: "var(--text-primary)" }}>
                    {match.encoding} · {transformLabels[match.transform]}
                  </div>
                  <div style={{ color: "var(--text-secondary)", marginTop: 2 }}>{match.hashedByteLen} hashed / {match.byteLen} indexed</div>
                </div>
                <span>{match.xrefCount}</span>
                <div style={{ display: "flex", gap: 5, alignItems: "center" }}>
                  <button type="button" style={buttonStyle} onClick={() => onJumpToSeq(match.seq)}>跳转</button>
                  <button type="button" style={buttonStyle} onClick={() => emit("action:view-in-memory", { addr: match.addr, seq: match.seq })}>查看内存</button>
                  <button type="button" style={buttonStyle} onClick={() => void showXRefs(match)}>交叉引用</button>
                  <button
                    type="button"
                    style={{ ...buttonStyle, opacity: onTraceInput ? 1 : 0.45, cursor: onTraceInput ? "pointer" : "default" }}
                    disabled={!onTraceInput}
                    onClick={() => onTraceInput && void onTraceInput(match)}
                  title="沿数据依赖向后追踪已索引字符串的字节"
                  >
                    追踪输入
                  </button>
                </div>
              </div>
            ))}
          </div>
        ) : null}
      </div>
    </div>
  );
}
