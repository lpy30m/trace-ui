import React, { useState, useCallback } from "react";
import { invoke } from "@tauri-apps/api/core";
import type {
  TraceSessionInfo,
  WhiteBoxMultiTraceReport,
  WhiteBoxReport,
  WhiteBoxIoBlock,
  WhiteBoxTableRegion,
  WhiteBoxTraceCaseRequest,
} from "../types/trace";

interface Props {
  sessionId: string | null;
  onJumpToSeq: (seq: number) => void;
}

function confColor(confidence: string): string {
  switch (confidence) {
    case "high": return "#3fb950";
    case "medium": return "#f5a623";
    default: return "#8a8f98";
  }
}

function Section({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <div style={{ padding: "8px 12px", borderBottom: "1px solid var(--border-color)" }}>
      <div style={{ fontSize: 11, textTransform: "uppercase", letterSpacing: 0.5, color: "var(--text-tertiary)", marginBottom: 6 }}>
        {title}
      </div>
      {children}
    </div>
  );
}

function IoRow({ label, block, onJumpToSeq }: { label: string; block: WhiteBoxIoBlock | null; onJumpToSeq: (s: number) => void }) {
  if (!block) {
    return <div style={{ fontSize: 12, color: "var(--text-tertiary)" }}>{label}: <span style={{ fontStyle: "italic" }}>未定位</span></div>;
  }
  return (
    <div style={{ fontSize: 12, marginBottom: 6 }}>
      <div style={{ color: "var(--text-secondary)" }}>
        {label} · {block.byteLen}B ·{" "}
        <span
          onClick={() => onJumpToSeq(block.firstSeq)}
          style={{ color: "var(--syntax-literal)", textDecoration: "underline", cursor: "pointer" }}
          title="Jump to first access"
        >{block.baseAddr}</span>{" "}
        <span style={{ color: "var(--text-tertiary)" }}>@seq {block.firstSeq + 1}</span>
      </div>
      <div style={{ color: "var(--syntax-keyword)", fontFamily: "monospace" }}>"{block.ascii}"</div>
      <div style={{ color: "var(--text-tertiary)", fontFamily: "monospace", wordBreak: "break-all" }}>{block.bytesHex}</div>
    </div>
  );
}

function TableRow({ t, onJumpToSeq }: { t: WhiteBoxTableRegion; onJumpToSeq: (s: number) => void }) {
  const dispatcher = t.roleHint === "controlFlowDispatcherCandidate";
  return (
    <div style={{ display: "flex", gap: 8, fontSize: 12, padding: "2px 0", fontFamily: "monospace", flexWrap: "wrap" }}>
      <span
        onClick={() => onJumpToSeq(t.firstSeq)}
        style={{ color: "var(--syntax-literal)", textDecoration: "underline", cursor: "pointer", minWidth: 120 }}
        title="Jump to first read"
      >{t.baseAddr}</span>
      <span style={{ color: "var(--text-tertiary)", minWidth: 90 }}>+{t.moduleOffset}</span>
      <span style={{ color: "var(--text-secondary)", minWidth: 90 }}>{t.readCount} reads</span>
      <span style={{ color: "var(--text-tertiary)" }}>{t.distinctAddrs} addrs · {t.spanBytes}B · {t.dominantSize}-byte</span>
      <span style={{ color: dispatcher ? "#f5a623" : "var(--text-tertiary)" }}>
        {dispatcher
          ? `dispatcher candidate · ${t.pointerLikeEntries} code targets · excluded from crypto score`
          : "lookup data"}
      </span>
    </div>
  );
}

export default function WhiteBoxPanel({ sessionId, onJumpToSeq }: Props) {
  const [report, setReport] = useState<WhiteBoxReport | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [staticBinaryPath, setStaticBinaryPath] = useState("");
  const [compareOpen, setCompareOpen] = useState(false);
  const [compareCases, setCompareCases] = useState<Array<WhiteBoxTraceCaseRequest & { included: boolean }>>([]);
  const [compareReport, setCompareReport] = useState<WhiteBoxMultiTraceReport | null>(null);
  const [compareLoading, setCompareLoading] = useState(false);
  const [compareError, setCompareError] = useState<string | null>(null);

  const chooseStaticBinary = useCallback(async () => {
    const { open } = await import("@tauri-apps/plugin-dialog");
    const selected = await open({
      multiple: false,
      directory: false,
      filters: [{ name: "ELF shared object", extensions: ["so", "elf"] }],
    });
    if (typeof selected === "string") setStaticBinaryPath(selected);
  }, []);

  const analyze = useCallback(async () => {
    if (!sessionId) return;
    setLoading(true);
    setError(null);
    try {
      const r = await invoke<WhiteBoxReport>("analyze_whitebox_crypto", {
        sessionId,
        algorithm: "aes",
        staticBinaryPath: staticBinaryPath.trim() || null,
      });
      setReport(r);
    } catch (e) {
      setError(String(e));
      setReport(null);
    } finally {
      setLoading(false);
    }
  }, [sessionId, staticBinaryPath]);

  const toggleCompare = useCallback(async () => {
    const next = !compareOpen;
    setCompareOpen(next);
    if (!next) return;
    setCompareError(null);
    try {
      const sessions = await invoke<TraceSessionInfo[]>("list_trace_sessions");
      setCompareCases(sessions.map((session, index) => ({
        sessionId: session.sessionId,
        label: session.filePath.split(/[\\/]/).pop() || `trace-${index + 1}`,
        keyGroup: "key-1",
        inputGroup: `input-${index + 1}`,
        staticBinaryPath: staticBinaryPath.trim() || null,
        included: true,
      })));
    } catch (loadError) {
      setCompareError(String(loadError));
    }
  }, [compareOpen, staticBinaryPath]);

  const updateCompareCase = useCallback((index: number, changes: Partial<WhiteBoxTraceCaseRequest & { included: boolean }>) => {
    setCompareCases(previous => previous.map((item, itemIndex) => itemIndex === index ? { ...item, ...changes } : item));
  }, []);

  const compareTraces = useCallback(async () => {
    const cases = compareCases.filter(item => item.included).map(({ included: _included, ...item }) => item);
    if (cases.length < 2) {
      setCompareError("Select at least two open trace sessions.");
      return;
    }
    if (cases.some(item => !item.label || !item.keyGroup || !item.inputGroup)) {
      setCompareError("Every selected case needs a label, key group, and input group.");
      return;
    }
    setCompareLoading(true);
    setCompareError(null);
    try {
      setCompareReport(await invoke<WhiteBoxMultiTraceReport>("compare_whitebox_traces", { request: { cases } }));
    } catch (compareFailure) {
      setCompareReport(null);
      setCompareError(String(compareFailure));
    } finally {
      setCompareLoading(false);
    }
  }, [compareCases]);

  return (
    <div style={{ flex: 1, display: "flex", flexDirection: "column", overflow: "hidden" }}>
      <div style={{
        display: "flex", alignItems: "center", gap: 8, padding: "4px 8px",
        borderBottom: "1px solid var(--border-color)", flexShrink: 0,
      }}>
        <button
          type="button"
          onClick={analyze}
          disabled={!sessionId || loading}
          style={{
            height: 24, padding: "0 12px", fontSize: 12, cursor: sessionId ? "pointer" : "default",
            background: "var(--btn-primary)", color: "#fff", border: "none", borderRadius: 3,
            opacity: !sessionId || loading ? 0.6 : 1,
          }}
        >{loading ? "分析中…" : "分析软件/查表型加密"}</button>
        <input
          value={staticBinaryPath}
          onChange={(event) => setStaticBinaryPath(event.target.value)}
          placeholder="可选：本地 ELF .so 路径"
          aria-label="可选的静态 ELF 共享对象路径"
          style={{
            height: 22, minWidth: 230, flex: "0 1 360px", padding: "0 7px", fontSize: 11,
            color: "var(--text-secondary)", background: "var(--input-bg)",
            border: "1px solid var(--border-color)", borderRadius: 3,
          }}
        />
        <button type="button" onClick={chooseStaticBinary} disabled={loading} style={{ height: 24, fontSize: 11 }}>
          选择 .so
        </button>
        <button type="button" onClick={() => void toggleCompare()} disabled={loading || compareLoading} style={{ height: 24, fontSize: 11 }}>
          {compareOpen ? "隐藏 trace 矩阵" : "比较 trace"}
        </button>
        {report && (
          <span style={{ color: "var(--text-tertiary)", fontSize: 11 }}>
            {report.totalReads.toLocaleString()} reads · {report.totalWrites.toLocaleString()} writes · {report.tableReadTotal.toLocaleString()} table lookups
          </span>
        )}
      </div>

      {compareOpen && (
        <div style={{ padding: 8, borderBottom: "1px solid var(--border-color)", flexShrink: 0, maxHeight: 250, overflow: "auto" }}>
          <div style={{ fontSize: 11, color: "var(--text-secondary)", marginBottom: 6 }}>
            请明确标注受控测试矩阵。强密钥依赖证据至少需要两个密钥、每个密钥至少两个输入，并保持 SO 构建版本和覆盖范围一致。
          </div>
          {compareCases.length === 0 && <div style={{ fontSize: 11, color: "var(--text-tertiary)" }}>没有已打开且已索引的会话。</div>}
          {compareCases.map((item, index) => (
            <div key={item.sessionId} style={{ display: "grid", gridTemplateColumns: "24px minmax(150px, 1fr) 110px 110px", gap: 6, marginBottom: 4, alignItems: "center" }}>
              <input type="checkbox" checked={item.included} onChange={event => updateCompareCase(index, { included: event.target.checked })} />
              <input value={item.label} onChange={event => updateCompareCase(index, { label: event.target.value })} title={item.sessionId} style={{ minWidth: 0 }} />
              <input value={item.keyGroup} onChange={event => updateCompareCase(index, { keyGroup: event.target.value })} placeholder="密钥分组" />
              <input value={item.inputGroup} onChange={event => updateCompareCase(index, { inputGroup: event.target.value })} placeholder="输入分组" />
            </div>
          ))}
          <div style={{ display: "flex", alignItems: "center", gap: 8, marginTop: 6 }}>
            <button type="button" disabled={compareLoading || compareCases.length < 2} onClick={() => void compareTraces()}>
              {compareLoading ? "比较中…" : "判断查表依赖"}
            </button>
            <span style={{ fontSize: 10, color: "var(--text-tertiary)" }}>调用方标签只是前提假设；分类不会自动通过语义验证门槛。</span>
          </div>
          {compareError && <div style={{ color: "#e5484d", fontSize: 11, marginTop: 5 }}>{compareError}</div>}
          {compareReport && (
            <div style={{ marginTop: 7, padding: 7, border: "1px solid var(--border-color)", borderRadius: 4, fontSize: 11 }}>
              <div style={{ color: "var(--syntax-keyword)", fontWeight: 600 }}>
                {compareReport.classification} · {compareReport.whiteboxStatus} · gate {String(compareReport.verificationGateMet)}
              </div>
              <div style={{ color: "var(--text-secondary)", marginTop: 3 }}>{compareReport.rationale}</div>
              {compareReport.keyGroups.map(group => (
                <div key={group.keyGroup} style={{ color: group.inputStable ? "#3fb950" : "#f5a623", marginTop: 3 }}>
                  {group.keyGroup}: {group.distinctInputGroups} inputs · stable {String(group.inputStable)} · {group.rationale}
                </div>
              ))}
              {compareReport.crossKeyComparisons.map(comparison => (
                <div key={`${comparison.leftKeyGroup}-${comparison.rightKeyGroup}`} style={{ color: "var(--text-tertiary)", marginTop: 3 }}>
                  {comparison.leftKeyGroup} ↔ {comparison.rightKeyGroup}: shape {comparison.sameTableShape ? "same" : "different"}, values {comparison.sameFingerprintValues ? "same" : "different"}. {comparison.rationale}
                </div>
              ))}
            </div>
          )}
        </div>
      )}

      <div style={{ flex: 1, overflow: "auto" }}>
        {error && <div style={{ padding: 16, color: "#e5484d", fontSize: 12 }}>{error}</div>}
        {!error && !report && !loading && (
          <div style={{ padding: 16, color: "var(--text-secondary)", fontSize: 12, lineHeight: 1.6 }}>
            识别软件/查表密码的结构候选。结构信号只产生 candidate/related，不证明具体算法或 white-box；
            输入输出角色需由数据流确认，verified 需要完整分组语义复算。
          </div>
        )}
        {report && (
          <>
            {/* Verdict banner */}
            <div style={{ display: "flex", alignItems: "center", gap: 10, padding: "10px 12px", borderBottom: "1px solid var(--border-color)" }}>
              <span style={{
                padding: "2px 8px", borderRadius: 3, fontSize: 11, textTransform: "uppercase",
                background: confColor(report.assessment.confidence), color: "#fff",
              }}>{report.assessment.grade}</span>
              <span style={{ fontSize: 16, color: "var(--syntax-keyword)", fontWeight: 600 }}>{report.verdict.algorithm}</span>
              <span style={{ fontSize: 12, color: "var(--text-tertiary)" }}>
                score {report.assessment.score} · {report.verdict.blockBits}-bit
                {report.verdict.roundCount != null && ` · ${report.verdict.roundCount} rounds`}
              </span>
            </div>
            <div style={{ padding: "6px 12px", fontSize: 12, color: "var(--text-secondary)", borderBottom: "1px solid var(--border-color)" }}>
              {report.verdict.rationale}
            </div>
            <div style={{ padding: "6px 12px", fontSize: 11, color: "var(--text-tertiary)", borderBottom: "1px solid var(--border-color)" }}>
              implementation: {report.implementationKind} · key exposure: {report.keyExposure} · white-box: {report.whiteboxStatus}
            </div>

            {report.softwareCrypto && (
              <Section title="已验证的软件加密">
                <div style={{ fontSize: 13, color: "var(--syntax-keyword)", fontWeight: 600 }}>
                  {report.softwareCrypto.algorithm} · {report.softwareCrypto.direction} · {report.softwareCrypto.mode} · {report.softwareCrypto.verification}
                </div>
                <div style={{ fontSize: 12, color: "var(--text-secondary)", marginTop: 4 }}>
                  {report.softwareCrypto.inputLength}B → {report.softwareCrypto.paddedLength}B · {report.softwareCrypto.blockCount} blocks · stride 0x{report.softwareCrypto.outputStride.toString(16)} · {report.softwareCrypto.padding}
                </div>
                <div style={{ fontSize: 11, color: "var(--text-tertiary)", fontFamily: "monospace", marginTop: 4 }}>
                  key: {report.softwareCrypto.keyAscii} ({report.softwareCrypto.keyExposure})<br />
                  {report.softwareCrypto.ivHex && <>iv/counter: {report.softwareCrypto.ivHex}<br /></>}
                  {report.softwareCrypto.authTagHex && <>auth tag: {report.softwareCrypto.authTagHex}<br /></>}
                  {report.softwareCrypto.aadHex && <>AAD: {report.softwareCrypto.aadHex}<br /></>}
                  state layout: {report.softwareCrypto.stateLayout}<br />
                  implementation: {report.softwareCrypto.implementationKind} · white-box: {report.softwareCrypto.whiteboxStatus}<br />
                  first: {report.softwareCrypto.firstCipherBlock}<br />last: {report.softwareCrypto.lastCipherBlock}<br />sha256: {report.softwareCrypto.ciphertextSha256}
                </div>
                <div style={{ fontSize: 11, color: "var(--text-tertiary)", marginTop: 4 }}>
                  {report.softwareCrypto.stateLayoutEvidence}
                </div>
                <div style={{ display: "flex", gap: 8, marginTop: 6, fontSize: 11, alignItems: "center" }}>
                  <button type="button" onClick={() => onJumpToSeq(report.softwareCrypto!.keyObservationSeq)}>跳转到密钥</button>
                  <button type="button" onClick={() => onJumpToSeq(report.softwareCrypto!.inputObservationSeq)}>跳转到输入</button>
                  {report.softwareCrypto.ivObservationSeq != null && (
                    <button type="button" onClick={() => onJumpToSeq(report.softwareCrypto!.ivObservationSeq!)}>跳转到 IV</button>
                  )}
                  {report.softwareCrypto.authTagObservationSeq != null && (
                    <button type="button" onClick={() => onJumpToSeq(report.softwareCrypto!.authTagObservationSeq!)}>跳转到认证标签</button>
                  )}
                  {report.softwareCrypto.aadObservationSeq != null && (
                    <button type="button" onClick={() => onJumpToSeq(report.softwareCrypto!.aadObservationSeq!)}>跳转到 AAD</button>
                  )}
                  <button type="button" onClick={() => onJumpToSeq(report.softwareCrypto!.outputFirstSeq)}>跳转到输出</button>
                  <span style={{ color: "var(--text-tertiary)" }}>
                    output lines {report.softwareCrypto.outputFirstSeq + 1}–{report.softwareCrypto.outputLastSeq + 1}
                  </span>
                </div>
                <details style={{ marginTop: 6 }}><summary style={{ cursor: "pointer", fontSize: 11 }}>Python 复现脚本</summary>
                  <pre style={{ whiteSpace: "pre-wrap", fontSize: 10, color: "var(--text-tertiary)" }}>{report.softwareCrypto.reproducer}</pre>
                </details>
              </Section>
            )}

            {((report.aesSboxFingerprints?.length ?? 0) > 0
              || (report.aesKeySchedules?.length ?? 0) > 0
              || report.aesSemanticVerification) && (
              <Section title="动态 AES 证据">
                {report.aesSboxFingerprints?.map(fingerprint => (
                  <div key={`${fingerprint.directionCandidate}-${fingerprint.baseAddr}`} style={{ marginBottom: 5, fontSize: 11 }}>
                    <button type="button" onClick={() => onJumpToSeq(fingerprint.firstSeq)} style={{ marginRight: 6 }}>
                      {fingerprint.baseAddr}
                    </button>
                    <span style={{ color: "var(--text-secondary)" }}>
                      {fingerprint.directionCandidate} S-box · {fingerprint.matchingReads} reads · {fingerprint.distinctIndices}/256 indices · {(fingerprint.matchRatio * 100).toFixed(1)}%
                    </span>
                  </div>
                ))}
                {report.aesKeySchedules?.map(schedule => (
                  <div key={schedule.scheduleAddress} style={{ marginBottom: 5, fontSize: 11 }}>
                    <button type="button" onClick={() => onJumpToSeq(schedule.startSeq)} style={{ marginRight: 6 }}>
                      {schedule.scheduleAddress}
                    </button>
                    <span style={{ color: "var(--text-secondary)" }}>
                      AES-{schedule.verification.keyBits} schedule · {schedule.verification.wordsMatched}/{schedule.verification.wordsChecked} words
                    </span>
                  </div>
                ))}
                {report.aesSemanticVerification && (
                  <div style={{ fontSize: 11, color: "#3fb950" }}>
                    {report.aesSemanticVerification.status} · {report.aesSemanticVerification.direction} {report.aesSemanticVerification.mode} · {report.aesSemanticVerification.matchedBlocks}/{report.aesSemanticVerification.blocksChecked} blocks · {report.aesSemanticVerification.byteLen} bytes
                  </div>
                )}
              </Section>
            )}

            <Section title="中性 I/O 候选">
              {report.inputCandidates.map((block, i) => <IoRow key={`in-${i}`} label={`输入候选 ${i + 1}`} block={block} onJumpToSeq={onJumpToSeq} />)}
              {report.outputCandidates.map((block, i) => <IoRow key={`out-${i}`} label={`输出候选 ${i + 1}`} block={block} onJumpToSeq={onJumpToSeq} />)}
            </Section>

            <Section title={`Lookup tables (${report.tables.length})`}>
              {report.tables.length === 0
                ? <div style={{ fontSize: 12, color: "var(--text-tertiary)" }}>无</div>
                : report.tables.map((t, i) => <TableRow key={i} t={t} onJumpToSeq={onJumpToSeq} />)}
            </Section>

            {report.tableFingerprints.length > 0 && (
              <Section title="规范化查表指纹">
                {report.tableFingerprints.map((fingerprint, i) => (
                  <div key={`${fingerprint.scope}-${i}`} style={{ marginBottom: 8, fontSize: 11 }}>
                    <div style={{ color: fingerprint.algorithmHint ? "var(--syntax-keyword)" : "var(--text-secondary)" }}>
                      {fingerprint.algorithmHint || "Unclassified table"} · {fingerprint.distinctWords} distinct words · {fingerprint.scope}
                    </div>
                    <div style={{ color: "var(--text-tertiary)", fontFamily: "monospace", overflowWrap: "anywhere" }}>
                      sha256 {fingerprint.normalizedSha256}
                    </div>
                    <div style={{ color: "var(--text-tertiary)" }}>{fingerprint.normalization}</div>
                  </div>
                ))}
              </Section>
            )}

            {report.encodingBoundaries.length > 0 && (
              <Section title="动态编码边界（候选）">
                {report.encodingBoundaries.map((boundary, i) => (
                  <div key={`${boundary.direction}-${boundary.boundarySite}-${i}`} style={{ marginBottom: 9, fontSize: 11 }}>
                    <div style={{ color: "var(--syntax-keyword)", fontWeight: 600 }}>
                      {boundary.direction === "InputEncodingCandidate" ? "Input encoding" : "Output encoding"} candidate
                    </div>
                    <div style={{ color: "var(--text-secondary)", fontFamily: "monospace", marginTop: 2 }}>
                      table {boundary.tableBase} · site {boundary.boundarySite} · external {boundary.externalBaseAddr}–{boundary.externalEndAddr}
                    </div>
                    <div style={{ color: "var(--text-tertiary)", marginTop: 2 }}>
                      {boundary.matchedEvents} matched events · {boundary.distinctExternalAddrs} external addresses · seq {boundary.firstSeq + 1}–{boundary.lastSeq + 1}
                    </div>
                    <div style={{ color: "var(--text-tertiary)", marginTop: 2 }}>{boundary.rationale}</div>
                    <button type="button" onClick={() => onJumpToSeq(boundary.firstSeq)} style={{ marginTop: 4 }}>
                      跳转到边界
                    </button>
                  </div>
                ))}
                <div style={{ color: "var(--text-tertiary)", fontSize: 10 }}>
                  短窗口动态相关性仅是结构候选；不会单独升级 verified 或 white-box 状态。
                </div>
              </Section>
            )}

            {report.staticBinary && (
              <Section title="静态 ELF ↔ 动态查表关联">
                <div style={{ fontSize: 11, color: "var(--text-secondary)", marginBottom: 7 }}>
                  {report.staticBinary.format} · {report.staticBinary.architecture} (e_machine {report.staticBinary.elfMachine}) · {report.staticBinary.loadSegments} PT_LOAD segments · {report.staticBinary.binaryPath}
                </div>
                {report.staticBinary.buildId && (
                  <div style={{ fontSize: 10, color: "var(--text-tertiary)", fontFamily: "monospace", marginBottom: 4 }}>
                    Build ID {report.staticBinary.buildId}
                  </div>
                )}
                <div style={{ fontSize: 10, color: "var(--text-tertiary)", fontFamily: "monospace", overflowWrap: "anywhere", marginBottom: 8 }}>
                  sha256 {report.staticBinary.binarySha256}
                </div>
                {report.staticBinary.tableMatches.length === 0 ? (
                  <div style={{ fontSize: 11, color: "var(--text-tertiary)" }}>
                    没有至少 16 个可映射的动态表条目；这不表示二进制中没有密码表。
                  </div>
                ) : report.staticBinary.tableMatches.map((match, i) => (
                  <div key={`${match.tableBase}-${i}`} style={{ marginBottom: 9, fontSize: 11 }}>
                    <div style={{ color: match.matchKind === "ExactStaticDynamicMatch" ? "#3fb950" : match.matchKind === "PartialStaticDynamicMatch" ? "#f5a623" : "#e5484d" }}>
                      {match.matchKind} · {(match.matchRatio * 100).toFixed(1)}% · {match.algorithmHint || "unclassified table"}
                    </div>
                    <div style={{ color: "var(--text-secondary)", fontFamily: "monospace", marginTop: 2 }}>
                      runtime {match.tableBase} (+{match.moduleOffset}) → file {match.fileOffset}
                    </div>
                    <div style={{ color: "var(--text-tertiary)", marginTop: 2 }}>
                      {match.matchingEntries}/{match.comparedEntries} entries match · {match.mismatchedEntries} mismatch
                    </div>
                    <div style={{ color: "var(--text-tertiary)", marginTop: 2 }}>{match.rationale}</div>
                  </div>
                ))}
                <div style={{ color: "var(--text-tertiary)", fontSize: 10 }}>
                  文件来源一致性仍是结构证据；算法与 white-box 验证继续依赖语义复算或多样本 key-fusion 证据。
                </div>
              </Section>
            )}

            {report.rounds && (
              <Section title="查表重复度启发式">
                <div style={{ fontSize: 12, color: "var(--text-secondary)" }}>
                  ≈ {report.rounds.roundCount} rounds
                </div>
                <div style={{ fontSize: 11, color: "var(--text-tertiary)", fontFamily: "monospace", marginTop: 4 }}>
                  {report.rounds.lookups} lookups ÷ {report.rounds.distinctEntries} entries ≈ {(report.rounds.lookups / Math.max(1, report.rounds.distinctEntries)).toFixed(2)} / entry · table {report.rounds.landmarkTable}
                </div>
              </Section>
            )}

            <Section title="证据">
              {report.assessment.factors.filter(f => f.observed).map(f => (
                <div key={f.code} style={{ display: "flex", gap: 8, fontSize: 12, marginBottom: 2 }}>
                  <span style={{ width: 34, color: f.awardedPoints >= 0 ? "#3fb950" : "#e5484d" }}>
                    {f.awardedPoints >= 0 ? "+" : ""}{f.awardedPoints}
                  </span>
                  <span style={{ color: "var(--text-secondary)" }}>{f.label}</span>
                </div>
              ))}
            </Section>

            <Section title="基于证据的下一步">
              {report.nextSteps.map((s, i) => (
                <div key={i} style={{ fontSize: 11, color: "var(--text-tertiary)", marginBottom: 3, lineHeight: 1.5 }}>• {s}</div>
              ))}
            </Section>

            <Section title="限制说明">
              {report.assessment.limitations.map((s, i) => (
                <div key={i} style={{ fontSize: 11, color: "var(--text-tertiary)", marginBottom: 3, lineHeight: 1.5 }}>• {s}</div>
              ))}
            </Section>
          </>
        )}
      </div>
    </div>
  );
}
