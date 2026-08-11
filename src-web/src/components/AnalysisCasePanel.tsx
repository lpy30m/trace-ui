import React, { useCallback, useEffect, useMemo, useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import type {
  CryptoDetectionDoctorReport,
  ReplayDoctorReport,
  TraceAnalysisCaseDocument,
  TraceCaseArtifact,
  TraceCaseClaimStatus,
  TraceCaseExperiment,
} from "../types/trace";

interface Props { sessionId: string | null; }

const buttonStyle: React.CSSProperties = {
  height: 26, padding: "0 10px", border: "1px solid var(--border-color)", borderRadius: 4,
  background: "var(--bg-input)", color: "var(--text-primary)", cursor: "pointer", fontSize: 11,
};
const cardStyle: React.CSSProperties = {
  border: "1px solid var(--border-color)", borderRadius: 5, background: "var(--bg-secondary)", padding: 9,
};

function statusColor(status: string): string {
  const value = status.toLowerCase();
  if (value.includes("not-captured") || value.includes("not-observed") || value.includes("no-match") || value.includes("partial") || value.includes("incomplete")) return "#d29922";
  if (value.includes("verified") || value === "valid" || value.includes("progress") || value.includes("ready") || value.includes("captured") || value.includes("matched") || value.includes("passed")) return "#3fb950";
  if (value.includes("invalid") || value.includes("mismatch") || value.includes("failed") || value.includes("refuted") || value.includes("regress")) return "#e5484d";
  if (value.includes("related") || value.includes("blocked") || value.includes("stall") || value.includes("warning")) return "#d29922";
  return "var(--text-secondary)";
}

function claimColor(status: TraceCaseClaimStatus): string {
  if (status === "verified") return "#3fb950";
  if (status === "refuted") return "#e5484d";
  if (status === "observed") return "#58a6ff";
  if (status === "related") return "#d29922";
  return "var(--text-secondary)";
}

function shortHash(value?: string): string {
  return value && value.length > 18 ? `${value.slice(0, 12)}…${value.slice(-6)}` : value ?? "";
}

function artifactSummary(artifact: TraceCaseArtifact): string {
  const parts: string[] = [];
  if (artifact.summary.moduleName) parts.push(artifact.summary.moduleName);
  if (artifact.summary.captureOffsets.length) parts.push(`${artifact.summary.captureOffsets.length} offsets`);
  if (artifact.summary.eventCount) parts.push(`${artifact.summary.eventCount} events/seeds`);
  if (artifact.summary.runCount) parts.push(`${artifact.summary.runCount} runs/probes`);
  return parts.join(" · ") || artifact.path;
}

export default function AnalysisCasePanel({ sessionId }: Props) {
  const storageKey = sessionId ? `trace-ui-analysis-case:${sessionId}` : "trace-ui-analysis-case:last";
  const [document, setDocument] = useState<TraceAnalysisCaseDocument | null>(null);
  const [report, setReport] = useState<ReplayDoctorReport | null>(null);
  const [cryptoReport, setCryptoReport] = useState<CryptoDetectionDoctorReport | null>(null);
  const [binaryPath, setBinaryPath] = useState("");
  const [experimentLabel, setExperimentLabel] = useState("");
  const [experimentBinarySha, setExperimentBinarySha] = useState("");
  const [experimentKeyGroup, setExperimentKeyGroup] = useState("");
  const [experimentInputGroup, setExperimentInputGroup] = useState("");
  const [experimentEnvironmentGroup, setExperimentEnvironmentGroup] = useState("");
  const [experimentChangedAxis, setExperimentChangedAxis] = useState("baseline");
  const [selectedExperimentArtifacts, setSelectedExperimentArtifacts] = useState<string[]>([]);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const remember = useCallback((next: TraceAnalysisCaseDocument) => {
    setDocument(next);
    localStorage.setItem(storageKey, next.casePath);
  }, [storageKey]);

  const loadPath = useCallback(async (casePath: string) => {
    setBusy(true); setError(null);
    try {
      const next = await invoke<TraceAnalysisCaseDocument>("load_analysis_case", { casePath });
      remember(next); setReport(null);
    } catch (e) { setError(String(e)); }
    finally { setBusy(false); }
  }, [remember]);

  useEffect(() => {
    const saved = localStorage.getItem(storageKey);
    if (saved) void loadPath(saved);
  }, [storageKey, loadPath]);

  const createCase = useCallback(async () => {
    const { save } = await import("@tauri-apps/plugin-dialog");
    const selected = await save({
      title: "创建 Trace UI 案件工作区", defaultPath: "trace-analysis.traceui-case",
      filters: [{ name: "Trace UI Case", extensions: ["traceui-case"] }],
    });
    if (!selected) return;
    setBusy(true); setError(null);
    try {
      const next = await invoke<TraceAnalysisCaseDocument>("create_analysis_case", {
        casePath: selected, title: "Trace UI 分析案件", sessionId,
        primaryTracePath: null, exactBinaryPath: null,
      });
      remember(next); setReport(null);
    } catch (e) { setError(String(e)); }
    finally { setBusy(false); }
  }, [remember, sessionId]);

  const openCase = useCallback(async () => {
    const { open } = await import("@tauri-apps/plugin-dialog");
    const selected = await open({
      title: "打开 Trace UI 案件工作区", multiple: false, directory: false,
      filters: [{ name: "Trace UI Case", extensions: ["traceui-case"] }],
    });
    if (typeof selected === "string") await loadPath(selected);
  }, [loadPath]);

  const importArtifacts = useCallback(async () => {
    if (!document) return;
    const { open } = await import("@tauri-apps/plugin-dialog");
    const selected = await open({ title: "导入分析 artifact", multiple: true, directory: false });
    const paths = typeof selected === "string" ? [selected] : Array.isArray(selected) ? selected : [];
    if (!paths.length) return;
    setBusy(true); setError(null);
    try {
      let next = document;
      for (const artifactPath of paths) {
        const imported = await invoke<{ case: TraceAnalysisCaseDocument["case"] }>("add_analysis_case_artifact", {
          casePath: document.casePath, artifactPath, kindHint: null, label: null, parentArtifactIds: [],
        });
        next = { casePath: document.casePath, case: imported.case };
      }
      remember(next); setReport(null);
    } catch (e) { setError(String(e)); }
    finally { setBusy(false); }
  }, [document, remember]);

  const runDoctor = useCallback(async (persistGeneratedClaims = false) => {
    if (!document) return;
    setBusy(true); setError(null);
    try {
      const nextReport = await invoke<ReplayDoctorReport>("diagnose_analysis_case", {
        casePath: document.casePath, persistGeneratedClaims,
      });
      setReport(nextReport);
      if (persistGeneratedClaims) {
        remember(await invoke<TraceAnalysisCaseDocument>("load_analysis_case", { casePath: document.casePath }));
      }
    } catch (e) { setError(String(e)); }
    finally { setBusy(false); }
  }, [document, remember]);

  const chooseBinary = useCallback(async () => {
    const { open } = await import("@tauri-apps/plugin-dialog");
    const selected = await open({ title: "选择精确 AArch64 ELF/shared object", multiple: false, directory: false });
    if (typeof selected === "string") setBinaryPath(selected);
  }, []);

  const diagnoseAes = useCallback(async () => {
    if (!sessionId) return;
    setBusy(true); setError(null);
    try {
      setCryptoReport(await invoke<CryptoDetectionDoctorReport>("diagnose_crypto_detection", {
        sessionId, targetAlgorithm: "AES", staticBinaryPath: binaryPath || null,
      }));
    } catch (e) { setError(String(e)); }
    finally { setBusy(false); }
  }, [sessionId, binaryPath]);

  const saveExperiment = useCallback(async () => {
    if (!document) return;
    if (!experimentLabel.trim()) {
      setError("实验标签不能为空。");
      return;
    }
    const axes = ["binarySha256", "keyGroup", "inputGroup", "environmentGroup"];
    const experiment: TraceCaseExperiment = {
      experimentId: "",
      label: experimentLabel.trim(),
      binarySha256: experimentBinarySha.trim() || undefined,
      keyGroup: experimentKeyGroup.trim() || undefined,
      inputGroup: experimentInputGroup.trim() || undefined,
      environmentGroup: experimentEnvironmentGroup.trim() || undefined,
      artifactIds: selectedExperimentArtifacts,
      controlledVariables: experimentChangedAxis === "baseline"
        ? axes
        : axes.filter(axis => axis !== experimentChangedAxis),
      changedVariables: experimentChangedAxis === "baseline" ? [] : [experimentChangedAxis],
      notes: [],
    };
    setBusy(true); setError(null);
    try {
      const next = await invoke<TraceAnalysisCaseDocument>("upsert_analysis_case_experiment", {
        casePath: document.casePath, experiment,
      });
      remember(next);
      setExperimentLabel("");
      setSelectedExperimentArtifacts([]);
      setReport(null);
    } catch (e) { setError(String(e)); }
    finally { setBusy(false); }
  }, [
    document, experimentLabel, experimentBinarySha, experimentKeyGroup, experimentInputGroup,
    experimentEnvironmentGroup, experimentChangedAxis, selectedExperimentArtifacts, remember,
  ]);

  const healthById = useMemo(
    () => new Map(report?.artifactHealth.map(item => [item.artifactId, item]) ?? []),
    [report],
  );

  return (
    <div style={{ height: "100%", display: "flex", flexDirection: "column", overflow: "hidden" }}>
      <div style={{ display: "flex", alignItems: "center", gap: 6, padding: "5px 8px", borderBottom: "1px solid var(--border-color)", flexShrink: 0 }}>
        <button style={buttonStyle} disabled={busy} onClick={createCase}>新建案件</button>
        <button style={buttonStyle} disabled={busy} onClick={openCase}>打开案件</button>
        <button style={buttonStyle} disabled={busy || !document} onClick={importArtifacts}>导入 artifact</button>
        <button style={{ ...buttonStyle, background: document ? "var(--btn-primary)" : "var(--bg-input)", color: document ? "#fff" : "var(--text-secondary)" }} disabled={busy || !document} onClick={() => runDoctor(false)}>Replay Doctor</button>
        <button style={buttonStyle} disabled={busy || !report?.generatedClaims.length} onClick={() => runDoctor(true)}>保存诊断结论</button>
        <span style={{ flex: 1 }} />
        <span style={{ fontSize: 11, color: busy ? "#d29922" : statusColor(report?.status ?? "") }}>{busy ? "处理中…" : report?.status ?? ""}</span>
      </div>

      <div style={{ flex: 1, overflow: "auto", padding: 10, display: "flex", flexDirection: "column", gap: 10 }}>
        {error && <div style={{ ...cardStyle, color: "#e5484d", borderColor: "#e5484d" }}>{error}</div>}
        {!document && <div style={{ ...cardStyle, color: "var(--text-secondary)", lineHeight: 1.6 }}>新建或打开 <code>.traceui-case</code>。案件保存 Trace、精确 ELF、Frida、Unicorn/angr、SHA-256、来源关系和结论账本。</div>}

        {document && <>
          <div style={cardStyle}>
            <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
              <strong style={{ color: "var(--text-primary)", fontSize: 13 }}>{document.case.title}</strong>
              <span style={{ color: "var(--text-secondary)", fontSize: 10 }}>{document.case.artifacts.length} artifacts · {document.case.claims.length} claims · {document.case.experiments.length} experiments</span>
            </div>
            <div title={document.casePath} style={{ marginTop: 4, color: "var(--text-tertiary)", fontSize: 10, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{document.casePath}</div>
          </div>

          <section style={cardStyle}>
            <div style={{ marginBottom: 7, color: "var(--text-primary)", fontSize: 12, fontWeight: 600 }}>案件时间线与完整性</div>
            {!document.case.artifacts.length && <div style={{ color: "var(--text-secondary)", fontSize: 11 }}>尚未导入 artifact。</div>}
            <div style={{ display: "flex", flexDirection: "column", gap: 6 }}>
              {document.case.artifacts.map(artifact => {
                const health = healthById.get(artifact.artifactId);
                return <div key={artifact.artifactId} style={{ borderLeft: `3px solid ${statusColor(health?.status ?? "unknown")}`, padding: "5px 8px", background: "var(--bg-primary)", borderRadius: 3 }}>
                  <div style={{ display: "flex", gap: 7, alignItems: "center", fontSize: 11 }}>
                    <span style={{ color: "var(--text-primary)", fontWeight: 600 }}>{artifact.label}</span>
                    <code style={{ color: "#58a6ff" }}>{artifact.kind}</code>
                    <span style={{ color: statusColor(health?.status ?? "unknown") }}>{health?.status ?? "未检查"}</span>
                    <span style={{ marginLeft: "auto", color: "var(--text-tertiary)" }}>{shortHash(artifact.sha256)}</span>
                  </div>
                  <div style={{ marginTop: 3, color: "var(--text-secondary)", fontSize: 10 }}>{artifactSummary(artifact)}</div>
                  {health?.error && <div style={{ marginTop: 3, color: "#e5484d", fontSize: 10 }}>{health.error}</div>}
                </div>;
              })}
            </div>
          </section>

          <section style={cardStyle}>
            <div style={{ color: "var(--text-primary)", fontSize: 12, fontWeight: 600 }}>受控实验记录</div>
            <div style={{ marginTop: 4, color: "var(--text-secondary)", fontSize: 10, lineHeight: 1.5 }}>
              记录 build/key/input/environment，Replay Doctor 才能区分真正的单变量变化与混杂比较。运行目标、Frida 或模拟器仍由用户手动完成。
            </div>
            <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(170px, 1fr))", gap: 6, marginTop: 8 }}>
              <input aria-label="实验标签" value={experimentLabel} onChange={event => setExperimentLabel(event.target.value)} placeholder="实验标签" style={{ ...buttonStyle, height: 28 }} />
              <input aria-label="实验 ELF SHA-256" value={experimentBinarySha} onChange={event => setExperimentBinarySha(event.target.value)} placeholder="ELF SHA-256（可由 artifact 推断）" style={{ ...buttonStyle, height: 28 }} />
              <input aria-label="Key 分组" value={experimentKeyGroup} onChange={event => setExperimentKeyGroup(event.target.value)} placeholder="key group" style={{ ...buttonStyle, height: 28 }} />
              <input aria-label="Input 分组" value={experimentInputGroup} onChange={event => setExperimentInputGroup(event.target.value)} placeholder="input group" style={{ ...buttonStyle, height: 28 }} />
              <input aria-label="环境分组" value={experimentEnvironmentGroup} onChange={event => setExperimentEnvironmentGroup(event.target.value)} placeholder="environment group" style={{ ...buttonStyle, height: 28 }} />
              <select aria-label="本轮变化变量" value={experimentChangedAxis} onChange={event => setExperimentChangedAxis(event.target.value)} style={{ ...buttonStyle, height: 28 }}>
                <option value="baseline">baseline（无刻意变化）</option>
                <option value="binarySha256">仅 build 变化</option>
                <option value="keyGroup">仅 key 变化</option>
                <option value="inputGroup">仅 input 变化</option>
                <option value="environmentGroup">仅 environment 变化</option>
              </select>
            </div>
            {!!document.case.artifacts.length && <div style={{ display: "flex", flexWrap: "wrap", gap: 7, marginTop: 8 }}>
              {document.case.artifacts.map(artifact => <label key={artifact.artifactId} style={{ color: "var(--text-secondary)", fontSize: 10 }}>
                <input
                  type="checkbox"
                  checked={selectedExperimentArtifacts.includes(artifact.artifactId)}
                  onChange={() => setSelectedExperimentArtifacts(current => current.includes(artifact.artifactId)
                    ? current.filter(id => id !== artifact.artifactId)
                    : [...current, artifact.artifactId])}
                /> {artifact.label}
              </label>)}
            </div>}
            <button style={{ ...buttonStyle, marginTop: 8 }} disabled={busy || !experimentLabel.trim()} onClick={saveExperiment}>保存实验记录</button>
          </section>

          {report && <>
            <section style={cardStyle}>
              <div style={{ marginBottom: 7, color: "var(--text-primary)", fontSize: 12, fontWeight: 600 }}>确定性下一步</div>
              <div style={{ display: "flex", flexDirection: "column", gap: 7 }}>
                {report.nextActions.map((action, index) => <div key={`${action.action}-${index}`} style={{ padding: 8, background: "var(--bg-primary)", borderRadius: 4, border: "1px solid var(--border-color)" }}>
                  <div style={{ display: "flex", alignItems: "center", gap: 7 }}>
                    <span style={{ color: "#58a6ff", fontSize: 11, fontWeight: 700 }}>P{action.priority}</span>
                    <span style={{ color: "var(--text-primary)", fontSize: 11, fontWeight: 600 }}>{action.action}</span>
                    {action.toolName && <code style={{ color: "#d29922", fontSize: 10 }}>{action.toolName}</code>}
                    {action.manualExecutionRequired && <span style={{ marginLeft: "auto", color: "#d29922", fontSize: 10 }}>用户手动执行</span>}
                  </div>
                  <div style={{ marginTop: 4, color: "var(--text-secondary)", fontSize: 10, lineHeight: 1.5 }}>{action.reason}</div>
                  <div style={{ marginTop: 3, color: "var(--text-primary)", fontSize: 10, lineHeight: 1.5 }}>{action.instructions}</div>
                  {!!action.seedCaptureOffsets.length && <div style={{ marginTop: 3, color: "var(--text-tertiary)", fontSize: 10 }}>seed offsets: {action.seedCaptureOffsets.join(", ")}</div>}
                </div>)}
              </div>
            </section>

            <section style={cardStyle}>
              <div style={{ marginBottom: 7, color: "var(--text-primary)", fontSize: 12, fontWeight: 600 }}>诊断结论账本（待保存）</div>
              {!report.generatedClaims.length && <div style={{ color: "var(--text-secondary)", fontSize: 11 }}>当前没有可生成的结构化结论。</div>}
              {report.generatedClaims.map(claim => <div key={claim.claimId} style={{ marginBottom: 6, padding: "6px 8px", background: "var(--bg-primary)", borderLeft: `3px solid ${claimColor(claim.status)}` }}>
                <div style={{ color: claimColor(claim.status), fontSize: 10, textTransform: "uppercase" }}>{claim.status}</div>
                <div style={{ color: "var(--text-primary)", fontSize: 11, marginTop: 2 }}>{claim.statement}</div>
                {!!claim.missingEvidence.length && <div style={{ color: "#d29922", fontSize: 10, marginTop: 3 }}>缺失：{claim.missingEvidence.join("；")}</div>}
              </div>)}
            </section>

            <section style={cardStyle}>
              <div style={{ display: "flex", alignItems: "center", gap: 7 }}>
                <div style={{ color: "var(--text-primary)", fontSize: 12, fontWeight: 600 }}>模拟状态完整度</div>
                <span style={{ color: statusColor(report.stateReadiness.status), fontSize: 10 }}>{report.stateReadiness.status}</span>
              </div>
              <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(230px, 1fr))", gap: 6, marginTop: 7 }}>
                {report.stateReadiness.components.map(component => <div key={component.component} style={{ padding: 7, background: "var(--bg-primary)", border: "1px solid var(--border-color)", borderRadius: 4 }}>
                  <div style={{ display: "flex", gap: 6, alignItems: "center" }}>
                    <span style={{ color: "var(--text-primary)", fontSize: 10, fontWeight: 600 }}>{component.component}</span>
                    <span style={{ marginLeft: "auto", color: statusColor(component.status), fontSize: 10 }}>{component.status}</span>
                  </div>
                  <div style={{ marginTop: 3, color: "var(--text-secondary)", fontSize: 10, lineHeight: 1.45 }}>{component.details}</div>
                  {component.nextAction && <div style={{ marginTop: 3, color: "#d29922", fontSize: 10 }}>{component.nextAction}</div>}
                </div>)}
              </div>
            </section>

            <section style={cardStyle}>
              <div style={{ display: "flex", alignItems: "center", gap: 7 }}>
                <div style={{ color: "var(--text-primary)", fontSize: 12, fontWeight: 600 }}>Claim 反证门禁</div>
                <span style={{ color: report.claimLedgerAudit.blockedClaimCount ? "#d29922" : "#3fb950", fontSize: 10 }}>
                  {report.claimLedgerAudit.passedClaimCount} passed · {report.claimLedgerAudit.blockedClaimCount} blocked · {report.claimLedgerAudit.verifiedGatePassedCount} verified
                </span>
              </div>
              {report.claimLedgerAudit.contradictions.map((item, index) => <div key={index} style={{ marginTop: 5, color: "#e5484d", fontSize: 10 }}>{item}</div>)}
              {report.claimLedgerAudit.claims.filter(claim => claim.gateStatus === "blocked").map(claim => <div key={`${claim.source}-${claim.claimId}`} style={{ marginTop: 6, padding: 7, background: "var(--bg-primary)", borderLeft: "3px solid #d29922" }}>
                <div style={{ color: "var(--text-primary)", fontSize: 10 }}>{claim.claimId} · {claim.currentStatus} → {claim.recommendedStatus}</div>
                {claim.blockers.map((blocker, index) => <div key={index} style={{ marginTop: 3, color: "var(--text-secondary)", fontSize: 10 }}>{blocker}</div>)}
              </div>)}
            </section>

            <section style={cardStyle}>
              <div style={{ display: "flex", alignItems: "center", gap: 7 }}>
                <div style={{ color: "var(--text-primary)", fontSize: 12, fontWeight: 600 }}>受控实验矩阵</div>
                <span style={{ color: statusColor(report.experimentMatrix.status), fontSize: 10 }}>{report.experimentMatrix.status}</span>
                <span style={{ color: "var(--text-tertiary)", fontSize: 10 }}>{report.experimentMatrix.completeExperimentCount}/{report.experimentMatrix.experimentCount} complete · {report.experimentMatrix.controlledPairs.length} controlled pairs</span>
              </div>
              <div style={{ display: "flex", flexWrap: "wrap", gap: 6, marginTop: 7 }}>
                {report.experimentMatrix.axes.map(axis => <span key={axis.axis} style={{ padding: "3px 6px", background: "var(--bg-primary)", color: "var(--text-secondary)", fontSize: 10, borderRadius: 3 }}>
                  {axis.axis}: {axis.values.length} values / {axis.unspecifiedExperimentCount} unspecified
                </span>)}
              </div>
              {report.experimentMatrix.recommendations.slice(0, 4).map(recommendation => <div key={recommendation.action} style={{ marginTop: 6, padding: 7, background: "var(--bg-primary)", borderLeft: "3px solid #58a6ff" }}>
                <div style={{ color: "var(--text-primary)", fontSize: 10, fontWeight: 600 }}>P{recommendation.priority} · {recommendation.action}</div>
                <div style={{ marginTop: 3, color: "var(--text-secondary)", fontSize: 10 }}>{recommendation.reason}</div>
              </div>)}
            </section>
          </>}
        </>}

        <section style={cardStyle}>
          <div style={{ display: "flex", alignItems: "center", gap: 6, marginBottom: 7 }}>
            <div style={{ color: "var(--text-primary)", fontSize: 12, fontWeight: 600 }}>AES 未识别原因诊断</div>
            <button style={buttonStyle} disabled={busy} onClick={chooseBinary}>选择 exact ELF</button>
            <button style={{ ...buttonStyle, background: sessionId ? "var(--btn-primary)" : "var(--bg-input)", color: sessionId ? "#fff" : "var(--text-secondary)" }} disabled={busy || !sessionId} onClick={diagnoseAes}>运行诊断</button>
          </div>
          <div title={binaryPath} style={{ color: "var(--text-tertiary)", fontSize: 10, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{binaryPath || "未选择 ELF；仍可诊断动态 Trace，但不会做静态表来源校验。"}</div>
          {cryptoReport && <div style={{ marginTop: 8 }}>
            <div style={{ color: statusColor(cryptoReport.status), fontSize: 11, fontWeight: 700 }}>{cryptoReport.targetAlgorithm} · {cryptoReport.status} · gate {String(cryptoReport.verificationGateMet)}</div>
            <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(230px, 1fr))", gap: 6, marginTop: 7 }}>
              {cryptoReport.stages.map(stage => <div key={stage.code} style={{ padding: 7, background: "var(--bg-primary)", border: "1px solid var(--border-color)", borderRadius: 4 }}>
                <div style={{ display: "flex", alignItems: "center", gap: 6 }}>
                  <span style={{ color: "var(--text-primary)", fontSize: 11, fontWeight: 600 }}>{stage.label}</span>
                  <span style={{ marginLeft: "auto", color: statusColor(stage.status), fontSize: 10 }}>{stage.status} · {stage.observedCount}</span>
                </div>
                <div style={{ marginTop: 3, color: "var(--text-secondary)", fontSize: 10, lineHeight: 1.45 }}>{stage.details}</div>
                {stage.blockers.map((blocker, index) => <div key={index} style={{ marginTop: 3, color: "#d29922", fontSize: 10 }}>{blocker}</div>)}
              </div>)}
            </div>
            {!!cryptoReport.nextActions.length && <div style={{ marginTop: 8, color: "var(--text-primary)", fontSize: 10, lineHeight: 1.55 }}>{cryptoReport.nextActions.map((action, index) => <div key={index}>• {action}</div>)}</div>}
          </div>}
        </section>
      </div>
    </div>
  );
}
