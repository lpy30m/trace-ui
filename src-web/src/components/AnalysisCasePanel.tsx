import React, { useCallback, useEffect, useMemo, useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import type {
  CoverageCounts,
  CoverageReconciliationInspectionReport,
  CoverageReconciliationScript,
  CoverageReconciliationScriptRequest,
  CoverageScriptScopeKind,
  CryptoDetectionDoctorReport,
  FridaRuntimeAttestationRequest,
  FridaRuntimeAttestationScript,
  ReplayDoctorReport,
  RuntimeAttestationInspectionReport,
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
  if (value.includes("verified") || value === "valid" || value.includes("progress") || value.includes("ready") || value.includes("captured") || value.includes("matched") || value.includes("passed") || value.includes("complete")) return "#3fb950";
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

function coveragePercent(basisPoints?: number): string {
  return basisPoints === undefined ? "" : `${(basisPoints / 100).toFixed(2)}%`;
}

function compactCoverageCounts(counts?: CoverageCounts): string {
  if (!counts) return "";
  return `insn ${counts.instructions} · blocks ${counts.blocks} · branches ${counts.branches} · functions ${counts.functions} · edges ${counts.edges}`;
}

function artifactSummary(artifact: TraceCaseArtifact): string {
  const parts: string[] = [];
  if (artifact.summary.moduleName) parts.push(artifact.summary.moduleName);
  if (artifact.summary.runtimeAttestationStatus) parts.push(artifact.summary.runtimeAttestationStatus);
  if (artifact.summary.cryptoKatAlgorithm) parts.push(artifact.summary.cryptoKatAlgorithm);
  if (artifact.summary.cryptoKatStatus) parts.push(artifact.summary.cryptoKatStatus);
  if (artifact.summary.cryptoKatBytesChecked !== undefined) parts.push(`${artifact.summary.cryptoKatBytesChecked} KAT bytes`);
  if (artifact.summary.coverageStatus) parts.push(artifact.summary.coverageStatus);
  if (artifact.summary.coverageObservedStaticCounts && artifact.summary.coverageStaticCounts) {
    parts.push(`${artifact.summary.coverageObservedStaticCounts.blocks}/${artifact.summary.coverageStaticCounts.blocks} static blocks`);
  }
  if (artifact.summary.matchedExecutableBytes !== undefined && artifact.summary.totalExecutableBytes !== undefined) {
    parts.push(`${artifact.summary.matchedExecutableBytes}/${artifact.summary.totalExecutableBytes} executable bytes`);
  }
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
  const [attestationModuleName, setAttestationModuleName] = useState("");
  const [attestationBinaryArtifactId, setAttestationBinaryArtifactId] = useState("");
  const [attestationBinaryPath, setAttestationBinaryPath] = useState("");
  const [attestationWindowBytes, setAttestationWindowBytes] = useState(4096);
  const [attestationMaxWindows, setAttestationMaxWindows] = useState(1024);
  const [attestationScript, setAttestationScript] = useState<FridaRuntimeAttestationScript | null>(null);
  const [attestationCapturePath, setAttestationCapturePath] = useState("");
  const [attestationInspection, setAttestationInspection] = useState<RuntimeAttestationInspectionReport | null>(null);
  const [attestationSavedPath, setAttestationSavedPath] = useState("");
  const [coverageBinaryArtifactId, setCoverageBinaryArtifactId] = useState("");
  const [coverageOllvmArtifactId, setCoverageOllvmArtifactId] = useState("");
  const [coverageBinaryPath, setCoverageBinaryPath] = useState("");
  const [coverageOllvmPath, setCoverageOllvmPath] = useState("");
  const [coverageClaimScope, setCoverageClaimScope] = useState("");
  const [coverageScopeKind, setCoverageScopeKind] = useState<CoverageScriptScopeKind>("function-closure");
  const [coverageRangeStart, setCoverageRangeStart] = useState("");
  const [coverageRangeEnd, setCoverageRangeEnd] = useState("");
  const [coverageScript, setCoverageScript] = useState<CoverageReconciliationScript | null>(null);
  const [coverageSavedPath, setCoverageSavedPath] = useState("");
  const [coverageArtifactPath, setCoverageArtifactPath] = useState("");
  const [coverageInspection, setCoverageInspection] = useState<CoverageReconciliationInspectionReport | null>(null);
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

  useEffect(() => {
    if (!document) return;
    const binaries = document.case.artifacts.filter(artifact => artifact.kind === "static-binary");
    const preferred = document.case.exactBinaryArtifactId && binaries.some(artifact => artifact.artifactId === document.case.exactBinaryArtifactId)
      ? document.case.exactBinaryArtifactId
      : binaries[0]?.artifactId ?? "";
    setAttestationBinaryArtifactId(current => binaries.some(artifact => artifact.artifactId === current) ? current : preferred);
    const selected = binaries.find(artifact => artifact.artifactId === preferred);
    setAttestationModuleName(current => current || selected?.summary.moduleName || "");
    setCoverageBinaryArtifactId(current => binaries.some(artifact => artifact.artifactId === current) ? current : preferred);
    const ollvmArtifacts = document.case.artifacts.filter(artifact => artifact.kind === "ollvm-report");
    setCoverageOllvmArtifactId(current => ollvmArtifacts.some(artifact => artifact.artifactId === current)
      ? current
      : ollvmArtifacts[0]?.artifactId ?? "");
    setCoverageClaimScope(current => current || document.case.claims[0]?.scope || "");
  }, [document]);

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

  const buildAttestationRequest = useCallback((): FridaRuntimeAttestationRequest => {
    if (!attestationModuleName.trim()) throw new Error("请输入运行时模块 basename，例如 libtarget.so。");
    if (!attestationBinaryPath.trim()) throw new Error("请选择生成认证计划所用的 exact AArch64 ELF。");
    return {
      moduleName: attestationModuleName.trim(),
      staticBinaryPath: attestationBinaryPath.trim(),
      windowBytes: attestationWindowBytes,
      maxWindows: attestationMaxWindows,
    };
  }, [attestationModuleName, attestationBinaryPath, attestationWindowBytes, attestationMaxWindows]);

  const chooseAttestationBinary = useCallback(async () => {
    const { open } = await import("@tauri-apps/plugin-dialog");
    const selected = await open({
      title: "选择运行时认证对应的 exact AArch64 ELF",
      multiple: false,
      directory: false,
    });
    if (typeof selected === "string") {
      setAttestationBinaryPath(selected);
      setAttestationScript(null);
      setAttestationInspection(null);
      setAttestationSavedPath("");
    }
  }, []);

  const generateRuntimeAttestation = useCallback(async () => {
    setBusy(true); setError(null);
    try {
      const request = buildAttestationRequest();
      const generated = await invoke<FridaRuntimeAttestationScript>("generate_frida_runtime_attestation", { request });
      setAttestationScript(generated);
      setAttestationSavedPath("");
    } catch (e) { setError(String(e)); }
    finally { setBusy(false); }
  }, [buildAttestationRequest]);

  const saveRuntimeAttestation = useCallback(async () => {
    let request: FridaRuntimeAttestationRequest;
    try { request = buildAttestationRequest(); }
    catch (e) { setError(String(e)); return; }
    const { save } = await import("@tauri-apps/plugin-dialog");
    const selected = await save({
      title: "保存 Frida 运行时镜像认证脚本",
      defaultPath: attestationScript?.fileName ?? "trace-ui-runtime-attestation.js",
      filters: [{ name: "JavaScript", extensions: ["js"] }],
    });
    if (!selected) return;
    setBusy(true); setError(null);
    try {
      setAttestationSavedPath(await invoke<string>("save_frida_runtime_attestation", { path: selected, request }));
    } catch (e) { setError(String(e)); }
    finally { setBusy(false); }
  }, [attestationScript, buildAttestationRequest]);

  const inspectRuntimeAttestation = useCallback(async () => {
    let request: FridaRuntimeAttestationRequest;
    try { request = buildAttestationRequest(); }
    catch (e) { setError(String(e)); return; }
    const { open } = await import("@tauri-apps/plugin-dialog");
    const selected = await open({
      title: "选择手动运行 Frida 后保存的认证 JSON/NDJSON/日志",
      multiple: false,
      directory: false,
    });
    if (typeof selected !== "string") return;
    setBusy(true); setError(null);
    try {
      const inspection = await invoke<RuntimeAttestationInspectionReport>("inspect_runtime_attestation", {
        capturePath: selected,
        exactBinaryPath: request.staticBinaryPath,
      });
      setAttestationCapturePath(selected);
      setAttestationInspection(inspection);
    } catch (e) { setError(String(e)); }
    finally { setBusy(false); }
  }, [buildAttestationRequest]);

  const importRuntimeAttestation = useCallback(async () => {
    if (!document || !attestationCapturePath || !attestationBinaryArtifactId) return;
    setBusy(true); setError(null);
    try {
      const imported = await invoke<{ case: TraceAnalysisCaseDocument["case"] }>("add_analysis_case_artifact", {
        casePath: document.casePath,
        artifactPath: attestationCapturePath,
        kindHint: "runtime-attestation",
        label: `Runtime attestation · ${attestationModuleName.trim() || "module"}`,
        parentArtifactIds: [attestationBinaryArtifactId],
      });
      remember({ casePath: document.casePath, case: imported.case });
      setReport(null);
    } catch (e) { setError(String(e)); }
    finally { setBusy(false); }
  }, [document, attestationCapturePath, attestationBinaryArtifactId, attestationModuleName, remember]);

  const buildCoverageRequest = useCallback((): CoverageReconciliationScriptRequest => {
    if (!coverageBinaryPath.trim()) throw new Error("请选择用于静态覆盖清单的 exact AArch64 ELF。");
    if (!coverageOllvmPath.trim()) throw new Error("请选择作为动态已执行集合来源的 trace-ui/ollvm-v1 JSON。");
    if (!coverageClaimScope.trim()) throw new Error("请输入与 Claim Ledger 完全一致的 claim scope。");
    if (coverageScopeKind === "range" && (!coverageRangeStart.trim() || !coverageRangeEnd.trim())) {
      throw new Error("range 覆盖范围需要起止 module-relative offset。");
    }
    return {
      staticBinaryPath: coverageBinaryPath.trim(),
      ollvmReportPath: coverageOllvmPath.trim(),
      claimScope: coverageClaimScope.trim(),
      scopeKind: coverageScopeKind,
      rangeStartOffset: coverageScopeKind === "range" ? coverageRangeStart.trim() : undefined,
      rangeEndOffset: coverageScopeKind === "range" ? coverageRangeEnd.trim() : undefined,
      maxInstructions: 500_000,
      maxBlocks: 100_000,
      maxEdges: 250_000,
      maxFunctions: 25_000,
    };
  }, [coverageBinaryPath, coverageOllvmPath, coverageClaimScope, coverageScopeKind, coverageRangeStart, coverageRangeEnd]);

  const chooseCoverageBinary = useCallback(async () => {
    const { open } = await import("@tauri-apps/plugin-dialog");
    const selected = await open({ title: "选择覆盖核对使用的 exact AArch64 ELF", multiple: false, directory: false });
    if (typeof selected === "string") {
      setCoverageBinaryPath(selected);
      setCoverageScript(null);
      setCoverageInspection(null);
    }
  }, []);

  const chooseCoverageOllvm = useCallback(async () => {
    const { open } = await import("@tauri-apps/plugin-dialog");
    const selected = await open({
      title: "选择动态来源 trace-ui/ollvm-v1 JSON",
      multiple: false,
      directory: false,
      filters: [{ name: "JSON", extensions: ["json"] }],
    });
    if (typeof selected === "string") {
      setCoverageOllvmPath(selected);
      setCoverageScript(null);
      setCoverageInspection(null);
    }
  }, []);

  const generateCoverageScript = useCallback(async () => {
    let request: CoverageReconciliationScriptRequest;
    try { request = buildCoverageRequest(); }
    catch (e) { setError(String(e)); return; }
    setBusy(true); setError(null);
    try {
      setCoverageScript(await invoke<CoverageReconciliationScript>("generate_coverage_reconciliation_script", {
        request,
        outputPath: null,
      }));
      setCoverageSavedPath("");
    } catch (e) { setError(String(e)); }
    finally { setBusy(false); }
  }, [buildCoverageRequest]);

  const saveCoverageScript = useCallback(async () => {
    let request: CoverageReconciliationScriptRequest;
    try { request = buildCoverageRequest(); }
    catch (e) { setError(String(e)); return; }
    const { save } = await import("@tauri-apps/plugin-dialog");
    const selected = await save({
      title: "保存手动 angr 覆盖核对脚本",
      defaultPath: coverageScript?.fileName ?? "trace-ui-coverage.py",
      filters: [{ name: "Python", extensions: ["py"] }],
    });
    if (!selected) return;
    setBusy(true); setError(null);
    try {
      const generated = await invoke<CoverageReconciliationScript>("generate_coverage_reconciliation_script", {
        request,
        outputPath: selected,
      });
      setCoverageScript(generated);
      setCoverageSavedPath(selected.endsWith(".py") ? selected : `${selected}.py`);
    } catch (e) { setError(String(e)); }
    finally { setBusy(false); }
  }, [buildCoverageRequest, coverageScript]);

  const inspectCoverageArtifact = useCallback(async () => {
    let request: CoverageReconciliationScriptRequest;
    try { request = buildCoverageRequest(); }
    catch (e) { setError(String(e)); return; }
    const { open } = await import("@tauri-apps/plugin-dialog");
    const selected = await open({
      title: "选择手动运行 angr 后生成的 coverage JSON",
      multiple: false,
      directory: false,
      filters: [{ name: "JSON", extensions: ["json"] }],
    });
    if (typeof selected !== "string") return;
    setBusy(true); setError(null);
    try {
      const inspection = await invoke<CoverageReconciliationInspectionReport>("inspect_coverage_reconciliation", {
        artifactPath: selected,
        staticBinaryPath: request.staticBinaryPath,
        sourceArtifactPaths: [request.ollvmReportPath],
      });
      setCoverageArtifactPath(selected);
      setCoverageInspection(inspection);
    } catch (e) { setError(String(e)); }
    finally { setBusy(false); }
  }, [buildCoverageRequest]);

  const importCoverageArtifact = useCallback(async () => {
    if (!document || !coverageArtifactPath || !coverageBinaryArtifactId || !coverageOllvmArtifactId) return;
    setBusy(true); setError(null);
    try {
      const imported = await invoke<{ case: TraceAnalysisCaseDocument["case"] }>("add_analysis_case_artifact", {
        casePath: document.casePath,
        artifactPath: coverageArtifactPath,
        kindHint: "coverage-report",
        label: `Coverage · ${coverageInspection?.moduleName ?? "module"}`,
        parentArtifactIds: [coverageBinaryArtifactId, coverageOllvmArtifactId],
      });
      remember({ casePath: document.casePath, case: imported.case });
      setReport(null);
    } catch (e) { setError(String(e)); }
    finally { setBusy(false); }
  }, [document, coverageArtifactPath, coverageBinaryArtifactId, coverageOllvmArtifactId, coverageInspection, remember]);

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

  const staticBinaryArtifacts = useMemo(
    () => document?.case.artifacts.filter(artifact => artifact.kind === "static-binary") ?? [],
    [document],
  );
  const ollvmArtifacts = useMemo(
    () => document?.case.artifacts.filter(artifact => artifact.kind === "ollvm-report") ?? [],
    [document],
  );
  const selectedAttestationBinary = useMemo(
    () => staticBinaryArtifacts.find(artifact => artifact.artifactId === attestationBinaryArtifactId),
    [staticBinaryArtifacts, attestationBinaryArtifactId],
  );
  const selectedCoverageBinary = useMemo(
    () => staticBinaryArtifacts.find(artifact => artifact.artifactId === coverageBinaryArtifactId),
    [staticBinaryArtifacts, coverageBinaryArtifactId],
  );
  const selectedCoverageOllvm = useMemo(
    () => ollvmArtifacts.find(artifact => artifact.artifactId === coverageOllvmArtifactId),
    [ollvmArtifacts, coverageOllvmArtifactId],
  );

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
            <div style={{ display: "flex", alignItems: "center", gap: 7 }}>
              <div style={{ color: "var(--text-primary)", fontSize: 12, fontWeight: 600 }}>运行时镜像认证（手动 Frida）</div>
              {attestationInspection && <span style={{ color: statusColor(attestationInspection.status), fontSize: 10 }}>
                {attestationInspection.status} · gate {String(attestationInspection.verificationGateMet)}
              </span>}
            </div>
            <div style={{ marginTop: 4, color: "var(--text-secondary)", fontSize: 10, lineHeight: 1.5 }}>
              生成脚本后由你在目标环境手动运行，再导入输出。Trace UI 不会连接、启动、加载或执行 Frida。只有 exact ELF、计划和全部 file-backed executable PT_LOAD 字节完整匹配，才会得到仅限 runtime-image 的 Verified；抽样匹配只能是 Related。
            </div>
            <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(190px, 1fr))", gap: 6, marginTop: 8 }}>
              <input
                aria-label="运行时模块 basename"
                value={attestationModuleName}
                onChange={event => { setAttestationModuleName(event.target.value); setAttestationScript(null); }}
                placeholder="libtarget.so"
                style={{ ...buttonStyle, height: 28 }}
              />
              <select
                aria-label="认证绑定的 exact ELF artifact"
                value={attestationBinaryArtifactId}
                onChange={event => { setAttestationBinaryArtifactId(event.target.value); setAttestationInspection(null); }}
                style={{ ...buttonStyle, height: 28 }}
              >
                <option value="">选择案件中的 exact ELF</option>
                {staticBinaryArtifacts.map(artifact => <option key={artifact.artifactId} value={artifact.artifactId}>
                  {artifact.label} · {shortHash(artifact.summary.binarySha256 ?? artifact.sha256)}
                </option>)}
              </select>
              <input
                aria-label="运行时认证 exact ELF 路径"
                value={attestationBinaryPath}
                onChange={event => { setAttestationBinaryPath(event.target.value); setAttestationScript(null); setAttestationInspection(null); }}
                placeholder="exact ELF 绝对路径"
                style={{ ...buttonStyle, height: 28 }}
              />
              <button type="button" style={buttonStyle} disabled={busy} onClick={chooseAttestationBinary}>选择 ELF 文件</button>
              <label style={{ color: "var(--text-secondary)", fontSize: 10 }}>
                window bytes
                <input
                  aria-label="认证窗口字节"
                  type="number"
                  min={256}
                  max={65536}
                  step={256}
                  value={attestationWindowBytes}
                  onChange={event => { setAttestationWindowBytes(Number(event.target.value)); setAttestationScript(null); }}
                  style={{ ...buttonStyle, width: "100%", height: 28, marginTop: 2 }}
                />
              </label>
              <label style={{ color: "var(--text-secondary)", fontSize: 10 }}>
                max windows
                <input
                  aria-label="认证最大窗口数"
                  type="number"
                  min={1}
                  max={4096}
                  value={attestationMaxWindows}
                  onChange={event => { setAttestationMaxWindows(Number(event.target.value)); setAttestationScript(null); }}
                  style={{ ...buttonStyle, width: "100%", height: 28, marginTop: 2 }}
                />
              </label>
            </div>
            {!staticBinaryArtifacts.length && <div style={{ marginTop: 6, color: "#d29922", fontSize: 10 }}>请先把 exact AArch64 ELF 导入案件；认证捕获必须绑定唯一 static-binary parent。</div>}
            {selectedAttestationBinary && <div style={{ marginTop: 5, color: "var(--text-tertiary)", fontSize: 10 }}>
              parent artifact: {selectedAttestationBinary.label} · {shortHash(selectedAttestationBinary.summary.binarySha256 ?? selectedAttestationBinary.sha256)}
            </div>}
            <div style={{ display: "flex", flexWrap: "wrap", gap: 6, marginTop: 8 }}>
              <button type="button" style={{ ...buttonStyle, background: "var(--btn-primary)", color: "#fff" }} disabled={busy || !attestationBinaryPath.trim() || !attestationModuleName.trim()} onClick={generateRuntimeAttestation}>生成认证脚本</button>
              <button type="button" style={buttonStyle} disabled={busy || !attestationScript} onClick={saveRuntimeAttestation}>保存脚本</button>
              <button type="button" style={buttonStyle} disabled={busy || !attestationBinaryPath.trim()} onClick={inspectRuntimeAttestation}>检查手动捕获</button>
              <button type="button" style={buttonStyle} disabled={busy || !attestationInspection || !attestationCapturePath || !attestationBinaryArtifactId} onClick={importRuntimeAttestation}>导入案件（反证也保留）</button>
            </div>
            {attestationScript && <div style={{ marginTop: 8, padding: 7, background: "var(--bg-primary)", borderLeft: `3px solid ${attestationScript.plan.completeExecutableCoverage ? "#3fb950" : "#d29922"}` }}>
              <div style={{ color: "var(--text-primary)", fontSize: 10, fontWeight: 600 }}>{attestationScript.fileName}</div>
              <div style={{ marginTop: 3, color: "var(--text-secondary)", fontSize: 10 }}>
                {attestationScript.plan.coverageStrategy} · {attestationScript.plan.selectedExecutableBytes}/{attestationScript.plan.totalExecutableBytes} executable bytes · {attestationScript.plan.windows.length} windows
              </div>
              {!attestationScript.plan.completeExecutableCoverage && <div style={{ marginTop: 3, color: "#d29922", fontSize: 10 }}>当前计划为确定性抽样，匹配后仍只能标记 Related。提高 max windows 或调整 window bytes 后重新生成。</div>}
              {attestationSavedPath && <div title={attestationSavedPath} style={{ marginTop: 3, color: "#58a6ff", fontSize: 10, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>已保存：{attestationSavedPath}</div>}
            </div>}
            {attestationInspection && <div style={{ marginTop: 8, display: "flex", flexDirection: "column", gap: 6 }}>
              {attestationInspection.records.map(record => <div key={record.attestationId} style={{ padding: 7, background: "var(--bg-primary)", border: "1px solid var(--border-color)", borderRadius: 4 }}>
                <div style={{ display: "flex", alignItems: "center", gap: 6 }}>
                  <span style={{ color: "var(--text-primary)", fontSize: 10, fontWeight: 600 }}>{record.moduleName}</span>
                  <span style={{ marginLeft: "auto", color: statusColor(record.status), fontSize: 10 }}>{record.status}</span>
                </div>
                <div style={{ marginTop: 3, color: "var(--text-secondary)", fontSize: 10 }}>
                  executable bytes {record.matchedExecutableBytes}/{record.totalExecutableBytes} · windows {record.matchedWindowCount} matched / {record.mismatchedWindowCount} mismatched / {record.unreadableWindowCount} unreadable / {record.missingWindowCount} missing
                </div>
                {record.counterEvidence.slice(0, 3).map((item, index) => <div key={index} style={{ marginTop: 3, color: "#e5484d", fontSize: 10 }}>{item}</div>)}
                {record.blockers.slice(0, 3).map((item, index) => <div key={index} style={{ marginTop: 3, color: "#d29922", fontSize: 10 }}>{item}</div>)}
              </div>)}
            </div>}
            {!!report?.runtimeAttestations.length && <div style={{ marginTop: 8 }}>
              <div style={{ color: "var(--text-primary)", fontSize: 10, fontWeight: 600 }}>案件中的严格认证报告</div>
              {report.runtimeAttestations.map(item => <div key={item.artifactId} style={{ marginTop: 5, padding: 7, background: "var(--bg-primary)", borderLeft: `3px solid ${statusColor(item.report.status)}` }}>
                <span style={{ color: statusColor(item.report.status), fontSize: 10 }}>{item.report.status}</span>
                <span style={{ marginLeft: 6, color: "var(--text-secondary)", fontSize: 10 }}>{item.report.records.reduce((sum, record) => sum + record.matchedExecutableBytes, 0)}/{item.report.records.reduce((sum, record) => sum + record.totalExecutableBytes, 0)} executable bytes</span>
              </div>)}
            </div>}
            {!!report?.cryptoKats.length && <div style={{ marginTop: 8 }}>
              <div style={{ color: "var(--text-primary)", fontSize: 10, fontWeight: 600 }}>Strict crypto KAT reports</div>
              {report.cryptoKats.map(item => <div key={item.artifactId} style={{ marginTop: 5, padding: 7, background: "var(--bg-primary)", borderLeft: `3px solid ${statusColor(item.report.status)}` }}>
                <span style={{ color: statusColor(item.report.status), fontSize: 10 }}>{item.report.status}</span>
                <span style={{ marginLeft: 6, color: "var(--text-secondary)", fontSize: 10 }}>{item.report.algorithm} · {item.report.bytesChecked + item.report.tagBytesChecked} checked bytes</span>
                <div title={item.report.claimScope} style={{ marginTop: 3, color: "var(--text-tertiary)", fontSize: 9, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{item.report.claimScope}</div>
                {item.report.firstMismatch && <div style={{ marginTop: 3, color: "#e5484d", fontSize: 10 }}>first {item.report.firstMismatch.component} mismatch: [{item.report.firstMismatch.startOffset}, {item.report.firstMismatch.endOffsetExclusive})</div>}
              </div>)}
            </div>}
          </section>

          <section style={cardStyle}>
            <div style={{ display: "flex", alignItems: "center", gap: 7 }}>
              <div style={{ color: "var(--text-primary)", fontSize: 12, fontWeight: 600 }}>Coverage-aware Claim Gate（手动 angr）</div>
              {coverageInspection && <span style={{ color: statusColor(coverageInspection.status), fontSize: 10 }}>
                {coverageInspection.status} · gate {String(coverageInspection.coverageGateMet)}
              </span>}
            </div>
            <div style={{ marginTop: 4, color: "var(--text-secondary)", fontSize: 10, lineHeight: 1.5 }}>
              用 exact ELF 建立显式静态指令/块/分支/函数/边集合，再与 OLLVM 动态已执行集合核对。脚本由你手动运行；Trace UI 不安装或执行 angr。即使覆盖门禁通过，也只限制结论的最高等级，不能单独证明“没有 AES”、全局 opaque 或完整 CFG。
            </div>
            <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(210px, 1fr))", gap: 6, marginTop: 8 }}>
              <select
                aria-label="Coverage exact ELF parent"
                value={coverageBinaryArtifactId}
                onChange={event => { setCoverageBinaryArtifactId(event.target.value); setCoverageInspection(null); }}
                style={{ ...buttonStyle, height: 28 }}
              >
                <option value="">选择 exact ELF parent</option>
                {staticBinaryArtifacts.map(artifact => <option key={artifact.artifactId} value={artifact.artifactId}>
                  {artifact.label} · {shortHash(artifact.summary.binarySha256 ?? artifact.sha256)}
                </option>)}
              </select>
              <select
                aria-label="Coverage OLLVM source parent"
                value={coverageOllvmArtifactId}
                onChange={event => { setCoverageOllvmArtifactId(event.target.value); setCoverageInspection(null); }}
                style={{ ...buttonStyle, height: 28 }}
              >
                <option value="">选择 OLLVM source parent</option>
                {ollvmArtifacts.map(artifact => <option key={artifact.artifactId} value={artifact.artifactId}>
                  {artifact.label} · {shortHash(artifact.sha256)}
                </option>)}
              </select>
              <input
                aria-label="Coverage exact ELF path"
                value={coverageBinaryPath}
                onChange={event => { setCoverageBinaryPath(event.target.value); setCoverageScript(null); setCoverageInspection(null); }}
                placeholder="exact ELF 绝对路径"
                style={{ ...buttonStyle, height: 28 }}
              />
              <button type="button" style={buttonStyle} disabled={busy} onClick={chooseCoverageBinary}>选择 Coverage ELF</button>
              <input
                aria-label="Coverage OLLVM report path"
                value={coverageOllvmPath}
                onChange={event => { setCoverageOllvmPath(event.target.value); setCoverageScript(null); setCoverageInspection(null); }}
                placeholder="trace-ui/ollvm-v1 JSON 绝对路径"
                style={{ ...buttonStyle, height: 28 }}
              />
              <button type="button" style={buttonStyle} disabled={busy} onClick={chooseCoverageOllvm}>选择 OLLVM 报告</button>
              <input
                aria-label="Coverage claim scope"
                list="coverage-claim-scopes"
                value={coverageClaimScope}
                onChange={event => { setCoverageClaimScope(event.target.value); setCoverageScript(null); setCoverageInspection(null); }}
                placeholder="必须与 claim.scope 完全一致"
                style={{ ...buttonStyle, height: 28 }}
              />
              <datalist id="coverage-claim-scopes">
                {document.case.claims.map(claim => <option key={claim.claimId} value={claim.scope}>{claim.statement}</option>)}
              </datalist>
              <select
                aria-label="Coverage scope kind"
                value={coverageScopeKind}
                onChange={event => { setCoverageScopeKind(event.target.value as CoverageScriptScopeKind); setCoverageScript(null); setCoverageInspection(null); }}
                style={{ ...buttonStyle, height: 28 }}
              >
                <option value="function-closure">function closure（推荐）</option>
                <option value="range">module-relative range</option>
                <option value="module">whole module（昂贵）</option>
              </select>
              {coverageScopeKind === "range" && <>
                <input aria-label="Coverage range start" value={coverageRangeStart} onChange={event => { setCoverageRangeStart(event.target.value); setCoverageScript(null); }} placeholder="0x1000" style={{ ...buttonStyle, height: 28 }} />
                <input aria-label="Coverage range end" value={coverageRangeEnd} onChange={event => { setCoverageRangeEnd(event.target.value); setCoverageScript(null); }} placeholder="0x1ffc" style={{ ...buttonStyle, height: 28 }} />
              </>}
            </div>
            {(!staticBinaryArtifacts.length || !ollvmArtifacts.length) && <div style={{ marginTop: 6, color: "#d29922", fontSize: 10 }}>
              请先把 exact ELF 和源 OLLVM report 都导入案件；coverage artifact 必须同时绑定二者，不能只信百分比字段。
            </div>}
            {(selectedCoverageBinary || selectedCoverageOllvm) && <div style={{ marginTop: 5, color: "var(--text-tertiary)", fontSize: 10 }}>
              parents: {selectedCoverageBinary?.label ?? "missing ELF"} · {selectedCoverageOllvm?.label ?? "missing OLLVM source"}
            </div>}
            <div style={{ display: "flex", flexWrap: "wrap", gap: 6, marginTop: 8 }}>
              <button type="button" style={{ ...buttonStyle, background: "var(--btn-primary)", color: "#fff" }} disabled={busy || !coverageBinaryPath.trim() || !coverageOllvmPath.trim() || !coverageClaimScope.trim()} onClick={generateCoverageScript}>生成 angr Coverage 脚本</button>
              <button type="button" style={buttonStyle} disabled={busy || !coverageScript} onClick={saveCoverageScript}>保存 Coverage 脚本</button>
              <button type="button" style={buttonStyle} disabled={busy || !coverageBinaryPath.trim() || !coverageOllvmPath.trim()} onClick={inspectCoverageArtifact}>检查 Coverage JSON</button>
              <button type="button" style={buttonStyle} disabled={busy || !coverageInspection || !coverageArtifactPath || !coverageBinaryArtifactId || !coverageOllvmArtifactId} onClick={importCoverageArtifact}>导入 Coverage 案件证据</button>
            </div>
            {coverageScript && <div style={{ marginTop: 8, padding: 7, background: "var(--bg-primary)", borderLeft: "3px solid #58a6ff" }}>
              <div style={{ color: "var(--text-primary)", fontSize: 10, fontWeight: 600 }}>{coverageScript.fileName}</div>
              <div style={{ marginTop: 3, color: "var(--text-secondary)", fontSize: 10 }}>
                {coverageScript.moduleName} · exact ELF {shortHash(coverageScript.expectedBinaryIdentity.binarySha256)} · source {shortHash(coverageScript.sourceOllvmSha256)}
              </div>
              <div title={coverageScript.claimScope} style={{ marginTop: 3, color: "var(--text-tertiary)", fontSize: 9, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>scope: {coverageScript.claimScope}</div>
              {coverageSavedPath && <div title={coverageSavedPath} style={{ marginTop: 3, color: "#58a6ff", fontSize: 10, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>已保存：{coverageSavedPath}</div>}
            </div>}
            {coverageInspection && <div style={{ marginTop: 8, padding: 8, background: "var(--bg-primary)", border: "1px solid var(--border-color)", borderLeft: `3px solid ${coverageInspection.coverageGateMet ? "#3fb950" : "#d29922"}`, borderRadius: 4 }}>
              <div style={{ display: "flex", alignItems: "center", gap: 7 }}>
                <span style={{ color: "var(--text-primary)", fontSize: 10, fontWeight: 600 }}>{coverageInspection.moduleName}</span>
                <span style={{ color: statusColor(coverageInspection.status), fontSize: 10 }}>{coverageInspection.status}</span>
                <span style={{ marginLeft: "auto", color: coverageInspection.coverageGateMet ? "#3fb950" : "#d29922", fontSize: 10 }}>gate {String(coverageInspection.coverageGateMet)}</span>
              </div>
              <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(160px, 1fr))", gap: 5, marginTop: 6 }}>
                {(["instructions", "blocks", "branches", "functions", "edges"] as const).map(kind => <div key={kind} style={{ padding: 5, borderRadius: 3, background: "var(--bg-secondary)", color: "var(--text-secondary)", fontSize: 9 }}>
                  <strong style={{ color: "var(--text-primary)" }}>{kind}</strong> {coverageInspection.summary.observedStaticCounts[kind]}/{coverageInspection.summary.staticCounts[kind]} · {coveragePercent(coverageInspection.summary.coverageBasisPoints[kind])}
                </div>)}
              </div>
              <div style={{ marginTop: 5, color: coverageInspection.summary.coverageComplete ? "#3fb950" : "#d29922", fontSize: 10 }}>
                static complete {String(coverageInspection.summary.staticInventoryComplete)} · dynamic complete {String(coverageInspection.summary.dynamicCaptureComplete)} · listed-site complete {String(coverageInspection.summary.coverageComplete)}
              </div>
              <div style={{ marginTop: 3, color: "#d29922", fontSize: 9 }}>uncovered: {compactCoverageCounts(coverageInspection.summary.uncoveredCounts)}</div>
              <div style={{ marginTop: 3, color: coverageInspection.summary.dynamicOnlyCounts.instructions || coverageInspection.summary.dynamicOnlyCounts.blocks ? "#e5484d" : "var(--text-tertiary)", fontSize: 9 }}>dynamic-only: {compactCoverageCounts(coverageInspection.summary.dynamicOnlyCounts)}</div>
              {!!coverageInspection.uncoveredSamples.blocks.length && <div style={{ marginTop: 3, color: "#58a6ff", fontSize: 9 }}>uncovered blocks: {coverageInspection.uncoveredSamples.blocks.slice(0, 12).join(", ")}</div>}
              {!!coverageInspection.uncoveredSamples.branches.length && <div style={{ marginTop: 3, color: "#58a6ff", fontSize: 9 }}>uncovered branches: {coverageInspection.uncoveredSamples.branches.slice(0, 12).join(", ")}</div>}
              {coverageInspection.missingSourceSha256s.map(value => <div key={value} style={{ marginTop: 3, color: "#e5484d", fontSize: 9 }}>missing source SHA-256: {value}</div>)}
            </div>}
            {!!report?.coverageReconciliations.length && <div style={{ marginTop: 8 }}>
              <div style={{ color: "var(--text-primary)", fontSize: 10, fontWeight: 600 }}>案件中的 Coverage Claim Gates</div>
              {report.coverageReconciliations.map(item => <div key={item.artifactId} style={{ marginTop: 5, padding: 7, background: "var(--bg-primary)", borderLeft: `3px solid ${item.report.coverageGateMet ? "#3fb950" : "#d29922"}` }}>
                <span style={{ color: statusColor(item.report.status), fontSize: 10 }}>{item.report.status}</span>
                <span style={{ marginLeft: 6, color: "var(--text-secondary)", fontSize: 10 }}>blocks {item.report.summary.observedStaticCounts.blocks}/{item.report.summary.staticCounts.blocks} · branches {item.report.summary.observedStaticCounts.branches}/{item.report.summary.staticCounts.branches}</span>
                <div title={item.report.claimScope} style={{ marginTop: 3, color: "var(--text-tertiary)", fontSize: 9, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{item.report.claimScope}</div>
              </div>)}
            </div>}
          </section>

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
              <div style={{ display: "flex", alignItems: "center", gap: 7 }}>
                <div style={{ color: "var(--text-primary)", fontSize: 12, fontWeight: 600 }}>AI 信息增益补采样计划</div>
                <span style={{ color: statusColor(report.capturePlan.status), fontSize: 10 }}>{report.capturePlan.status}</span>
                <span style={{ color: "var(--text-tertiary)", fontSize: 10 }}>{report.capturePlan.targetCount} targets</span>
              </div>
              {report.capturePlan.targets.slice(0, 6).map(target => <div key={target.redundancyKey} style={{ marginTop: 7, padding: 8, background: "var(--bg-primary)", borderRadius: 4, borderLeft: `3px solid ${target.informationGainScore >= 95 ? "#e5484d" : target.informationGainScore >= 85 ? "#d29922" : "#58a6ff"}` }}>
                <div style={{ display: "flex", alignItems: "center", gap: 7 }}>
                  <span style={{ color: "#58a6ff", fontSize: 10, fontWeight: 700 }}>#{target.rank} · IG {target.informationGainScore}</span>
                  <span style={{ color: "var(--text-primary)", fontSize: 10, fontWeight: 600 }}>{target.action}</span>
                  <code style={{ color: "var(--text-tertiary)", fontSize: 9 }}>{target.targetKind}</code>
                  {target.manualExecutionRequired && <span style={{ marginLeft: "auto", color: "#d29922", fontSize: 9 }}>用户手动执行</span>}
                </div>
                <div style={{ marginTop: 3, color: "var(--text-secondary)", fontSize: 10, lineHeight: 1.45 }}>{target.reason}</div>
                {!!target.moduleRelativeOffsets.length && <div style={{ marginTop: 3, color: "#58a6ff", fontSize: 9 }}>offsets: {target.moduleRelativeOffsets.join(", ")}</div>}
                {!!target.registers.length && <div style={{ marginTop: 3, color: "var(--text-tertiary)", fontSize: 9 }}>registers: {target.registers.join(" · ")}</div>}
                {!!target.memoryRequirements.length && <div style={{ marginTop: 3, color: "var(--text-tertiary)", fontSize: 9 }}>memory: {target.memoryRequirements.join(" · ")}</div>}
                <div style={{ marginTop: 3, color: "#3fb950", fontSize: 9 }}>成功条件：{target.successCriteria}</div>
              </div>)}
            </section>

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
                {claim.coverageRequirement && claim.coverageRequirement !== "not-required" && <div style={{ color: "#58a6ff", fontSize: 9, marginTop: 3 }}>coverage requirement: {claim.coverageRequirement} · scope: {claim.scope}</div>}
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
              {report.claimLedgerAudit.claims.map(claim => <div key={`${claim.source}-${claim.claimId}`} style={{ marginTop: 6, padding: 7, background: "var(--bg-primary)", borderLeft: `3px solid ${claim.gateStatus === "blocked" ? "#d29922" : "#3fb950"}` }}>
                <div style={{ color: "var(--text-primary)", fontSize: 10 }}>{claim.claimId} · {claim.currentStatus} → {claim.recommendedStatus}</div>
                <div style={{ marginTop: 3, color: claim.coverageGatePassed ? "#3fb950" : "#58a6ff", fontSize: 9 }}>
                  coverage {claim.coverageRequirement} ({claim.coverageRequirementSource}) · {claim.coverageGateStatus} · max {claim.coverageMaxStatus}
                </div>
                {claim.coverageUncoveredCounts && <div style={{ marginTop: 3, color: "#d29922", fontSize: 9 }}>uncovered: {compactCoverageCounts(claim.coverageUncoveredCounts)}</div>}
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
