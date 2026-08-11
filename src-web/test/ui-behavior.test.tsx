import { render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { MaterialRow } from "../src/components/CryptoMaterialsPanel";
import AnalysisCasePanel from "../src/components/AnalysisCasePanel";
import AnalysisHistoryPanel from "../src/components/AnalysisHistoryPanel";
import MemoryObjectsPanel from "../src/components/MemoryObjectsPanel";
import OllvmUnicornPanel from "../src/components/OllvmUnicornPanel";
import { filterFridaCaptureEvents } from "../src/utils/fridaCaptureFilter";
import type { AngrOllvmScript, CryptoDetectionDoctorReport, CryptoMaterial, FridaCaptureBundle, FridaCaptureEvent, MinimalEvidenceSliceBundle, MinimalEvidenceSliceInspectionReport, OllvmReport, ReplayDoctorReport, TraceAnalysisCaseDocument, UnicornOllvmResultBundle } from "../src/types/trace";
import type { MemoryObjectGraphReport, MemoryPointerExplanation } from "../src/types/trace";

const mocks = vi.hoisted(() => ({
  invoke: vi.fn(),
  open: vi.fn(),
  save: vi.fn(),
}));

vi.mock("@tauri-apps/api/core", () => ({ invoke: mocks.invoke }));
vi.mock("@tauri-apps/plugin-dialog", () => ({ open: mocks.open, save: mocks.save }));

const fullHex = "00112233445566778899aabbccddeeff";
const maskedHex = "0011223344556677••••••••ccddeeff";

const material: CryptoMaterial = {
  materialId: "material-1",
  kind: "key",
  role: "key",
  algorithm: "AES",
  bytesHex: fullHex,
  asciiPreview: null,
  byteLen: 16,
  address: "0x1000",
  observationSeq: 4,
  completionSeq: 5,
  functionName: "encrypt",
  register: "X0",
  source: "capture",
  evidence: ["test evidence"],
  assessment: {
    scope: "test",
    score: 90,
    grade: "verified",
    confidence: "high",
    verificationGateMet: true,
    factors: [],
    limitations: [],
  },
};

function makeEvent(patch: Partial<FridaCaptureEvent> = {}): FridaCaptureEvent {
  return {
    index: 0,
    protocol: "trace-ui/frida-hook-v1",
    eventId: null,
    hookId: "hook-1",
    event: "hook-enter",
    functionName: "encrypt",
    timestampMs: 1,
    threadId: 1,
    callId: "call-1",
    moduleName: "libtarget.so",
    moduleBase: "0x1000",
    moduleSize: 4096,
    target: "0x1234",
    dispatcherOffset: null,
    captureSessionId: null,
    flowId: null,
    hitSequence: null,
    candidateStateRegisters: [],
    registers: {},
    captures: [],
    returnValue: null,
    backtrace: [],
    stalkerMode: null,
    stalkerEventCount: null,
    error: null,
    ...patch,
  };
}

describe("敏感材料交互", () => {
  it("默认遮罩并且只展开当前材料", async () => {
    const user = userEvent.setup();
    render(<MaterialRow material={material} onJumpToSeq={() => undefined} />);

    expect(screen.getByText(maskedHex)).toBeInTheDocument();
    await user.click(screen.getByText(maskedHex));
    const revealButton = screen.getByRole("button", { name: "显示完整材料" });
    await user.click(revealButton);

    expect(screen.getAllByText(fullHex).length).toBeGreaterThan(0);
    await user.click(screen.getByRole("button", { name: "隐藏完整材料" }));
    expect(screen.queryByText(fullHex)).not.toBeInTheDocument();
  });
});

describe("Frida 捕获筛选", () => {
  it("按元数据、事件类型和 payload 过滤", () => {
    const events = [
      makeEvent({ index: 1, event: "hook-enter", moduleName: "libcrypto.so", registers: { X0: "0x1" } }),
      makeEvent({ index: 2, event: "hook-leave", functionName: "finish", callId: "call-2" }),
      makeEvent({ index: 3, event: "ollvm-dispatcher-hit", functionName: "dispatch", captures: [{ index: 0, label: "state", kind: "integer", direction: "input", phase: "enter", pointer: null, value: "7", byteLength: null, requestedLength: null, readError: null }] }),
    ];

    expect(filterFridaCaptureEvents(events, { query: "libcrypto" }).map(event => event.index)).toEqual([1]);
    expect(filterFridaCaptureEvents(events, { eventType: "hook-leave" }).map(event => event.index)).toEqual([2]);
    expect(filterFridaCaptureEvents(events, { onlyPayload: true }).map(event => event.index)).toEqual([1, 3]);
  });
});

describe("OLLVM Unicorn concrete replay", () => {
  beforeEach(() => {
    mocks.invoke.mockReset();
    mocks.open.mockReset();
    mocks.save.mockReset();
  });

  it("requires exact ELF and Frida event, then exposes seed quality", async () => {
    const user = userEvent.setup();
    const event = makeEvent({
      index: 7,
      event: "ollvm-dispatcher-hit",
      dispatcherOffset: "0x100",
      registers: { x0: "0x1", sp: "0x50000000", nzcv: "0x0" },
    });
    const capture: FridaCaptureBundle = {
      schema: "trace-ui/frida-hook-v1",
      sourceFormat: "json",
      events: [event],
      hookIds: [event.hookId],
      enterEventCount: 0,
      leaveEventCount: 0,
      stalkerEventCount: 0,
      warnings: [],
    };
    mocks.open
      .mockResolvedValueOnce("C:\\samples\\libtarget.so")
      .mockResolvedValueOnce("C:\\samples\\capture.ndjson");
    mocks.invoke.mockImplementation(async (command: string) => {
      if (command === "load_frida_capture") return capture;
      if (command === "generate_unicorn_ollvm_script") {
        return {
          fileName: "target-trace-ui-unicorn.py",
          script: "print('replay')",
          schemaVersion: "trace-ui/unicorn-ollvm-v1",
          seeds: [],
          seedQualities: [{
            sourceEventIndex: 7,
            captureOffset: "0x100",
            status: "partial",
            registerCount: 3,
            missingRegisters: ["X1"],
            memoryRegionCount: 0,
            capturedMemoryBytes: 0,
            stackMemoryCaptured: false,
            warnings: [],
          }],
          expectedBinaryIdentity: { binarySha256: "a".repeat(64) },
          config: {},
          warnings: [],
        };
      }
      throw new Error(`unexpected command ${command}`);
    });
    const report = { scope: { moduleName: "libtarget.so" } } as OllvmReport;
    render(<OllvmUnicornPanel report={report} />);

    await user.click(screen.getByRole("button", { name: "选择 ELF" }));
    await user.click(screen.getByRole("button", { name: "导入捕获" }));
    expect(await screen.findByText(/#7/)).toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: "生成 Unicorn Python" }));

    expect(await screen.findByText("Seed 完整度")).toBeInTheDocument();
    expect(screen.getByText(/partial/)).toBeInTheDocument();
    expect(screen.getByText(/pip install unicorn==2\.1\.4/)).toBeInTheDocument();
    expect(mocks.invoke).toHaveBeenCalledWith("generate_unicorn_ollvm_script", expect.objectContaining({
      staticBinaryPath: "C:\\samples\\libtarget.so",
      fridaEventIndices: [7],
      stopOnCall: true,
    }));
  });

  it("requires explicit exact-call assumptions before embedding replay authorization", async () => {
    const user = userEvent.setup();
    const event = makeEvent({
      index: 7,
      event: "hook-enter",
      exactCallRecord: true,
      targetOffset: "0x900",
      callerModuleName: "libtarget.so",
      callSiteOffset: "0x180",
      returnOffset: "0x184",
      registers: { x0: "0x1", sp: "0x50000000", nzcv: "0x0" },
    });
    const capture: FridaCaptureBundle = {
      schema: "trace-ui/frida-hook-v1",
      sourceFormat: "ndjson",
      events: [event],
      hookIds: [event.hookId],
      enterEventCount: 1,
      leaveEventCount: 1,
      stalkerEventCount: 0,
      warnings: [],
    };
    const summary = {
      schema: "trace-ui/exact-call-summary-v1",
      request: { callerModuleName: "libtarget.so", staticBinaryPath: "C:\\samples\\libtarget.so", maxCalls: 1024, maxMemoryBytesPerCall: 1048576 },
      sourceCapturePath: "C:\\samples\\capture.ndjson",
      sourceCaptureSha256: "b".repeat(64),
      exactBinaryIdentity: { binaryPath: "C:\\samples\\libtarget.so", binarySha256: "a".repeat(64), fileSize: 8192, format: "ELF64", architecture: "AArch64", elfMachine: 183, buildId: null },
      calls: [{
        callId: "call-1",
        hookId: "hook-1",
        functionName: "external_helper",
        callSiteOffset: "0x180",
        targetModuleName: "libhelper.so",
        targetOffset: "0x900",
        returnOffset: "0x184",
        registerEffects: [{ register: "x0", before: "0x1", after: "0x2" }],
        memoryEffects: [],
        completeness: { captureReady: true },
        blockers: [],
      }],
      pairedCallCount: 1,
      captureReadyCallCount: 1,
      incompleteCallCount: 0,
      unpairedEnterEventIndices: [],
      unpairedLeaveEventIndices: [],
      callsTruncated: false,
      verificationGateMet: false,
      warnings: [],
      limitations: [],
    } as unknown as import("../src/types/trace").ExactCallSummaryBundle;
    const authorization = {
      schema: "trace-ui/exact-call-replay-authorization-v1",
      authorizations: [{ authorizationId: "auth-1", callId: "call-1", authorized: true, status: "authorized-candidate" }],
      authorizedCount: 1,
      blockedCount: 0,
      verificationGateMet: false,
      warnings: [],
      limitations: [],
    } as unknown as import("../src/types/trace").ExactCallReplayAuthorizationBundle;
    mocks.open
      .mockResolvedValueOnce("C:\\samples\\libtarget.so")
      .mockResolvedValueOnce("C:\\samples\\capture.ndjson");
    mocks.save
      .mockResolvedValueOnce("C:\\samples\\exact-call-summary.json")
      .mockResolvedValueOnce("C:\\samples\\exact-call-authorization.json");
    mocks.invoke.mockImplementation(async (command: string) => {
      if (command === "load_frida_capture") return capture;
      if (command === "summarize_exact_calls") return summary;
      if (command === "authorize_exact_call_replay") return authorization;
      if (command === "generate_unicorn_ollvm_script") return {
        fileName: "target-trace-ui-unicorn.py",
        script: "print('replay')",
        schemaVersion: "trace-ui/unicorn-ollvm-v1",
        seeds: [],
        seedQualities: [],
        seedRecapturePlans: [],
        expectedBinaryIdentity: summary.exactBinaryIdentity,
        exactCallAuthorizations: [{
          authorizationId: "auth-1",
          callId: "call-1",
          callSiteOffset: "0x180",
          returnOffset: "0x184",
          targetModuleName: "libhelper.so",
          targetOffset: "0x900",
          preconditionRegisterCount: 9,
          registerWriteCount: 1,
          memoryEffectCount: 0,
        }],
        config: {},
        warnings: [],
      };
      throw new Error(`unexpected command ${command}`);
    });
    const report = { scope: { moduleName: "libtarget.so" } } as OllvmReport;
    const view = render(<OllvmUnicornPanel report={report} />);
    const panel = within(view.container);

    await user.click(panel.getByRole("button", { name: "选择 ELF" }));
    await user.click(panel.getByRole("button", { name: "导入捕获" }));
    await user.click(panel.getByRole("button", { name: "生成并保存摘要" }));
    expect(await panel.findByText(/capture-ready 1/)).toBeInTheDocument();
    expect(panel.getByRole("button", { name: "显式授权并保存" })).toBeDisabled();
    for (const label of [
      "已捕获全部内存副作用",
      "没有 SIMD/FP 副作用",
      "没有 TLS/errno 副作用",
      "没有系统寄存器或 syscall 副作用",
      "没有线程、信号或 callback 副作用",
      "对这些精确前置状态确定性一致",
    ]) {
      await user.click(panel.getByRole("checkbox", { name: label }));
    }
    await user.click(panel.getByRole("button", { name: "显式授权并保存" }));
    expect(await panel.findByText(/1 authorized/)).toBeInTheDocument();
    await user.click(panel.getByRole("button", { name: "生成 Unicorn Python" }));
    expect(await panel.findByText("Exact-call replay candidates")).toBeInTheDocument();
    expect(mocks.invoke).toHaveBeenCalledWith("generate_unicorn_ollvm_script", expect.objectContaining({
      exactCallAuthorizationPaths: ["C:\\samples\\exact-call-authorization.json"],
      stopOnCall: true,
    }));
  });

  it("generates a closer checkpoint hook and carries the prior result into the next replay", async () => {
    const user = userEvent.setup();
    const result = {
      schema: "trace-ui/unicorn-ollvm-v1",
      moduleName: "libtarget.so",
      binarySha256: "a".repeat(64),
      expectedBinarySha256: "a".repeat(64),
      binaryIdentityMatched: true,
      architecture: "AArch64",
      unicornVersion: "2.1.4",
      capstoneVersion: "5.0.6",
      config: {},
      seeds: [{ sourceEventIndex: 7, captureOffset: "0x100" }],
      seedQualities: [],
      seedRecapturePlans: [],
      runs: [{
        sourceEventIndex: 7,
        startOffset: "0x100",
        stopReason: "missing-memory",
        instructionCount: 4,
        elapsedMs: 1,
        terminalOffset: "0x180",
        matchedDispatcherOffset: null,
        sourceStateValues: [],
        targetStateValues: [],
        blockOffsets: ["0x100", "0x180"],
        registerChanges: [],
        memoryWrites: [],
        callBoundaries: [],
        missingMemory: [],
        error: null,
      }],
      transitionMatrix: [],
      recaptureSuggestions: [],
      warnings: [],
    } as unknown as UnicornOllvmResultBundle;
    mocks.open.mockResolvedValueOnce("C:\\samples\\round-1.json");
    mocks.invoke.mockImplementation(async (command: string) => {
      if (command === "load_unicorn_ollvm_results") return result;
      if (command === "generate_frida_unicorn_checkpoint_hook") {
        return {
          schemaVersion: "trace-ui/frida-unicorn-checkpoint-hook-v1",
          moduleName: "libtarget.so",
          fileName: "libtarget-checkpoint.js",
          expectedBinarySha256: "a".repeat(64),
          selectedSeedOffsets: ["0x100"],
          targets: [{
            hookId: "unicorn-checkpoint-180",
            offset: "0x180",
            sourceEventIndices: [7],
            sourceSeedOffsets: ["0x100"],
            stopReasons: ["missing-memory"],
            captures: [],
          }],
          captureWindowCount: 0,
          maxEvents: 5000,
          script: "Interceptor.attach(moduleBase.add(0x180), {})",
          warnings: [],
          protocolVersion: "trace-ui/frida-hook-v1",
          fridaApiVersion: "16.x",
        };
      }
      throw new Error(`unexpected command ${command}`);
    });
    const report = { scope: { moduleName: "libtarget.so" } } as OllvmReport;
    const view = render(<OllvmUnicornPanel report={report} />);
    const panel = within(view.container);

    await user.click(panel.getByRole("button", { name: "导入结果 JSON" }));
    expect(await panel.findByText(/^原 seed/)).toHaveTextContent("0x100");
    await user.click(panel.getByRole("button", { name: "生成更近 checkpoint Hook" }));

    expect(await panel.findByText(/1 个更近目标/)).toBeInTheDocument();
    expect(mocks.invoke).toHaveBeenCalledWith("generate_frida_unicorn_checkpoint_hook", {
      unicornResultPath: "C:\\samples\\round-1.json",
      seedCaptureOffsets: ["0x100"],
      maxEvents: 5000,
    });
  });

  it("offers a post-call return checkpoint for a Unicorn call boundary", async () => {
    const user = userEvent.setup();
    const result = {
      schema: "trace-ui/unicorn-ollvm-v1",
      moduleName: "libtarget.so",
      binarySha256: "a".repeat(64),
      expectedBinarySha256: "a".repeat(64),
      binaryIdentityMatched: true,
      architecture: "AArch64",
      unicornVersion: "2.1.4",
      capstoneVersion: "5.0.6",
      config: {},
      seeds: [{ sourceEventIndex: 7, captureOffset: "0x100" }],
      seedQualities: [],
      seedRecapturePlans: [],
      runs: [{
        sourceEventIndex: 7,
        startOffset: "0x100",
        stopReason: "call-boundary",
        instructionCount: 4,
        elapsedMs: 1,
        terminalOffset: "0x180",
        matchedDispatcherOffset: null,
        sourceStateValues: [],
        targetStateValues: [],
        blockOffsets: ["0x100", "0x180"],
        registerChanges: [],
        memoryWrites: [],
        callBoundaries: [{
          pcOffset: "0x180",
          mnemonic: "blr x9",
          targetAddress: "0x70001000",
          targetOffset: null,
          returnAddress: "0x40000184",
          returnOffset: "0x184",
        }],
        missingMemory: [],
        error: null,
      }],
      transitionMatrix: [],
      recaptureSuggestions: [],
      warnings: [],
    } as unknown as UnicornOllvmResultBundle;
    mocks.open.mockResolvedValueOnce("C:\\samples\\call-boundary.json");
    mocks.invoke.mockImplementation(async (command: string) => {
      if (command === "load_unicorn_ollvm_results") return result;
      if (command === "generate_frida_unicorn_checkpoint_hook") {
        return {
          schemaVersion: "trace-ui/frida-unicorn-checkpoint-hook-v1",
          moduleName: "libtarget.so",
          fileName: "libtarget-post-call-checkpoint.js",
          expectedBinarySha256: "a".repeat(64),
          selectedSeedOffsets: ["0x100"],
          targets: [{
            hookId: "unicorn-checkpoint-184",
            offset: "0x184",
            sourceEventIndices: [7],
            sourceSeedOffsets: ["0x100"],
            stopReasons: ["call-boundary"],
            captures: [],
          }],
          captureWindowCount: 0,
          maxEvents: 5000,
          script: "Interceptor.attach(moduleBase.add(0x184), {})",
          warnings: [],
          protocolVersion: "trace-ui/frida-hook-v1",
          fridaApiVersion: "16.x",
        };
      }
      throw new Error(`unexpected command ${command}`);
    });
    const report = { scope: { moduleName: "libtarget.so" } } as OllvmReport;
    const view = render(<OllvmUnicornPanel report={report} />);
    const panel = within(view.container);

    await user.click(panel.getByRole("button", { name: "导入结果 JSON" }));
    expect(await panel.findByText(/post-call return checkpoint 0x184/)).toBeInTheDocument();
    await user.click(panel.getByRole("button", { name: "生成更近 checkpoint Hook" }));

    expect(await panel.findByText(/0x184 \(call-boundary\)/)).toBeInTheDocument();
    expect(mocks.invoke).toHaveBeenCalledWith("generate_frida_unicorn_checkpoint_hook", {
      unicornResultPath: "C:\\samples\\call-boundary.json",
      seedCaptureOffsets: ["0x100"],
      maxEvents: 5000,
    });
  });

  it("bridges an authorized closer checkpoint into bounded angr", async () => {
    const user = userEvent.setup();
    const event = makeEvent({
      index: 9,
      moduleName: "libtarget.so",
      moduleBase: "0x71000000",
      target: "0x71000180",
      registers: { x0: "0x1", x1: "0x2", sp: "0x72000000", lr: "0x710001f0", nzcv: "0x40000000" },
    });
    const capture: FridaCaptureBundle = {
      schema: "trace-ui/frida-hook-v1",
      sourceFormat: "ndjson",
      events: [event],
      hookIds: [event.hookId],
      enterEventCount: 1,
      leaveEventCount: 0,
      stalkerEventCount: 0,
      warnings: [],
    };
    const priorResult = {
      schema: "trace-ui/unicorn-ollvm-v1",
      moduleName: "libtarget.so",
      binarySha256: "a".repeat(64),
      expectedBinarySha256: "a".repeat(64),
      binaryIdentityMatched: true,
      architecture: "AArch64",
      unicornVersion: "2.1.4",
      capstoneVersion: "5.0.6",
      config: {},
      seeds: [{ sourceEventIndex: 7, captureOffset: "0x100" }],
      seedQualities: [],
      seedRecapturePlans: [],
      runs: [{
        sourceEventIndex: 7,
        startOffset: "0x100",
        stopReason: "missing-memory",
        instructionCount: 4,
        elapsedMs: 1,
        terminalOffset: "0x180",
        matchedDispatcherOffset: null,
        sourceStateValues: [],
        targetStateValues: [],
        blockOffsets: ["0x100", "0x180"],
        registerChanges: [],
        memoryWrites: [],
        callBoundaries: [],
        missingMemory: [{ pcOffset: "0x180" }],
        error: null,
      }],
      transitionMatrix: [],
      recaptureSuggestions: [],
      warnings: [],
    } as unknown as UnicornOllvmResultBundle;
    const angrScript: AngrOllvmScript = {
      fileName: "libtarget-trace-ui-angr.py",
      script: "print('bounded checkpoint flow')",
      schemaVersion: "trace-ui/angr-ollvm-v1",
      fridaSeed: null,
      fridaSeeds: [{
        sourceEventIndex: 9,
        hookId: "hook-1",
        callId: "call-1",
        moduleName: "libtarget.so",
        functionName: "encrypt",
        captureOffset: "0x180",
        registersSeeded: ["X0", "X1", "SP", "LR", "NZCV"],
        memoryRegionCount: 0,
        matchedProbeOffsets: ["0x180"],
        matchedBranchOffsets: [],
        matchedDispatcherOffsets: [],
      }],
      expectedBinaryIdentity: { binarySha256: "a".repeat(64) },
      authorizedCheckpointOffsets: ["0x180"],
      flowConfig: { enabled: true, maxDepth: 8, maxStatesPerProbe: 32 },
      warnings: [],
    };
    mocks.open
      .mockResolvedValueOnce("C:\\samples\\libtarget.so")
      .mockResolvedValueOnce("C:\\samples\\checkpoint.ndjson")
      .mockResolvedValueOnce("C:\\samples\\round-1.json");
    mocks.invoke.mockImplementation(async (command: string) => {
      if (command === "load_frida_capture") return capture;
      if (command === "load_unicorn_ollvm_results") return priorResult;
      if (command === "generate_angr_ollvm_script") return angrScript;
      throw new Error(`unexpected command ${command}`);
    });
    const report = { scope: { moduleName: "libtarget.so" } } as OllvmReport;
    const view = render(<OllvmUnicornPanel report={report} />);
    const panel = within(view.container);

    await user.click(panel.getByRole("button", { name: "选择 ELF" }));
    await user.click(panel.getByRole("button", { name: "导入捕获" }));
    await user.click(panel.getByRole("button", { name: "导入结果 JSON" }));
    await user.click(await panel.findByRole("button", { name: "生成 bounded angr" }));

    expect(await panel.findByText(/授权 checkpoint：0x180/)).toBeInTheDocument();
    expect(mocks.invoke).toHaveBeenCalledWith(
      "generate_angr_ollvm_script",
      expect.objectContaining({
        probeOpaqueBranches: false,
        useCfgEmulated: false,
        exploreSeededFlows: true,
        flowMaxDepth: 8,
        flowMaxStatesPerProbe: 32,
        fridaIncludeSp: true,
        fridaIncludeLr: true,
        staticBinaryPath: "C:\\samples\\libtarget.so",
        checkpointResultPath: "C:\\samples\\round-1.json",
        fridaEventIndices: [9],
      }),
    );
  });
});

describe("案件工作区准确率门禁", () => {
  const caseDocument: TraceAnalysisCaseDocument = {
    casePath: "C:\\cases\\sample.traceui-case",
    case: {
      schema: "trace-ui/case-v1",
      caseId: "case-1",
      title: "AES / OLLVM case",
      createdAtMs: 1,
      updatedAtMs: 1,
      artifacts: [],
      claims: [],
      experiments: [],
      notes: [],
    },
  };

  const replayReport: ReplayDoctorReport = {
    schema: "trace-ui/replay-doctor-v1",
    caseId: "case-1",
    casePath: caseDocument.casePath,
    generatedAtMs: 2,
    status: "seed-ready",
    artifactHealth: [],
    timeline: [],
    generatedClaims: [],
    nextActions: [],
    claimLedgerAudit: {
      schema: "trace-ui/claim-ledger-audit-v1",
      totalClaimCount: 1,
      passedClaimCount: 0,
      blockedClaimCount: 1,
      refutedClaimCount: 0,
      verifiedGatePassedCount: 0,
      claims: [{
        claimId: "claim-1",
        source: "persisted",
        currentStatus: "verified",
        recommendedStatus: "observed",
        gateStatus: "blocked",
        verificationGatePassed: false,
        validSupportingEvidenceCount: 1,
        validCounterEvidenceCount: 0,
        invalidEvidenceCount: 0,
        evidenceArtifactKinds: ["trace"],
        coverageRequirement: "negative-existence",
        coverageRequirementSource: "auto-statement",
        coverageGateStatus: "missing-coverage-report",
        coverageGatePassed: false,
        coverageMaxStatus: "observed",
        coverageArtifactIds: [],
        coverageUncoveredCounts: {
          instructions: 1,
          blocks: 1,
          branches: 0,
          functions: 0,
          edges: 0,
        },
        blockers: ["Verified requires semantic evidence."],
        notes: [],
      }],
      contradictions: [],
      limitations: [],
    },
    stateReadiness: {
      schema: "trace-ui/replay-state-readiness-v1",
      status: "partial",
      components: [{
        component: "simd-fp",
        status: "not-captured",
        observedCount: 0,
        expectedCount: 32,
        sourceArtifactIds: [],
        details: "A bounded run read uncaptured SIMD state.",
        nextAction: "Capture a closer exact checkpoint.",
      }],
      blockers: ["simd-fp missing"],
      limitations: [],
    },
    experimentMatrix: {
      schema: "trace-ui/experiment-matrix-v1",
      status: "no-experiments",
      experimentCount: 0,
      completeExperimentCount: 0,
      axes: [{ axis: "keyGroup", values: [], unspecifiedExperimentCount: 0 }],
      observedCells: [],
      missingCells: [],
      missingCellsTruncated: false,
      controlledPairs: [],
      confoundedPairCount: 0,
      recommendations: [{
        priority: 100,
        action: "record-baseline-experiment",
        reason: "No controlled baseline exists.",
      }],
      warnings: [],
      limitations: [],
    },
    capturePlan: {
      schema: "trace-ui/information-gain-capture-plan-v1",
      status: "no-additional-targets",
      targetCount: 0,
      omittedTargetCount: 0,
      targets: [],
      limitations: [],
    },
    runtimeAttestations: [],
    exactCallSummaries: [{
      artifactId: "exact-summary-1",
      exactBinaryArtifactId: "elf-1",
      sourceCaptureArtifactId: "frida-1",
      callerModuleName: "libtarget.so",
      sourceCaptureSha256: "a".repeat(64),
      binarySha256: "b".repeat(64),
      pairedCallCount: 1,
      captureReadyCallCount: 1,
      incompleteCallCount: 0,
      captureReadyCallIds: ["callee:7:1"],
      verificationGateMet: false,
      warnings: [],
      limitations: ["Candidate/Related only."],
    }],
    exactCallAuthorizations: [{
      artifactId: "exact-auth-1",
      exactBinaryArtifactId: "elf-1",
      summaryArtifactId: "exact-summary-1",
      sourceCaptureArtifactId: "frida-1",
      summarySha256: "c".repeat(64),
      binarySha256: "b".repeat(64),
      authorizedCount: 1,
      blockedCount: 0,
      authorizedCallIds: ["callee:7:1"],
      blockedCallIds: [],
      verificationGateMet: false,
      warnings: [],
      limitations: ["Candidate/Related only."],
    }],
    cryptoKats: [],
    coverageReconciliations: [],
    evidenceSlices: [],
    warnings: [],
    limitations: [],
  };

  const cryptoReport: CryptoDetectionDoctorReport = {
    schema: "trace-ui/crypto-detection-doctor-v1",
    sessionId: "session-case",
    targetAlgorithm: "AES",
    status: "related",
    verificationGateMet: false,
    totalLinesScanned: 10,
    algorithmsObserved: ["AES"],
    targetMagicHitCount: 1,
    targetCryptoInstructionCount: 0,
    targetFunctionCandidateCount: 1,
    structuralSignalCount: 1,
    stages: [{
      code: "semantic-verification",
      label: "Semantic verification",
      status: "blocked",
      observedCount: 0,
      details: "A same-call key/input/output tuple is missing.",
      evidence: [],
      blockers: ["Missing exact output bytes."],
    }],
    failureReasons: ["Semantic verification missing."],
    nextActions: ["Capture the exact call tuple."],
    limitations: [],
  };

  beforeEach(() => {
    mocks.invoke.mockReset();
    mocks.open.mockReset();
    mocks.save.mockReset();
    localStorage.clear();
  });

  it("从分析历史二级页签进入案件工作区", async () => {
    const user = userEvent.setup();
    mocks.invoke.mockResolvedValue([]);
    render(<AnalysisHistoryPanel sessionId="session-case" />);
    await user.click(screen.getByRole("button", { name: "案件 / Replay Doctor" }));
    expect(screen.getByRole("button", { name: "新建案件" })).toBeInTheDocument();
    expect(screen.getByText("AES 未识别原因诊断")).toBeInTheDocument();
  });

  it("显示状态完整度、反证门禁、实验矩阵和 AES 阶段诊断", async () => {
    const user = userEvent.setup();
    localStorage.setItem("trace-ui-analysis-case:session-case", caseDocument.casePath);
    mocks.invoke.mockImplementation(async (command: string) => {
      if (command === "load_analysis_case") return caseDocument;
      if (command === "diagnose_analysis_case") return replayReport;
      if (command === "diagnose_crypto_detection") return cryptoReport;
      throw new Error(`unexpected command ${command}`);
    });
    const view = render(<AnalysisCasePanel sessionId="session-case" />);
    const panel = within(view.container);
    expect(await panel.findByText("AES / OLLVM case")).toBeInTheDocument();

    await user.click(panel.getByRole("button", { name: "Replay Doctor" }));
    expect(await panel.findByText("模拟状态完整度")).toBeInTheDocument();
    expect(panel.getByText("Claim 反证门禁")).toBeInTheDocument();
    expect(panel.getByText("受控实验矩阵")).toBeInTheDocument();
    expect(panel.getByText("Verified requires semantic evidence.")).toBeInTheDocument();
    expect(panel.getByText("Exact-call provenance reports")).toBeInTheDocument();
    expect(panel.getByText("Exact-call replay authorizations")).toBeInTheDocument();

    await user.click(panel.getByRole("button", { name: "运行诊断" }));
    expect(await panel.findByText("Semantic verification")).toBeInTheDocument();
    expect(panel.getByText("Missing exact output bytes.")).toBeInTheDocument();
  });

  it("生成、严格检查并以 exact ELF parent 导入运行时镜像认证", async () => {
    const user = userEvent.setup();
    const exactArtifactId = "elf-runtime-1";
    const runtimeCase: TraceAnalysisCaseDocument = {
      ...caseDocument,
      case: {
        ...caseDocument.case,
        exactBinaryArtifactId: exactArtifactId,
        artifacts: [{
          artifactId: exactArtifactId,
          kind: "static-binary",
          label: "Exact libtarget.so",
          path: "libtarget.so",
          sha256: "a".repeat(64),
          fileSize: 8192,
          importedAtMs: 1,
          parentArtifactIds: [],
          summary: {
            schema: "elf-identity",
            moduleName: "libtarget.so",
            architecture: "AArch64",
            binarySha256: "a".repeat(64),
            expectedBinarySha256: "a".repeat(64),
            exactIdentityMatched: true,
            captureOffsets: [],
            eventCount: 0,
            runCount: 0,
            warningCount: 0,
            stopReasonCounts: {},
            notes: [],
          },
        }],
      },
    };
    const generated = {
      fileName: "runtime-attestation-libtarget.js",
      moduleName: "libtarget.so",
      staticBinaryPath: "C:\\samples\\libtarget.so",
      protocolVersion: "trace-ui/frida-runtime-attestation-v1",
      fridaApiVersion: "16.x",
      script: "send(result);",
      plan: {
        schema: "trace-ui/frida-runtime-attestation-v1",
        attestationId: "runtime-attestation-libtarget",
        moduleName: "libtarget.so",
        expectedIdentity: {
          binarySha256: "a".repeat(64), fileSize: 8192, architecture: "AArch64", elfMachine: 183,
        },
        loadBaseVaddr: "0x0",
        expectedMappedSize: 8192,
        windowBytes: 4096,
        maxWindows: 1024,
        coverageStrategy: "full-file-backed-executable-coverage",
        completeExecutableCoverage: true,
        totalExecutableBytes: 8192,
        selectedExecutableBytes: 8192,
        planSha256: "b".repeat(64),
        windows: [],
      },
      warnings: [],
    };
    const inspection = {
      schema: "trace-ui/runtime-attestation-verification-v1",
      capturePath: "C:\\captures\\runtime.json",
      exactBinaryPath: "C:\\samples\\libtarget.so",
      status: "verified-full",
      verificationGateMet: true,
      recordCount: 1,
      records: [{
        schema: "trace-ui/runtime-attestation-verification-v1",
        attestationId: "runtime-attestation-libtarget",
        moduleName: "libtarget.so",
        status: "verified-full",
        verificationGateMet: true,
        attestedScope: "file-backed executable PT_LOAD bytes",
        exactBinarySha256: "a".repeat(64),
        expectedBinarySha256: "a".repeat(64),
        exactBuildId: null,
        expectedBuildId: null,
        planSha256: "b".repeat(64),
        regeneratedPlanSha256: "b".repeat(64),
        planMatched: true,
        moduleSize: 8192,
        expectedMappedSize: 8192,
        moduleSizeSufficient: true,
        completeExecutableCoverage: true,
        totalExecutableBytes: 8192,
        selectedExecutableBytes: 8192,
        matchedExecutableBytes: 8192,
        matchedWindowCount: 2,
        mismatchedWindowCount: 0,
        unreadableWindowCount: 0,
        missingWindowCount: 0,
        unexpectedWindowCount: 0,
        windows: [],
        evidence: ["all executable bytes matched"],
        counterEvidence: [],
        blockers: [],
        limitations: [],
      }],
      warnings: [],
      limitations: [],
    };

    localStorage.setItem("trace-ui-analysis-case:session-case", runtimeCase.casePath);
    mocks.invoke.mockImplementation(async (command: string) => {
      if (command === "load_analysis_case") return runtimeCase;
      if (command === "generate_frida_runtime_attestation") return generated;
      if (command === "inspect_runtime_attestation") return inspection;
      if (command === "add_analysis_case_artifact") return { case: runtimeCase.case };
      throw new Error(`unexpected command ${command}`);
    });
    const view = render(<AnalysisCasePanel sessionId="session-case" />);
    const panel = within(view.container);
    expect(await panel.findByText("运行时镜像认证（手动 Frida）")).toBeInTheDocument();

    mocks.open.mockResolvedValueOnce("C:\\samples\\libtarget.so");
    await user.click(panel.getByRole("button", { name: "选择 ELF 文件" }));
    await user.click(panel.getByRole("button", { name: "生成认证脚本" }));
    expect(await panel.findByText("runtime-attestation-libtarget.js")).toBeInTheDocument();
    expect(mocks.invoke).toHaveBeenCalledWith("generate_frida_runtime_attestation", {
      request: {
        moduleName: "libtarget.so",
        staticBinaryPath: "C:\\samples\\libtarget.so",
        windowBytes: 4096,
        maxWindows: 1024,
      },
    });

    mocks.open.mockResolvedValueOnce("C:\\captures\\runtime.json");
    await user.click(panel.getByRole("button", { name: "检查手动捕获" }));
    expect((await panel.findAllByText("verified-full")).length).toBeGreaterThan(0);
    await user.click(panel.getByRole("button", { name: "导入案件（反证也保留）" }));
    expect(mocks.invoke).toHaveBeenCalledWith("add_analysis_case_artifact", expect.objectContaining({
      artifactPath: "C:\\captures\\runtime.json",
      kindHint: "runtime-attestation",
      parentArtifactIds: [exactArtifactId],
    }));
    expect(mocks.invoke.mock.calls.map(call => call[0])).not.toEqual(expect.arrayContaining([
      "attach_frida", "spawn_frida", "load_frida", "run_frida",
    ]));
  });

  it("生成、保存、检查并绑定 exact ELF 与 OLLVM source 导入 coverage gate", async () => {
    const user = userEvent.setup();
    const exactArtifactId = "elf-coverage-1";
    const ollvmArtifactId = "ollvm-source-1";
    const coverageCase: TraceAnalysisCaseDocument = {
      ...caseDocument,
      case: {
        ...caseDocument.case,
        exactBinaryArtifactId: exactArtifactId,
        artifacts: [{
          artifactId: exactArtifactId,
          kind: "static-binary",
          label: "Exact libtarget.so",
          path: "libtarget.so",
          sha256: "a".repeat(64),
          fileSize: 8192,
          importedAtMs: 1,
          parentArtifactIds: [],
          summary: {
            schema: "elf-identity",
            moduleName: "libtarget.so",
            architecture: "AArch64",
            binarySha256: "a".repeat(64),
            expectedBinarySha256: "a".repeat(64),
            exactIdentityMatched: true,
            captureOffsets: [],
            eventCount: 0,
            runCount: 0,
            warningCount: 0,
            stopReasonCounts: {},
            notes: [],
          },
        }, {
          artifactId: ollvmArtifactId,
          kind: "ollvm-report",
          label: "Observed OLLVM scope",
          path: "ollvm.json",
          sha256: "b".repeat(64),
          fileSize: 4096,
          importedAtMs: 2,
          parentArtifactIds: [],
          summary: {
            schema: "trace-ui/ollvm-v1",
            moduleName: "libtarget.so",
            architecture: "AArch64",
            captureOffsets: ["0x100"],
            eventCount: 4,
            runCount: 1,
            warningCount: 0,
            stopReasonCounts: {},
            notes: [],
          },
        }],
      },
    };
    const generated = {
      fileName: "encrypt-trace-ui-coverage.py",
      script: "print('manual angr')",
      schema: "trace-ui/coverage-reconciliation-v1",
      moduleName: "libtarget.so",
      claimScope: "libtarget.so:encrypt",
      expectedBinaryIdentity: {
        binaryPath: "C:\\samples\\libtarget.so",
        binarySha256: "a".repeat(64),
        fileSize: 8192,
        format: "ELF64",
        architecture: "AArch64",
        elfMachine: 183,
        buildId: null,
      },
      sourceOllvmSha256: "b".repeat(64),
      warnings: ["Run manually."],
    };
    const counts = { instructions: 4, blocks: 2, branches: 1, functions: 1, edges: 1 };
    const zeroCounts = { instructions: 0, blocks: 0, branches: 0, functions: 0, edges: 0 };
    const inspection = {
      schema: "trace-ui/coverage-reconciliation-inspection-v1",
      status: "complete-site-coverage",
      moduleName: "libtarget.so",
      claimScope: "libtarget.so:encrypt",
      exactBinaryIdentity: generated.expectedBinaryIdentity,
      identityMatched: true,
      sourceProvenanceMatched: true,
      missingSourceSha256s: [],
      coverageGateMet: true,
      scope: { kind: "function-closure", startOffset: "0x100", endOffset: "0x10c", functionOffsets: ["0x100"] },
      summary: {
        staticCounts: counts,
        observedStaticCounts: counts,
        uncoveredCounts: zeroCounts,
        dynamicOnlyCounts: zeroCounts,
        coverageBasisPoints: { instructions: 10000, blocks: 10000, branches: 10000, functions: 10000, edges: 10000 },
        staticInventoryComplete: true,
        dynamicCaptureComplete: true,
        coverageComplete: true,
      },
      uncoveredSamples: { instructions: [], blocks: [], branches: [], functions: [], edges: [] },
      dynamicOnlySamples: { instructions: [], blocks: [], branches: [], functions: [], edges: [] },
      warnings: [],
      limitations: ["Coverage is not semantic proof."],
    };

    localStorage.setItem("trace-ui-analysis-case:session-case", coverageCase.casePath);
    mocks.invoke.mockImplementation(async (command: string) => {
      if (command === "load_analysis_case") return coverageCase;
      if (command === "generate_coverage_reconciliation_script") return generated;
      if (command === "inspect_coverage_reconciliation") return inspection;
      if (command === "add_analysis_case_artifact") return { case: coverageCase.case };
      throw new Error(`unexpected command ${command}`);
    });
    const view = render(<AnalysisCasePanel sessionId="session-case" />);
    const panel = within(view.container);
    expect(await panel.findByText("Coverage-aware Claim Gate（手动 angr）")).toBeInTheDocument();

    mocks.open
      .mockResolvedValueOnce("C:\\samples\\libtarget.so")
      .mockResolvedValueOnce("C:\\cases\\ollvm.json")
      .mockResolvedValueOnce("C:\\cases\\coverage.json");
    await user.click(panel.getByRole("button", { name: "选择 Coverage ELF" }));
    await user.click(panel.getByRole("button", { name: "选择 OLLVM 报告" }));
    await user.type(panel.getByLabelText("Coverage claim scope"), "libtarget.so:encrypt");
    await user.click(panel.getByRole("button", { name: "生成 angr Coverage 脚本" }));
    expect(await panel.findByText("encrypt-trace-ui-coverage.py")).toBeInTheDocument();
    expect(mocks.invoke).toHaveBeenCalledWith("generate_coverage_reconciliation_script", expect.objectContaining({
      request: expect.objectContaining({
        staticBinaryPath: "C:\\samples\\libtarget.so",
        ollvmReportPath: "C:\\cases\\ollvm.json",
        claimScope: "libtarget.so:encrypt",
        scopeKind: "function-closure",
      }),
      outputPath: null,
    }));

    mocks.save.mockResolvedValueOnce("C:\\cases\\coverage-script.py");
    await user.click(panel.getByRole("button", { name: "保存 Coverage 脚本" }));
    expect(mocks.invoke).toHaveBeenCalledWith("generate_coverage_reconciliation_script", expect.objectContaining({
      outputPath: "C:\\cases\\coverage-script.py",
    }));

    await user.click(panel.getByRole("button", { name: "检查 Coverage JSON" }));
    expect((await panel.findAllByText("complete-site-coverage")).length).toBeGreaterThan(0);
    expect(mocks.invoke).toHaveBeenCalledWith("inspect_coverage_reconciliation", {
      artifactPath: "C:\\cases\\coverage.json",
      staticBinaryPath: "C:\\samples\\libtarget.so",
      sourceArtifactPaths: ["C:\\cases\\ollvm.json"],
    });
    await user.click(panel.getByRole("button", { name: "导入 Coverage 案件证据" }));
    expect(mocks.invoke).toHaveBeenCalledWith("add_analysis_case_artifact", expect.objectContaining({
      artifactPath: "C:\\cases\\coverage.json",
      kindHint: "coverage-report",
      parentArtifactIds: [exactArtifactId, ollvmArtifactId],
    }));
    expect(mocks.invoke.mock.calls.map(call => call[0])).not.toEqual(expect.arrayContaining([
      "run_angr", "install_angr", "execute_target",
    ]));
  });

  it("选择 claim、自动绑定当前 Trace、保存检查并导入 Minimal Evidence Slice", async () => {
    const user = userEvent.setup();
    const traceArtifactId = "trace-slice-1";
    const sliceCase: TraceAnalysisCaseDocument = {
      ...caseDocument,
      case: {
        ...caseDocument.case,
        primaryTraceArtifactId: traceArtifactId,
        artifacts: [{
          artifactId: traceArtifactId,
          kind: "trace",
          label: "Primary trace",
          path: "sample.log",
          sha256: "a".repeat(64),
          fileSize: 128,
          importedAtMs: 1,
          parentArtifactIds: [],
          summary: {
            schema: "trace-file",
            captureOffsets: [],
            eventCount: 0,
            runCount: 0,
            warningCount: 0,
            stopReasonCounts: {},
            notes: [],
          },
        }],
        claims: [{
          claimId: "claim-slice-1",
          statement: "Observed instruction",
          scope: "trace:sample",
          status: "observed",
          coverageRequirement: "not-required",
          supportingEvidence: [{
            artifactId: traceArtifactId,
            locator: "seq:1",
            description: "Exact line",
          }],
          counterEvidence: [],
          missingEvidence: [],
          limitations: [],
          createdBy: "test",
          createdAtMs: 1,
          updatedAtMs: 1,
        }],
      },
    };
    const summary = {
      selectedClaimCount: 1,
      selectedReferenceCount: 1,
      materializedReferenceCount: 1,
      unresolvedReferenceCount: 0,
      sourceArtifactCount: 1,
      recordCount: 1,
      truncatedRecordCount: 0,
      traceLineRecordCount: 1,
      memoryRecordCount: 0,
      fridaEventRecordCount: 0,
      moduleBytesRecordCount: 0,
      jsonFragmentRecordCount: 0,
      containsSensitiveValues: false,
      payloadBytes: 2048,
      materializationComplete: true,
    };
    const bundle: MinimalEvidenceSliceBundle = {
      schema: "trace-ui/minimal-evidence-slice-v1",
      sliceId: "slice-1234567890abcdef",
      generatedAtMs: 2,
      contentSha256: "b".repeat(64),
      content: {
        caseId: "case-1",
        caseTitle: "AES / OLLVM case",
        config: {
          includeGeneratedClaims: true,
          includeSensitiveValues: false,
          contextBefore: 2,
          contextAfter: 2,
          moduleBytesBefore: 16,
          moduleBytesAfter: 32,
          maxMemoryBytesPerRecord: 4096,
          maxRecords: 256,
          maxTotalPayloadBytes: 8 * 1024 * 1024,
        },
        selectedClaimIds: ["claim-slice-1"],
        sourceArtifacts: [{
          artifactId: traceArtifactId,
          kind: "trace",
          label: "Primary trace",
          storedPath: "sample.log",
          sha256: "a".repeat(64),
          fileSize: 128,
          parentArtifactIds: [],
          role: "primary-trace",
        }],
        references: [],
        records: [],
        provenance: { nodes: [], edges: [] },
        summary,
        warnings: [],
        limitations: ["Not semantic proof."],
      },
    };
    const inspection: MinimalEvidenceSliceInspectionReport = {
      schema: "trace-ui/minimal-evidence-slice-inspection-v1",
      sliceId: bundle.sliceId,
      status: "valid-complete",
      contentSha256Matched: true,
      sourceArtifactsMatched: true,
      claimBindingsMatched: true,
      generatedClaimBindingsRevalidated: true,
      recordContentMatched: true,
      provenanceGraphValid: true,
      summaryRecomputed: summary,
      sourceArtifactIds: [traceArtifactId],
      staleClaimIds: [],
      unrevalidatedGeneratedClaimIds: [],
      mismatchedRecordIds: [],
      blockers: [],
      warnings: [],
      limitations: ["Not semantic proof."],
    };

    localStorage.setItem("trace-ui-analysis-case:session-case", sliceCase.casePath);
    mocks.invoke.mockImplementation(async (command: string) => {
      if (command === "load_analysis_case") return sliceCase;
      if (command === "generate_minimal_evidence_slice") return bundle;
      if (command === "inspect_minimal_evidence_slice") return inspection;
      if (command === "add_analysis_case_artifact") return { case: sliceCase.case };
      throw new Error(`unexpected command ${command}`);
    });
    mocks.save.mockResolvedValueOnce("C:\\cases\\evidence-slice.json");
    const view = render(<AnalysisCasePanel sessionId="session-case" />);
    const panel = within(view.container);
    expect((await panel.findAllByText("Observed instruction")).length).toBeGreaterThan(0);
    await user.click(panel.getByRole("button", { name: "生成并保存" }));
    expect(mocks.invoke).toHaveBeenCalledWith("generate_minimal_evidence_slice", {
      request: expect.objectContaining({
        casePath: sliceCase.casePath,
        claimIds: ["claim-slice-1"],
        traceSessionBindings: [{ artifactId: traceArtifactId, sessionId: "session-case" }],
        includeSensitiveValues: false,
      }),
      outputPath: "C:\\cases\\evidence-slice.json",
    });
    expect((await panel.findAllByText("valid-complete")).length).toBeGreaterThan(0);
    await user.click(panel.getByRole("button", { name: "导入案件并绑定源 parents" }));
    expect(mocks.invoke).toHaveBeenCalledWith("add_analysis_case_artifact", expect.objectContaining({
      artifactPath: "C:\\cases\\evidence-slice.json",
      kindHint: "evidence-slice",
      parentArtifactIds: [traceArtifactId],
    }));
    expect(mocks.invoke.mock.calls.map(call => call[0])).not.toEqual(expect.arrayContaining([
      "execute_target", "run_angr", "run_unicorn", "attach_frida",
    ]));
  });
});

describe("Memory object / alias / lifetime UI", () => {
  beforeEach(() => {
    mocks.invoke.mockReset();
  });

  it("reconstructs bounded candidates and explains one pointer without claiming proof", async () => {
    const user = userEvent.setup();
    const report: MemoryObjectGraphReport = {
      schemaVersion: "trace-ui/memory-object-graph-v1",
      scope: { startSeq: 0, endSeq: 40 },
      objects: [{
        objectId: "heap:0x1000:g1",
        kind: "heap",
        generation: 1,
        baseAddress: "0x1000",
        endAddress: "0x1040",
        size: 64,
        startSeq: 2,
        endSeq: 20,
        allocationCallSeq: 1,
        releaseCallSeq: 19,
        allocator: "malloc",
        releaseFunction: "free",
        releaseReason: "released-by-free",
        callNodeId: null,
        parentCallNodeId: null,
        functionName: null,
        entrySp: null,
        exitSp: null,
        lifecycleState: "released",
        evidenceLevel: "related",
        accessSummary: {
          readCount: 3,
          writeCount: 2,
          firstAccessSeq: 3,
          lastAccessSeq: 25,
          firstReadSeq: 4,
          lastReadSeq: 25,
          firstWriteSeq: 3,
          lastWriteSeq: 6,
        },
        accessSamples: [],
        accessSamplesTruncated: false,
        aliases: [{
          seq: 2,
          sourceKind: "allocator-return",
          source: "malloc",
          pointer: "0x1000",
          offset: "0x0",
          relation: "base-pointer",
          lifetimeState: "live",
          evidenceLevel: "related",
        }],
        aliasesTruncated: false,
        fieldWindows: [{
          offset: "0x10",
          endOffset: "0x20",
          readCount: 3,
          writeCount: 2,
          firstSeq: 3,
          lastSeq: 25,
          sampleAddresses: ["0x1010"],
        }],
        fieldWindowsTruncated: false,
        warnings: ["Candidate only."],
      }],
      runtimeClusters: [],
      anomalies: [{
        kind: "access-after-lifetime",
        status: "candidate",
        seq: 25,
        address: "0x1010",
        objectId: "heap:0x1000:g1",
        functionName: null,
        accessKind: "read",
        accessSize: 4,
        instructionAddress: "0x4000",
        occurrenceCount: 1,
        reason: "No newer live generation covers this access.",
        counterEvidence: ["An omitted allocation may exist."],
        requiredEvidence: ["Capture and replay the exact call."],
      }],
      statistics: {
        totalObjects: 1,
        heapObjects: 1,
        mmapObjects: 0,
        stackFrameObjects: 0,
        activeAtScopeEnd: 0,
        releasedOrEnded: 1,
        reusedAddressCount: 0,
        failedAllocationCount: 0,
        lifecycleUnknownCount: 0,
        processedAccessCount: 5,
        attributedAccessCount: 5,
        unattributedAccessCount: 0,
        aliasCount: 1,
        anomalyCount: 1,
      },
      objectsTruncated: false,
      runtimeClustersTruncated: false,
      anomaliesTruncated: false,
      accessesTruncated: false,
      verificationGateMet: false,
      limitations: ["This is not a proof."],
      nextSteps: ["Capture exact allocator state."],
    };
    const explanation: MemoryPointerExplanation = {
      schemaVersion: "trace-ui/memory-pointer-explanation-v1",
      address: "0x1010",
      seq: 40,
      objectMatches: [{
        objectId: "heap:0x1000:g1",
        kind: "heap",
        generation: 1,
        baseAddress: "0x1000",
        size: 64,
        offset: "0x10",
        lifetimeStateAtSeq: "released",
        evidenceLevel: "related",
        rationale: "The query is after the reconstructed lifetime.",
      }],
      registerAliases: [{
        register: "X0",
        value: "0x1010",
        relation: "exact-pointer",
        displacement: "0x0",
        objectId: "heap:0x1000:g1",
        evidenceLevel: "observed",
      }],
      callAliases: [],
      nearbyAccesses: [],
      assessment: "released-generation-candidate",
      risks: ["Stale pointer remains Candidate."],
      unknowns: ["An omitted allocation may exist."],
      nextSteps: ["Capture exact state."],
      verificationGateMet: false,
    };
    mocks.invoke.mockImplementation(async (command: string) => {
      if (command === "reconstruct_memory_objects") return report;
      if (command === "explain_memory_pointer") return explanation;
      throw new Error(`unexpected command ${command}`);
    });

    render(<MemoryObjectsPanel sessionId="memory-session" isPhase2Ready onJumpToSeq={() => undefined} />);
    await user.click(screen.getByRole("button", { name: "Reconstruct objects" }));
    expect(mocks.invoke).toHaveBeenCalledWith("reconstruct_memory_objects", expect.objectContaining({
      sessionId: "memory-session",
      options: expect.objectContaining({ includeStackFrames: true, maxObjects: 1000 }),
    }));
    expect((await screen.findAllByText(/malloc/)).length).toBeGreaterThan(0);
    expect(screen.getByText(/access-after-lifetime/)).toBeInTheDocument();

    await user.type(screen.getByLabelText("Pointer address"), "0x1010");
    await user.click(screen.getByRole("button", { name: "Explain @ end" }));
    expect(mocks.invoke).toHaveBeenCalledWith("explain_memory_pointer", {
      sessionId: "memory-session",
      address: "0x1010",
      seq: null,
      includeStackFrames: true,
    });
    expect(await screen.findByText(/released-generation-candidate/)).toBeInTheDocument();
    expect(screen.getByText(/Candidate: Stale pointer remains Candidate/)).toBeInTheDocument();
  });
});
