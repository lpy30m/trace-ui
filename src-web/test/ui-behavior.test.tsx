import { render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { MaterialRow } from "../src/components/CryptoMaterialsPanel";
import OllvmUnicornPanel from "../src/components/OllvmUnicornPanel";
import { filterFridaCaptureEvents } from "../src/utils/fridaCaptureFilter";
import type { AngrOllvmScript, CryptoMaterial, FridaCaptureBundle, FridaCaptureEvent, OllvmReport, UnicornOllvmResultBundle } from "../src/types/trace";

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
