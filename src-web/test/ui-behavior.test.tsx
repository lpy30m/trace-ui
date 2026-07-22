import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it } from "vitest";
import { MaterialRow } from "../src/components/CryptoMaterialsPanel";
import { filterFridaCaptureEvents } from "../src/utils/fridaCaptureFilter";
import type { CryptoMaterial, FridaCaptureEvent } from "../src/types/trace";

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
