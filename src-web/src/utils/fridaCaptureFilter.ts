import type { FridaCaptureEvent } from "../types/trace";

export type CaptureEventType = "all" | "hook-enter" | "hook-leave" | "ollvm-dispatcher-hit" | "stalker";

export interface CaptureEventFilterOptions {
  query?: string;
  eventType?: CaptureEventType;
  onlyPayload?: boolean;
}

export function filterFridaCaptureEvents(
  events: FridaCaptureEvent[],
  { query = "", eventType = "all", onlyPayload = false }: CaptureEventFilterOptions = {},
): FridaCaptureEvent[] {
  const normalizedQuery = query.trim().toLowerCase();
  return events.filter(event => {
    if (eventType !== "all") {
      const matchesType = eventType === "stalker"
        ? event.event.toLowerCase().includes("stalker")
        : event.event === eventType;
      if (!matchesType) return false;
    }
    if (onlyPayload && Object.keys(event.registers).length === 0 && event.captures.length === 0 && !event.returnValue) {
      return false;
    }
    if (!normalizedQuery) return true;
    const searchable = [
      event.event,
      event.functionName,
      event.moduleName,
      event.target,
      event.callId,
      event.hookId,
      event.dispatcherOffset,
      event.captureSessionId,
      event.flowId,
    ].filter(Boolean).join(" ").toLowerCase();
    return searchable.includes(normalizedQuery);
  });
}
