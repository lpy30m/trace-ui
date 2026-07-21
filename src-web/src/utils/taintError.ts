export interface TaintErrorPresentation {
  title: string;
  suggestion: string;
  detail: string;
}

function cleanError(error: unknown): string {
  return String(error)
    .replace(/^Error:\s*/i, "")
    .replace(/^invalid argument:\s*/i, "")
    .trim();
}

export function explainTaintError(error: unknown): TaintErrorPresentation {
  const detail = cleanError(error);
  const normalized = detail.toLowerCase();

  if (normalized.includes("index not built") || normalized.includes("index not ready")) {
    return {
      title: "Trace index is not ready",
      suggestion: "Wait for indexing to finish, then run the analysis again.",
      detail,
    };
  }

  if (normalized.includes("从未被定义") || normalized.includes("没有可用定义") || normalized.includes("no available definition")) {
    return {
      title: "No earlier definition was found",
      suggestion: "Move to a later instruction, expand the history range, or confirm that the trace starts before this value is created.",
      detail,
    };
  }

  if (normalized.includes("未知寄存器") || normalized.includes("unknown register")) {
    return {
      title: "The register name is not valid",
      suggestion: "Select a register directly from the trace row or use an ARM64 register such as X0, SP, or NZCV.",
      detail,
    };
  }

  if (normalized.includes("4096") || normalized.includes("长度不能超过") || normalized.includes("地址溢出")) {
    return {
      title: "The memory range is not valid",
      suggestion: "Use a range between 1 and 4096 bytes and verify the start address.",
      detail,
    };
  }

  if (normalized.includes("行号") || normalized.includes("source line") || normalized.includes("out of range")) {
    return {
      title: "The selected instruction is outside the trace",
      suggestion: "Select an instruction inside the loaded trace and run the analysis again.",
      detail,
    };
  }

  if (normalized.includes("session not found")) {
    return {
      title: "The trace session is no longer available",
      suggestion: "Reopen the trace file before running the analysis again.",
      detail,
    };
  }

  if (normalized.includes("cancelled")) {
    return {
      title: "Analysis was cancelled",
      suggestion: "Run it again when the trace is ready.",
      detail,
    };
  }

  return {
    title: "Taint analysis failed",
    suggestion: "Verify the selected source and instruction, then retry with Focused scope.",
    detail,
  };
}
