import { useState, useEffect, useCallback } from "react";
import { invoke } from "@tauri-apps/api/core";
import { listen } from "@tauri-apps/api/event";

export interface McpStatusInfo {
  status: "running" | "stopped" | "error";
  port: number | null;
  url: string | null;
  error: string | null;
}

const INITIAL: McpStatusInfo = {
  status: "stopped",
  port: null,
  url: null,
  error: null,
};

export function useMcpStatus() {
  const [mcpStatus, setMcpStatus] = useState<McpStatusInfo>(INITIAL);

  useEffect(() => {
    // 挂载时同步一次实际状态
    invoke<McpStatusInfo>("get_mcp_status").then(setMcpStatus).catch(console.error);

    const promise = listen<McpStatusInfo>("mcp:status-changed", (e) => {
      setMcpStatus(e.payload);
    });
    return () => {
      promise.then((fn) => fn());
    };
  }, []);

  const startMcp = useCallback(async (port?: number) => {
    const info = await invoke<McpStatusInfo>("start_mcp", { port: port ?? null });
    setMcpStatus(info);
    return info;
  }, []);

  const stopMcp = useCallback(async () => {
    const info = await invoke<McpStatusInfo>("stop_mcp");
    setMcpStatus(info);
    return info;
  }, []);

  const refreshStatus = useCallback(async () => {
    const info = await invoke<McpStatusInfo>("get_mcp_status");
    setMcpStatus(info);
  }, []);

  return { mcpStatus, startMcp, stopMcp, refreshStatus };
}
