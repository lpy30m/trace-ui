import { listen, emitTo } from "@tauri-apps/api/event";
import { WebviewWindow } from "@tauri-apps/api/webviewWindow";

interface DepTreeInitData {
  sessionId: string;
  seq?: number;
  target?: string;
  dataOnly?: boolean;
  fromSlice?: boolean;
}

export async function openDepTreeWindow(data: DepTreeInitData): Promise<void> {
  const winLabel = `panel-dep-tree-${Date.now()}`;
  const unlisten = await listen(`dep-tree:ready:${winLabel}`, () => {
    emitTo(winLabel, "dep-tree:init-data", data);
    unlisten();
  });
  new WebviewWindow(winLabel, {
    url: `index.html?panel=dep-tree`,
    title: "Dependency Tree",
    width: 800,
    height: 700,
    decorations: false,
    transparent: true,
  });
}
