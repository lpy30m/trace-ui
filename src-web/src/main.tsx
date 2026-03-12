import ReactDOM from "react-dom/client";
import App from "./App";
import FloatingPanel from "./FloatingPanel";
import FloatingSession from "./FloatingSession";
import "./theme/global.css";

// 全局禁用原生右键菜单，所有右键功能由自定义组件接管
document.addEventListener("contextmenu", (e) => e.preventDefault());

// 检测 URL 参数，决定渲染主窗口、浮动面板还是浮动 session
const params = new URLSearchParams(window.location.search);
const panel = params.get("panel");
const session = params.get("session");

function renderRoot() {
  if (panel) {
    return <FloatingPanel panel={panel} />;
  }
  if (session) {
    return (
      <FloatingSession
        sessionId={session}
        totalLines={Number(params.get("totalLines") || "0")}
        fileName={params.get("fileName") || ""}
        filePath={params.get("filePath") || ""}
        initialTaintActive={params.get("taintActive") === "1"}
        initialTaintFilterMode={(params.get("taintFilterMode") as "highlight" | "filter-only") || "filter-only"}
        initialTaintSourceSeq={params.get("taintSourceSeq") ? Number(params.get("taintSourceSeq")) : undefined}
      />
    );
  }
  return <App />;
}

ReactDOM.createRoot(document.getElementById("root") as HTMLElement).render(
  renderRoot(),
);
