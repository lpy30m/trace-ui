import { readFile, readdir } from "node:fs/promises";
import { extname, join, relative } from "node:path";

const sourceRoot = new URL("../src/", import.meta.url);
const allowedExtensions = new Set([".ts", ".tsx", ".js", ".jsx"]);
const requiredChecks = [
  ["components/TabPanel.tsx", "const FLOATABLE_PANELS"],
  ["utils/sensitiveMaterial.ts", "maskSensitiveHex"],
  ["components/FridaHookPanel.tsx", "手动工作流"],
  ["components/FridaHookPanel.tsx", "filteredCaptureEvents"],
  ["components/OllvmPanel.tsx", "手动工作流"],
  ["components/CryptoPanel.tsx", "mountedViews"],
];
const forbiddenPatterns = [
  [/(?:^|[^A-Za-z])frida\.attach\s*\(/, "禁止由前端自动 attach Frida"],
  [/(?:^|[^A-Za-z])frida\.spawn\s*\(/, "禁止由前端自动 spawn Frida"],
  [/get_usb_device\s*\(/, "禁止由前端自动发现 Frida 设备"],
];
const staleUiText = [
  "Panel not yet implemented",
  "Analyze Functions",
  "Index Materials",
  "Include unclassified call buffers",
  "Multi-trace Salt/Nonce",
  "One digest per line",
  "No saved analyses.",
  "No results found for",
  "Searching...",
];

async function collectFiles(directory) {
  const entries = await readdir(directory, { withFileTypes: true });
  const files = [];
  for (const entry of entries) {
    const path = new URL(`${entry.name}${entry.isDirectory() ? "/" : ""}`, directory);
    if (entry.isDirectory()) files.push(...await collectFiles(path));
    else if (allowedExtensions.has(extname(entry.name))) files.push(path);
  }
  return files;
}

const failures = [];
for (const file of await collectFiles(sourceRoot)) {
  const content = await readFile(file, "utf8");
  const label = relative(sourceRoot.pathname, file.pathname).replaceAll("\\", "/");
  for (const [pattern, message] of forbiddenPatterns) {
    if (pattern.test(content)) failures.push(`${label}: ${message}`);
  }
  for (const text of staleUiText) {
    if (content.includes(text)) failures.push(`${label}: 残留旧界面文案 ${JSON.stringify(text)}`);
  }
}

for (const [path, marker] of requiredChecks) {
  const content = await readFile(new URL(path, sourceRoot), "utf8");
  if (!content.includes(marker)) failures.push(`${path}: 缺少 UI 防护标记 ${JSON.stringify(marker)}`);
}

if (failures.length > 0) {
  console.error(failures.join("\n"));
  process.exitCode = 1;
} else {
  console.log("UI guards passed: manual Frida boundary, floatable panels, masking, and localized text.");
}
