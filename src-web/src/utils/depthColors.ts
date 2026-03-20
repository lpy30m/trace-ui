export const DEPTH_COLORS = [
  "#e06c75", // red
  "#e5c07b", // yellow
  "#98c379", // green
  "#61afef", // blue
  "#c678dd", // purple
  "#abb2bf", // gray
];

export function getDepthColor(depth: number): string {
  return DEPTH_COLORS[depth % DEPTH_COLORS.length];
}
