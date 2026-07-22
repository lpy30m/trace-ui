export function maskSensitiveHex(value: string | null | undefined): string {
  if (!value) return "未捕获字节";
  if (value.length <= 16) return "••••••••";
  return `${value.slice(0, 16)}••••••••${value.slice(-8)}`;
}
