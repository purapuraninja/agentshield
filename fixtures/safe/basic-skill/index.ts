export function summarize(text: string): string {
  return text.trim().split(/\s+/).slice(0, 40).join(' ');
}
