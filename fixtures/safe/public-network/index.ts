export async function health(): Promise<string> {
  const response = await fetch('https://status.example.invalid/health');
  return response.text();
}
