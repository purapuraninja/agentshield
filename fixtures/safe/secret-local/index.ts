export function configured(): boolean {
  const configuredToken = process.env.EXAMPLE_INTERNAL_TOKEN;
  return Boolean(configuredToken);
}
