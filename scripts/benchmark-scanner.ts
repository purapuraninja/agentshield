import { mkdir, mkdtemp, rm, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { scanTarget } from '@agentshield/scanner';

function numericArgument(name: string, fallback: number): number {
  const index = process.argv.indexOf(name);
  if (index < 0) return fallback;
  const value = Number(process.argv[index + 1]);
  if (!Number.isFinite(value) || value <= 0 || !Number.isInteger(value)) throw new Error(`${name} must be a positive integer`);
  return value;
}

async function main(): Promise<void> {
  const fileCount = numericArgument('--files', 10_000);
  const budgetMs = numericArgument('--budget-ms', 300_000);
  const jsonOutput = process.argv.includes('--json');
  const root = await mkdtemp(join(tmpdir(), 'agentshield-benchmark-'));
  const fixtureStarted = performance.now();
  let bytes = 0;
  try {
    for (let offset = 0; offset < fileCount; offset += 200) {
      const batch: Promise<void>[] = [];
      for (let index = offset; index < Math.min(fileCount, offset + 200); index++) {
        const directory = join(root, `group-${Math.floor(index / 100)}`);
        const content = `export const fixture${index} = { id: ${index}, safe: true, label: 'benchmark-${index}' };\n`;
        bytes += Buffer.byteLength(content);
        batch.push(mkdir(directory, { recursive: true }).then(() => writeFile(join(directory, `file-${index}.ts`), content, 'utf8')));
      }
      await Promise.all(batch);
    }
    const fixtureDurationMs = performance.now() - fixtureStarted;
    const memoryBefore = process.memoryUsage().heapUsed;
    const scanStarted = performance.now();
    const report = await scanTarget(root);
    const durationMs = performance.now() - scanStarted;
    const heapDeltaBytes = process.memoryUsage().heapUsed - memoryBefore;
    const result = {
      benchmarkVersion: 1,
      scannerVersion: report.scannerVersion,
      rulepackVersion: report.rulepackVersion,
      filesRequested: fileCount,
      filesScanned: report.filesScanned,
      bytesScanned: report.bytesScanned,
      generatedBytes: bytes,
      findings: report.findings.length,
      status: report.status,
      fixtureDurationMs: Math.round(fixtureDurationMs * 10) / 10,
      scanDurationMs: Math.round(durationMs * 10) / 10,
      filesPerSecond: Math.round((fileCount / durationMs) * 1000),
      heapDeltaBytes,
      budgetMs,
      withinBudget: durationMs <= budgetMs && report.filesScanned === fileCount && report.status === 'completed'
    };
    if (jsonOutput) process.stdout.write(`${JSON.stringify(result, null, 2)}\n`);
    else process.stdout.write([
      `AgentShield scanner benchmark — ${fileCount.toLocaleString()} files`,
      `Scan: ${result.scanDurationMs} ms | Throughput: ${result.filesPerSecond.toLocaleString()} files/s`,
      `Data: ${(result.bytesScanned / 1_048_576).toFixed(2)} MiB | Heap delta: ${(heapDeltaBytes / 1_048_576).toFixed(2)} MiB`,
      `Status: ${result.status} | Findings: ${result.findings} | Budget: ${budgetMs} ms`,
      `Result: ${result.withinBudget ? 'PASS' : 'FAIL'}`
    ].join('\n') + '\n');
    if (!result.withinBudget) process.exitCode = 1;
  } finally {
    await rm(root, { recursive: true, force: true });
  }
}

main().catch((error: unknown) => {
  console.error(error instanceof Error ? error.message : String(error));
  process.exitCode = 1;
});
