import { mkdir, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { dirname, join, resolve } from 'node:path';
import { tmpdir } from 'node:os';
import { scanTarget, staticRules } from '@agentshield/scanner';
import type { Confidence, Severity } from '@agentshield/core';

interface GoldenCase {
  id: string;
  path: string;
  positive: string;
  negative: [string, string];
  severity: Severity;
  confidence: Confidence;
  evidence: string;
}

interface RuleQuality {
  ruleId: string;
  truePositive: boolean;
  falseNegative: boolean;
  falsePositives: number;
  trueNegatives: number;
  metadataValid: boolean;
  reviewAgeDays: number;
}

async function main(): Promise<void> {
  const jsonOutput = process.argv.includes('--json');
  const catalogPath = resolve('fixtures/rules/golden-cases.json');
  const cases = JSON.parse(await readFile(catalogPath, 'utf8')) as GoldenCase[];
  const root = await mkdtemp(join(tmpdir(), 'agentshield-rule-quality-'));
  const started = performance.now();
  const results: RuleQuality[] = [];

  async function scanFixture(testCase: GoldenCase, variant: string, content: string) {
    const target = join(root, testCase.id, variant, testCase.path);
    await mkdir(dirname(target), { recursive: true });
    await writeFile(target, content, 'utf8');
    return scanTarget(target);
  }

try {
  for (const testCase of cases) {
    const rule = staticRules.find((item) => item.id === testCase.id);
    if (!rule) throw new Error(`Golden case references unknown rule ${testCase.id}`);
    const positive = await scanFixture(testCase, 'positive', testCase.positive);
    const finding = positive.findings.find((item) => item.ruleId === testCase.id);
    let falsePositives = 0;
    for (let index = 0; index < testCase.negative.length; index++) {
      const negative = await scanFixture(testCase, `negative-${index + 1}`, testCase.negative[index]!);
      if (negative.findings.some((item) => item.ruleId === testCase.id)) falsePositives++;
    }
    results.push({
      ruleId: testCase.id,
      truePositive: Boolean(finding),
      falseNegative: !finding,
      falsePositives,
      trueNegatives: testCase.negative.length - falsePositives,
      metadataValid: Boolean(finding && finding.severity === testCase.severity && finding.confidence === testCase.confidence && finding.remediation.length > 20),
      reviewAgeDays: Math.max(0, Math.floor((Date.now() - Date.parse(rule.reviewDate)) / 86_400_000))
    });
  }
} finally {
  await rm(root, { recursive: true, force: true });
}

const truePositives = results.filter((item) => item.truePositive).length;
const falseNegatives = results.filter((item) => item.falseNegative).length;
const falsePositives = results.reduce((sum, item) => sum + item.falsePositives, 0);
const trueNegatives = results.reduce((sum, item) => sum + item.trueNegatives, 0);
const precision = truePositives + falsePositives ? truePositives / (truePositives + falsePositives) : 0;
const recall = truePositives + falseNegatives ? truePositives / (truePositives + falseNegatives) : 0;
const summary = {
  catalogVersion: 1,
  rulepackVersion: '2026.08.2',
  rules: results.length,
  fixtures: { positive: cases.length, negative: cases.length * 2 },
  confusionMatrix: { truePositives, falsePositives, trueNegatives, falseNegatives },
  precision,
  recall,
  metadataValid: results.every((item) => item.metadataValid),
  staleReviews: results.filter((item) => item.reviewAgeDays > 90).map((item) => item.ruleId),
  durationMs: Math.round((performance.now() - started) * 10) / 10,
  perRule: results
};

if (jsonOutput) process.stdout.write(`${JSON.stringify(summary, null, 2)}\n`);
else {
  process.stdout.write([
    `AgentShield rule quality — ${summary.rulepackVersion}`,
    `Rules: ${summary.rules} | Positive fixtures: ${summary.fixtures.positive} | Safe negatives: ${summary.fixtures.negative}`,
    `Precision: ${(precision * 100).toFixed(1)}% | Recall: ${(recall * 100).toFixed(1)}%`,
    `TP ${truePositives} / FP ${falsePositives} / TN ${trueNegatives} / FN ${falseNegatives}`,
    `Metadata: ${summary.metadataValid ? 'valid' : 'invalid'} | Stale reviews: ${summary.staleReviews.length}`,
    `Completed in ${summary.durationMs} ms`
  ].join('\n') + '\n');
}

  if (falseNegatives || falsePositives || !summary.metadataValid || summary.staleReviews.length) process.exitCode = 1;
}

main().catch((error: unknown) => {
  console.error(error instanceof Error ? error.message : String(error));
  process.exitCode = 1;
});
