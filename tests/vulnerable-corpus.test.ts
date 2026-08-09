import { readFileSync } from 'node:fs';
import { readdir } from 'node:fs/promises';
import { join, resolve } from 'node:path';
import { describe, expect, it } from 'vitest';
import { scanTarget } from '@agentshield/scanner';

interface VulnerableTarget {
  id: string;
  path: string;
  expect: string[];
}

interface VulnerableManifest {
  version: number;
  targets: VulnerableTarget[];
}

const VULNERABLE_ROOT = resolve('fixtures/vulnerable');
const SAFE_ROOT = resolve('fixtures/safe');
const manifest = JSON.parse(readFileSync(join(VULNERABLE_ROOT, 'manifest.json'), 'utf8')) as VulnerableManifest;

describe('intentionally vulnerable scanner corpus', () => {
  it('defines at least 15 intentionally vulnerable fixtures', () => {
    expect(manifest.targets.length).toBeGreaterThanOrEqual(15);
  });

  it('every vulnerable fixture triggers its expected rules with deterministic evidence', async () => {
    for (const target of manifest.targets) {
      const report = await scanTarget(join(VULNERABLE_ROOT, target.path));
      const found = new Set(report.findings.map((item) => item.ruleId));
      for (const ruleId of target.expect) {
        expect(found, `${target.id} should trigger ${ruleId}`).toContain(ruleId);
      }
      // Every expected finding must carry remediation and evidence.
      for (const finding of report.findings.filter((item) => target.expect.includes(item.ruleId))) {
        expect(finding.remediation.length, `${target.id}:${finding.ruleId} remediation`).toBeGreaterThan(20);
        expect(finding.evidence.length, `${target.id}:${finding.ruleId} evidence`).toBeGreaterThan(0);
      }
    }
  });

  it('keeps the maintained safe corpus free of critical/high false positives', async () => {
    const names = (await readdir(SAFE_ROOT)).filter((name) => !name.startsWith('.'));
    expect(names.length).toBeGreaterThanOrEqual(5);
    for (const name of names) {
      const report = await scanTarget(join(SAFE_ROOT, name));
      const critical = report.findings.filter((item) => ['critical', 'high'].includes(item.severity));
      // Documented gate: high-severity FP rate < 10% on the maintained safe corpus.
      expect(critical, `safe fixture ${name} produced high/critical findings`).toHaveLength(0);
    }
  });
});
