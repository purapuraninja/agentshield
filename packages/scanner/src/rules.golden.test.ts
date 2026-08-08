import { mkdir, mkdtemp, readFile, writeFile } from 'node:fs/promises';
import { dirname, join, resolve } from 'node:path';
import { tmpdir } from 'node:os';
import { beforeAll, describe, expect, it } from 'vitest';
import type { Confidence, Severity } from '@agentshield/core';
import { scanTarget, staticRules } from './index.js';

interface GoldenCase {
  id: string;
  path: string;
  positive: string;
  negative: [string, string];
  severity: Severity;
  confidence: Confidence;
  evidence: string;
}

let cases: GoldenCase[] = [];
let fixtureRoot = '';

beforeAll(async () => {
  cases = JSON.parse(await readFile(resolve('fixtures/rules/golden-cases.json'), 'utf8')) as GoldenCase[];
  fixtureRoot = await mkdtemp(join(tmpdir(), 'agentshield-golden-'));
});

async function scanCase(testCase: GoldenCase, variant: string, content: string) {
  const target = join(fixtureRoot, testCase.id, variant, testCase.path);
  await mkdir(dirname(target), { recursive: true });
  await writeFile(target, content, 'utf8');
  return scanTarget(target);
}

describe('production rule golden matrix', () => {
  it('covers every registered production rule exactly once', () => {
    const registered = staticRules.map((rule) => rule.id).sort();
    const catalogued = cases.map((testCase) => testCase.id).sort();
    expect(catalogued).toEqual(registered);
    expect(new Set(catalogued).size).toBe(catalogued.length);
  });

  it('defines one positive and two safe negative cases per rule', () => {
    for (const testCase of cases) {
      expect(testCase.positive.trim()).not.toBe('');
      expect(testCase.negative).toHaveLength(2);
      expect(testCase.negative.every((item) => item.trim() !== '')).toBe(true);
    }
  });

  it('matches every true-positive with canonical evidence and metadata', async () => {
    for (const testCase of cases) {
      const report = await scanCase(testCase, 'positive', testCase.positive);
      const finding = report.findings.find((item) => item.ruleId === testCase.id);
      expect(finding, `${testCase.id} should match its positive fixture`).toBeDefined();
      expect(finding?.severity).toBe(testCase.severity);
      expect(finding?.confidence).toBe(testCase.confidence);
      expect(finding?.evidence[0]?.excerpt.toLowerCase()).toContain(testCase.evidence.toLowerCase());
      expect(finding?.remediation.length).toBeGreaterThan(20);
    }
  });

  it('does not match either safe negative case', async () => {
    for (const testCase of cases) {
      for (let index = 0; index < testCase.negative.length; index++) {
        const report = await scanCase(testCase, `negative-${index + 1}`, testCase.negative[index]!);
        expect(report.findings.some((item) => item.ruleId === testCase.id), `${testCase.id} matched safe negative ${index + 1}`).toBe(false);
      }
    }
  });
});
