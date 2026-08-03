import { mkdtemp, writeFile } from 'node:fs/promises';
import { join, resolve } from 'node:path';
import { tmpdir } from 'node:os';
import { describe, expect, it } from 'vitest';
import { evaluatePolicy, scanTarget, staticRules, type PolicyFile } from './index.js';

const fixture = (...parts: string[]) => resolve('fixtures', ...parts);

describe('static scanner', () => {
  it('keeps the minimal safe fixture free of high-severity findings', async () => {
    const report = await scanTarget(fixture('safe', 'basic-skill'));
    expect(report.status).toBe('completed');
    expect(report.filesScanned).toBe(3);
    expect(report.findings.filter((item) => ['critical', 'high'].includes(item.severity))).toHaveLength(0);
  });

  it('detects secret/network correlation with redacted evidence', async () => {
    const report = await scanTarget(fixture('vulnerable', 'exfiltration'));
    expect(report.findings.map((item) => item.ruleId)).toContain('AS-SC-001');
    expect(report.overallRisk).toBe(100);
    expect(report.permissions).toEqual(expect.arrayContaining([
      expect.objectContaining({ resource: 'environment', action: 'read' }),
      expect.objectContaining({ resource: 'network', action: 'connect' })
    ]));
  });

  it('detects download-to-execute and dangerous MCP scopes', async () => {
    const download = await scanTarget(fixture('vulnerable', 'download-execute'));
    const mcp = await scanTarget(fixture('vulnerable', 'mcp'));
    expect(download.findings.map((item) => item.ruleId)).toContain('AS-SC-002');
    expect(mcp.findings.map((item) => item.ruleId)).toEqual(expect.arrayContaining(['AS-SC-024', 'AS-SC-025']));
  });

  it('reports malformed structured input as incomplete analysis', async () => {
    const directory = await mkdtemp(join(tmpdir(), 'agentshield-parser-'));
    await writeFile(join(directory, 'broken.json'), '{"tools": [}', 'utf8');
    const report = await scanTarget(directory);
    expect(report.status).toBe('partial');
    expect(report.findings.some((item) => item.ruleId === 'AS-SC-900')).toBe(true);
  });

  it('has production metadata for every static rule', () => {
    expect(staticRules.length).toBeGreaterThanOrEqual(20);
    for (const rule of staticRules) {
      expect(rule.remediation.length).toBeGreaterThan(20);
      expect(rule.owner).toBeTruthy();
      expect(Number.isNaN(Date.parse(rule.reviewDate))).toBe(false);
      expect(rule.limitations).toBeTruthy();
    }
  });

  it('blocks critical reports through default policy', async () => {
    const report = await scanTarget(fixture('vulnerable', 'exfiltration'));
    const policy: PolicyFile = { version: 1, defaults: { on_critical: 'block' } };
    expect(evaluatePolicy(report, policy).action).toBe('block');
  });
});
