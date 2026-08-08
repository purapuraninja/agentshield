import { mkdtemp, readFile } from 'node:fs/promises';
import { join, resolve } from 'node:path';
import { tmpdir } from 'node:os';
import { describe, expect, it } from 'vitest';
import {
  addBaselineSuppressions, createBaseline, loadBaseline, pruneExpiredSuppressions, saveBaseline,
  scanTarget, validateBaseline, type Baseline
} from './index.js';

async function vulnerableReport() {
  return scanTarget(resolve('fixtures/vulnerable/exfiltration'));
}

describe('baseline lifecycle', () => {
  it('creates owned, reasoned, expiring suppressions from selected findings', async () => {
    const report = await vulnerableReport();
    const baseline = createBaseline(report, {
      owner: 'security-team', reason: 'accepted fixture during migration', expiresInDays: 30, minimumSeverity: 'critical'
    });
    expect(baseline.suppressions).toHaveLength(1);
    expect(baseline.suppressions[0]).toEqual(expect.objectContaining({
      fingerprint: report.findings.find((item) => item.ruleId === 'AS-SC-001')?.id,
      ruleId: 'AS-SC-001', owner: 'security-team', reason: 'accepted fixture during migration'
    }));
    expect(validateBaseline(baseline).valid).toBe(true);
  });

  it('suppresses only active exact fingerprints and never expired entries', async () => {
    const report = await vulnerableReport();
    const active = createBaseline(report, { owner: 'reviewer', reason: 'temporary review', expiresInDays: 1, minimumSeverity: 'critical' });
    const suppressed = await scanTarget(resolve('fixtures/vulnerable/exfiltration'), { baseline: active });
    expect(suppressed.findings.find((item) => item.ruleId === 'AS-SC-001')?.status).toBe('suppressed');

    const expired: Baseline = { ...active, suppressions: active.suppressions.map((item) => ({ ...item, expiresAt: '2020-01-01T00:00:00.000Z' })) };
    expect(validateBaseline(expired).expired).toBe(1);
    const visible = await scanTarget(resolve('fixtures/vulnerable/exfiltration'), { baseline: expired });
    expect(visible.findings.find((item) => item.ruleId === 'AS-SC-001')?.status).toBe('open');
  });

  it('rejects missing ownership, malformed fingerprints, and duplicates', async () => {
    const report = await vulnerableReport();
    const valid = createBaseline(report, { owner: 'reviewer', reason: 'temporary review', expiresInDays: 7, minimumSeverity: 'critical' });
    const invalid = {
      ...valid,
      suppressions: [
        { ...valid.suppressions[0]!, owner: '' },
        { ...valid.suppressions[0]!, fingerprint: 'not-a-hash' }
      ]
    };
    const result = validateBaseline(invalid);
    expect(result.valid).toBe(false);
    expect(result.invalid).toEqual(expect.arrayContaining([expect.stringContaining('owner is required'), expect.stringContaining('sha256 fingerprint')]));
    await expect(scanTarget(resolve('fixtures/vulnerable/exfiltration'), { baseline: invalid as Baseline })).rejects.toThrow('Invalid baseline');
  });

  it('adds unique selected findings and rejects duplicates', async () => {
    const report = await vulnerableReport();
    const critical = report.findings.find((item) => item.ruleId === 'AS-SC-001')!;
    const network = report.findings.find((item) => item.ruleId === 'AS-SC-006')!;
    const baseline = createBaseline(report, { owner: 'reviewer', reason: 'critical review', expiresInDays: 7, fingerprints: [critical.id] });
    const updated = addBaselineSuppressions(baseline, report, { owner: 'network-owner', reason: 'known destination', expiresInDays: 14, fingerprints: [network.id] });
    expect(updated.suppressions).toHaveLength(2);
    expect(() => addBaselineSuppressions(updated, report, { owner: 'reviewer', reason: 'duplicate', expiresInDays: 7, fingerprints: [critical.id] })).toThrow('already contains');
  });

  it('prunes expired entries and persists atomically', async () => {
    const report = await vulnerableReport();
    const baseline = createBaseline(report, { owner: 'reviewer', reason: 'temporary', expiresInDays: 7, minimumSeverity: 'high' });
    baseline.suppressions[0] = { ...baseline.suppressions[0]!, expiresAt: '2020-01-01T00:00:00.000Z' };
    const result = pruneExpiredSuppressions(baseline);
    expect(result.removed).toHaveLength(1);
    expect(result.baseline.suppressions.length).toBe(baseline.suppressions.length - 1);
    const directory = await mkdtemp(join(tmpdir(), 'agentshield-baseline-'));
    const path = join(directory, 'nested', 'baseline.json');
    await saveBaseline(path, result.baseline);
    expect(await loadBaseline(path)).toEqual(result.baseline);
    expect(JSON.parse(await readFile(path, 'utf8'))).toEqual(result.baseline);
  });
});
