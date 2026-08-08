import { mkdtemp, readFile } from 'node:fs/promises';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { describe, expect, it } from 'vitest';
import {
  appendConsentEvent, buildTelemetryDataPreview, consentState, readConsent
} from './telemetry.js';

async function consentPath(): Promise<string> {
  const directory = await mkdtemp(join(tmpdir(), 'agentshield-telemetry-'));
  return join(directory, 'telemetry-consent.json');
}

describe('telemetry consent', () => {
  it('is disabled by default and never transmits', async () => {
    const path = await consentPath();
    expect(consentState(await readConsent(path))).toBe('disabled');
    expect(buildTelemetryDataPreview().transmission).toBe('disabled');
  });

  it('records a hash-chained consent receipt on enable and revokes on disable', async () => {
    const path = await consentPath();
    const enabled = await appendConsentEvent(path, 'enable', 'analyst', 'team opt-in');
    expect(enabled.action).toBe('enable');
    expect(enabled.previousHash).toBe('genesis');
    expect(enabled.hash).toMatch(/^sha256:[a-f0-9]{64}$/);
    expect(consentState(await readConsent(path))).toBe('enabled');

    const disabled = await appendConsentEvent(path, 'disable', 'analyst', 'rolling back opt-in');
    expect(disabled.previousHash).toBe(enabled.hash);
    expect(consentState(await readConsent(path))).toBe('disabled');

    const file = JSON.parse(await readFile(path, 'utf8'));
    expect(file.events).toHaveLength(2);
    expect(file.events[0].hash).toBe(enabled.hash);
  });

  it('requires a non-empty actor and reason', async () => {
    const path = await consentPath();
    await expect(appendConsentEvent(path, 'enable', '  ', 'reason')).rejects.toThrow(/actor and reason/);
  });

  it('persists a versioned consent schema atomically', async () => {
    const path = await consentPath();
    await appendConsentEvent(path, 'enable', 'analyst', 'team opt-in');
    const file = JSON.parse(await readFile(path, 'utf8'));
    expect(file.version).toBe(1);
  });

  it('describes a telemetry schema that excludes raw and sensitive content', () => {
    const preview = buildTelemetryDataPreview();
    expect(preview.schemaVersion).toBe('1.0.0');
    expect(preview.metrics.length).toBeGreaterThan(0);
    const exclusions = preview.exclusions.join(' ');
    expect(exclusions).toMatch(/raw file content/);
    expect(exclusions).toMatch(/secrets/);
    expect(exclusions).toMatch(/personal data/);
  });
});
