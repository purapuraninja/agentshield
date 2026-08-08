import { mkdir, readFile, rename, writeFile } from 'node:fs/promises';
import { dirname } from 'node:path';
import { createId, sha256 } from '@agentshield/core';

export const DEFAULT_CONSENT_PATH = '.agentshield/telemetry-consent.json';

export interface TelemetryConsentEvent {
  eventId: string;
  timestamp: string;
  actor: string;
  action: 'enable' | 'disable';
  reason: string;
  previousHash: string;
  hash: string;
}
export interface TelemetryConsentFile {
  version: 1;
  events: TelemetryConsentEvent[];
}

export async function readConsent(path: string): Promise<TelemetryConsentFile> {
  try {
    return JSON.parse(await readFile(path, 'utf8')) as TelemetryConsentFile;
  } catch {
    return { version: 1, events: [] };
  }
}

/**
 * Consent is determined by the latest event: an `enable` with no later `disable` means enabled.
 * Absence of any event means disabled, which is the default.
 */
export function consentState(file: TelemetryConsentFile): 'enabled' | 'disabled' {
  const last = file.events.at(-1);
  return last && last.action === 'enable' ? 'enabled' : 'disabled';
}

export async function appendConsentEvent(
  path: string,
  action: 'enable' | 'disable',
  actor: string,
  reason: string
): Promise<TelemetryConsentEvent> {
  if (!actor.trim() || !reason.trim()) throw new Error('Telemetry consent requires a non-empty actor and reason');
  const file = await readConsent(path);
  const previousHash = file.events.at(-1)?.hash ?? 'genesis';
  const base = { eventId: createId('consent'), timestamp: new Date().toISOString(), actor, action, reason, previousHash };
  const event: TelemetryConsentEvent = { ...base, hash: sha256(JSON.stringify(base)) };
  file.events.push(event);
  await mkdir(dirname(path), { recursive: true });
  const temporary = `${path}.${process.pid}.tmp`;
  await writeFile(temporary, `${JSON.stringify(file, null, 2)}\n`, { encoding: 'utf8', mode: 0o600 });
  await rename(temporary, path);
  return event;
}

/**
 * Describes the schema of telemetry that a future opt-in could collect. The Community edition never
 * transmits telemetry; this preview is for transparency so a user can see exactly what would and
 * would not be collected before deciding.
 */
export function buildTelemetryDataPreview(): {
  schemaVersion: string;
  transmission: 'disabled';
  metrics: Array<{ name: string; description: string; granularity: string }>;
  exclusions: string[];
  note: string;
} {
  return {
    schemaVersion: '1.0.0',
    transmission: 'disabled',
    metrics: [
      { name: 'scan.count', description: 'Number of scans run', granularity: 'aggregate' },
      { name: 'scan.findings.by_severity', description: 'Finding counts grouped by severity', granularity: 'aggregate' },
      { name: 'memory.records.audited', description: 'Number of memory records audited', granularity: 'aggregate' },
      { name: 'rule.matched', description: 'Rule IDs that matched, without target paths', granularity: 'aggregate' }
    ],
    exclusions: ['raw file content', 'raw memory content', 'secrets', 'personal data', 'environment variable values', 'target paths', 'user identifiers'],
    note: 'The Community edition never transmits telemetry. This preview describes the schema a future opt-in could collect; enabling consent only records the opt-in locally.'
  };
}
