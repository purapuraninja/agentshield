import { mkdir, readFile, rename, writeFile } from 'node:fs/promises';
import { dirname, resolve } from 'node:path';
import { severityRank, type ScanReport, type Severity } from '@agentshield/core';

export interface BaselineSuppression {
  fingerprint: string;
  ruleId?: string;
  path?: string;
  owner: string;
  reason: string;
  expiresAt: string;
  createdAt?: string;
}

export interface Baseline {
  version: 1;
  createdAt?: string;
  suppressions: BaselineSuppression[];
}

export interface BaselineValidation {
  valid: boolean;
  active: number;
  expired: number;
  invalid: string[];
  duplicateFingerprints: string[];
}

export interface BaselineSelection {
  owner: string;
  reason: string;
  expiresInDays: number;
  fingerprints?: string[];
  minimumSeverity?: Severity;
  now?: Date;
}

export function validateBaseline(value: unknown, now = new Date()): BaselineValidation {
  const invalid: string[] = [];
  if (!value || typeof value !== 'object') return { valid: false, active: 0, expired: 0, invalid: ['Baseline must be an object'], duplicateFingerprints: [] };
  const object = value as Record<string, unknown>;
  if (object.version !== 1) invalid.push('version must equal 1');
  if (!Array.isArray(object.suppressions)) return { valid: false, active: 0, expired: 0, invalid: [...invalid, 'suppressions must be an array'], duplicateFingerprints: [] };
  const seen = new Set<string>();
  const duplicateFingerprints = new Set<string>();
  let active = 0;
  let expired = 0;
  object.suppressions.forEach((raw, index) => {
    const prefix = `suppressions[${index}]`;
    if (!raw || typeof raw !== 'object') { invalid.push(`${prefix} must be an object`); return; }
    const item = raw as Record<string, unknown>;
    const fingerprint = typeof item.fingerprint === 'string' ? item.fingerprint.trim() : '';
    if (!/^sha256:[a-f0-9]{64}$/.test(fingerprint)) invalid.push(`${prefix}.fingerprint must be a sha256 fingerprint`);
    if (seen.has(fingerprint)) duplicateFingerprints.add(fingerprint); else if (fingerprint) seen.add(fingerprint);
    if (typeof item.owner !== 'string' || !item.owner.trim()) invalid.push(`${prefix}.owner is required`);
    if (typeof item.reason !== 'string' || !item.reason.trim()) invalid.push(`${prefix}.reason is required`);
    if (typeof item.expiresAt !== 'string' || !Number.isFinite(Date.parse(item.expiresAt))) invalid.push(`${prefix}.expiresAt must be an ISO date`);
    else if (Date.parse(item.expiresAt) <= now.getTime()) expired++; else active++;
  });
  if (duplicateFingerprints.size) invalid.push(`duplicate fingerprints: ${[...duplicateFingerprints].join(', ')}`);
  return { valid: invalid.length === 0, active, expired, invalid, duplicateFingerprints: [...duplicateFingerprints] };
}

export function parseBaseline(value: unknown, now = new Date()): Baseline {
  const validation = validateBaseline(value, now);
  if (!validation.valid) throw new Error(`Invalid baseline: ${validation.invalid.join('; ')}`);
  return value as Baseline;
}

export async function loadBaseline(path: string, now = new Date()): Promise<Baseline> {
  let value: unknown;
  try { value = JSON.parse(await readFile(path, 'utf8')); }
  catch (error) { throw new Error(`Cannot read baseline ${resolve(path)}: ${error instanceof Error ? error.message : String(error)}`); }
  return parseBaseline(value, now);
}

export async function saveBaseline(path: string, baseline: Baseline): Promise<void> {
  parseBaseline(baseline);
  const absolute = resolve(path);
  await mkdir(dirname(absolute), { recursive: true });
  const temporary = `${absolute}.${process.pid}.tmp`;
  await writeFile(temporary, `${JSON.stringify(baseline, null, 2)}\n`, { encoding: 'utf8', mode: 0o600 });
  await rename(temporary, absolute);
}

export function createBaseline(report: ScanReport, selection: BaselineSelection): Baseline {
  assertSelection(selection);
  const now = selection.now ?? new Date();
  const requested = selection.fingerprints ? new Set(selection.fingerprints) : undefined;
  const findings = report.findings.filter((finding) => {
    if (finding.status !== 'open') return false;
    if (requested && !requested.has(finding.id)) return false;
    if (selection.minimumSeverity && severityRank[finding.severity] < severityRank[selection.minimumSeverity]) return false;
    return true;
  });
  if (requested) {
    const found = new Set(findings.map((finding) => finding.id));
    const missing = [...requested].filter((fingerprint) => !found.has(fingerprint));
    if (missing.length) throw new Error(`Finding fingerprints not present or not open in report: ${missing.join(', ')}`);
  }
  if (!findings.length) throw new Error('No open findings matched the baseline selection');
  const expiresAt = new Date(now.getTime() + selection.expiresInDays * 86_400_000).toISOString();
  return {
    version: 1,
    createdAt: now.toISOString(),
    suppressions: findings.map((finding) => ({
      fingerprint: finding.id,
      ruleId: finding.ruleId,
      path: finding.evidence[0]?.path,
      owner: selection.owner.trim(),
      reason: selection.reason.trim(),
      expiresAt,
      createdAt: now.toISOString()
    }))
  };
}

export function addBaselineSuppressions(baseline: Baseline, report: ScanReport, selection: BaselineSelection): Baseline {
  parseBaseline(baseline, selection.now ?? new Date());
  const addition = createBaseline(report, selection);
  const existing = new Set(baseline.suppressions.map((item) => item.fingerprint));
  const duplicates = addition.suppressions.filter((item) => existing.has(item.fingerprint)).map((item) => item.fingerprint);
  if (duplicates.length) throw new Error(`Baseline already contains fingerprints: ${duplicates.join(', ')}`);
  return { ...baseline, suppressions: [...baseline.suppressions, ...addition.suppressions] };
}

export function pruneExpiredSuppressions(baseline: Baseline, now = new Date()): { baseline: Baseline; removed: BaselineSuppression[] } {
  parseBaseline(baseline, now);
  const removed = baseline.suppressions.filter((item) => Date.parse(item.expiresAt) <= now.getTime());
  return { baseline: { ...baseline, suppressions: baseline.suppressions.filter((item) => Date.parse(item.expiresAt) > now.getTime()) }, removed };
}

function assertSelection(selection: BaselineSelection): void {
  if (!selection.owner.trim()) throw new Error('Baseline owner is required');
  if (!selection.reason.trim()) throw new Error('Baseline reason is required');
  if (!Number.isInteger(selection.expiresInDays) || selection.expiresInDays < 1 || selection.expiresInDays > 365) throw new Error('expiresInDays must be an integer between 1 and 365');
}
