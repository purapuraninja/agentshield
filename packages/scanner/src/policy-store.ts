import { mkdir, readFile, rename, writeFile } from 'node:fs/promises';
import { dirname, join, resolve } from 'node:path';
import { createId, sha256, type PolicyAction, type ScanReport } from '@agentshield/core';
import { evaluatePolicy, simulatePolicy, validatePolicy, type PolicyFile } from './policy.js';

/**
 * Persisted, immutable policy version store. Policies are published as content-addressed versions;
 * activation switches the current pointer, and every transition records actor, reason, and time.
 * Exceptions are separate approved records that suppress matching findings before evaluation.
 */

export type PolicyVersionState = 'published' | 'active' | 'retired';

export interface PolicySimulationSummary {
  reports: number;
  distribution: Record<PolicyAction, number>;
}

export interface PolicyVersion {
  versionId: string;
  contentHash: string;
  policyVersion: 1 | 2;
  state: PolicyVersionState;
  publishedBy: string;
  reason: string;
  publishedAt: string;
  activatedAt?: string;
  retiredAt?: string;
  simulation: PolicySimulationSummary;
}

export type PolicyExceptionStatus = 'requested' | 'approved' | 'rejected';

export interface PolicyExceptionTarget {
  kind: 'rule' | 'permission';
  ruleId?: string;
  resource?: string;
  action?: string;
}

export interface PolicyException {
  exceptionId: string;
  target: PolicyExceptionTarget;
  reason: string;
  owner: string;
  expiresAt: string;
  status: PolicyExceptionStatus;
  requestedBy: string;
  requestedAt: string;
  approvedBy?: string;
  approvedAt?: string;
  approvalReason?: string;
  rejectionReason?: string;
}

export interface PolicyStoreFile {
  version: 1;
  currentVersionId?: string;
  versions: PolicyVersion[];
  exceptions: PolicyException[];
}

export interface PublishOptions {
  reason?: string;
  activate?: boolean;
  reports?: ScanReport[];
}

function policyStoreDir(target: string): string {
  const absolute = resolve(target);
  return join(dirname(absolute), '.agentshield');
}

export async function readPolicyStore(target: string): Promise<PolicyStoreFile> {
  try {
    return JSON.parse(await readFile(join(policyStoreDir(target), 'policy-store.json'), 'utf8')) as PolicyStoreFile;
  } catch { return { version: 1, versions: [], exceptions: [] }; }
}

async function writePolicyStore(target: string, store: PolicyStoreFile): Promise<void> {
  const path = join(policyStoreDir(target), 'policy-store.json');
  await mkdir(dirname(path), { recursive: true });
  const temporary = `${path}.${process.pid}.tmp`;
  await writeFile(temporary, `${JSON.stringify(store, null, 2)}\n`, { encoding: 'utf8', mode: 0o600 });
  await rename(temporary, path);
}

export async function loadStoredPolicy(target: string): Promise<PolicyFile | undefined> {
  const store = await readPolicyStore(target);
  const current = store.versions.find((item) => item.versionId === store.currentVersionId);
  if (!current) return;
  const path = join(policyStoreDir(target), 'policies', `${current.versionId}.json`);
  try { return JSON.parse(await readFile(path, 'utf8')) as PolicyFile; } catch { return; }
}

async function writeStoredPolicy(target: string, versionId: string, policy: PolicyFile): Promise<void> {
  const path = join(policyStoreDir(target), 'policies', `${versionId}.json`);
  await mkdir(dirname(path), { recursive: true });
  const temporary = `${path}.${process.pid}.tmp`;
  await writeFile(temporary, `${JSON.stringify(policy, null, 2)}\n`, { encoding: 'utf8', mode: 0o600 });
  await rename(temporary, path);
}

/**
 * Publish a policy as an immutable version. Optional historical reports run a simulation first; the
 * summary is stored with the version so operators can review blast radius before activation.
 */
export async function publishPolicyVersion(
  target: string, policy: PolicyFile, publishedBy: string, options: PublishOptions = {}
): Promise<{ version: PolicyVersion; simulation: PolicySimulationSummary }> {
  if (!publishedBy.trim()) throw new Error('Policy publish requires a non-empty actor');
  validatePolicy(policy);
  const store = await readPolicyStore(target);
  const contentHash = sha256(JSON.stringify(policy));
  const existing = store.versions.find((item) => item.contentHash === contentHash);
  if (existing) {
    if (options.activate && existing.state !== 'active') {
      const activated = await activatePolicyVersion(target, existing.versionId, publishedBy, options.reason ?? 'activated');
      return { version: activated, simulation: existing.simulation };
    }
    return { version: existing, simulation: existing.simulation };
  }
  const simulation = options.reports?.length
    ? summarizeSimulation(simulatePolicy(options.reports, policy))
    : { reports: 0, distribution: { allow: 0, warn: 0, require_review: 0, quarantine: 0, block: 0 } };
  const version: PolicyVersion = {
    versionId: createId('polv'), contentHash, policyVersion: policy.version, state: 'published',
    publishedBy, reason: options.reason ?? 'published', publishedAt: new Date().toISOString(), simulation
  };
  await writeStoredPolicy(target, version.versionId, policy);
  store.versions.push(version);
  if (options.activate) {
    for (const item of store.versions) {
      if (item.state === 'active' && item.versionId !== version.versionId) {
        item.state = 'retired';
        item.retiredAt = new Date().toISOString();
      }
    }
    store.currentVersionId = version.versionId;
    version.state = 'active';
    version.activatedAt = new Date().toISOString();
  }
  await writePolicyStore(target, store);
  return { version, simulation };
}

export async function activatePolicyVersion(target: string, versionId: string, actor: string, reason = 'activated'): Promise<PolicyVersion> {
  if (!actor.trim()) throw new Error('Policy activation requires a non-empty actor');
  const store = await readPolicyStore(target);
  const version = store.versions.find((item) => item.versionId === versionId);
  if (!version) throw new Error(`Policy version not found: ${versionId}`);
  for (const item of store.versions) {
    if (item.state === 'active' && item.versionId !== versionId) { item.state = 'retired'; item.retiredAt = new Date().toISOString(); }
  }
  version.state = 'active';
  version.activatedAt = new Date().toISOString();
  version.reason = reason;
  store.currentVersionId = versionId;
  await writePolicyStore(target, store);
  return version;
}

/** Switch the active pointer to the highest published version below the current one. */
export async function rollbackPolicyVersion(target: string, actor: string, reason = 'rolled back'): Promise<PolicyVersion | undefined> {
  if (!actor.trim()) throw new Error('Policy rollback requires a non-empty actor');
  const store = await readPolicyStore(target);
  const currentIndex = store.versions.findIndex((item) => item.versionId === store.currentVersionId);
  const candidates = store.versions
    .map((item, index) => ({ item, index }))
    .filter(({ index }) => currentIndex < 0 || index < currentIndex)
    .sort((a, b) => b.index - a.index);
  const fallback = candidates[0];
  if (!fallback) return;
  return activatePolicyVersion(target, fallback.item.versionId, actor, reason);
}

export async function listPolicyVersions(target: string): Promise<{ currentVersionId?: string; versions: PolicyVersion[] }> {
  const store = await readPolicyStore(target);
  return { currentVersionId: store.currentVersionId, versions: store.versions };
}

function summarizeSimulation(result: ReturnType<typeof simulatePolicy>): PolicySimulationSummary {
  return { reports: result.reports, distribution: result.distribution };
}

export async function requestPolicyException(
  target: string, exception: Omit<PolicyException, 'exceptionId' | 'status' | 'requestedAt' | 'requestedBy'>,
  requestedBy: string
): Promise<PolicyException> {
  if (!requestedBy.trim()) throw new Error('Exception request requires a non-empty actor');
  if (!exception.target || (!exception.target.ruleId && !exception.target.resource)) throw new Error('Exception target must name a rule or a permission');
  if (!exception.reason.trim() || !exception.owner.trim()) throw new Error('Exception requires a non-empty reason and owner');
  if (!exception.expiresAt || Number.isNaN(Date.parse(exception.expiresAt))) throw new Error('Exception requires a valid expiresAt date');
  const store = await readPolicyStore(target);
  const record: PolicyException = {
    exceptionId: createId('excp'), ...exception, status: 'requested', requestedBy, requestedAt: new Date().toISOString()
  };
  store.exceptions.push(record);
  await writePolicyStore(target, store);
  return record;
}

export async function approvePolicyException(target: string, exceptionId: string, actor: string, reason = 'approved'): Promise<PolicyException> {
  if (!actor.trim()) throw new Error('Exception approval requires a non-empty actor');
  const store = await readPolicyStore(target);
  const record = store.exceptions.find((item) => item.exceptionId === exceptionId);
  if (!record) throw new Error(`Policy exception not found: ${exceptionId}`);
  if (record.status !== 'requested') throw new Error(`Exception ${exceptionId} is ${record.status}, not requested`);
  if (record.requestedBy === actor) throw new Error('Exception approval requires a different actor than the requester');
  record.status = 'approved';
  record.approvedBy = actor;
  record.approvedAt = new Date().toISOString();
  record.approvalReason = reason;
  record.rejectionReason = undefined;
  await writePolicyStore(target, store);
  return record;
}

export async function rejectPolicyException(target: string, exceptionId: string, actor: string, reason: string): Promise<PolicyException> {
  if (!actor.trim() || !reason.trim()) throw new Error('Exception rejection requires a non-empty actor and reason');
  const store = await readPolicyStore(target);
  const record = store.exceptions.find((item) => item.exceptionId === exceptionId);
  if (!record) throw new Error(`Policy exception not found: ${exceptionId}`);
  if (record.status !== 'requested') throw new Error(`Exception ${exceptionId} is ${record.status}, not requested`);
  record.status = 'rejected';
  record.approvedBy = actor;
  record.approvedAt = new Date().toISOString();
  record.rejectionReason = reason;
  await writePolicyStore(target, store);
  return record;
}

export async function listPolicyExceptions(target: string): Promise<PolicyException[]> {
  return (await readPolicyStore(target)).exceptions;
}

function exceptionMatchesFinding(exception: PolicyException, ruleId: string, now: number): boolean {
  if (exception.status !== 'approved') return false;
  if (Date.parse(exception.expiresAt) < now) return false;
  if (exception.target.kind === 'rule') return exception.target.ruleId === ruleId;
  return false;
}

function exceptionMatchesPermission(exception: PolicyException, resource: string, action: string, now: number): boolean {
  if (exception.status !== 'approved') return false;
  if (Date.parse(exception.expiresAt) < now) return false;
  if (exception.target.kind !== 'permission') return false;
  return exception.target.resource === resource && (!exception.target.action || exception.target.action === action);
}

/**
 * Evaluate a report under a policy with approved, unexpired exceptions applied. Rule-kind exceptions
 * suppress matching findings; permission-kind exceptions suppress matching declared permissions.
 * Suppression happens before evaluation, so exceptions reduce the decision rather than layering on top.
 */
export function evaluatePolicyWithExceptions(
  report: ScanReport, policy: PolicyFile, exceptions: PolicyException[], now = Date.now()
): ReturnType<typeof evaluatePolicy> {
  const filtered: ScanReport = {
    ...report,
    findings: report.findings.filter((finding) =>
      !exceptions.some((exception) => exceptionMatchesFinding(exception, finding.ruleId, now))),
    permissions: report.permissions.filter((permission) =>
      !exceptions.some((exception) => exceptionMatchesPermission(exception, permission.resource, permission.action, now)))
  };
  return evaluatePolicy(filtered, policy);
}

export { evaluatePolicy, simulatePolicy, validatePolicy };
export type { PolicyFile };
