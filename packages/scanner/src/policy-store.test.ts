import { mkdtemp } from 'node:fs/promises';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { describe, expect, it } from 'vitest';
import { SCHEMA_VERSION, type Finding, type ScanReport } from '@agentshield/core';
import {
  activatePolicyVersion, approvePolicyException, evaluatePolicyWithExceptions, listPolicyExceptions,
  listPolicyVersions, loadStoredPolicy, publishPolicyVersion, rejectPolicyException,
  requestPolicyException, rollbackPolicyVersion, type PolicyFile
} from './index.js';

const policyV1: PolicyFile = {
  version: 2, id: 'baseline-policy',
  rules: [
    { id: 'block-high', when: { field: 'finding.severity', operator: 'gte', value: 'high' }, action: 'block' },
    { id: 'review-exec', when: { field: 'permission.name', operator: 'eq', value: 'process.execute' }, action: 'require_review' }
  ]
};

const policyV2: PolicyFile = {
  ...policyV1,
  rules: [
    ...(policyV1.rules ?? []),
    { id: 'warn-medium', when: { field: 'finding.severity', operator: 'eq', value: 'medium' }, action: 'warn' }
  ]
};

function finding(ruleId: string, severity: Finding['severity']): Finding {
  return {
    id: `id-${ruleId}`, ruleId, title: 't', description: 'd', severity, confidence: 'high', category: 'secrets',
    evidence: [{ path: 'fixture.ts', excerpt: 'process.env', redacted: false }], remediation: 'r', status: 'open', metadata: {}
  };
}

function report(findings: Finding[]): ScanReport {
  return {
    schemaVersion: SCHEMA_VERSION, scanId: 'scan-test', scannerVersion: 'test', rulepackVersion: 'test',
    target: 'fixture', startedAt: new Date(0).toISOString(), completedAt: new Date(0).toISOString(),
    status: 'completed', filesScanned: 1, bytesScanned: 1, components: [], permissions: [],
    findings, risk: { permission: 0, execution: 0, exfiltration: 0, secret: 0, supplyChain: 0, memoryPoison: 0 },
    overallRisk: 0, errors: []
  };
}

async function tempTarget(): Promise<string> {
  return join(await mkdtemp(join(tmpdir(), 'agentshield-policy-')), 'policies.yaml');
}

describe('persisted policy version store', () => {
  it('publishes immutable versions, activates the current pointer, and loads it back', async () => {
    const target = await tempTarget();
    const first = await publishPolicyVersion(target, policyV1, 'analyst', { activate: true, reason: 'initial baseline' });
    expect(first.version.state).toBe('active');
    expect(first.version.contentHash).toMatch(/^sha256:/);
    expect(first.version.simulation.reports).toBe(0);

    const second = await publishPolicyVersion(target, policyV2, 'admin', { reason: 'add warn-medium' });
    expect(second.version.state).toBe('published');
    expect(second.version.versionId).not.toBe(first.version.versionId);

    const listing = await listPolicyVersions(target);
    expect(listing.currentVersionId).toBe(first.version.versionId);
    expect(listing.versions).toHaveLength(2);
    expect(await loadStoredPolicy(target)).toEqual(policyV1);
  });

  it('runs a simulation against historical reports before activation', async () => {
    const target = await tempTarget();
    const reports = [
      report([finding('AS-SC-001', 'critical')]),
      report([finding('AS-SC-005', 'medium')])
    ];
    const result = await publishPolicyVersion(target, policyV1, 'analyst', { reports });
    expect(result.simulation.reports).toBe(2);
    expect(result.simulation.distribution.block).toBe(1);
    expect(result.simulation.distribution.allow).toBe(1);
  });

  it('is idempotent: publishing the same content returns the existing version', async () => {
    const target = await tempTarget();
    const first = await publishPolicyVersion(target, policyV1, 'analyst', { activate: true });
    const duplicate = await publishPolicyVersion(target, policyV1, 'analyst', { activate: true });
    expect(duplicate.version.versionId).toBe(first.version.versionId);
    expect((await listPolicyVersions(target)).versions).toHaveLength(1);
  });

  it('activates and retires versions, then rolls back to the previous one', async () => {
    const target = await tempTarget();
    const v1 = await publishPolicyVersion(target, policyV1, 'analyst', { activate: true });
    const v2 = await publishPolicyVersion(target, policyV2, 'admin', { activate: true, reason: 'stricter' });
    expect(v2.version.state).toBe('active');

    const listing = await listPolicyVersions(target);
    const retired = listing.versions.find((item) => item.versionId === v1.version.versionId);
    expect(retired?.state).toBe('retired');
    expect(retired?.retiredAt).toBeDefined();

    const rolled = await rollbackPolicyVersion(target, 'admin', 'regression in warn-medium');
    expect(rolled?.versionId).toBe(v1.version.versionId);
    expect(rolled?.state).toBe('active');
    expect((await listPolicyVersions(target)).currentVersionId).toBe(v1.version.versionId);
  });

  it('rejects invalid publishes and unknown activations', async () => {
    const target = await tempTarget();
    await expect(publishPolicyVersion(target, policyV1, '   ')).rejects.toThrow(/non-empty actor/);
    await expect(publishPolicyVersion(target, { ...policyV1, version: 3 } as unknown as PolicyFile, 'analyst')).rejects.toThrow(/Only policy versions/);
    await expect(activatePolicyVersion(target, 'nope', 'analyst')).rejects.toThrow(/not found/);
    await expect(rollbackPolicyVersion(target, '  ')).rejects.toThrow(/non-empty actor/);
  });
});

describe('policy exception approval', () => {
  it('requests, approves, and applies an exception that suppresses matching findings', async () => {
    const target = await tempTarget();
    await publishPolicyVersion(target, policyV1, 'analyst', { activate: true });
    const policy = (await loadStoredPolicy(target))!;
    const exceptions = [await requestPolicyException(target, {
      target: { kind: 'rule', ruleId: 'AS-SC-001' }, reason: 'documented legacy service', owner: 'platform-team',
      expiresAt: new Date(Date.now() + 86_400_000).toISOString()
    }, 'analyst')];

    // A requested-but-unapproved exception must not suppress anything yet.
    const pending = evaluatePolicyWithExceptions(report([finding('AS-SC-001', 'critical')]), policy, exceptions);
    expect(pending.action).toBe('block');

    const requested = await approvePolicyException(target, exceptions[0]!.exceptionId, 'admin', 'risk accepted');
    expect(requested.status).toBe('approved');
    expect(requested.approvedBy).toBe('admin');

    const approved = await listPolicyExceptions(target);
    const decisionAfter = evaluatePolicyWithExceptions(report([finding('AS-SC-001', 'critical')]), policy, approved);
    expect(decisionAfter.action).toBe('allow');
  });

  it('does not apply requested, rejected, or expired exceptions', async () => {
    const target = await tempTarget();
    const policy = policyV1;
    const pending = await requestPolicyException(target, {
      target: { kind: 'rule', ruleId: 'AS-SC-001' }, reason: 'still under review', owner: 'team',
      expiresAt: new Date(Date.now() + 86_400_000).toISOString()
    }, 'analyst');
    expect(evaluatePolicyWithExceptions(report([finding('AS-SC-001', 'critical')]), policy, [pending]).action).toBe('block');

    const rejected = await rejectPolicyException(target, pending.exceptionId, 'admin', 'not warranted');
    expect(rejected.status).toBe('rejected');
    expect(rejected.rejectionReason).toBe('not warranted');
    expect(evaluatePolicyWithExceptions(report([finding('AS-SC-001', 'critical')]), policy, [rejected]).action).toBe('block');

    const expired = await requestPolicyException(target, {
      target: { kind: 'rule', ruleId: 'AS-SC-001' }, reason: 'expired soon', owner: 'team',
      expiresAt: new Date(Date.now() - 1).toISOString()
    }, 'analyst');
    const approvedExpired = await approvePolicyException(target, expired.exceptionId, 'admin', 'accepted');
    const now = Date.now();
    expect(evaluatePolicyWithExceptions(report([finding('AS-SC-001', 'critical')]), policy, [approvedExpired], now).action).toBe('block');
    // An approved, in-the-future exception on the same target does suppress.
    const future = await requestPolicyException(target, {
      target: { kind: 'rule', ruleId: 'AS-SC-001' }, reason: 'valid', owner: 'team',
      expiresAt: new Date(now + 86_400_000).toISOString()
    }, 'analyst');
    const approvedFuture = await approvePolicyException(target, future.exceptionId, 'admin', 'accepted');
    expect(evaluatePolicyWithExceptions(report([finding('AS-SC-001', 'critical')]), policy, [approvedFuture], now).action).toBe('allow');
  });

  it('enforces four-eyes: the requester cannot approve their own exception', async () => {
    const target = await tempTarget();
    const exception = await requestPolicyException(target, {
      target: { kind: 'rule', ruleId: 'AS-SC-005' }, reason: 'self-approved attempt', owner: 'team',
      expiresAt: new Date(Date.now() + 86_400_000).toISOString()
    }, 'analyst');
    await expect(approvePolicyException(target, exception.exceptionId, 'analyst', 'myself')).rejects.toThrow(/different actor/);
    await expect(approvePolicyException(target, 'missing', 'admin', 'x')).rejects.toThrow(/not found/);
    await expect(requestPolicyException(target, {
      target: { kind: 'rule', ruleId: 'AS-SC-005' }, reason: '', owner: 'team',
      expiresAt: new Date(Date.now() + 86_400_000).toISOString()
    }, 'analyst')).rejects.toThrow(/non-empty reason/);
  });

  it('matches permission-kind exceptions against the rule gating that permission', async () => {
    const target = await tempTarget();
    const policy: PolicyFile = {
      version: 2,
      rules: [{ id: 'block-writes', when: { field: 'permission.name', operator: 'eq', value: 'filesystem.write' }, action: 'block' }]
    };
    const exception = await requestPolicyException(target, {
      target: { kind: 'permission', resource: 'filesystem', action: 'write' }, reason: 'CI scratch dir', owner: 'dev',
      expiresAt: new Date(Date.now() + 86_400_000).toISOString()
    }, 'dev');
    const approved = await approvePolicyException(target, exception.exceptionId, 'admin', 'accepted');
    const reportWithPermission: ScanReport = {
      ...report([]), permissions: [{ resource: 'filesystem', action: 'write', scope: 'scratch', risk: 'medium',
        evidence: { path: 'a.ts', excerpt: 'writeFile', redacted: false } }]
    };
    expect(evaluatePolicyWithExceptions(reportWithPermission, policy, [approved]).action).toBe('allow');
  });
});
