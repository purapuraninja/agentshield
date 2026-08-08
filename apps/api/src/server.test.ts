import { copyFile, mkdtemp } from 'node:fs/promises';
import { resolve, join, basename } from 'node:path';
import { tmpdir } from 'node:os';
import { describe, expect, it } from 'vitest';
import { hashToken } from './auth.js';
import { buildServer } from './server.js';

async function tempMemory(): Promise<string> {
  const directory = await mkdtemp(join(tmpdir(), 'agentshield-api-'));
  const target = join(directory, basename('memories.jsonl'));
  await copyFile(resolve('fixtures/poisoned-memory/memories.jsonl'), target);
  return target;
}

describe('local API', () => {
  it('exposes health and persists canonical scan results', async () => {
    const directory = await mkdtemp(join(tmpdir(), 'agentshield-api-'));
    const app = await buildServer({ dataDir: directory, logger: false });
    const health = await app.inject({ method: 'GET', url: '/health' });
    expect(health.statusCode).toBe(200);
    expect(health.json().rawContentUpload).toBe(false);
    const scan = await app.inject({ method: 'POST', url: '/v1/scans', payload: { target: resolve('fixtures/safe/basic-skill') } });
    expect(scan.statusCode).toBe(201);
    const report = scan.json();
    const loaded = await app.inject({ method: 'GET', url: `/v1/scans/${report.scanId}` });
    expect(loaded.statusCode).toBe(200);
    expect(loaded.json().scanId).toBe(report.scanId);
    await app.close();
  });

  it('rejects missing scan targets with a stable error schema', async () => {
    const app = await buildServer({ logger: false });
    const response = await app.inject({ method: 'POST', url: '/v1/scans', payload: {} });
    expect(response.statusCode).toBe(400);
    expect(response.json().error.code).toBe('invalid_request');
    await app.close();
  });

  it('lists scans with cursor pagination', async () => {
    const directory = await mkdtemp(join(tmpdir(), 'agentshield-api-'));
    const app = await buildServer({ dataDir: directory, logger: false });
    await app.inject({ method: 'POST', url: '/v1/scans', payload: { target: resolve('fixtures/safe/basic-skill') } });
    await app.inject({ method: 'POST', url: '/v1/scans', payload: { target: resolve('fixtures/safe/basic-skill') } });
    const page = await app.inject({ method: 'GET', url: '/v1/scans?limit=1' });
    expect(page.statusCode).toBe(200);
    expect(page.json().data).toHaveLength(1);
    expect(page.json().nextCursor).not.toBeNull();
    const next = await app.inject({ method: 'GET', url: `/v1/scans?limit=1&cursor=${page.json().data[0]}` });
    expect(next.json().data).toHaveLength(1);
    await app.close();
  });

  it('lists rules and explains a memory rule by id', async () => {
    const app = await buildServer({ logger: false });
    const list = await app.inject({ method: 'GET', url: '/v1/rules?kind=memory' });
    expect(list.statusCode).toBe(200);
    expect(list.json().data.some((rule: { id: string }) => rule.id === 'AS-ME-010')).toBe(true);
    const rule = await app.inject({ method: 'GET', url: '/v1/rules/AS-ME-013' });
    expect(rule.statusCode).toBe(200);
    expect(rule.json().data.kind).toBe('memory');
    const missing = await app.inject({ method: 'GET', url: '/v1/rules/AS-ME-999' });
    expect(missing.statusCode).toBe(404);
    await app.close();
  });

  it('exports a memory audit evidence bundle and lists remediation plans', async () => {
    const directory = await mkdtemp(join(tmpdir(), 'agentshield-api-'));
    const app = await buildServer({ dataDir: directory, logger: false });
    const target = await tempMemory();
    const audit = await app.inject({ method: 'POST', url: '/v1/memory-audits', payload: { target } });
    expect(audit.statusCode).toBe(201);
    const auditId = audit.json().auditId;
    const exported = await app.inject({ method: 'GET', url: `/v1/memory-audits/${auditId}/export` });
    expect(exported.statusCode).toBe(200);
    expect(exported.json().bundleSchemaVersion).toBe('1.0.0');
    const plans = await app.inject({ method: 'GET', url: `/v1/memory-audits/${auditId}/remediation-plans` });
    expect(plans.statusCode).toBe(200);
    await app.close();
  });

  it('runs a remediation plan -> approve -> execute lifecycle over the API', async () => {
    const directory = await mkdtemp(join(tmpdir(), 'agentshield-api-'));
    const app = await buildServer({ dataDir: directory, logger: false });
    const target = await tempMemory();
    const plan = await app.inject({ method: 'POST', url: '/v1/remediation/plan', payload: { target, memoryId: 'web-override', action: 'quarantine', actor: 'analyst', reason: 'api test' } });
    expect(plan.statusCode).toBe(200);
    expect(plan.json().state).toBe('planned');
    const planId = plan.json().planId;
    const approved = await app.inject({ method: 'POST', url: '/v1/remediation/approve', payload: { target, planId, actor: 'reviewer', reason: 'ok' } });
    expect(approved.json().state).toBe('approved');
    const executed = await app.inject({ method: 'POST', url: '/v1/remediation/execute', payload: { target, planId, actor: 'system' } });
    expect(executed.statusCode).toBe(200);
    expect(executed.json().state).toBe('executed');
    const rollback = await app.inject({ method: 'POST', url: '/v1/remediation/rollback', payload: { target, planId, actor: 'reviewer', reason: 'revert' } });
    expect(rollback.json().state).toBe('rolled_back');
    const conflict = await app.inject({ method: 'POST', url: '/v1/remediation/execute', payload: { target, planId, actor: 'system' } });
    expect(conflict.statusCode).toBe(409);
    expect(conflict.json().error.code).toBe('remediation_conflict');
    await app.close();
  });

  it('exposes a stable error catalog', async () => {
    const app = await buildServer({ logger: false });
    const catalog = await app.inject({ method: 'GET', url: '/v1/errors' });
    expect(catalog.statusCode).toBe(200);
    const codes = catalog.json().catalog.map((entry: { code: string }) => entry.code);
    expect(codes).toEqual(expect.arrayContaining(['invalid_request', 'not_found', 'remediation_conflict']));
    await app.close();
  });

  it('reconciles inventory and classifies memory types over the API', async () => {
    const app = await buildServer({ logger: false });
    const target = await tempMemory();
    const reconcile = await app.inject({ method: 'POST', url: '/v1/memory/reconcile', payload: { target } });
    expect(reconcile.statusCode).toBe(200);
    expect(reconcile.json().reconciled).toBe(true);
    expect(reconcile.json().sourceTotal).toBe(5);
    const classify = await app.inject({ method: 'POST', url: '/v1/memory/classify', payload: { target } });
    expect(classify.statusCode).toBe(200);
    expect(classify.json().data).toHaveLength(5);
    await app.close();
  });

  it('rejects requests without a valid bearer token when auth is enabled', async () => {
    const token = 'as_test_server_token_456';
    const app = await buildServer({ logger: false, auth: { enabled: true, tokenHash: hashToken(token) } });
    const health = await app.inject({ method: 'GET', url: '/health' });
    expect(health.statusCode).toBe(200);
    expect(health.json().authEnabled).toBe(true);
    const unauth = await app.inject({ method: 'GET', url: '/v1/scans' });
    expect(unauth.statusCode).toBe(401);
    expect(unauth.json().error.code).toBe('unauthorized');
    const authed = await app.inject({ method: 'GET', url: '/v1/scans', headers: { authorization: `Bearer ${token}` } });
    expect(authed.statusCode).toBe(200);
    await app.close();
  });

  it('returns 429 when the rate limit is exceeded', async () => {
    const app = await buildServer({ logger: false, rateLimit: { max: 2, windowMs: 60_000 } });
    await app.inject({ method: 'GET', url: '/v1/scans' });
    await app.inject({ method: 'GET', url: '/v1/scans' });
    const blocked = await app.inject({ method: 'GET', url: '/v1/scans' });
    expect(blocked.statusCode).toBe(429);
    expect(blocked.json().error.code).toBe('rate_limited');
    expect(blocked.headers['retry-after']).toBeTruthy();
    await app.close();
  });
});
