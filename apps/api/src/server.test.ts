import { mkdtemp } from 'node:fs/promises';
import { resolve, join } from 'node:path';
import { tmpdir } from 'node:os';
import { describe, expect, it } from 'vitest';
import { buildServer } from './server.js';

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
});
