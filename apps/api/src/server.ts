import { mkdir, readFile, writeFile } from 'node:fs/promises';
import { dirname, join, resolve } from 'node:path';
import Fastify, { type FastifyInstance } from 'fastify';
import cors from '@fastify/cors';
import { createId, memoryAuditReportSchema, scanReportSchema } from '@agentshield/core';
import { evaluatePolicy, scanTarget, type PolicyFile } from '@agentshield/scanner';
import { auditMemory, listQuarantine, quarantineMemory, restoreMemory } from '@agentshield/memory';
import { EventStore, createRuntimeEvent } from '@agentshield/runtime';

interface ApiOptions { dataDir?: string; logger?: boolean }

async function persist(path: string, value: unknown): Promise<void> {
  await mkdir(dirname(path), { recursive: true });
  await writeFile(path, `${JSON.stringify(value, null, 2)}\n`, { encoding: 'utf8', mode: 0o600 });
}

async function loadJson<T>(path: string): Promise<T | undefined> {
  try { return JSON.parse(await readFile(path, 'utf8')) as T; } catch { return; }
}

export async function buildServer(options: ApiOptions = {}): Promise<FastifyInstance> {
  const dataDir = resolve(options.dataDir ?? process.env.AGENTSHIELD_DATA_DIR ?? '.agentshield');
  const app = Fastify({ logger: options.logger ?? true, bodyLimit: 1_048_576, requestIdHeader: 'x-request-id', genReqId: () => createId('req') });
  await app.register(cors, {
    origin: (origin, callback) => {
      if (!origin || /^https?:\/\/(?:127\.0\.0\.1|localhost)(?::\d+)?$/.test(origin)) callback(null, true);
      else callback(new Error('Origin not allowed'), false);
    }
  });

  app.addHook('onSend', async (_request, reply) => {
    reply.header('x-content-type-options', 'nosniff').header('x-frame-options', 'DENY').header('referrer-policy', 'no-referrer');
  });
  app.setErrorHandler((error, request, reply) => {
    request.log.error({ err: error, path: request.url }, 'request failed');
    const typed = error as { statusCode?: number; message?: string };
    const status = typed.statusCode && typed.statusCode >= 400 ? typed.statusCode : 400;
    reply.status(status).send({ error: { code: status === 404 ? 'not_found' : 'request_failed', message: typed.message ?? String(error), requestId: request.id } });
  });

  app.get('/health', async () => ({ status: 'ok', version: '0.1.0', rawContentUpload: false }));

  app.post('/v1/scans', async (request, reply) => {
    const body = request.body as { target?: string };
    if (!body?.target) return reply.status(400).send({ error: { code: 'invalid_request', message: 'target is required', requestId: request.id } });
    const report = await scanTarget(body.target);
    await persist(join(dataDir, 'scans', `${report.scanId}.json`), report);
    return reply.status(201).send(report);
  });
  app.get('/v1/scans/:scanId', async (request, reply) => {
    const { scanId } = request.params as { scanId: string };
    const report = await loadJson(join(dataDir, 'scans', `${scanId}.json`));
    return report ? report : reply.status(404).send({ error: { code: 'not_found', message: 'Scan not found', requestId: request.id } });
  });
  app.get('/v1/scans/:scanId/findings', async (request, reply) => {
    const { scanId } = request.params as { scanId: string };
    const raw = await loadJson(join(dataDir, 'scans', `${scanId}.json`));
    if (!raw) return reply.status(404).send({ error: { code: 'not_found', message: 'Scan not found', requestId: request.id } });
    const report = scanReportSchema.parse(raw);
    return { data: report.findings, nextCursor: null };
  });
  app.get('/v1/scans/:scanId/components', async (request, reply) => {
    const { scanId } = request.params as { scanId: string };
    const raw = await loadJson(join(dataDir, 'scans', `${scanId}.json`));
    if (!raw) return reply.status(404).send({ error: { code: 'not_found', message: 'Scan not found', requestId: request.id } });
    const report = scanReportSchema.parse(raw);
    return { data: report.components, permissions: report.permissions };
  });

  app.post('/v1/policies/evaluate', async (request) => {
    const body = request.body as { report: unknown; policy: PolicyFile };
    return evaluatePolicy(scanReportSchema.parse(body.report), body.policy);
  });

  app.post('/v1/memory-connections/test', async (request) => {
    const body = request.body as { target: string; table?: string; contentColumn?: string };
    const report = await auditMemory(body.target, { table: body.table, contentColumn: body.contentColumn, privacyMode: 'metadata-only' });
    return { valid: report.status !== 'failed', adapter: report.adapter, records: report.inventory.total, errors: report.errors };
  });
  app.post('/v1/memory-audits', async (request, reply) => {
    const body = request.body as { target: string; privacyMode?: 'none' | 'secrets' | 'pii-secrets' | 'metadata-only'; table?: string; idColumn?: string; contentColumn?: string };
    const report = await auditMemory(body.target, body);
    await persist(join(dataDir, 'memory-audits', `${report.auditId}.json`), report);
    return reply.status(201).send(report);
  });
  app.get('/v1/memory-audits/:auditId', async (request, reply) => {
    const { auditId } = request.params as { auditId: string };
    const raw = await loadJson(join(dataDir, 'memory-audits', `${auditId}.json`));
    return raw ? memoryAuditReportSchema.parse(raw) : reply.status(404).send({ error: { code: 'not_found', message: 'Audit not found', requestId: request.id } });
  });
  app.post('/v1/memories/:memoryId/quarantine-plan', async (request) => {
    const { memoryId } = request.params as { memoryId: string }; const body = request.body as { target: string; actor: string; reason: string; execute?: boolean };
    if (!body.execute) return { state: 'review_required', dryRun: true, memoryId, action: 'quarantine', target: resolve(body.target), reason: body.reason };
    return quarantineMemory(body.target, memoryId, body.actor, body.reason);
  });
  app.post('/v1/memories/:memoryId/restore', async (request) => {
    const { memoryId } = request.params as { memoryId: string }; const body = request.body as { target: string; actor: string; reason: string };
    return restoreMemory(body.target, memoryId, body.actor, body.reason);
  });
  app.get('/v1/quarantine', async (request) => {
    const query = request.query as { target: string }; return { data: await listQuarantine(query.target) };
  });

  const eventStore = new EventStore(join(dataDir, 'runtime', 'events.jsonl'));
  app.post('/v1/runtime/events', async (request, reply) => {
    const body = request.body as any; const event = body.schemaVersion ? body : createRuntimeEvent(body);
    const result = await eventStore.ingest(event);
    return reply.status(result.duplicate ? 200 : 201).send(result);
  });
  app.get('/v1/traces/:traceId', async (request) => {
    const { traceId } = request.params as { traceId: string }; return { traceId, events: await eventStore.trace(traceId) };
  });
  app.get('/v1/evidence-graphs/:traceId', async (request) => {
    const { traceId } = request.params as { traceId: string }; return eventStore.graph(traceId);
  });
  return app;
}
