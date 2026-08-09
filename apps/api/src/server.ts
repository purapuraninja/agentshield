import { mkdir, readFile, readdir, writeFile } from 'node:fs/promises';
import { dirname, join, resolve } from 'node:path';
import Fastify, { type FastifyInstance } from 'fastify';
import cors from '@fastify/cors';
import { createId, memoryAuditReportSchema, scanReportSchema } from '@agentshield/core';
import { evaluatePolicy, scanInjectionText, scanTarget, staticRules, getRule, type PolicyFile } from '@agentshield/scanner';
import { auditMemory, classifyMemoryTypes, getMemoryRule, listQuarantine, listRemediationPlans, memoryRules, planRemediation, approveRemediation, executeRemediation, rollbackRemediation, quarantineMemory, reconcileMemoryInventory, restoreMemory } from '@agentshield/memory';
import { applyPersona, buildModelRequest, getPersona, listPersonaApplications, listPersonas, loadPersonaFile, modelRequestOptionsSchema, registerPersona, registerPersonaText, removePersona, validatePersona, verifyApplicationChain } from '@agentshield/persona';
import { EventStore, createRuntimeEvent } from '@agentshield/runtime';
import { renderMemoryEvidenceBundle, renderMemorySarif } from '@agentshield/reports';
import {
  loadAuthConfig, loadRateLimitConfig, validateBearerToken, isPublicPath, RateLimiter,
  type AuthConfig, type RateLimitConfig
} from './auth.js';

interface ApiOptions { dataDir?: string; logger?: boolean; auth?: AuthConfig; rateLimit?: RateLimitConfig; allowedOrigins?: string[]; tls?: { cert: string; key: string } }

async function persist(path: string, value: unknown): Promise<void> {
  await mkdir(dirname(path), { recursive: true });
  await writeFile(path, `${JSON.stringify(value, null, 2)}\n`, { encoding: 'utf8', mode: 0o600 });
}

async function loadJson<T>(path: string): Promise<T | undefined> {
  try { return JSON.parse(await readFile(path, 'utf8')) as T; } catch { return; }
}

async function listJsonIds(dir: string): Promise<string[]> {
  try { return (await readdir(dir)).filter((name) => name.endsWith('.json')).map((name) => name.replace(/\.json$/, '')); } catch { return []; }
}

export async function buildServer(options: ApiOptions = {}): Promise<FastifyInstance> {
  const dataDir = resolve(options.dataDir ?? process.env.AGENTSHIELD_DATA_DIR ?? '.agentshield');
  const auth = options.auth ?? loadAuthConfig();
  const rateLimitConfig = options.rateLimit ?? loadRateLimitConfig();
  const rateLimiter = new RateLimiter(rateLimitConfig);
  const allowedOrigins = options.allowedOrigins ?? (process.env.AGENTSHIELD_ALLOWED_ORIGINS ? process.env.AGENTSHIELD_ALLOWED_ORIGINS.split(',').map((item) => item.trim()).filter(Boolean) : undefined);
  const fastifyOptions = { logger: options.logger ?? true, bodyLimit: 1_048_576, requestIdHeader: 'x-request-id', genReqId: () => createId('req'), ...(options.tls ? { https: options.tls } : {}) };
  const app = Fastify(fastifyOptions as never) as unknown as FastifyInstance;
  await app.register(cors, {
    origin: (origin, callback) => {
      if (!origin) return callback(null, true);
      if (allowedOrigins) { callback(allowedOrigins.includes(origin) ? null : new Error('Origin not allowed'), allowedOrigins.includes(origin)); return; }
      if (/^https?:\/\/(?:127\.0\.0\.1|localhost)(?::\d+)?$/.test(origin)) callback(null, true);
      else callback(new Error('Origin not allowed'), false);
    }
  });

  app.addHook('onSend', async (_request, reply) => {
    reply.header('x-content-type-options', 'nosniff').header('x-frame-options', 'DENY').header('referrer-policy', 'no-referrer').header('strict-transport-security', 'max-age=31536000; includeSubDomains');
  });

  app.addHook('preHandler', async (request, reply) => {
    if (isPublicPath(request.url.split('?')[0] ?? '')) return;
    const rateKey = (request.headers.authorization ?? request.ip) as string;
    const result = rateLimiter.check(rateKey);
    reply.header('x-ratelimit-limit', String(rateLimitConfig.max)).header('x-ratelimit-remaining', String(Math.max(0, result.remaining)));
    if (!result.allowed) {
      reply.header('retry-after', String(result.retryAfter));
      return reply.status(429).send({ error: { code: 'rate_limited', message: `Rate limit exceeded. Retry after ${result.retryAfter}s.`, requestId: request.id } });
    }
    if (auth.enabled && !validateBearerToken(request.headers.authorization, auth)) {
      return reply.status(401).send({ error: { code: 'unauthorized', message: 'A valid bearer token is required.', requestId: request.id } });
    }
  });

  app.setErrorHandler((error, request, reply) => {
    request.log.error({ err: error, path: request.url }, 'request failed');
    const typed = error as { statusCode?: number; message?: string };
    const status = typed.statusCode && typed.statusCode >= 400 ? typed.statusCode : 400;
    reply.status(status).send({ error: { code: status === 404 ? 'not_found' : 'request_failed', message: typed.message ?? String(error), requestId: request.id } });
  });

  app.get('/health', async () => ({ status: 'ok', version: '0.2.0', rawContentUpload: false, authEnabled: auth.enabled, rateLimit: rateLimitConfig }));

  app.get('/v1/scans', async (request) => {
    const query = request.query as { limit?: string; cursor?: string };
    const limit = Math.min(Math.max(Number(query.limit ?? '50'), 1), 200);
    const ids = (await listJsonIds(join(dataDir, 'scans'))).sort();
    const startIndex = query.cursor ? ids.indexOf(query.cursor) + 1 : 0;
    const slice = ids.slice(startIndex, startIndex + limit);
    const nextCursor = startIndex + limit < ids.length ? slice.at(-1) : null;
    return { data: slice, nextCursor };
  });

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

  app.get('/v1/rules', async (request) => {
    const query = request.query as { kind?: string };
    const catalog = [...staticRules.map((rule) => ({ ...rule, kind: 'static' as const })), ...memoryRules.map((rule) => ({ ...rule, kind: 'memory' as const }))];
    const data = query.kind ? catalog.filter((rule) => rule.kind === query.kind) : catalog;
    return { data, total: data.length };
  });
  app.get('/v1/rules/:ruleId', async (request, reply) => {
    const { ruleId } = request.params as { ruleId: string };
    const rule = getRule(ruleId) ?? getMemoryRule(ruleId);
    return rule ? { data: { ...rule, kind: rule.id.startsWith('AS-ME') ? 'memory' : 'static' } } : reply.status(404).send({ error: { code: 'not_found', message: 'Rule not found', requestId: request.id } });
  });

  // Injection lab: runs the prompt-injection/jailbreak rule set against arbitrary pasted text.
  // Detection-only — it never generates or executes the content under test.
  app.post('/v1/injection/lab', async (request, reply) => {
    const body = request.body as { text?: string };
    if (typeof body?.text !== 'string' || !body.text.trim()) {
      return reply.status(400).send({ error: { code: 'invalid_request', message: 'text is required', requestId: request.id } });
    }
    const findings = scanInjectionText(body.text);
    return { data: { findings, detected: findings.length > 0 } };
  });

  app.get('/v1/memory-audits', async (request) => {
    const query = request.query as { limit?: string; cursor?: string };
    const limit = Math.min(Math.max(Number(query.limit ?? '50'), 1), 200);
    const ids = (await listJsonIds(join(dataDir, 'memory-audits'))).sort();
    const startIndex = query.cursor ? ids.indexOf(query.cursor) + 1 : 0;
    const slice = ids.slice(startIndex, startIndex + limit);
    const nextCursor = startIndex + limit < ids.length ? slice.at(-1) : null;
    return { data: slice, nextCursor };
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
  app.get('/v1/memory-audits/:auditId/export', async (request, reply) => {
    const { auditId } = request.params as { auditId: string };
    const format = (request.query as { format?: string }).format ?? 'bundle';
    const raw = await loadJson(join(dataDir, 'memory-audits', `${auditId}.json`));
    if (!raw) return reply.status(404).send({ error: { code: 'not_found', message: 'Audit not found', requestId: request.id } });
    const report = memoryAuditReportSchema.parse(raw);
    return format === 'sarif' ? renderMemorySarif(report) : renderMemoryEvidenceBundle(report);
  });
  app.get('/v1/memory-audits/:auditId/remediation-plans', async (request) => {
    const { auditId } = request.params as { auditId: string };
    const raw = await loadJson(join(dataDir, 'memory-audits', `${auditId}.json`));
    const target = raw ? (raw as { target: string }).target : '';
    return { data: target ? await listRemediationPlans(target) : [] };
  });

  const remediationRouter = async (request: any, reply: any, stage: 'plan' | 'approve' | 'execute' | 'rollback') => {
    const body = request.body as { target?: string; planId?: string; memoryId?: string; action?: string; actor?: string; reason?: string; idempotencyKey?: string; requireTwoPerson?: boolean };
    try {
      if (stage === 'plan') return await planRemediation(body.target!, body.memoryId!, body.action as 'quarantine' | 'restore' | 'deprecate', body.actor!, body.reason!, { idempotencyKey: body.idempotencyKey, requireTwoPerson: body.requireTwoPerson });
      if (stage === 'approve') return await approveRemediation(body.target!, body.planId!, body.actor!, body.reason!);
      if (stage === 'execute') return await executeRemediation(body.target!, body.planId!, body.actor!);
      if (stage === 'rollback') return await rollbackRemediation(body.target!, body.planId!, body.actor!, body.reason!);
    } catch (error) {
      return reply.status(409).send({ error: { code: 'remediation_conflict', message: error instanceof Error ? error.message : String(error), requestId: request.id } });
    }
  };
  app.post('/v1/remediation/plan', async (request, reply) => remediationRouter(request, reply, 'plan'));
  app.post('/v1/remediation/approve', async (request, reply) => remediationRouter(request, reply, 'approve'));
  app.post('/v1/remediation/execute', async (request, reply) => remediationRouter(request, reply, 'execute'));
  app.post('/v1/remediation/rollback', async (request, reply) => remediationRouter(request, reply, 'rollback'));
  app.get('/v1/remediation/plans', async (request) => {
    const query = request.query as { target: string };
    return { data: await listRemediationPlans(query.target) };
  });
  app.post('/v1/memory/reconcile', async (request) => {
    const body = request.body as { target: string; table?: string; contentColumn?: string };
    return reconcileMemoryInventory(body.target, { table: body.table, contentColumn: body.contentColumn });
  });
  app.post('/v1/memory/classify', async (request) => {
    const body = request.body as { target: string; table?: string; contentColumn?: string };
    return { data: await classifyMemoryTypes(body.target, { table: body.table, contentColumn: body.contentColumn }) };
  });

  // Persona store lives under the data directory; the persona package keeps its sidecar in
  // `<target>/.agentshield/personas.json` + `persona-applications.jsonl`.
  const personaTarget = join(dataDir, 'personas');
  const personaError = (request: { id?: string }, status: number, code: string, message: string) => ({
    error: { code, message, requestId: request.id }
  });
  app.get('/v1/personas', async () => ({ data: await listPersonas(personaTarget) }));
  app.get('/v1/personas/applications', async () => {
    const applications = await listPersonaApplications(personaTarget);
    return { chain: verifyApplicationChain(applications), applications };
  });
  app.get('/v1/personas/:id', async (request, reply) => {
    const { id } = request.params as { id: string };
    const persona = await getPersona(personaTarget, id);
    return persona ? { data: persona } : reply.status(404).send(personaError(request, 404, 'not_found', 'Persona not found'));
  });
  app.post('/v1/personas', async (request, reply) => {
    const body = request.body as { definition?: unknown; definitionText?: string; actor: string; format?: string };
    if (!body?.actor) return reply.status(400).send(personaError(request, 400, 'invalid_request', 'actor is required'));
    try {
      // Free-form registration: any pasted text becomes the persona; id/name are derived and the
      // advisory scanner reports warnings (never blocks). No YAML/JSON structure is required.
      if (body.format === 'freeform') {
        if (typeof body.definitionText !== 'string' || !body.definitionText.trim()) {
          return reply.status(400).send(personaError(request, 400, 'invalid_request', 'definitionText is required for freeform registration'));
        }
        const registered = await registerPersonaText(personaTarget, body.definitionText, body.actor);
        return reply.status(201).send({ data: registered.persona, warnings: registered.warnings });
      }
      let definition: unknown;
      if (body.definition !== undefined) definition = body.definition;
      else if (typeof body.definitionText === 'string' && body.definitionText.trim()) definition = loadPersonaFile(body.definitionText);
      else return reply.status(400).send(personaError(request, 400, 'invalid_request', 'definition or definitionText is required'));
      // Advisory warnings accompany every registration so the operator sees the same signal
      // regardless of format; they never block registration.
      const validation = validatePersona(definition);
      return reply.status(201).send({ data: await registerPersona(personaTarget, definition, body.actor), warnings: validation.warnings });
    } catch (error) {
      return reply.status(400).send(personaError(request, 400, 'invalid_request', error instanceof Error ? error.message : String(error)));
    }
  });
  app.delete('/v1/personas/:id', async (request, reply) => {
    const { id } = request.params as { id: string };
    const actor = (request.body as { actor?: string } | undefined)?.actor;
    if (!actor) return reply.status(400).send(personaError(request, 400, 'invalid_request', 'actor is required'));
    const removed = await removePersona(personaTarget, id, actor);
    return removed ? { data: removed } : reply.status(404).send(personaError(request, 404, 'not_found', 'Persona not found'));
  });
  app.post('/v1/personas/:id/apply', async (request, reply) => {
    const { id } = request.params as { id: string };
    const body = request.body as { actor: string; reason?: string; variables?: Record<string, string> };
    if (!body?.actor) return reply.status(400).send(personaError(request, 400, 'invalid_request', 'actor is required'));
    try {
      return { data: await applyPersona(personaTarget, id, { actor: body.actor, reason: body.reason, variables: body.variables }) };
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      const status = /not found/i.test(message) ? 404 : 400;
      return reply.status(status).send(personaError(request, status, status === 404 ? 'not_found' : 'invalid_request', message));
    }
  });
  app.post('/v1/personas/:id/model-request', async (request, reply) => {
    const { id } = request.params as { id: string };
    const body = request.body as {
      actor: string; reason?: string; variables?: Record<string, string>;
      provider?: string; model?: string; temperature?: number; maxTokens?: number; topP?: number
    };
    if (!body?.actor) return reply.status(400).send(personaError(request, 400, 'invalid_request', 'actor is required'));
    let requestOptions;
    try {
      requestOptions = modelRequestOptionsSchema.parse({
        provider: body.provider, model: body.model, temperature: body.temperature,
        maxTokens: body.maxTokens, topP: body.topP
      });
    } catch (error) {
      return reply.status(400).send(personaError(request, 400, 'invalid_request', error instanceof Error ? error.message : String(error)));
    }
    try {
      const applied = await applyPersona(personaTarget, id, { actor: body.actor, reason: body.reason, variables: body.variables });
      return { data: { applicationId: applied.applicationId, receipt: applied.receipt, warnings: applied.warnings, ...buildModelRequest(applied.prompt, requestOptions) } };
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      const status = /not found/i.test(message) ? 404 : 400;
      return reply.status(status).send(personaError(request, status, status === 404 ? 'not_found' : 'invalid_request', message));
    }
  });

  app.get('/v1/errors', async () => ({
    catalog: [
      { code: 'invalid_request', httpStatus: 400, description: 'The request body or query was missing a required field.' },
      { code: 'unauthorized', httpStatus: 401, description: 'A valid bearer token (Authorization: Bearer <token>) is required when auth is enabled.' },
      { code: 'rate_limited', httpStatus: 429, description: 'Too many requests. Respect the Retry-After header and x-ratelimit-remaining.' },
      { code: 'not_found', httpStatus: 404, description: 'The referenced scan, audit, rule, remediation plan, or persona was not found.' },
      { code: 'remediation_conflict', httpStatus: 409, description: 'A remediation transition was rejected: wrong state, compare-and-swap failure, or two-person violation.' },
      { code: 'request_failed', httpStatus: 400, description: 'An unexpected operational error occurred while processing the request.' }
    ]
  }));
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
