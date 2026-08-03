import { appendFile, mkdir, readFile } from 'node:fs/promises';
import { dirname, resolve } from 'node:path';
import {
  SCHEMA_VERSION, createId, redactSecrets, runtimeEventSchema, sha256,
  type PolicyAction, type RuntimeEvent
} from '@agentshield/core';

const FORBIDDEN_METADATA_KEYS = /(?:content|prompt|secret|token|password|credential|body|raw|payload)/i;

export interface CreateEventInput {
  eventId?: string;
  traceId: string;
  parentId?: string | null;
  causalityIds?: string[];
  type: RuntimeEvent['type'];
  actor: string;
  target?: string;
  payload?: unknown;
  metadata?: Record<string, unknown>;
  timestamp?: string;
}

export interface EvidenceNode { id: string; kind: string; label: string; timestamp?: string; metadata: Record<string, unknown> }
export interface EvidenceEdge { from: string; to: string; relation: string }
export interface EvidenceGraph { traceId: string; nodes: EvidenceNode[]; edges: EvidenceEdge[]; gaps: string[] }

function sanitizeMetadata(metadata: Record<string, unknown> = {}): Record<string, unknown> {
  const result: Record<string, unknown> = {};
  for (const [key, value] of Object.entries(metadata)) {
    if (FORBIDDEN_METADATA_KEYS.test(key)) {
      result[`${key}Hash`] = sha256(typeof value === 'string' ? value : JSON.stringify(value));
      continue;
    }
    if (typeof value === 'string') result[key] = redactSecrets(value).slice(0, 500);
    else if (typeof value === 'number' || typeof value === 'boolean' || value === null) result[key] = value;
    else if (Array.isArray(value)) result[key] = value.slice(0, 50).map((item) => typeof item === 'string' ? redactSecrets(item).slice(0, 200) : String(item));
    else result[key] = sha256(JSON.stringify(value));
  }
  return result;
}

export function createRuntimeEvent(input: CreateEventInput): RuntimeEvent {
  const payloadText = input.payload === undefined ? '' : typeof input.payload === 'string' ? input.payload : JSON.stringify(input.payload);
  return runtimeEventSchema.parse({
    schemaVersion: SCHEMA_VERSION, eventId: input.eventId ?? createId('event'), traceId: input.traceId,
    parentId: input.parentId, causalityIds: input.causalityIds ?? [], type: input.type, actor: input.actor,
    target: input.target, timestamp: input.timestamp ?? new Date().toISOString(), payloadHash: sha256(payloadText),
    metadata: sanitizeMetadata(input.metadata)
  });
}

export class EventStore {
  constructor(readonly path = resolve('.agentshield/events.jsonl')) {}

  async all(): Promise<RuntimeEvent[]> {
    try {
      const lines = (await readFile(this.path, 'utf8')).split(/\r?\n/).filter(Boolean);
      const events: RuntimeEvent[] = [];
      for (const line of lines) {
        try { events.push(runtimeEventSchema.parse(JSON.parse(line))); } catch { /* preserve service despite malformed legacy line */ }
      }
      return events;
    } catch { return []; }
  }

  async ingest(input: RuntimeEvent | CreateEventInput): Promise<{ event: RuntimeEvent; duplicate: boolean }> {
    const event = 'schemaVersion' in input ? runtimeEventSchema.parse(input) : createRuntimeEvent(input);
    const events = await this.all();
    const existing = events.find((item) => item.eventId === event.eventId);
    if (existing) return { event: existing, duplicate: true };
    await mkdir(dirname(this.path), { recursive: true });
    await appendFile(this.path, `${JSON.stringify(event)}\n`, { encoding: 'utf8', mode: 0o600 });
    return { event, duplicate: false };
  }

  async trace(traceId: string): Promise<RuntimeEvent[]> {
    return (await this.all()).filter((item) => item.traceId === traceId).sort((a, b) => a.timestamp.localeCompare(b.timestamp));
  }

  async graph(traceId: string): Promise<EvidenceGraph> {
    return buildEvidenceGraph(await this.trace(traceId), traceId);
  }
}

function relationFor(event: RuntimeEvent): string {
  return ({
    'source.read': 'read_by', 'model.requested': 'influenced', 'model.responded': 'produced', 'memory.proposed': 'proposed',
    'memory.written': 'stored_as', 'memory.retrieved': 'retrieved', 'policy.evaluated': 'evaluated',
    'approval.requested': 'requested_approval', 'approval.resolved': 'approved_or_denied', 'tool.requested': 'requested',
    'tool.executed': 'executed', 'tool.failed': 'failed', 'memory.quarantined': 'quarantined', 'memory.restored': 'restored',
    'agent.run.started': 'started', 'agent.run.completed': 'completed'
  } as Record<RuntimeEvent['type'], string>)[event.type];
}

export function buildEvidenceGraph(events: RuntimeEvent[], traceId?: string): EvidenceGraph {
  const eventById = new Map(events.map((event) => [event.eventId, event]));
  const nodes: EvidenceNode[] = events.map((event) => ({ id: event.eventId, kind: event.type, label: event.target ?? event.actor, timestamp: event.timestamp, metadata: event.metadata }));
  const edges: EvidenceEdge[] = [];
  const gaps: string[] = [];
  for (const event of events) {
    if (event.parentId) {
      if (eventById.has(event.parentId)) edges.push({ from: event.parentId, to: event.eventId, relation: relationFor(event) });
      else gaps.push(`Missing parent event ${event.parentId} referenced by ${event.eventId}`);
    }
    for (const cause of event.causalityIds) {
      if (eventById.has(cause)) edges.push({ from: cause, to: event.eventId, relation: 'caused' });
      else gaps.push(`Missing causality event ${cause} referenced by ${event.eventId}`);
    }
  }
  if (events.length && !events.some((item) => item.type === 'agent.run.started')) gaps.push('Trace has no agent.run.started event');
  if (events.some((item) => item.type === 'tool.executed') && !events.some((item) => item.type === 'policy.evaluated')) gaps.push('Executed tool has no recorded policy decision');
  return { traceId: traceId ?? events[0]?.traceId ?? 'unknown', nodes, edges, gaps: [...new Set(gaps)] };
}

export interface RuntimePolicy {
  id: string;
  toolPattern?: string;
  memorySourcePattern?: string;
  sensitivity?: 'low' | 'medium' | 'high';
  action: PolicyAction;
}

export function evaluateRuntimePolicy(event: RuntimeEvent, policies: RuntimePolicy[]): { action: PolicyAction; policyIds: string[]; reason: string } {
  const rank: Record<PolicyAction, number> = { allow: 0, warn: 1, require_review: 2, quarantine: 3, block: 4 };
  const matched = policies.filter((policy) => {
    if (policy.toolPattern && event.type.startsWith('tool.') && !new RegExp(policy.toolPattern, 'i').test(event.target ?? '')) return false;
    if (policy.memorySourcePattern && event.type.startsWith('memory.') && !new RegExp(policy.memorySourcePattern, 'i').test(String(event.metadata.source ?? ''))) return false;
    if (policy.sensitivity && event.metadata.sensitivity !== policy.sensitivity) return false;
    return Boolean(policy.toolPattern || policy.memorySourcePattern || policy.sensitivity);
  });
  const action = matched.reduce<PolicyAction>((current, policy) => rank[policy.action] > rank[current] ? policy.action : current, 'allow');
  return { action, policyIds: matched.map((item) => item.id), reason: matched.length ? `Matched ${matched.length} runtime policy rule(s)` : 'No policy rule matched' };
}

export function createTraceId(): string { return createId('trace'); }
