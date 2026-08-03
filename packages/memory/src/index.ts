import { appendFile, mkdir, readFile, readdir, rename, stat, writeFile } from 'node:fs/promises';
import { DatabaseSync } from 'node:sqlite';
import { dirname, extname, join, relative, resolve } from 'node:path';
import {
  SCHEMA_VERSION, createId, maskEvidence, memoryAuditReportSchema, memoryRecordSchema, normalizePath,
  redactSecrets, sha256, type Finding, type MemoryAuditReport, type MemoryRecord, type TrustAssessment
} from '@agentshield/core';

export type PrivacyMode = 'none' | 'secrets' | 'pii-secrets' | 'metadata-only';
export interface MemoryAdapterOptions {
  table?: string;
  idColumn?: string;
  contentColumn?: string;
  createdAtColumn?: string;
  sourceColumn?: string;
}
export interface AuditOptions extends MemoryAdapterOptions { privacyMode?: PrivacyMode; includeQuarantined?: boolean }

interface LoadResult { adapter: string; records: MemoryRecord[]; errors: string[] }
interface QuarantineEntry {
  memoryId: string; externalId: string; target: string; sourceHash: string; snapshot: MemoryRecord;
  actor: string; reason: string; quarantinedAt: string; status: 'quarantined' | 'restored'; restoredAt?: string;
}
interface QuarantineFile { version: 1; entries: QuarantineEntry[] }

function recordId(adapter: string, target: string, externalId: string): string {
  return `mem_${sha256(`${adapter}\0${resolve(target)}\0${externalId}`).replace('sha256:', '').slice(0, 24)}`;
}

function normalizeRecord(raw: unknown, adapter: string, target: string, externalId: string, sourceUri?: string): MemoryRecord {
  const object = raw && typeof raw === 'object' ? raw as Record<string, unknown> : { content: raw };
  const contentValue = object.content ?? object.text ?? object.value ?? object.memory ?? object.message ?? raw;
  const content = typeof contentValue === 'string' ? contentValue : JSON.stringify(contentValue);
  const createdAt = stringValue(object.created_at ?? object.createdAt ?? object.timestamp ?? object.date);
  const validUntil = stringValue(object.valid_until ?? object.validUntil ?? object.expires_at ?? object.expiresAt);
  const rawType = stringValue(object.type)?.toLowerCase();
  const type = ['working', 'episodic', 'semantic', 'procedural'].includes(rawType ?? '') ? rawType as MemoryRecord['type'] : 'unknown';
  return memoryRecordSchema.parse({
    memoryId: recordId(adapter, target, externalId), externalId, type, content, contentHash: sha256(content),
    source: { kind: stringValue(object.source_kind) ?? adapter, uri: stringValue(object.source_uri ?? object.source) ?? sourceUri ?? normalizePath(target), capturedAt: createdAt },
    createdBy: stringValue(object.created_by ?? object.createdBy), createdAt, validFrom: stringValue(object.valid_from ?? object.validFrom),
    validUntil, confidence: numberValue(object.confidence, 0.5), authority: numberValue(object.authority, 0.5),
    integrityStatus: object.integrity_status === 'verified' || object.integrity_status === 'mismatch' ? object.integrity_status : 'unverified',
    labels: Array.isArray(object.labels) ? object.labels.map(String) : [], version: numberValue(object.version, 1),
    metadata: { originalKeys: Object.keys(object).filter((key) => !['content', 'text', 'value', 'memory', 'message'].includes(key)) }
  });
}

function stringValue(value: unknown): string | undefined {
  if (typeof value === 'string' && value.trim()) return value;
  if (value instanceof Date) return value.toISOString();
  return;
}
function numberValue(value: unknown, fallback: number): number {
  const number = typeof value === 'number' ? value : Number(value);
  return Number.isFinite(number) ? number : fallback;
}

async function loadJson(path: string): Promise<LoadResult> {
  const adapter = extname(path).toLowerCase() === '.jsonl' ? 'jsonl' : 'json';
  const errors: string[] = [];
  const records: MemoryRecord[] = [];
  const content = await readFile(path, 'utf8');
  if (adapter === 'jsonl') {
    const lines = content.split(/\r?\n/);
    for (let index = 0; index < lines.length; index++) {
      const line = lines[index]?.trim(); if (!line) continue;
      try {
        const parsed = JSON.parse(line) as unknown;
        records.push(normalizeRecord(parsed, adapter, path, externalIdFor(parsed, index)));
      }
      catch (error) { errors.push(`line ${index + 1}: ${String(error)}`); }
    }
  } else {
    const value = JSON.parse(content) as unknown;
    const items = Array.isArray(value) ? value : value && typeof value === 'object' && Array.isArray((value as any).records) ? (value as any).records : [value];
    items.forEach((item: unknown, index: number) => records.push(normalizeRecord(item, adapter, path, externalIdFor(item, index))));
  }
  return { adapter, records, errors };
}

function externalIdFor(item: unknown, index: number): string {
  if (item && typeof item === 'object') {
    const object = item as Record<string, unknown>;
    const value = object.external_id ?? object.externalId ?? object.id ?? object.key;
    if (typeof value === 'string' || typeof value === 'number') return String(value);
  }
  return `index:${index}`;
}

async function loadMarkdown(target: string): Promise<LoadResult> {
  const rootInfo = await stat(target);
  const paths: string[] = [];
  async function walk(path: string): Promise<void> {
    for (const entry of await readdir(path, { withFileTypes: true })) {
      if (entry.name === '.agentshield' || entry.name === 'node_modules' || entry.name === '.git') continue;
      const absolute = join(path, entry.name);
      if (entry.isDirectory()) await walk(absolute);
      else if (entry.isFile() && ['.md', '.mdx'].includes(extname(entry.name).toLowerCase())) paths.push(absolute);
    }
  }
  if (rootInfo.isDirectory()) await walk(target); else paths.push(target);
  paths.sort();
  const records: MemoryRecord[] = [];
  const errors: string[] = [];
  const root = rootInfo.isDirectory() ? target : dirname(target);
  for (const path of paths) {
    try {
      const content = await readFile(path, 'utf8');
      const sections = content.split(/\n\s*\n+/).map((item) => item.trim()).filter(Boolean);
      sections.forEach((section, index) => records.push(normalizeRecord({ content: section }, 'markdown', target, `${normalizePath(relative(root, path))}#${index + 1}`, normalizePath(path))));
    } catch (error) { errors.push(`${normalizePath(path)}: ${String(error)}`); }
  }
  return { adapter: 'markdown', records, errors };
}

function assertIdentifier(value: string, label: string): string {
  if (!/^[A-Za-z_][A-Za-z0-9_]*$/.test(value)) throw new Error(`${label} must be a simple SQL identifier`);
  return value;
}

async function loadSqlite(path: string, options: MemoryAdapterOptions): Promise<LoadResult> {
  const database = new DatabaseSync(resolve(path), { readOnly: true });
  const errors: string[] = [];
  try {
    const table = options.table ? assertIdentifier(options.table, 'table') : undefined;
    if (!table) throw new Error('SQLite audit requires --table');
    const columns = database.prepare(`PRAGMA table_info("${table}")`).all() as Array<{ name: string }>;
    if (!columns.length) throw new Error(`Table ${table} does not exist or has no columns`);
    const names = new Set(columns.map((item) => item.name));
    const idColumn = options.idColumn ?? (names.has('id') ? 'id' : columns[0]!.name);
    const contentColumn = options.contentColumn ?? ['content', 'text', 'value', 'memory'].find((name) => names.has(name));
    if (!contentColumn) throw new Error('Could not infer content column; pass --content-column');
    assertIdentifier(idColumn, 'id-column'); assertIdentifier(contentColumn, 'content-column');
    const rows = database.prepare(`SELECT * FROM "${table}"`).all() as Array<Record<string, unknown>>;
    const records = rows.map((row, index) => normalizeRecord({
      ...row, content: row[contentColumn], created_at: options.createdAtColumn ? row[assertIdentifier(options.createdAtColumn, 'created-at-column')] : row.created_at,
      source: options.sourceColumn ? row[assertIdentifier(options.sourceColumn, 'source-column')] : row.source
    }, 'sqlite', path, String(row[idColumn] ?? index), `sqlite://${normalizePath(resolve(path))}/${table}`));
    return { adapter: 'sqlite', records, errors };
  } finally { database.close(); }
}

export async function loadMemory(target: string, options: MemoryAdapterOptions = {}): Promise<LoadResult> {
  const absolute = resolve(target);
  const info = await stat(absolute);
  if (info.isDirectory()) return loadMarkdown(absolute);
  const extension = extname(absolute).toLowerCase();
  if (extension === '.json' || extension === '.jsonl') return loadJson(absolute);
  if (extension === '.md' || extension === '.mdx') return loadMarkdown(absolute);
  if (['.sqlite', '.sqlite3', '.db'].includes(extension)) return loadSqlite(absolute, options);
  throw new Error(`Unsupported memory target: ${extension || 'unknown format'}`);
}

function finding(ruleId: string, title: string, description: string, severity: Finding['severity'], record: MemoryRecord,
  excerpt: string, remediation: string, metadata: Record<string, unknown> = {}): Finding {
  return {
    id: sha256(`${ruleId}\0${record.memoryId}\0${excerpt}`), ruleId, title, description, severity, confidence: 'high', category: 'memory',
    evidence: [{ path: record.source.uri, excerpt: maskEvidence(excerpt), redacted: true }], remediation, status: 'open',
    metadata: { memoryId: record.memoryId, externalId: record.externalId, ...metadata }
  };
}

const SECRET_TESTS = [
  /\b(?:sk|rk|pk)-[A-Za-z0-9_-]{12,}\b/, /\bAKIA[0-9A-Z]{16}\b/, /\bgh[pousr]_[A-Za-z0-9]{20,}\b/,
  /(?:password|passwd|token|secret|api[_-]?key)\s*[:=]\s*['\"]?[^\s'\"]{8,}/i
];
const PII_TESTS = [
  /\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b/i,
  /\b(?:\+?62|0)8[1-9][0-9]{7,11}\b/,
  /\b\d{3}-\d{2}-\d{4}\b/,
  /\b\d{16}\b/
];
const POISON_TESTS = [
  /(?:ignore|disregard|forget)\s+(?:all\s+)?(?:previous|prior|system|developer)\s+instructions?/i,
  /(?:bypass|disable|override)\s+(?:approval|policy|safety|guardrail|system)/i,
  /(?:call|invoke|run|execute|use)\s+(?:the\s+)?(?:tool|function|shell|command)\b/i,
  /(?:you are now|new identity|replace your instructions)/i,
  /(?:do not tell|hide this|secret instruction)/i
];

function tokens(value: string): Set<string> {
  return new Set(value.toLowerCase().replaceAll(/[^\p{L}\p{N}\s]/gu, ' ').split(/\s+/).filter((item) => item.length > 2));
}
function jaccard(a: Set<string>, b: Set<string>): number {
  if (!a.size && !b.size) return 1;
  let intersection = 0; for (const value of a) if (b.has(value)) intersection++;
  return intersection / (a.size + b.size - intersection);
}

function entityValue(content: string): { entity: string; value: string } | undefined {
  const cleaned = content.replaceAll(/[*_`#]/g, '').trim();
  const match = /^(?:the\s+)?([\p{L}\p{N}][\p{L}\p{N} _-]{1,60}?)\s+(?:is|are|=|:)\s+([^.!?\n]{1,120})/iu.exec(cleaned);
  if (!match) return;
  return { entity: match[1]!.trim().toLowerCase(), value: match[2]!.trim().toLowerCase() };
}

function applyPrivacy(value: string, mode: PrivacyMode): string {
  if (mode === 'metadata-only') return '[CONTENT REDACTED:metadata-only]';
  let output = mode === 'none' ? value : redactSecrets(value);
  if (mode === 'pii-secrets') {
    for (const pattern of PII_TESTS) output = output.replace(new RegExp(pattern.source, `${pattern.flags}g`), '[REDACTED:pii]');
  }
  return maskEvidence(output);
}

function assess(records: MemoryRecord[], privacyMode: PrivacyMode): { findings: Finding[]; assessments: TrustAssessment[] } {
  const findings: Finding[] = [];
  const now = Date.now();
  const hashes = new Map<string, MemoryRecord[]>();
  const entities = new Map<string, Array<{ record: MemoryRecord; value: string }>>();
  const tokenized = records.map((record) => tokens(record.content));

  records.forEach((record) => {
    const same = hashes.get(record.contentHash) ?? []; same.push(record); hashes.set(record.contentHash, same);
    const pair = entityValue(record.content); if (pair) { const list = entities.get(pair.entity) ?? []; list.push({ record, value: pair.value }); entities.set(pair.entity, list); }
  });

  for (const group of hashes.values()) if (group.length > 1) {
    for (const record of group.slice(1)) findings.push(finding('AS-ME-001', 'Exact duplicate memory', 'This content duplicates another record.', 'low', record,
      `Duplicate of ${group[0]!.memoryId}`, 'Keep the most authoritative record and quarantine redundant copies after review.', { relatedMemoryId: group[0]!.memoryId }));
  }
  for (let a = 0; a < records.length; a++) for (let b = a + 1; b < records.length && b < a + 250; b++) {
    if (records[a]!.contentHash === records[b]!.contentHash) continue;
    const similarity = jaccard(tokenized[a]!, tokenized[b]!);
    if (similarity >= 0.88) findings.push(finding('AS-ME-002', 'Near-duplicate memory', 'Two records carry substantially similar content.', 'low', records[b]!,
      `${Math.round(similarity * 100)}% similar to ${records[a]!.memoryId}`, 'Review both records and retain the freshest authoritative version.', { relatedMemoryId: records[a]!.memoryId, similarity }));
  }
  for (const [entity, values] of entities) {
    const distinct = new Set(values.map((item) => item.value));
    if (distinct.size > 1) for (const item of values.slice(1)) findings.push(finding('AS-ME-003', 'Conflicting memory values', `Records disagree about “${entity}”.`, 'high', item.record,
      `${entity}: ${applyPrivacy(item.value, privacyMode)}`, 'Review both records, prefer the fresher authoritative source, and quarantine the superseded value.',
      { entity, relatedMemoryIds: values.filter((other) => other.record.memoryId !== item.record.memoryId).map((other) => other.record.memoryId) }));
  }

  const assessments = records.map((record): TrustAssessment => {
    const created = record.createdAt ? Date.parse(record.createdAt) : Number.NaN;
    const ageDays = Number.isFinite(created) ? Math.max(0, (now - created) / 86_400_000) : undefined;
    const expired = record.validUntil ? Date.parse(record.validUntil) < now : false;
    const secrets = SECRET_TESTS.some((pattern) => pattern.test(record.content));
    const pii = PII_TESTS.some((pattern) => pattern.test(record.content));
    const poisonMatches = POISON_TESTS.filter((pattern) => pattern.test(record.content)).length;
    const untrustedSource = /(?:web|email|pdf|document|unknown|markdown)/i.test(record.source.kind);
    if (expired) findings.push(finding('AS-ME-004', 'Expired memory', 'The record is past its explicit validity date.', 'high', record, `validUntil=${record.validUntil}`, 'Quarantine or refresh the record from its authoritative source.'));
    else if (ageDays !== undefined && ageDays > 180) findings.push(finding('AS-ME-005', 'Stale memory', `The record is approximately ${Math.floor(ageDays)} days old.`, 'medium', record, `createdAt=${record.createdAt}`, 'Verify the fact and set an explicit review date or TTL.'));
    if (!record.createdAt) findings.push(finding('AS-ME-006', 'Missing memory timestamp', 'Freshness cannot be established without a creation timestamp.', 'low', record, 'createdAt is absent', 'Add a creation timestamp and validity window at ingestion.'));
    if (!record.source.uri || record.source.kind === 'unknown') findings.push(finding('AS-ME-007', 'Weak memory provenance', 'The source is missing or not attributable.', 'medium', record, 'source provenance is incomplete', 'Record the source URI, capture time, and creating component.'));
    if (secrets) findings.push(finding('AS-ME-008', 'Secret material in memory', 'The record contains credential-like material.', 'critical', record, applyPrivacy(record.content, 'secrets'), 'Rotate any exposed credential and store only a secret reference, never the value.'));
    if (pii) findings.push(finding('AS-ME-009', 'Personal data in memory', 'The record contains a personal-data pattern.', 'high', record, applyPrivacy(record.content, 'pii-secrets'), 'Minimize or tokenize personal data and apply an explicit retention policy.'));
    if (poisonMatches) findings.push(finding('AS-ME-010', 'Instruction-like untrusted memory', 'The record contains language that may redirect agent policy or tool behavior.', poisonMatches > 1 || untrustedSource ? 'critical' : 'high', record,
      applyPrivacy(record.content, privacyMode), 'Quarantine the record, inspect its provenance, and prevent retrieved content from becoming trusted instructions.', { deterministic: true, matchedIndicators: poisonMatches }));
    const freshness = expired ? 0 : ageDays === undefined ? 35 : Math.max(0, Math.round(100 - ageDays / 3.65));
    const corroboration = (hashes.get(record.contentHash)?.length ?? 0) > 1 ? 75 : 25;
    return {
      memoryId: record.memoryId, freshness, authority: Math.round(record.authority * 100),
      integrity: record.integrityStatus === 'verified' ? 100 : record.integrityStatus === 'mismatch' ? 0 : 40,
      corroboration, sensitivity: secrets ? 100 : pii ? 75 : 0,
      poisonRisk: Math.min(100, poisonMatches * 45 + (poisonMatches && untrustedSource ? 20 : 0)),
      suggestedReviewAt: new Date(now + (record.type === 'working' ? 7 : record.type === 'episodic' ? 90 : 180) * 86_400_000).toISOString(),
      suggestedTtlDays: record.type === 'working' ? 7 : record.type === 'episodic' ? 90 : 180
    };
  });
  return { findings, assessments };
}

function dataDirectory(target: string): string {
  const absolute = resolve(target);
  try { return extname(absolute) ? join(dirname(absolute), '.agentshield') : join(absolute, '.agentshield'); }
  catch { return join(dirname(absolute), '.agentshield'); }
}
async function readQuarantine(target: string): Promise<QuarantineFile> {
  try { return JSON.parse(await readFile(join(dataDirectory(target), 'quarantine.json'), 'utf8')) as QuarantineFile; }
  catch { return { version: 1, entries: [] }; }
}

export async function auditMemory(target: string, options: AuditOptions = {}): Promise<MemoryAuditReport> {
  const startedAt = new Date().toISOString();
  const privacyMode = options.privacyMode ?? 'pii-secrets';
  const loaded = await loadMemory(target, options);
  const quarantine = await readQuarantine(target);
  const quarantined = new Set(quarantine.entries.filter((item) => item.status === 'quarantined').map((item) => item.memoryId));
  const records = options.includeQuarantined ? loaded.records : loaded.records.filter((item) => !quarantined.has(item.memoryId));
  const checkpoint = sha256(records.map((record) => record.contentHash).sort().join('\n'));
  const result = assess(records, privacyMode);
  const byType: Record<string, number> = {};
  for (const record of records) byType[record.type] = (byType[record.type] ?? 0) + 1;
  const report: MemoryAuditReport = {
    schemaVersion: SCHEMA_VERSION, auditId: createId('audit'), target: resolve(target), adapter: loaded.adapter,
    startedAt, completedAt: new Date().toISOString(), status: loaded.errors.length ? 'partial' : 'completed',
    inventory: { total: loaded.records.length, audited: records.length, quarantined: loaded.records.length - records.length, failed: loaded.errors.length, byType },
    findings: result.findings, assessments: result.assessments, checkpoint, privacyMode, errors: loaded.errors.map(redactSecrets)
  };
  return memoryAuditReportSchema.parse(report);
}

async function atomicJson(path: string, value: unknown): Promise<void> {
  await mkdir(dirname(path), { recursive: true });
  const temporary = `${path}.${process.pid}.tmp`;
  await writeFile(temporary, `${JSON.stringify(value, null, 2)}\n`, { encoding: 'utf8', mode: 0o600 });
  await rename(temporary, path);
}

async function appendAudit(target: string, action: string, actor: string, metadata: Record<string, unknown>): Promise<void> {
  const path = join(dataDirectory(target), 'audit.jsonl');
  await mkdir(dirname(path), { recursive: true });
  let previousHash = 'genesis';
  try {
    const lines = (await readFile(path, 'utf8')).trim().split(/\r?\n/); const last = JSON.parse(lines.at(-1) ?? '{}'); previousHash = last.hash ?? previousHash;
  } catch { /* first audit event */ }
  const event = { eventId: createId('evt'), timestamp: new Date().toISOString(), actor, action, metadata, previousHash };
  const record = { ...event, hash: sha256(JSON.stringify(event)) };
  await appendFile(path, `${JSON.stringify(record)}\n`, { encoding: 'utf8', mode: 0o600 });
}

export async function quarantineMemory(target: string, memoryId: string, actor: string, reason: string, options: MemoryAdapterOptions = {}): Promise<QuarantineEntry> {
  if (!actor.trim() || !reason.trim()) throw new Error('Quarantine requires a non-empty actor and reason');
  const loaded = await loadMemory(target, options);
  const record = loaded.records.find((item) => item.memoryId === memoryId || item.externalId === memoryId);
  if (!record) throw new Error(`Memory record not found: ${memoryId}`);
  const store = await readQuarantine(target);
  if (store.entries.some((item) => item.memoryId === record.memoryId && item.status === 'quarantined')) throw new Error('Memory record is already quarantined');
  const entry: QuarantineEntry = {
    memoryId: record.memoryId, externalId: record.externalId, target: resolve(target), sourceHash: record.contentHash,
    snapshot: record, actor, reason, quarantinedAt: new Date().toISOString(), status: 'quarantined'
  };
  store.entries.push(entry);
  await atomicJson(join(dataDirectory(target), 'quarantine.json'), store);
  await appendAudit(target, 'memory.quarantined', actor, { memoryId: record.memoryId, externalId: record.externalId, sourceHash: record.contentHash, reason });
  return entry;
}

export async function restoreMemory(target: string, memoryId: string, actor: string, reason: string): Promise<QuarantineEntry> {
  if (!actor.trim() || !reason.trim()) throw new Error('Restore requires a non-empty actor and reason');
  const store = await readQuarantine(target);
  const index = store.entries.findIndex((item) => (item.memoryId === memoryId || item.externalId === memoryId) && item.status === 'quarantined');
  if (index < 0) throw new Error(`Quarantined memory record not found: ${memoryId}`);
  const entry = store.entries[index]!;
  const restored: QuarantineEntry = { ...entry, status: 'restored', restoredAt: new Date().toISOString() };
  store.entries[index] = restored;
  await atomicJson(join(dataDirectory(target), 'quarantine.json'), store);
  await appendAudit(target, 'memory.restored', actor, { memoryId: entry.memoryId, externalId: entry.externalId, reason, originalSourceHash: entry.sourceHash });
  return restored;
}

export async function listQuarantine(target: string): Promise<Array<Omit<QuarantineEntry, 'snapshot'>>> {
  const store = await readQuarantine(target);
  return store.entries.map(({ snapshot: _snapshot, ...entry }) => entry);
}
