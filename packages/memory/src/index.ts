import { appendFile, mkdir, readFile, readdir, rename, stat, writeFile } from 'node:fs/promises';
import { DatabaseSync } from 'node:sqlite';
import { dirname, extname, join, relative, resolve } from 'node:path';
import {
  SCHEMA_VERSION, createId, findingSchema, maskEvidence, memoryAuditReportSchema, memoryRecordSchema,
  normalizePath, redactSecrets, sha256, trustAssessmentSchema, type Confidence, type Finding,
  type MemoryAuditReport, type MemoryRecord, type Severity, type TrustAssessment
} from '@agentshield/core';

export type PrivacyMode = 'none' | 'secrets' | 'pii-secrets' | 'metadata-only';
export interface MemoryAdapterOptions {
  table?: string;
  idColumn?: string;
  contentColumn?: string;
  createdAtColumn?: string;
  sourceColumn?: string;
  pageSize?: number;
}
export interface AuditOptions extends MemoryAdapterOptions {
  privacyMode?: PrivacyMode;
  includeQuarantined?: boolean;
  cache?: boolean;
}

export const MEMORY_ADAPTER_CONTRACT_VERSION = 1;
export interface MemoryAdapterCapabilities {
  readOnlyAudit: boolean;
  pagination: boolean;
  checkpoints: boolean;
  sourceMutation: boolean;
  snapshotRestore: boolean;
}
export interface MemoryInventoryRequest { cursor?: string; pageSize?: number }
export interface MemoryInventoryPage {
  records: MemoryRecord[];
  errors: string[];
  nextCursor?: string;
}
export interface MemoryConnectionResult {
  ok: boolean;
  adapter: string;
  message: string;
}
export interface MemoryMutationPlan {
  action: 'quarantine' | 'restore';
  externalId: string;
  expectedContentHash: string;
}
export interface MemoryMutationReceipt {
  mutationId: string;
  appliedAt: string;
  snapshotId?: string;
}
export interface MemoryAdapter {
  readonly contractVersion: typeof MEMORY_ADAPTER_CONTRACT_VERSION;
  readonly id: string;
  readonly target: string;
  readonly mode: 'audit' | 'remediation';
  readonly capabilities: MemoryAdapterCapabilities;
  testConnection(): Promise<MemoryConnectionResult>;
  inventoryPage(request?: MemoryInventoryRequest): Promise<MemoryInventoryPage>;
  checkpoint(): Promise<string>;
  planMutation?(plan: MemoryMutationPlan): Promise<MemoryMutationPlan>;
  applyMutation?(plan: MemoryMutationPlan): Promise<MemoryMutationReceipt>;
  restoreSnapshot?(snapshotId: string): Promise<MemoryMutationReceipt>;
}

export interface AdapterConformanceResult {
  adapterId: string;
  records: number;
  pages: number;
  checkpoint: string;
}

export interface LoadResult { adapter: string; records: MemoryRecord[]; errors: string[] }
interface QuarantineEntry {
  memoryId: string; externalId: string; target: string; sourceHash: string; snapshot: MemoryRecord;
  actor: string; reason: string; quarantinedAt: string; status: 'quarantined' | 'restored'; restoredAt?: string;
}
interface QuarantineFile { version: 1; entries: QuarantineEntry[] }

const MEMORY_DETECTOR_VERSION = '2026.08.2';
interface CachedRecordAssessment {
  sourceKey: string;
  adapterId: string;
  externalId: string;
  contentHash: string;
  recordFingerprint: string;
  detectorVersion: string;
  privacyMode: PrivacyMode;
  dateBucket: string;
  findings: Finding[];
  assessment: TrustAssessment;
  lastUsedAt: string;
}
interface MemoryCacheFile { version: 1; entries: Record<string, CachedRecordAssessment> }
interface MemoryCacheStats {
  enabled: boolean;
  hits: number;
  misses: number;
  entries: number;
  detectorVersion: string;
}
interface AssessmentCache {
  stats: MemoryCacheStats;
  get(record: MemoryRecord): { findings: Finding[]; assessment: TrustAssessment } | undefined;
  put(record: MemoryRecord, value: { findings: Finding[]; assessment: TrustAssessment }): void;
  save(): Promise<void>;
}

/**
 * Canonical catalog entry for a memory detector rule. Unlike static scanner rules, memory detection
 * is programmatic and contextual: the {@link severity} here is the baseline, and a concrete finding
 * may escalate (for example `AS-ME-010` becomes `critical` when multiple indicators match or the
 * source is untrusted). `rules list` and `explain` consume this catalog so memory rules are no longer
 * undocumented relative to `AS-SC-*`.
 */
export interface MemoryRule {
  id: string;
  title: string;
  description: string;
  severity: Severity;
  confidence: Confidence;
  category: string;
  remediation: string;
  owner: string;
  reviewDate: string;
  limitations: string;
}

export const memoryRules: MemoryRule[] = [
  { id: 'AS-ME-001', title: 'Exact duplicate memory', severity: 'low', confidence: 'high', category: 'memory',
    description: 'Two memory records carry identical content.',
    remediation: 'Keep the most authoritative record and quarantine redundant copies after review.',
    owner: 'core-security', reviewDate: '2026-08-04', limitations: 'Content equality does not measure semantic duplication.' },
  { id: 'AS-ME-002', title: 'Near-duplicate memory', severity: 'low', confidence: 'high', category: 'memory',
    description: 'Two memory records carry substantially similar content.',
    remediation: 'Review both records and retain the freshest authoritative version.',
    owner: 'core-security', reviewDate: '2026-08-04', limitations: 'Token Jaccard similarity may miss paraphrased duplicates.' },
  { id: 'AS-ME-003', title: 'Conflicting memory values', severity: 'high', confidence: 'high', category: 'memory',
    description: 'Memory records disagree about the same entity or attribute.',
    remediation: 'Review both records, prefer the fresher authoritative source, and quarantine the superseded value.',
    owner: 'core-security', reviewDate: '2026-08-04', limitations: 'Only simple entity/attribute/value patterns at the start of text are compared.' },
  { id: 'AS-ME-004', title: 'Expired memory', severity: 'high', confidence: 'high', category: 'memory',
    description: 'The record is past its explicit validity date.',
    remediation: 'Quarantine or refresh the record from its authoritative source.',
    owner: 'core-security', reviewDate: '2026-08-04', limitations: 'Validity is only checked when an explicit valid_until date is present.' },
  { id: 'AS-ME-005', title: 'Stale memory', severity: 'medium', confidence: 'high', category: 'memory',
    description: 'The record is older than the configured freshness threshold.',
    remediation: 'Verify the fact and set an explicit review date or TTL.',
    owner: 'core-security', reviewDate: '2026-08-04', limitations: 'Age is generic and does not consider volatility or memory type policy.' },
  { id: 'AS-ME-006', title: 'Missing memory timestamp', severity: 'low', confidence: 'high', category: 'memory',
    description: 'Freshness cannot be established without a creation timestamp.',
    remediation: 'Add a creation timestamp and validity window at ingestion.',
    owner: 'core-security', reviewDate: '2026-08-04', limitations: 'A timestamp alone does not prove freshness of the underlying fact.' },
  { id: 'AS-ME-007', title: 'Weak memory provenance', severity: 'medium', confidence: 'high', category: 'memory',
    description: 'The source is missing or not attributable.',
    remediation: 'Record the source URI, capture time, and creating component.',
    owner: 'core-security', reviewDate: '2026-08-04', limitations: 'A present URI does not prove the source is authoritative.' },
  { id: 'AS-ME-008', title: 'Secret material in memory', severity: 'critical', confidence: 'high', category: 'memory',
    description: 'The record contains credential-like material.',
    remediation: 'Rotate any exposed credential and store only a secret reference, never the value.',
    owner: 'core-security', reviewDate: '2026-08-04', limitations: 'Pattern matching can miss non-standard credential formats.' },
  { id: 'AS-ME-009', title: 'Personal data in memory', severity: 'high', confidence: 'high', category: 'memory',
    description: 'The record contains a personal-data pattern.',
    remediation: 'Minimize or tokenize personal data and apply an explicit retention policy.',
    owner: 'core-security', reviewDate: '2026-08-04', limitations: 'PII patterns are limited and lack locale or organization term packs.' },
  { id: 'AS-ME-010', title: 'Instruction-like untrusted memory', severity: 'high', confidence: 'high', category: 'memory',
    description: 'The record contains language that may redirect agent policy or tool behavior.',
    remediation: 'Quarantine the record, inspect its provenance, and prevent retrieved content from becoming trusted instructions.',
    owner: 'core-security', reviewDate: '2026-08-04', limitations: 'Phrase matching; hidden Unicode, encoding, and indirect tool instructions are covered by AS-ME-012/013 where applicable.' },
  { id: 'AS-ME-011', title: 'Memory integrity mismatch', severity: 'critical', confidence: 'high', category: 'memory',
    description: 'The stored content hash does not match the hash recorded at ingestion, so the record was modified outside the agent or corrupted.',
    remediation: 'Restore the record from the authoritative source and audit what changed and when.',
    owner: 'core-security', reviewDate: '2026-08-04', limitations: 'Only fires when an explicit integrity_status mismatch is recorded at ingestion.' },
  { id: 'AS-ME-012', title: 'Hidden Unicode in memory', severity: 'high', confidence: 'high', category: 'memory',
    description: 'The record contains zero-width or bidirectional control characters that can make reviewed text differ from interpreted text.',
    remediation: 'Normalize or strip invisible control characters, re-ingest from the authoritative source, and quarantine the record when it originated from untrusted content.',
    owner: 'core-security', reviewDate: '2026-08-08', limitations: 'Some internationalized text may legitimately contain directional controls; a leading BOM is treated as benign.' },
  { id: 'AS-ME-013', title: 'Encoded hidden instruction in memory', severity: 'high', confidence: 'high', category: 'memory',
    description: 'The record hides instruction-like text inside base64 or HTML numeric entities so it bypasses plain-text review.',
    remediation: 'Quarantine the record, decode the payload for review only, and block decoded retrieved content from becoming trusted instructions.',
    owner: 'core-security', reviewDate: '2026-08-08', limitations: 'Only well-formed base64 and contiguous numeric entities are decoded; other encodings are not covered.' }
];

export function getMemoryRule(id: string): MemoryRule | undefined {
  return memoryRules.find((rule) => rule.id.toLowerCase() === id.toLowerCase());
}

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

async function loadMemoryRaw(target: string, options: MemoryAdapterOptions = {}): Promise<LoadResult> {
  const absolute = resolve(target);
  const info = await stat(absolute);
  if (info.isDirectory()) return loadMarkdown(absolute);
  const extension = extname(absolute).toLowerCase();
  if (extension === '.json' || extension === '.jsonl') return loadJson(absolute);
  if (extension === '.md' || extension === '.mdx') return loadMarkdown(absolute);
  if (['.sqlite', '.sqlite3', '.db'].includes(extension)) return loadSqlite(absolute, options);
  throw new Error(`Unsupported memory target: ${extension || 'unknown format'}`);
}

function boundedPageSize(value: number | undefined): number {
  if (value === undefined) return 500;
  if (!Number.isInteger(value) || value < 1 || value > 5_000) throw new Error('Memory page size must be an integer between 1 and 5000');
  return value;
}

function cursorOffset(cursor: string | undefined): number {
  if (cursor === undefined) return 0;
  if (!/^\d+$/.test(cursor)) throw new Error('Invalid memory inventory cursor');
  const value = Number(cursor);
  if (!Number.isSafeInteger(value) || value < 0) throw new Error('Invalid memory inventory cursor');
  return value;
}

export function createMemoryAdapter(target: string, options: MemoryAdapterOptions = {}): MemoryAdapter {
  const absolute = resolve(target);
  let loaded: Promise<LoadResult> | undefined;
  const inventory = (): Promise<LoadResult> => loaded ??= loadMemoryRaw(absolute, options);
  const adapter: MemoryAdapter = {
    contractVersion: MEMORY_ADAPTER_CONTRACT_VERSION,
    id: `builtin:${sha256(absolute)}`,
    target: absolute,
    mode: 'audit',
    capabilities: {
      readOnlyAudit: true,
      pagination: true,
      checkpoints: true,
      sourceMutation: false,
      snapshotRestore: false
    },
    async testConnection() {
      try {
        const result = await inventory();
        return {
          ok: true,
          adapter: result.adapter,
          message: `${result.records.length} record(s) readable${result.errors.length ? ` with ${result.errors.length} record error(s)` : ''}`
        };
      } catch (error) {
        return { ok: false, adapter: 'unknown', message: redactSecrets(String(error)) };
      }
    },
    async inventoryPage(request = {}) {
      const pageSize = boundedPageSize(request.pageSize ?? options.pageSize);
      const offset = cursorOffset(request.cursor);
      const result = await inventory();
      if (offset > result.records.length) throw new Error('Memory inventory cursor is beyond the available records');
      const records = result.records.slice(offset, offset + pageSize);
      const nextOffset = offset + records.length;
      return {
        records,
        errors: offset === 0 ? result.errors : [],
        nextCursor: nextOffset < result.records.length ? String(nextOffset) : undefined
      };
    },
    async checkpoint() {
      const result = await inventory();
      return sha256(result.records
        .map((record) => `${record.externalId}\0${record.contentHash}\0${sha256(JSON.stringify(record))}`)
        .sort()
        .join('\n'));
    }
  };
  return adapter;
}

export async function validateMemoryAdapter(adapter: MemoryAdapter): Promise<AdapterConformanceResult> {
  if (adapter.contractVersion !== MEMORY_ADAPTER_CONTRACT_VERSION) throw new Error('Unsupported memory adapter contract version');
  if (!adapter.id.trim()) throw new Error('Memory adapter id is required');
  if (adapter.mode === 'audit') {
    if (!adapter.capabilities.readOnlyAudit || adapter.capabilities.sourceMutation || adapter.capabilities.snapshotRestore) {
      throw new Error('Audit adapter must declare read-only capabilities');
    }
    if (adapter.planMutation || adapter.applyMutation || adapter.restoreSnapshot) {
      throw new Error('Audit adapter must not expose mutation methods');
    }
  }
  const connection = await adapter.testConnection();
  if (!connection.ok) throw new Error(`Memory adapter connection failed: ${connection.message}`);
  const externalIds = new Set<string>();
  const cursors = new Set<string>();
  let cursor: string | undefined;
  let records = 0;
  let pages = 0;
  do {
    if (cursor && cursors.has(cursor)) throw new Error('Memory adapter returned a cursor loop');
    if (cursor) cursors.add(cursor);
    const page = await adapter.inventoryPage({ cursor, pageSize: 2 });
    pages++;
    for (const record of page.records) {
      memoryRecordSchema.parse(record);
      if (externalIds.has(record.externalId)) throw new Error(`Memory adapter returned duplicate external id: ${record.externalId}`);
      externalIds.add(record.externalId);
      records++;
    }
    if (page.nextCursor !== undefined && page.nextCursor === cursor) throw new Error('Memory adapter cursor did not advance');
    cursor = page.nextCursor;
  } while (cursor !== undefined);
  const checkpoint = await adapter.checkpoint();
  if (!/^sha256:[a-f0-9]{64}$/.test(checkpoint)) throw new Error('Memory adapter checkpoint must be a SHA-256 fingerprint');
  return { adapterId: adapter.id, records, pages, checkpoint };
}

/**
 * Source-store reconciliation: compares the audited inventory against the raw source record count and
 * reports documented exclusions. A non-reconciling audit (e.g. quarantined records skipped, parse
 * failures) is surfaced explicitly rather than silently undercounting. Returns the deltas a reviewer
 * needs to confirm no memory was lost or silently dropped.
 */
export interface ReconciliationResult {
  adapter: string;
  sourceTotal: number;
  audited: number;
  quarantined: number;
  failed: number;
  unaccounted: number;
  reconciled: boolean;
  exclusions: Array<{ kind: string; count: number; note: string }>;
}

export async function reconcileMemoryInventory(target: string, options: MemoryAdapterOptions = {}): Promise<ReconciliationResult> {
  const loaded = await loadMemory(target, options);
  const report = await auditMemory(target, options);
  const sourceTotal = loaded.records.length;
  const audited = report.inventory.audited;
  const quarantined = report.inventory.quarantined;
  const failed = report.inventory.failed;
  const exclusions: Array<{ kind: string; count: number; note: string }> = [];
  if (quarantined) exclusions.push({ kind: 'quarantined', count: quarantined, note: 'Quarantined records are excluded from detector assessment.' });
  if (failed) exclusions.push({ kind: 'failed', count: failed, note: 'Records that failed adapter parsing and were not assessed.' });
  const accounted = audited + quarantined + failed;
  const unaccounted = Math.max(0, sourceTotal - accounted);
  return { adapter: loaded.adapter, sourceTotal, audited, quarantined, failed, unaccounted, reconciled: unaccounted === 0, exclusions };
}

/**
 * Evidence-backed memory type classification. Falls back to the declared record type when present, but
 * derives a normalized type from content and provenance evidence so untyped or mis-typed stores still
 * receive a defensible label. The classifier never overwrites the source; it returns the derived label
 * and the evidence used so a reviewer can audit the decision.
 */
export type ClassifiedMemoryType = 'semantic' | 'procedural' | 'episodic' | 'working' | 'unknown';

export interface MemoryTypeClassification {
  externalId: string;
  declaredType: string;
  derivedType: ClassifiedMemoryType;
  evidence: string[];
}

const PROCEDURAL_HINTS = /\b(?:step|steps|procedure|run|execute|command|script|how to|instructions?|first|then|finally)\b/i;
const EPISODIC_HINTS = /\b(?:on .{3,30} we|yesterday|last week|meeting|conversation|discussed|happened|event|session)\b/i;
const WORKING_HINTS = /\b(?:todo|task|pending|in progress|draft|temporary|scratch|wip)\b/i;

export function classifyMemoryType(record: MemoryRecord): MemoryTypeClassification {
  const evidence: string[] = [];
  const declared = record.type;
  if (declared === 'semantic' || declared === 'procedural' || declared === 'episodic' || declared === 'working') {
    evidence.push(`declared type ${declared}`);
    return { externalId: record.externalId, declaredType: declared, derivedType: declared, evidence };
  }
  const content = record.content;
  if (WORKING_HINTS.test(content)) { evidence.push('working-scratch vocabulary'); return { externalId: record.externalId, declaredType: declared, derivedType: 'working', evidence }; }
  if (PROCEDURAL_HINTS.test(content)) { evidence.push('procedural vocabulary'); return { externalId: record.externalId, declaredType: declared, derivedType: 'procedural', evidence }; }
  if (EPISODIC_HINTS.test(content)) { evidence.push('episodic temporal vocabulary'); return { externalId: record.externalId, declaredType: declared, derivedType: 'episodic', evidence }; }
  if (record.source.kind === 'manual' && content.length < 120) { evidence.push('short manual fact'); return { externalId: record.externalId, declaredType: declared, derivedType: 'semantic', evidence }; }
  evidence.push('no decisive vocabulary; defaulting to unknown');
  return { externalId: record.externalId, declaredType: declared, derivedType: 'unknown', evidence };
}

export async function classifyMemoryTypes(target: string, options: MemoryAdapterOptions = {}): Promise<MemoryTypeClassification[]> {
  const loaded = await loadMemory(target, options);
  return loaded.records.map((record) => classifyMemoryType(record));
}

async function loadFromAdapter(adapter: MemoryAdapter, pageSize?: number): Promise<LoadResult> {
  const connection = await adapter.testConnection();
  if (!connection.ok) throw new Error(`Memory adapter connection failed: ${connection.message}`);
  const records: MemoryRecord[] = [];
  const errors: string[] = [];
  const seenCursors = new Set<string>();
  let cursor: string | undefined;
  do {
    if (cursor && seenCursors.has(cursor)) throw new Error('Memory adapter returned a cursor loop');
    if (cursor) seenCursors.add(cursor);
    const page = await adapter.inventoryPage({ cursor, pageSize });
    records.push(...page.records);
    errors.push(...page.errors);
    if (page.nextCursor !== undefined && page.nextCursor === cursor) throw new Error('Memory adapter cursor did not advance');
    cursor = page.nextCursor;
  } while (cursor !== undefined);
  return { adapter: connection.adapter, records, errors };
}

export async function loadMemory(target: string, options: MemoryAdapterOptions = {}): Promise<LoadResult> {
  return loadFromAdapter(createMemoryAdapter(target, options), options.pageSize);
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
  /(?:do not tell|hide this|secret instruction)/i,
  /(?:abaikan|hiraukan)\s+(?:semua\s+)?(?:instruksi|perintah)\s+(?:sebelumnya|terdahulu)/i,
  /(?:nonaktifkan|lewati|langgar)\s+(?:kebijakan|persetujuan|pengamanan?|aturan)/i,
  /(?:jalankan|panggil|eksekusi)\s+(?:perintah|alat|fungsi|shell)\b/i,
  /(?:jangan\s+(?:beri tahu|bocorkan)|sembunyikan|instruksi\s+rahasia)/i
];

const INVISIBLE_UNICODE_TEST = /[\u200B-\u200F\u202A-\u202E\u2060-\u206F\uFEFF]/;
const HTML_ENTITY_RUN = /(?:&#x[0-9a-fA-F]+;|&#[0-9]+;){4,}/g;
const BASE64_TOKEN = /[A-Za-z0-9+/]{20,}={0,2}/g;
const MAX_DECODED_TOKENS = 32;

function safeCodePoint(code: number): string {
  if (!Number.isInteger(code) || code < 0 || code > 0x10ffff || (code >= 0xd800 && code <= 0xdfff)) return '\uFFFD';
  try { return String.fromCodePoint(code); } catch { return '\uFFFD'; }
}

function isMostlyPrintable(value: string): boolean {
  if (!value) return false;
  let printable = 0;
  for (const ch of value) {
    const code = ch.codePointAt(0)!;
    if ((code >= 0x20 && code <= 0x7e) || code === 0x09 || code === 0x0a || code === 0x0d) printable++;
  }
  return printable / value.length >= 0.8;
}

/**
 * Detect instruction-injection phrases hidden inside base64 blobs or contiguous HTML numeric
 * entities. Only the decoded payload is matched against {@link POISON_TESTS}, so a plain-text
 * instruction next to an unrelated entity cannot fabricate an encoded-injection finding.
 */
function decodedInstructionHit(content: string): { base64: boolean; htmlEntity: boolean } {
  let htmlEntity = false;
  for (const match of content.matchAll(HTML_ENTITY_RUN)) {
    const decoded = match[0]
      .replace(/&#x([0-9a-fA-F]+);/g, (_, hex: string) => safeCodePoint(Number.parseInt(hex, 16)))
      .replace(/&#([0-9]+);/g, (_, dec: string) => safeCodePoint(Number.parseInt(dec, 10)));
    if (POISON_TESTS.some((pattern) => pattern.test(decoded))) { htmlEntity = true; break; }
  }
  let base64 = false;
  let scanned = 0;
  for (const match of content.matchAll(BASE64_TOKEN)) {
    if (scanned++ >= MAX_DECODED_TOKENS) break;
    const token = match[0];
    if (token.length % 4 !== 0) continue;
    let decoded: string;
    try { decoded = Buffer.from(token, 'base64').toString('utf8'); } catch { continue; }
    if (!isMostlyPrintable(decoded)) continue;
    if (POISON_TESTS.some((pattern) => pattern.test(decoded))) { base64 = true; break; }
  }
  return { base64, htmlEntity };
}

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

function cacheIdentity(sourceKey: string, adapterId: string, record: MemoryRecord, privacyMode: PrivacyMode, dateBucket: string): {
  key: string;
  recordFingerprint: string;
} {
  const recordFingerprint = sha256(JSON.stringify(record));
  return {
    key: sha256([sourceKey, adapterId, record.externalId, record.contentHash, recordFingerprint, MEMORY_DETECTOR_VERSION, privacyMode, dateBucket].join('\0')),
    recordFingerprint
  };
}

async function createAssessmentCache(target: string, adapterId: string, privacyMode: PrivacyMode): Promise<AssessmentCache> {
  const path = join(dataDirectory(target), 'memory-cache.json');
  const sourceKey = sha256(resolve(target));
  const dateBucket = new Date().toISOString().slice(0, 10);
  let store: MemoryCacheFile = { version: 1, entries: {} };
  try {
    const raw = JSON.parse(await readFile(path, 'utf8')) as Partial<MemoryCacheFile>;
    if (raw.version === 1 && raw.entries && typeof raw.entries === 'object') store = { version: 1, entries: raw.entries };
  } catch { /* cache is optional and never blocks a complete audit */ }
  const activeKeys = new Set<string>();
  const stats: MemoryCacheStats = { enabled: true, hits: 0, misses: 0, entries: Object.keys(store.entries).length, detectorVersion: MEMORY_DETECTOR_VERSION };
  return {
    stats,
    get(record) {
      const identity = cacheIdentity(sourceKey, adapterId, record, privacyMode, dateBucket);
      activeKeys.add(identity.key);
      const cached = store.entries[identity.key];
      if (!cached
        || cached.sourceKey !== sourceKey
        || cached.adapterId !== adapterId
        || cached.externalId !== record.externalId
        || cached.contentHash !== record.contentHash
        || cached.recordFingerprint !== identity.recordFingerprint
        || cached.detectorVersion !== MEMORY_DETECTOR_VERSION
        || cached.privacyMode !== privacyMode
        || cached.dateBucket !== dateBucket) {
        stats.misses++;
        return;
      }
      const assessment = trustAssessmentSchema.safeParse(cached.assessment);
      const findings = cached.findings.map((item) => findingSchema.safeParse(item));
      if (!assessment.success || findings.some((item) => !item.success)) {
        delete store.entries[identity.key];
        stats.misses++;
        return;
      }
      cached.lastUsedAt = new Date().toISOString();
      stats.hits++;
      return { assessment: assessment.data, findings: findings.map((item) => item.data!) };
    },
    put(record, value) {
      const identity = cacheIdentity(sourceKey, adapterId, record, privacyMode, dateBucket);
      activeKeys.add(identity.key);
      store.entries[identity.key] = {
        sourceKey,
        adapterId,
        externalId: record.externalId,
        contentHash: record.contentHash,
        recordFingerprint: identity.recordFingerprint,
        detectorVersion: MEMORY_DETECTOR_VERSION,
        privacyMode,
        dateBucket,
        findings: value.findings,
        assessment: value.assessment,
        lastUsedAt: new Date().toISOString()
      };
    },
    async save() {
      for (const [key, entry] of Object.entries(store.entries)) {
        if (entry.sourceKey === sourceKey && !activeKeys.has(key)) delete store.entries[key];
      }
      stats.entries = Object.keys(store.entries).length;
      await atomicJson(path, store);
    }
  };
}

function assessRecord(record: MemoryRecord, privacyMode: PrivacyMode, now: number): {
  findings: Finding[];
  assessment: TrustAssessment;
} {
  const findings: Finding[] = [];
  const created = record.createdAt ? Date.parse(record.createdAt) : Number.NaN;
  const ageDays = Number.isFinite(created) ? Math.max(0, (now - created) / 86_400_000) : undefined;
  const expired = record.validUntil ? Date.parse(record.validUntil) < now : false;
  const secrets = SECRET_TESTS.some((pattern) => pattern.test(record.content));
  const pii = PII_TESTS.some((pattern) => pattern.test(record.content));
  const poisonMatches = POISON_TESTS.filter((pattern) => pattern.test(record.content)).length;
  const untrustedSource = /(?:web|email|pdf|document|unknown|markdown)/i.test(record.source.kind);
  const invisibleUnicode = INVISIBLE_UNICODE_TEST.test(record.content.replace(/^\uFEFF/, ''));
  const encoded = decodedInstructionHit(record.content);
  const encodedEncodings: string[] = [];
  if (encoded.base64) encodedEncodings.push('base64');
  if (encoded.htmlEntity) encodedEncodings.push('html-entity');
  const encodedHit = encodedEncodings.length > 0;
  if (expired) findings.push(finding('AS-ME-004', 'Expired memory', 'The record is past its explicit validity date.', 'high', record, `validUntil=${record.validUntil}`, 'Quarantine or refresh the record from its authoritative source.'));
  else if (ageDays !== undefined && ageDays > 180) findings.push(finding('AS-ME-005', 'Stale memory', `The record is approximately ${Math.floor(ageDays)} days old.`, 'medium', record, `createdAt=${record.createdAt}`, 'Verify the fact and set an explicit review date or TTL.'));
  if (!record.createdAt) findings.push(finding('AS-ME-006', 'Missing memory timestamp', 'Freshness cannot be established without a creation timestamp.', 'low', record, 'createdAt is absent', 'Add a creation timestamp and validity window at ingestion.'));
  if (!record.source.uri || record.source.kind === 'unknown') findings.push(finding('AS-ME-007', 'Weak memory provenance', 'The source is missing or not attributable.', 'medium', record, 'source provenance is incomplete', 'Record the source URI, capture time, and creating component.'));
  if (secrets) findings.push(finding('AS-ME-008', 'Secret material in memory', 'The record contains credential-like material.', 'critical', record, applyPrivacy(record.content, 'secrets'), 'Rotate any exposed credential and store only a secret reference, never the value.'));
  if (pii) findings.push(finding('AS-ME-009', 'Personal data in memory', 'The record contains a personal-data pattern.', 'high', record, applyPrivacy(record.content, 'pii-secrets'), 'Minimize or tokenize personal data and apply an explicit retention policy.'));
  if (poisonMatches) findings.push(finding('AS-ME-010', 'Instruction-like untrusted memory', 'The record contains language that may redirect agent policy or tool behavior.', poisonMatches > 1 || untrustedSource ? 'critical' : 'high', record,
    applyPrivacy(record.content, privacyMode), 'Quarantine the record, inspect its provenance, and prevent retrieved content from becoming trusted instructions.', { deterministic: true, matchedIndicators: poisonMatches }));
  if (invisibleUnicode) findings.push(finding('AS-ME-012', 'Hidden Unicode in memory', 'The record contains zero-width or bidirectional control characters that can make reviewed text differ from interpreted text.', untrustedSource ? 'critical' : 'high', record,
    applyPrivacy(record.content, privacyMode), 'Normalize or strip invisible control characters, re-ingest from the authoritative source, and quarantine the record when it originated from untrusted content.', { deterministic: true, indicator: 'invisible-unicode' }));
  if (encodedHit) findings.push(finding('AS-ME-013', 'Encoded hidden instruction in memory', 'The record hides instruction-like text inside base64 or HTML numeric entities so it bypasses plain-text review.', untrustedSource ? 'critical' : 'high', record,
    applyPrivacy(record.content, privacyMode), 'Quarantine the record, decode the payload for review only, and block decoded retrieved content from becoming trusted instructions.', { deterministic: true, encodings: encodedEncodings }));
  if (record.integrityStatus === 'mismatch') findings.push(finding('AS-ME-011', 'Memory integrity mismatch', 'The stored content hash does not match the hash recorded at ingestion, so the record was modified outside the agent or corrupted.', 'critical', record,
    `integrityStatus=mismatch`, 'Restore the record from the authoritative source and audit what changed and when.', { deterministic: true }));
  const freshness = expired ? 0 : ageDays === undefined ? 35 : Math.max(0, Math.round(100 - ageDays / 3.65));
  return {
    findings,
    assessment: {
      memoryId: record.memoryId,
      freshness,
      authority: Math.round(record.authority * 100),
      integrity: record.integrityStatus === 'verified' ? 100 : record.integrityStatus === 'mismatch' ? 0 : 40,
      corroboration: 25,
      sensitivity: secrets ? 100 : pii ? 75 : 0,
      poisonRisk: Math.min(100, poisonMatches * 45 + (poisonMatches && untrustedSource ? 20 : 0) + (invisibleUnicode ? 30 : 0) + (encodedHit ? 40 : 0)),
      suggestedReviewAt: new Date(now + (record.type === 'working' ? 7 : record.type === 'episodic' ? 90 : 180) * 86_400_000).toISOString(),
      suggestedTtlDays: record.type === 'working' ? 7 : record.type === 'episodic' ? 90 : 180
    }
  };
}

function assess(records: MemoryRecord[], privacyMode: PrivacyMode, cache?: AssessmentCache): { findings: Finding[]; assessments: TrustAssessment[] } {
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
    let result = cache?.get(record);
    if (!result) {
      result = assessRecord(record, privacyMode, now);
      cache?.put(record, result);
    }
    findings.push(...result.findings);
    return {
      ...result.assessment,
      corroboration: (hashes.get(record.contentHash)?.length ?? 0) > 1 ? 75 : 25
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
  const adapter = createMemoryAdapter(target, options);
  const loaded = await loadFromAdapter(adapter, options.pageSize);
  const quarantine = await readQuarantine(target);
  const quarantined = new Set(quarantine.entries.filter((item) => item.status === 'quarantined').map((item) => item.memoryId));
  const records = options.includeQuarantined ? loaded.records : loaded.records.filter((item) => !quarantined.has(item.memoryId));
  const checkpoint = sha256(records
    .map((record) => `${record.externalId}\0${record.contentHash}\0${sha256(JSON.stringify(record))}`)
    .sort()
    .join('\n'));
  const cache = options.cache === false ? undefined : await createAssessmentCache(target, adapter.id, privacyMode);
  const result = assess(records, privacyMode, cache);
  if (cache) {
    try { await cache.save(); }
    catch { cache.stats.enabled = false; cache.stats.entries = 0; }
  }
  const byType: Record<string, number> = {};
  for (const record of records) byType[record.type] = (byType[record.type] ?? 0) + 1;
  const report: MemoryAuditReport = {
    schemaVersion: SCHEMA_VERSION, auditId: createId('audit'), target: resolve(target), adapter: loaded.adapter,
    startedAt, completedAt: new Date().toISOString(), status: loaded.errors.length ? 'partial' : 'completed',
    inventory: { total: loaded.records.length, audited: records.length, quarantined: loaded.records.length - records.length, failed: loaded.errors.length, byType },
    findings: result.findings, assessments: result.assessments, checkpoint, privacyMode,
    cache: cache?.stats ?? { enabled: false, hits: 0, misses: records.length, entries: 0, detectorVersion: MEMORY_DETECTOR_VERSION },
    errors: loaded.errors.map(redactSecrets)
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

export {
  planRemediation, approveRemediation, executeRemediation, rollbackRemediation, rejectRemediation,
  listRemediationPlans, getRemediationPlan,
  type RemediationPlan, type RemediationState, type RemediationAction, type RemediationStage, type PlanOptions
} from './remediation.js';
