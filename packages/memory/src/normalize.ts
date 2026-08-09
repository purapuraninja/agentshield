import { resolve } from 'node:path';
import { memoryRecordSchema, normalizePath, sha256, type MemoryRecord } from '@agentshield/core';

export function recordId(adapter: string, target: string, externalId: string): string {
  return `mem_${sha256(`${adapter}\0${resolve(target)}\0${externalId}`).replace('sha256:', '').slice(0, 24)}`;
}

export function stringValue(value: unknown): string | undefined {
  if (typeof value === 'string' && value.trim()) return value;
  if (value instanceof Date) return value.toISOString();
  return;
}

export function numberValue(value: unknown, fallback: number): number {
  const number = typeof value === 'number' ? value : Number(value);
  return Number.isFinite(number) ? number : fallback;
}

/**
 * Clamps a normalized number to [0, 1]. External stores may carry out-of-range confidence or
 * authority values (e.g. 1.5 or -0.3); those are dirty data to normalize, not fatal schema
 * violations, so a single bad record must never abort the whole audit.
 */
function boundedUnit(value: number): number {
  return Math.min(1, Math.max(0, value));
}

/** Maps an adapter row to the canonical `MemoryRecord` used by every detector. */
export function normalizeRecord(raw: unknown, adapter: string, target: string, externalId: string, sourceUri?: string): MemoryRecord {
  const object = raw && typeof raw === 'object' ? raw as Record<string, unknown> : { content: raw };
  const contentValue = object.content ?? object.text ?? object.value ?? object.memory ?? object.message ?? raw;
  const content = typeof contentValue === 'string' ? contentValue : JSON.stringify(contentValue);
  const createdAt = stringValue(object.created_at ?? object.createdAt ?? object.timestamp ?? object.date);
  const modifiedAt = stringValue(object.modified_at ?? object.modifiedAt ?? object.updated_at ?? object.updatedAt);
  const validUntil = stringValue(object.valid_until ?? object.validUntil ?? object.expires_at ?? object.expiresAt);
  const rawType = stringValue(object.type)?.toLowerCase();
  const type = ['working', 'episodic', 'semantic', 'procedural'].includes(rawType ?? '') ? rawType as MemoryRecord['type'] : 'unknown';
  return memoryRecordSchema.parse({
    memoryId: recordId(adapter, target, externalId), externalId, type, content, contentHash: sha256(content),
    source: { kind: stringValue(object.source_kind) ?? adapter, uri: stringValue(object.source_uri ?? object.source) ?? sourceUri ?? normalizePath(target), capturedAt: createdAt },
    createdBy: stringValue(object.created_by ?? object.createdBy), createdAt, modifiedAt,
    validFrom: stringValue(object.valid_from ?? object.validFrom),
    validUntil, confidence: boundedUnit(numberValue(object.confidence, 0.5)), authority: boundedUnit(numberValue(object.authority, 0.5)),
    integrityStatus: object.integrity_status === 'verified' || object.integrity_status === 'mismatch' ? object.integrity_status : 'unverified',
    labels: Array.isArray(object.labels) ? object.labels.map(String) : [], version: Math.max(1, Math.floor(numberValue(object.version, 1))),
    metadata: { originalKeys: Object.keys(object).filter((key) => !['content', 'text', 'value', 'memory', 'message'].includes(key)) }
  });
}
