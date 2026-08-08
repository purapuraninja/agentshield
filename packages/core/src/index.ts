import { createHash, randomUUID } from 'node:crypto';
import { z } from 'zod';

export const VERSION = '0.1.0';
export const SCHEMA_VERSION = '1.0.0';

export const severitySchema = z.enum(['info', 'low', 'medium', 'high', 'critical']);
export type Severity = z.infer<typeof severitySchema>;

export const confidenceSchema = z.enum(['low', 'medium', 'high']);
export type Confidence = z.infer<typeof confidenceSchema>;

export const evidenceSchema = z.object({
  path: z.string(),
  line: z.number().int().positive().optional(),
  column: z.number().int().positive().optional(),
  excerpt: z.string(),
  redacted: z.boolean().default(false)
});

export const findingSchema = z.object({
  id: z.string(),
  ruleId: z.string(),
  title: z.string(),
  description: z.string(),
  severity: severitySchema,
  confidence: confidenceSchema,
  category: z.string(),
  evidence: z.array(evidenceSchema).min(1),
  remediation: z.string(),
  status: z.enum(['open', 'reviewed', 'suppressed', 'resolved']).default('open'),
  metadata: z.record(z.string(), z.unknown()).default({})
});
export type Finding = z.infer<typeof findingSchema>;

export const permissionSchema = z.object({
  resource: z.string(),
  action: z.string(),
  scope: z.string(),
  evidence: evidenceSchema,
  risk: severitySchema
});
export type Permission = z.infer<typeof permissionSchema>;

/**
 * Supply-chain provenance evidence for a component.
 *
 * Every field is optional because provenance is discovered opportunistically from manifests and
 * lockfiles. An absent field means "not observed", never "verified absent".
 */
export const componentProvenanceSchema = z.object({
  packageName: z.string().optional(),
  declaredVersion: z.string().optional(),
  resolvedVersion: z.string().optional(),
  repositoryUrl: z.string().optional(),
  homepageUrl: z.string().optional(),
  registryUrl: z.string().optional(),
  integrity: z.string().optional(),
  lockfile: z.string().optional(),
  manifest: z.string().optional(),
  pinned: z.boolean().optional(),
  unpinnedDependencies: z.array(z.string()).default([]),
  remoteDependencies: z.array(z.string()).default([])
});
export type ComponentProvenance = z.infer<typeof componentProvenanceSchema>;

export const componentSchema = z.object({
  id: z.string(),
  type: z.enum(['skill', 'mcp-server', 'script', 'config', 'memory-store', 'unknown']),
  name: z.string(),
  version: z.string().optional(),
  hash: z.string(),
  source: z.string(),
  signatureStatus: z.enum(['verified', 'unsigned', 'invalid', 'unknown']).default('unknown'),
  provenance: componentProvenanceSchema.optional()
});
export type Component = z.infer<typeof componentSchema>;

export const riskDimensionsSchema = z.object({
  permission: z.number().min(0).max(100),
  execution: z.number().min(0).max(100),
  exfiltration: z.number().min(0).max(100),
  secret: z.number().min(0).max(100),
  supplyChain: z.number().min(0).max(100),
  memoryPoison: z.number().min(0).max(100).default(0)
});
export type RiskDimensions = z.infer<typeof riskDimensionsSchema>;

export const scanReportSchema = z.object({
  schemaVersion: z.literal(SCHEMA_VERSION),
  scanId: z.string(),
  scannerVersion: z.string(),
  rulepackVersion: z.string(),
  target: z.string(),
  startedAt: z.string(),
  completedAt: z.string(),
  status: z.enum(['completed', 'partial', 'failed']),
  filesScanned: z.number().int().nonnegative(),
  bytesScanned: z.number().int().nonnegative(),
  components: z.array(componentSchema),
  permissions: z.array(permissionSchema),
  findings: z.array(findingSchema),
  risk: riskDimensionsSchema,
  overallRisk: z.number().min(0).max(100),
  errors: z.array(z.string()).default([])
});
export type ScanReport = z.infer<typeof scanReportSchema>;

export const memorySourceSchema = z.object({
  kind: z.string(),
  uri: z.string(),
  capturedAt: z.string().optional()
});

export const memoryRecordSchema = z.object({
  memoryId: z.string(),
  externalId: z.string(),
  type: z.enum(['working', 'episodic', 'semantic', 'procedural', 'unknown']).default('unknown'),
  content: z.string(),
  contentHash: z.string(),
  source: memorySourceSchema,
  createdBy: z.string().optional(),
  createdAt: z.string().optional(),
  validFrom: z.string().nullable().optional(),
  validUntil: z.string().nullable().optional(),
  confidence: z.number().min(0).max(1).default(0.5),
  authority: z.number().min(0).max(1).default(0.5),
  integrityStatus: z.enum(['verified', 'unverified', 'mismatch']).default('unverified'),
  labels: z.array(z.string()).default([]),
  version: z.number().int().positive().default(1),
  metadata: z.record(z.string(), z.unknown()).default({})
});
export type MemoryRecord = z.infer<typeof memoryRecordSchema>;

export const trustAssessmentSchema = z.object({
  memoryId: z.string(),
  freshness: z.number().min(0).max(100),
  authority: z.number().min(0).max(100),
  integrity: z.number().min(0).max(100),
  corroboration: z.number().min(0).max(100),
  sensitivity: z.number().min(0).max(100),
  poisonRisk: z.number().min(0).max(100),
  suggestedReviewAt: z.string().optional(),
  suggestedTtlDays: z.number().int().positive().optional()
});
export type TrustAssessment = z.infer<typeof trustAssessmentSchema>;

export const memoryAuditReportSchema = z.object({
  schemaVersion: z.literal(SCHEMA_VERSION),
  auditId: z.string(),
  target: z.string(),
  adapter: z.string(),
  startedAt: z.string(),
  completedAt: z.string(),
  status: z.enum(['completed', 'partial', 'failed']),
  inventory: z.object({
    total: z.number().int().nonnegative(),
    audited: z.number().int().nonnegative(),
    quarantined: z.number().int().nonnegative(),
    failed: z.number().int().nonnegative(),
    byType: z.record(z.string(), z.number().int().nonnegative())
  }),
  findings: z.array(findingSchema),
  assessments: z.array(trustAssessmentSchema),
  checkpoint: z.string(),
  privacyMode: z.enum(['none', 'secrets', 'pii-secrets', 'metadata-only']),
  cache: z.object({
    enabled: z.boolean(),
    hits: z.number().int().nonnegative(),
    misses: z.number().int().nonnegative(),
    entries: z.number().int().nonnegative(),
    detectorVersion: z.string()
  }).optional(),
  errors: z.array(z.string()).default([])
});
export type MemoryAuditReport = z.infer<typeof memoryAuditReportSchema>;

export const runtimeEventTypeSchema = z.enum([
  'agent.run.started', 'source.read', 'model.requested', 'model.responded', 'memory.proposed',
  'memory.written', 'memory.retrieved', 'policy.evaluated', 'approval.requested',
  'approval.resolved', 'tool.requested', 'tool.executed', 'tool.failed',
  'memory.quarantined', 'memory.restored', 'agent.run.completed'
]);

export const runtimeEventSchema = z.object({
  schemaVersion: z.literal(SCHEMA_VERSION).default(SCHEMA_VERSION),
  eventId: z.string(),
  traceId: z.string(),
  parentId: z.string().nullable().optional(),
  causalityIds: z.array(z.string()).default([]),
  type: runtimeEventTypeSchema,
  actor: z.string(),
  target: z.string().optional(),
  timestamp: z.string(),
  payloadHash: z.string(),
  metadata: z.record(z.string(), z.unknown()).default({})
});
export type RuntimeEvent = z.infer<typeof runtimeEventSchema>;

export type PolicyAction = 'allow' | 'warn' | 'require_review' | 'quarantine' | 'block';
export interface PolicyDecision {
  action: PolicyAction;
  reasons: string[];
  matchedRules: string[];
}

const SECRET_PATTERNS: Array<[RegExp, string]> = [
  [/\b(?:sk|rk|pk)-[A-Za-z0-9_-]{12,}\b/g, 'api-key'],
  [/\bAKIA[0-9A-Z]{16}\b/g, 'aws-access-key'],
  [/\bgh[pousr]_[A-Za-z0-9]{20,}\b/g, 'github-token'],
  [/\b(?:Bearer\s+)?eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b/g, 'jwt'],
  [/(?:password|passwd|token|secret|api[_-]?key)\s*[:=]\s*['\"]?[^\s'\"]{8,}/gi, 'credential']
];

export function sha256(value: string | Uint8Array): string {
  return `sha256:${createHash('sha256').update(value).digest('hex')}`;
}

export function createId(prefix: string): string {
  return `${prefix}_${randomUUID().replaceAll('-', '').slice(0, 24)}`;
}

export function redactSecrets(value: string): string {
  let output = value;
  for (const [pattern, kind] of SECRET_PATTERNS) {
    pattern.lastIndex = 0;
    output = output.replace(pattern, `[REDACTED:${kind}]`);
  }
  return output;
}

export function maskEvidence(value: string, maxLength = 180): string {
  const redacted = redactSecrets(value).replaceAll(/\s+/g, ' ').trim();
  return redacted.length > maxLength ? `${redacted.slice(0, maxLength - 1)}…` : redacted;
}

export const severityRank: Record<Severity, number> = {
  info: 0,
  low: 1,
  medium: 2,
  high: 3,
  critical: 4
};

export function maxSeverity(findings: Finding[]): Severity {
  return findings.reduce<Severity>((max, item) =>
    severityRank[item.severity] > severityRank[max] ? item.severity : max, 'info');
}

export function normalizePath(value: string): string {
  return value.replaceAll('\\', '/');
}

export function safeJson(value: unknown): string {
  return JSON.stringify(value, (_key, item) =>
    typeof item === 'string' ? redactSecrets(item) : item, 2);
}

export function calculateOverallRisk(risk: RiskDimensions): number {
  const weighted = risk.permission * 0.2 + risk.execution * 0.2 + risk.exfiltration * 0.2 +
    risk.secret * 0.15 + risk.supplyChain * 0.1 + risk.memoryPoison * 0.15;
  return Math.round(weighted * 10) / 10;
}
