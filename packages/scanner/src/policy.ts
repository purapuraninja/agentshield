import { readFile } from 'node:fs/promises';
import YAML from 'yaml';
import { severityRank, type PolicyAction, type PolicyDecision, type ScanReport, type Severity } from '@agentshield/core';

export interface LegacyPolicyWhen {
  minimum_severity?: Severity;
  severity?: Severity;
  rule_id?: string;
  permission?: string;
  secret_access?: boolean;
  network_destination_trust?: 'unknown' | 'trusted';
}

export type PolicyField =
  | 'finding.severity'
  | 'finding.ruleId'
  | 'finding.category'
  | 'finding.status'
  | 'permission.name'
  | 'permission.resource'
  | 'permission.scope'
  | 'risk.overall'
  | 'scan.status';
export type PolicyOperator = 'eq' | 'neq' | 'gte' | 'lte' | 'in' | 'contains' | 'matches' | 'exists';
export interface PolicyPredicate { field: PolicyField; operator: PolicyOperator; value?: unknown }
export type PolicyExpression = PolicyPredicate | { all: PolicyExpression[] } | { any: PolicyExpression[] } | { not: PolicyExpression };

export interface PolicyRule {
  id: string;
  when: LegacyPolicyWhen | PolicyExpression;
  action: PolicyAction;
}

export interface PolicyFile {
  version: 1 | 2;
  id?: string;
  scope?: { organization?: string; project?: string };
  defaults?: { on_critical?: PolicyAction; on_high?: PolicyAction; on_medium?: PolicyAction };
  rules?: PolicyRule[];
  exceptions?: { require_owner?: boolean; expires_after_days?: number };
}

export interface ExpressionTrace {
  kind: 'predicate' | 'all' | 'any' | 'not' | 'legacy';
  matched: boolean;
  field?: string;
  operator?: string;
  expected?: unknown;
  actual?: Array<string | number | boolean>;
  children?: ExpressionTrace[];
}

export interface PolicyRuleTrace {
  ruleId: string;
  action: PolicyAction;
  matched: boolean;
  expression: ExpressionTrace;
}

export interface PolicyEvaluation extends PolicyDecision { trace: PolicyRuleTrace[] }

const actions = new Set<PolicyAction>(['allow', 'warn', 'require_review', 'quarantine', 'block']);
const fields = new Set<PolicyField>([
  'finding.severity', 'finding.ruleId', 'finding.category', 'finding.status', 'permission.name',
  'permission.resource', 'permission.scope', 'risk.overall', 'scan.status'
]);
const operators = new Set<PolicyOperator>(['eq', 'neq', 'gte', 'lte', 'in', 'contains', 'matches', 'exists']);
const actionRank: Record<PolicyAction, number> = { allow: 0, warn: 1, require_review: 2, quarantine: 3, block: 4 };

export async function loadPolicy(path: string): Promise<PolicyFile> {
  const policy = YAML.parse(await readFile(path, 'utf8')) as unknown;
  return validatePolicy(policy);
}

export function validatePolicy(value: unknown): PolicyFile {
  if (!value || typeof value !== 'object') throw new Error('Policy must be an object');
  const policy = value as PolicyFile;
  if (policy.version !== 1 && policy.version !== 2) throw new Error('Only policy versions 1 and 2 are supported');
  const ids = new Set<string>();
  for (const [index, rule] of (policy.rules ?? []).entries()) {
    if (!rule?.id?.trim()) throw new Error(`rules[${index}].id is required`);
    if (ids.has(rule.id)) throw new Error(`Duplicate policy rule id: ${rule.id}`);
    ids.add(rule.id);
    if (!actions.has(rule.action)) throw new Error(`rules[${index}].action is invalid`);
    if (policy.version === 2) validateExpression(rule.when as PolicyExpression, `rules[${index}].when`);
    else validateLegacyWhen(rule.when as LegacyPolicyWhen, `rules[${index}].when`);
  }
  for (const [key, action] of Object.entries(policy.defaults ?? {})) if (!actions.has(action as PolicyAction)) throw new Error(`defaults.${key} is invalid`);
  return policy;
}

function validateExpression(expression: PolicyExpression, path: string): void {
  if (!expression || typeof expression !== 'object') throw new Error(`${path} must be an expression object`);
  if ('all' in expression) {
    if (!Array.isArray(expression.all) || !expression.all.length) throw new Error(`${path}.all must be a non-empty array`);
    expression.all.forEach((child, index) => validateExpression(child, `${path}.all[${index}]`));
    return;
  }
  if ('any' in expression) {
    if (!Array.isArray(expression.any) || !expression.any.length) throw new Error(`${path}.any must be a non-empty array`);
    expression.any.forEach((child, index) => validateExpression(child, `${path}.any[${index}]`));
    return;
  }
  if ('not' in expression) { validateExpression(expression.not, `${path}.not`); return; }
  const predicate = expression as PolicyPredicate;
  if (!fields.has(predicate.field)) throw new Error(`${path}.field is unsupported: ${String(predicate.field)}`);
  if (!operators.has(predicate.operator)) throw new Error(`${path}.operator is unsupported: ${String(predicate.operator)}`);
  if (predicate.operator !== 'exists' && predicate.value === undefined) throw new Error(`${path}.value is required for ${predicate.operator}`);
  if (predicate.operator === 'in' && !Array.isArray(predicate.value)) throw new Error(`${path}.value must be an array for in`);
  if (predicate.operator === 'matches') validatePattern(predicate.value, path);
  if (['gte', 'lte'].includes(predicate.operator) && !['finding.severity', 'risk.overall'].includes(predicate.field)) throw new Error(`${path}.${predicate.operator} supports finding.severity or risk.overall only`);
}

function validatePattern(value: unknown, path: string): void {
  if (typeof value !== 'string' || !value || value.length > 100) throw new Error(`${path}.value must be a regex string of 1-100 characters`);
  if (/(?:\([^)]*[+*][^)]*\))[+*{]|(?:\.\*){2}|\\[1-9]/.test(value)) throw new Error(`${path}.value contains a potentially unsafe regular expression`);
  try { new RegExp(value, 'i'); } catch { throw new Error(`${path}.value is not a valid regular expression`); }
}

function validateLegacyWhen(when: LegacyPolicyWhen, path: string): void {
  if (!when || typeof when !== 'object' || !Object.keys(when).length) throw new Error(`${path} must contain at least one condition`);
  const allowed = new Set(['minimum_severity', 'severity', 'rule_id', 'permission', 'secret_access', 'network_destination_trust']);
  for (const key of Object.keys(when)) if (!allowed.has(key)) throw new Error(`${path}.${key} is unsupported in policy v1`);
}

export function evaluatePolicy(report: ScanReport, inputPolicy: PolicyFile): PolicyEvaluation {
  const policy = validatePolicy(inputPolicy);
  const matches: Array<{ id: string; action: PolicyAction; reason: string }> = [];
  const trace: PolicyRuleTrace[] = [];
  const active = report.findings.filter((item) => item.status === 'open');
  for (const rule of policy.rules ?? []) {
    const expression = policy.version === 2
      ? evaluateExpression(rule.when as PolicyExpression, report)
      : evaluateLegacy(rule.when as LegacyPolicyWhen, report);
    trace.push({ ruleId: rule.id, action: rule.action, matched: expression.matched, expression });
    if (expression.matched) matches.push({ id: rule.id, action: rule.action, reason: `Matched policy rule ${rule.id}` });
  }

  const defaults = policy.defaults ?? {};
  if (active.some((item) => item.severity === 'critical') && defaults.on_critical) matches.push({ id: 'default:critical', action: defaults.on_critical, reason: 'Active critical finding' });
  else if (active.some((item) => item.severity === 'high') && defaults.on_high) matches.push({ id: 'default:high', action: defaults.on_high, reason: 'Active high finding' });
  else if (active.some((item) => item.severity === 'medium') && defaults.on_medium) matches.push({ id: 'default:medium', action: defaults.on_medium, reason: 'Active medium finding' });

  const strongest = matches.reduce<PolicyAction>((current, item) => actionRank[item.action] > actionRank[current] ? item.action : current, 'allow');
  return { action: strongest, reasons: matches.map((item) => item.reason), matchedRules: matches.map((item) => item.id), trace };
}

function evaluateExpression(expression: PolicyExpression, report: ScanReport): ExpressionTrace {
  if ('all' in expression) {
    const children = expression.all.map((child) => evaluateExpression(child, report));
    return { kind: 'all', matched: children.every((child) => child.matched), children };
  }
  if ('any' in expression) {
    const children = expression.any.map((child) => evaluateExpression(child, report));
    return { kind: 'any', matched: children.some((child) => child.matched), children };
  }
  if ('not' in expression) {
    const child = evaluateExpression(expression.not, report);
    return { kind: 'not', matched: !child.matched, children: [child] };
  }
  const predicate = expression as PolicyPredicate;
  const actual = valuesForField(predicate.field, report);
  const matched = matchPredicate(actual, predicate);
  return { kind: 'predicate', matched, field: predicate.field, operator: predicate.operator, expected: predicate.value, actual };
}

function valuesForField(field: PolicyField, report: ScanReport): Array<string | number | boolean> {
  const active = report.findings.filter((item) => item.status === 'open');
  if (field === 'finding.severity') return active.map((item) => item.severity);
  if (field === 'finding.ruleId') return active.map((item) => item.ruleId);
  if (field === 'finding.category') return active.map((item) => item.category);
  if (field === 'finding.status') return report.findings.map((item) => item.status);
  if (field === 'permission.name') return report.permissions.map((item) => `${item.resource}.${item.action}`);
  if (field === 'permission.resource') return report.permissions.map((item) => item.resource);
  if (field === 'permission.scope') return report.permissions.map((item) => item.scope);
  if (field === 'risk.overall') return [report.overallRisk];
  return [report.status];
}

function matchPredicate(actual: Array<string | number | boolean>, predicate: PolicyPredicate): boolean {
  if (predicate.operator === 'exists') return actual.length > 0 === (predicate.value === undefined ? true : Boolean(predicate.value));
  if (!actual.length) return false;
  if (predicate.operator === 'neq') return actual.every((value) => value !== predicate.value);
  if (predicate.operator === 'in') return actual.some((value) => (predicate.value as unknown[]).includes(value));
  if (predicate.operator === 'contains') return actual.some((value) => String(value).includes(String(predicate.value)));
  if (predicate.operator === 'matches') { const regex = new RegExp(String(predicate.value), 'i'); return actual.some((value) => regex.test(String(value))); }
  if (predicate.operator === 'gte' || predicate.operator === 'lte') {
    const expected = comparable(predicate.field, predicate.value);
    return actual.some((value) => predicate.operator === 'gte' ? comparable(predicate.field, value) >= expected : comparable(predicate.field, value) <= expected);
  }
  return actual.some((value) => value === predicate.value);
}

function comparable(field: PolicyField, value: unknown): number {
  if (field === 'finding.severity') {
    if (typeof value !== 'string' || !(value in severityRank)) throw new Error(`Invalid severity comparison value: ${String(value)}`);
    return severityRank[value as Severity];
  }
  const number = Number(value);
  if (!Number.isFinite(number)) throw new Error(`Invalid numeric comparison value: ${String(value)}`);
  return number;
}

function evaluateLegacy(when: LegacyPolicyWhen, report: ScanReport): ExpressionTrace {
  const active = report.findings.filter((item) => item.status === 'open');
  const checks: boolean[] = [];
  if (when.minimum_severity) checks.push(active.some((item) => severityRank[item.severity] >= severityRank[when.minimum_severity!]));
  if (when.severity) checks.push(active.some((item) => item.severity === when.severity));
  if (when.rule_id) checks.push(active.some((item) => item.ruleId === when.rule_id));
  if (when.permission) {
    const [resource, action] = when.permission.split('.');
    checks.push(report.permissions.some((item) => item.resource === resource && (!action || item.action === action)));
  }
  if (when.secret_access) checks.push(report.permissions.some((item) => item.resource === 'environment') || active.some((item) => item.category === 'secrets'));
  if (when.network_destination_trust === 'unknown') checks.push(report.permissions.some((item) => item.resource === 'network' && item.scope === 'unspecified'));
  if (when.network_destination_trust === 'trusted') checks.push(report.permissions.some((item) => item.resource === 'network' && item.scope !== 'unspecified'));
  return { kind: 'legacy', matched: checks.length > 0 && checks.every(Boolean), actual: checks };
}

export function simulatePolicy(reports: ScanReport[], policy: PolicyFile) {
  const results = reports.map((report) => ({ scanId: report.scanId, target: report.target, decision: evaluatePolicy(report, policy) }));
  const distribution: Record<PolicyAction, number> = { allow: 0, warn: 0, require_review: 0, quarantine: 0, block: 0 };
  for (const result of results) distribution[result.decision.action]++;
  return { policyId: policy.id ?? 'unnamed', policyVersion: policy.version, reports: results.length, distribution, results };
}
