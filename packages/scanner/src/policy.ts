import { readFile } from 'node:fs/promises';
import YAML from 'yaml';
import { severityRank, type PolicyAction, type PolicyDecision, type ScanReport, type Severity } from '@agentshield/core';

export interface PolicyRule {
  id: string;
  when: {
    minimum_severity?: Severity;
    severity?: Severity;
    rule_id?: string;
    permission?: string;
    secret_access?: boolean;
    network_destination_trust?: 'unknown' | 'trusted';
  };
  action: PolicyAction;
}

export interface PolicyFile {
  version: 1;
  defaults?: { on_critical?: PolicyAction; on_high?: PolicyAction; on_medium?: PolicyAction };
  rules?: PolicyRule[];
  exceptions?: { require_owner?: boolean; expires_after_days?: number };
}

const actionRank: Record<PolicyAction, number> = { allow: 0, warn: 1, require_review: 2, quarantine: 3, block: 4 };

export async function loadPolicy(path: string): Promise<PolicyFile> {
  const policy = YAML.parse(await readFile(path, 'utf8')) as PolicyFile;
  if (policy.version !== 1) throw new Error('Only policy version 1 is supported');
  return policy;
}

export function evaluatePolicy(report: ScanReport, policy: PolicyFile): PolicyDecision {
  const matches: Array<{ id: string; action: PolicyAction; reason: string }> = [];
  const active = report.findings.filter((item) => item.status === 'open');
  for (const rule of policy.rules ?? []) {
    let matched = true;
    const when = rule.when;
    if (when.minimum_severity) matched &&= active.some((item) => severityRank[item.severity] >= severityRank[when.minimum_severity!]);
    if (when.severity) matched &&= active.some((item) => item.severity === when.severity);
    if (when.rule_id) matched &&= active.some((item) => item.ruleId === when.rule_id);
    if (when.permission) {
      const [resource, action] = when.permission.split('.');
      matched &&= report.permissions.some((item) => item.resource === resource && (!action || item.action === action));
    }
    if (when.secret_access) matched &&= report.permissions.some((item) => item.resource === 'environment') || active.some((item) => item.category === 'secrets');
    if (when.network_destination_trust === 'unknown') matched &&= report.permissions.some((item) => item.resource === 'network' && item.scope === 'unspecified');
    if (matched) matches.push({ id: rule.id, action: rule.action, reason: `Matched policy rule ${rule.id}` });
  }

  const defaults = policy.defaults ?? {};
  if (active.some((item) => item.severity === 'critical') && defaults.on_critical) matches.push({ id: 'default:critical', action: defaults.on_critical, reason: 'Active critical finding' });
  else if (active.some((item) => item.severity === 'high') && defaults.on_high) matches.push({ id: 'default:high', action: defaults.on_high, reason: 'Active high finding' });
  else if (active.some((item) => item.severity === 'medium') && defaults.on_medium) matches.push({ id: 'default:medium', action: defaults.on_medium, reason: 'Active medium finding' });

  const strongest = matches.reduce<PolicyAction>((current, item) => actionRank[item.action] > actionRank[current] ? item.action : current, 'allow');
  return { action: strongest, reasons: matches.map((item) => item.reason), matchedRules: matches.map((item) => item.id) };
}
