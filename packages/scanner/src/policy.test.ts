import { resolve } from 'node:path';
import { describe, expect, it } from 'vitest';
import { evaluatePolicy, scanTarget, simulatePolicy, validatePolicy, type PolicyFile } from './index.js';

const policyV2: PolicyFile = {
  version: 2,
  id: 'sensitive-network-policy',
  rules: [
    {
      id: 'block-high-network-risk',
      when: {
        all: [
          { field: 'finding.severity', operator: 'gte', value: 'high' },
          { field: 'permission.resource', operator: 'eq', value: 'network' },
          { not: { field: 'permission.scope', operator: 'eq', value: 'trusted.example.com' } }
        ]
      },
      action: 'block'
    },
    {
      id: 'review-execution-or-broad-files',
      when: {
        any: [
          { field: 'permission.name', operator: 'eq', value: 'process.execute' },
          { field: 'permission.scope', operator: 'eq', value: 'broad' }
        ]
      },
      action: 'require_review'
    }
  ]
};

describe('policy engine v2', () => {
  it('evaluates typed all/any/not expressions with deterministic traces', async () => {
    const report = await scanTarget(resolve('fixtures/vulnerable/exfiltration'));
    const decision = evaluatePolicy(report, policyV2);
    expect(decision.action).toBe('block');
    expect(decision.matchedRules).toEqual(['block-high-network-risk']);
    expect(decision.trace).toHaveLength(2);
    expect(decision.trace[0]).toEqual(expect.objectContaining({ ruleId: 'block-high-network-risk', matched: true }));
    expect(decision.trace[0]?.expression.children).toHaveLength(3);
    expect(decision.trace[1]).toEqual(expect.objectContaining({ ruleId: 'review-execution-or-broad-files', matched: false }));
  });

  it('simulates policy outcomes across multiple reports', async () => {
    const vulnerable = await scanTarget(resolve('fixtures/vulnerable/exfiltration'));
    const safe = await scanTarget(resolve('fixtures/safe/basic-skill'));
    const simulation = simulatePolicy([vulnerable, safe], policyV2);
    expect(simulation.reports).toBe(2);
    expect(simulation.distribution.block).toBe(1);
    expect(simulation.distribution.allow).toBe(1);
  });

  it('remains backward compatible with validated version-1 policies', async () => {
    const report = await scanTarget(resolve('fixtures/vulnerable/exfiltration'));
    const legacy: PolicyFile = { version: 1, rules: [{ id: 'legacy-secret', when: { secret_access: true }, action: 'require_review' }] };
    const decision = evaluatePolicy(report, legacy);
    expect(decision.action).toBe('require_review');
    expect(decision.trace[0]?.expression.kind).toBe('legacy');
  });

  it('rejects unsupported fields, duplicate IDs, and risky regex expressions', () => {
    expect(() => validatePolicy({ version: 2, rules: [{ id: 'bad-field', when: { field: 'runtime.raw', operator: 'eq', value: true }, action: 'block' }] })).toThrow('unsupported');
    expect(() => validatePolicy({ version: 2, rules: [
      { id: 'duplicate', when: { field: 'scan.status', operator: 'eq', value: 'completed' }, action: 'allow' },
      { id: 'duplicate', when: { field: 'scan.status', operator: 'eq', value: 'partial' }, action: 'warn' }
    ] })).toThrow('Duplicate');
    expect(() => validatePolicy({ version: 2, rules: [{ id: 'unsafe-regex', when: { field: 'finding.ruleId', operator: 'matches', value: '(a+)+$' }, action: 'block' }] })).toThrow('unsafe regular expression');
  });
});
