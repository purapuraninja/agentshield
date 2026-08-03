import { describe, expect, it } from 'vitest';
import { calculateOverallRisk, maskEvidence, redactSecrets, sha256 } from './index.js';

describe('core safety utilities', () => {
  it('redacts credential-like values without exposing them', () => {
    const input = 'token=example_super_secret_value and sk-example1234567890';
    const output = redactSecrets(input);
    expect(output).not.toContain('example_super_secret_value');
    expect(output).not.toContain('sk-example1234567890');
    expect(output).toContain('[REDACTED:');
  });

  it('creates stable hashes and bounded evidence', () => {
    expect(sha256('same')).toBe(sha256('same'));
    expect(sha256('same')).not.toBe(sha256('different'));
    expect(maskEvidence('x'.repeat(300))).toHaveLength(180);
  });

  it('calculates the documented weighted risk', () => {
    expect(calculateOverallRisk({ permission: 100, execution: 50, exfiltration: 25, secret: 0, supplyChain: 50, memoryPoison: 0 })).toBe(40);
  });
});
