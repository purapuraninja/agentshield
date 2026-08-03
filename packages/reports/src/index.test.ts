import { resolve } from 'node:path';
import { describe, expect, it } from 'vitest';
import { scanTarget } from '@agentshield/scanner';
import { renderAgentBom, renderHtml, renderSarif } from './index.js';

describe('report parity', () => {
  it('renders the same canonical findings across formats', async () => {
    const report = await scanTarget(resolve('fixtures/vulnerable/exfiltration'));
    const sarif = renderSarif(report) as any;
    const bom = renderAgentBom(report) as any;
    const html = renderHtml(report);
    expect(sarif.runs[0].results).toHaveLength(report.findings.length);
    expect(bom.vulnerabilities).toHaveLength(report.findings.length);
    for (const finding of report.findings) {
      expect(html).toContain(finding.ruleId);
      expect(JSON.stringify(sarif)).toContain(finding.ruleId);
    }
    expect(html).not.toContain('example_super_secret_value');
  });
});
