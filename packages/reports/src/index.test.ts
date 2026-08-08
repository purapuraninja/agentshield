import { resolve } from 'node:path';
import { describe, expect, it } from 'vitest';
import { scanTarget } from '@agentshield/scanner';
import { auditMemory } from '@agentshield/memory';
import { renderAgentBom, renderHtml, renderMemoryAgentBom, renderMemoryEvidenceBundle, renderMemoryHtml, renderMemorySarif, renderSarif } from './index.js';

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

  it('renders memory findings across SARIF, AgentBOM, and HTML', async () => {
    const report = await auditMemory(resolve('fixtures/poisoned-memory/memories.jsonl'));
    const sarif = renderMemorySarif(report) as any;
    const bom = renderMemoryAgentBom(report) as any;
    const html = renderMemoryHtml(report);
    const active = report.findings.filter((item) => item.status !== 'suppressed');
    expect(sarif.runs[0].results).toHaveLength(active.length);
    expect(bom.vulnerabilities).toHaveLength(active.length);
    expect(bom.bomFormat).toBe('CycloneDX');
    expect(bom.metadata.properties.map((p: { name: string }) => p.name)).toContain('agentshield:privacy-mode');
    for (const finding of active) {
      expect(html).toContain(finding.ruleId);
      expect(JSON.stringify(sarif)).toContain(finding.ruleId);
      expect(JSON.stringify(bom)).toContain(finding.ruleId);
    }
  });

  it('redacts secret material in every memory export format', async () => {
    const report = await auditMemory(resolve('fixtures/threats/T-10-redaction/memories.jsonl'));
    const secret = 'sk-test-abcdefghijklmnopqrstuvwxyz';
    const payload = JSON.stringify({
      sarif: renderMemorySarif(report), bom: renderMemoryAgentBom(report), html: renderMemoryHtml(report)
    });
    expect(payload).not.toContain(secret);
  });

  it('exports a self-contained memory evidence bundle with redacted excerpts', async () => {
    const report = await auditMemory(resolve('fixtures/poisoned-memory/memories.jsonl'));
    const bundle = renderMemoryEvidenceBundle(report) as any;
    expect(bundle.bundleSchemaVersion).toBe('1.0.0');
    expect(bundle.tool.name).toBe('AgentShield');
    expect(bundle.audit.auditId).toBe(report.auditId);
    expect(bundle.inventory).toEqual(report.inventory);
    expect(bundle.assessments).toHaveLength(report.assessments.length);
    expect(bundle.findings).toHaveLength(report.findings.length);
    expect(bundle.findings[0].evidence[0].redacted).toBe(true);
    expect(bundle.notes).toMatch(/redacted/i);

    const secretReport = await auditMemory(resolve('fixtures/threats/T-10-redaction/memories.jsonl'));
    expect(JSON.stringify(renderMemoryEvidenceBundle(secretReport))).not.toContain('sk-test-abcdefghijklmnopqrstuvwxyz');
  });
});
