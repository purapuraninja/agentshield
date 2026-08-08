import { VERSION, type Finding, type MemoryAuditReport, type ScanReport, type Severity } from '@agentshield/core';

function escapeHtml(value: string): string {
  return value.replaceAll('&', '&amp;').replaceAll('<', '&lt;').replaceAll('>', '&gt;').replaceAll('"', '&quot;').replaceAll("'", '&#039;');
}

export function renderSarif(report: ScanReport): object {
  const rules = [...new Map(report.findings.map((finding) => [finding.ruleId, finding])).values()];
  return {
    $schema: 'https://json.schemastore.org/sarif-2.1.0.json', version: '2.1.0', runs: [{
      tool: { driver: { name: 'AgentShield', version: report.scannerVersion, informationUri: 'https://github.com/agentshield/agentshield', rules: rules.map((item) => ({
        id: item.ruleId, name: item.title.replaceAll(/[^A-Za-z0-9]+/g, ''), shortDescription: { text: item.title },
        fullDescription: { text: item.description }, help: { text: item.remediation }, properties: { category: item.category, severity: item.severity }
      })) } },
      results: report.findings.filter((item) => item.status !== 'suppressed').map((item) => ({
        ruleId: item.ruleId, level: sarifLevel(item.severity), message: { text: `${item.title}. ${item.description}` },
        locations: item.evidence.map((evidence) => ({ physicalLocation: {
          artifactLocation: { uri: evidence.path }, region: { startLine: evidence.line ?? 1, startColumn: evidence.column ?? 1, snippet: { text: evidence.excerpt } }
        } })), fingerprints: { agentshieldFinding: item.id }, properties: { severity: item.severity, confidence: item.confidence, remediation: item.remediation }
      }))
    }]
  };
}

function sarifLevel(severity: Severity): 'none' | 'note' | 'warning' | 'error' {
  if (severity === 'critical' || severity === 'high') return 'error';
  if (severity === 'medium') return 'warning';
  if (severity === 'low') return 'note';
  return 'none';
}

export function renderAgentBom(report: ScanReport): object {
  return {
    bomFormat: 'CycloneDX', specVersion: '1.6', serialNumber: `urn:uuid:${report.scanId.replace(/^scan_/, '')}`, version: 1,
    metadata: { timestamp: report.completedAt, tools: { components: [{ type: 'application', name: 'AgentShield', version: report.scannerVersion }] },
      properties: [{ name: 'agentshield:target', value: report.target }, { name: 'agentshield:rulepack', value: report.rulepackVersion }] },
    components: report.components.map((component) => ({
      type: component.type === 'script' ? 'file' : 'application', 'bom-ref': component.id, name: component.name,
      version: component.version ?? 'unknown', hashes: [{ alg: 'SHA-256', content: component.hash.replace('sha256:', '') }],
      properties: [{ name: 'agentshield:type', value: component.type }, { name: 'agentshield:source', value: component.source },
        { name: 'agentshield:signature-status', value: component.signatureStatus }]
    })),
    vulnerabilities: report.findings.filter((item) => item.status !== 'suppressed').map((finding) => ({
      id: finding.id, source: { name: 'AgentShield Rulepack', url: `urn:agentshield:rule:${finding.ruleId}` },
      ratings: [{ severity: finding.severity, score: severityScore(finding.severity), method: 'other' }],
      description: finding.description, recommendation: finding.remediation,
      affects: [{ ref: report.components.find((item) => item.source === finding.evidence[0]?.path)?.id ?? report.scanId }]
    }))
  };
}

function severityScore(value: Severity): number {
  return ({ info: 0, low: 2.5, medium: 5, high: 8, critical: 10 })[value];
}

const style = `
:root{color-scheme:dark;--bg:#07110f;--panel:#0d1b17;--line:#20352e;--text:#eef9f5;--muted:#9ab4aa;--green:#69e2ad;--red:#ff6b6b;--orange:#ffad5a;--yellow:#f5df75;--blue:#77b8ff}
*{box-sizing:border-box}body{margin:0;background:radial-gradient(circle at 15% -10%,#12392b 0,transparent 36%),var(--bg);color:var(--text);font:14px/1.55 Inter,ui-sans-serif,system-ui,sans-serif}
main{width:min(1180px,calc(100% - 32px));margin:0 auto;padding:44px 0 80px}header{display:flex;justify-content:space-between;gap:24px;align-items:end;margin-bottom:32px}.eyebrow{color:var(--green);font:700 12px/1.2 ui-monospace,monospace;letter-spacing:.14em;text-transform:uppercase}h1{font-size:42px;line-height:1;margin:10px 0 8px;letter-spacing:-.04em}.muted{color:var(--muted)}.score{font-size:54px;font-weight:750;letter-spacing:-.06em}.score small{font-size:14px;color:var(--muted);letter-spacing:0}.grid{display:grid;grid-template-columns:repeat(6,1fr);gap:12px;margin:22px 0}.card{background:linear-gradient(145deg,rgba(19,38,32,.93),rgba(10,24,20,.96));border:1px solid var(--line);border-radius:14px;padding:18px}.metric strong{display:block;font-size:26px;margin-top:8px}.bar{height:6px;background:#172a24;border-radius:99px;overflow:hidden;margin-top:12px}.bar i{display:block;height:100%;background:var(--green)}.summary{display:flex;gap:8px;flex-wrap:wrap;margin:20px 0}.pill{padding:6px 10px;border-radius:99px;background:#13251f;border:1px solid var(--line)}.finding{margin:12px 0}.finding-head{display:flex;justify-content:space-between;gap:12px;align-items:flex-start}.finding h3{margin:0 0 5px;font-size:16px}.sev{font:700 11px/1 ui-monospace,monospace;text-transform:uppercase;padding:6px 8px;border-radius:6px}.critical,.high{color:#ffdada;background:#4a1e22}.medium{color:#ffe2b7;background:#3e2c18}.low{color:#fff5b8;background:#38331a}.info{color:#d9eaff;background:#18324a}code{display:block;white-space:pre-wrap;word-break:break-word;background:#06100d;border:1px solid #1a2d27;border-radius:8px;padding:10px;margin:12px 0;color:#bfe5d5}.path{font:12px ui-monospace,monospace;color:var(--green)}details summary{cursor:pointer;color:var(--green)}footer{margin-top:40px;color:var(--muted);font-size:12px}@media(max-width:800px){.grid{grid-template-columns:repeat(2,1fr)}header{align-items:start;flex-direction:column}h1{font-size:34px}}
`;

function findingHtml(finding: Finding): string {
  const evidence = finding.evidence.map((item) => `<div><span class="path">${escapeHtml(item.path)}${item.line ? `:${item.line}` : ''}</span><code>${escapeHtml(item.excerpt)}</code></div>`).join('');
  return `<article class="card finding"><div class="finding-head"><div><h3>${escapeHtml(finding.title)}</h3><span class="muted">${escapeHtml(finding.ruleId)} · ${escapeHtml(finding.category)} · ${escapeHtml(finding.confidence)} confidence</span></div><span class="sev ${finding.severity}">${finding.severity}</span></div><p>${escapeHtml(finding.description)}</p>${evidence}<details><summary>Remediation</summary><p>${escapeHtml(finding.remediation)}</p></details></article>`;
}

export function renderHtml(report: ScanReport): string {
  const counts = Object.fromEntries(['critical', 'high', 'medium', 'low', 'info'].map((severity) => [severity, report.findings.filter((item) => item.severity === severity && item.status === 'open').length]));
  const dimensions = Object.entries(report.risk).map(([name, value]) => `<div class="card metric"><span class="muted">${escapeHtml(name)}</span><strong>${value}</strong><div class="bar"><i style="width:${value}%"></i></div></div>`).join('');
  return `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>AgentShield report</title><style>${style}</style></head><body><main><header><div><div class="eyebrow">AgentShield / static scan</div><h1>Security evidence report</h1><div class="muted">${escapeHtml(report.target)} · ${escapeHtml(report.completedAt)}</div></div><div class="score">${report.overallRisk}<small> / 100 risk</small></div></header><div class="summary"><span class="pill">${report.filesScanned} files</span><span class="pill">${counts.critical} critical</span><span class="pill">${counts.high} high</span><span class="pill">${counts.medium} medium</span><span class="pill">${report.permissions.length} permissions</span><span class="pill">${escapeHtml(report.status)}</span></div><section class="grid">${dimensions}</section><section><div class="eyebrow">Findings / ${report.findings.length}</div>${report.findings.map(findingHtml).join('') || '<div class="card"><h3>No findings</h3><p class="muted">No configured deterministic rule matched this target.</p></div>'}</section><footer>Generated locally by AgentShield ${escapeHtml(report.scannerVersion)} · Rulepack ${escapeHtml(report.rulepackVersion)} · Raw target content was not uploaded.</footer></main></body></html>`;
}

export function renderMemoryHtml(report: MemoryAuditReport): string {
  const average = (key: 'freshness' | 'authority' | 'integrity' | 'corroboration' | 'sensitivity' | 'poisonRisk') => report.assessments.length ? Math.round(report.assessments.reduce((sum, item) => sum + item[key], 0) / report.assessments.length) : 0;
  const values = { freshness: average('freshness'), authority: average('authority'), integrity: average('integrity'), corroboration: average('corroboration'), sensitivity: average('sensitivity'), poisonRisk: average('poisonRisk') };
  const dimensions = Object.entries(values).map(([name, value]) => `<div class="card metric"><span class="muted">${escapeHtml(name)}</span><strong>${value}</strong><div class="bar"><i style="width:${value}%"></i></div></div>`).join('');
  return `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>AgentShield memory audit</title><style>${style}</style></head><body><main><header><div><div class="eyebrow">AgentShield / memory audit</div><h1>Memory health report</h1><div class="muted">${escapeHtml(report.target)} · ${escapeHtml(report.completedAt)}</div></div><div class="score">${report.inventory.audited}<small> records audited</small></div></header><div class="summary"><span class="pill">${report.inventory.total} total</span><span class="pill">${report.inventory.quarantined} quarantined</span><span class="pill">${report.findings.length} findings</span><span class="pill">${escapeHtml(report.privacyMode)}</span></div><section class="grid">${dimensions}</section><section><div class="eyebrow">Findings / ${report.findings.length}</div>${report.findings.map(findingHtml).join('') || '<div class="card"><h3>No findings</h3></div>'}</section><footer>Generated locally by AgentShield · Evidence is redacted according to privacy mode ${escapeHtml(report.privacyMode)}.</footer></main></body></html>`;
}

/**
 * SARIF 2.1 representation of a memory audit. Memory evidence carries a source URI rather than a
 * source file line/column, so each result location reports the record source URI and a redacted
 * excerpt. Suppressed findings are omitted, matching the static scan renderer.
 */
export function renderMemorySarif(report: MemoryAuditReport): object {
  const rules = [...new Map(report.findings.map((finding) => [finding.ruleId, finding])).values()];
  return {
    $schema: 'https://json.schemastore.org/sarif-2.1.0.json', version: '2.1.0', runs: [{
      tool: { driver: { name: 'AgentShield Memory Auditor', version: VERSION, informationUri: 'https://github.com/agentshield/agentshield', rules: rules.map((item) => ({
        id: item.ruleId, name: item.title.replaceAll(/[^A-Za-z0-9]+/g, ''), shortDescription: { text: item.title },
        fullDescription: { text: item.description }, help: { text: item.remediation }, properties: { category: item.category, severity: item.severity }
      })) } },
      results: report.findings.filter((item) => item.status !== 'suppressed').map((item) => ({
        ruleId: item.ruleId, level: sarifLevel(item.severity), message: { text: `${item.title}. ${item.description}` },
        locations: item.evidence.map((evidence) => ({ physicalLocation: {
          artifactLocation: { uri: evidence.path }, region: { startLine: evidence.line ?? 1, snippet: { text: evidence.excerpt } }
        } })),
        fingerprints: { agentshieldFinding: item.id }, properties: { severity: item.severity, confidence: item.confidence, remediation: item.remediation, memoryId: item.metadata.memoryId }
      }))
    }]
  };
}

/**
 * A self-contained, shareable evidence bundle for a memory audit. It carries the audit metadata,
 * inventory, trust assessments, and redacted findings with a manifest so a reviewer can inspect the
 * evidence without access to the source store. Raw memory content is never included; excerpts are
 * redacted according to the report privacy mode.
 */
export function renderMemoryEvidenceBundle(report: MemoryAuditReport): object {
  return {
    bundleSchemaVersion: '1.0.0',
    generatedAt: new Date().toISOString(),
    tool: { name: 'AgentShield', version: VERSION, component: 'Memory Auditor' },
    audit: {
      auditId: report.auditId, target: report.target, adapter: report.adapter,
      startedAt: report.startedAt, completedAt: report.completedAt, status: report.status,
      privacyMode: report.privacyMode, checkpoint: report.checkpoint
    },
    inventory: report.inventory,
    assessments: report.assessments,
    findings: report.findings.map((finding) => ({
      id: finding.id, ruleId: finding.ruleId, title: finding.title, description: finding.description,
      severity: finding.severity, confidence: finding.confidence, category: finding.category, status: finding.status,
      remediation: finding.remediation, memoryId: finding.metadata.memoryId, externalId: finding.metadata.externalId,
      evidence: finding.evidence.map((evidence) => ({ path: evidence.path, excerpt: evidence.excerpt, redacted: evidence.redacted })),
      metadata: finding.metadata
    })),
    notes: 'Raw memory content is never included. Excerpts are redacted according to the privacy mode shown above.'
  };
}

/**
 * CycloneDX-compatible AgentBOM for a memory audit. The audited memory store is modeled as a single
 * component and each non-suppressed finding becomes a vulnerability affecting it, carrying the
 * memory record id so consumers can correlate back to the source store.
 */
export function renderMemoryAgentBom(report: MemoryAuditReport): object {
  return {
    bomFormat: 'CycloneDX', specVersion: '1.6', serialNumber: `urn:uuid:${report.auditId.replace(/^audit_/, '')}`, version: 1,
    metadata: { timestamp: report.completedAt, tools: { components: [{ type: 'application', name: 'AgentShield Memory Auditor', version: VERSION }] },
      properties: [
        { name: 'agentshield:target', value: report.target }, { name: 'agentshield:adapter', value: report.adapter },
        { name: 'agentshield:privacy-mode', value: report.privacyMode },
        { name: 'agentshield:inventory:total', value: String(report.inventory.total) },
        { name: 'agentshield:inventory:audited', value: String(report.inventory.audited) },
        { name: 'agentshield:inventory:quarantined', value: String(report.inventory.quarantined) }
      ] },
    components: [{ type: 'application', 'bom-ref': report.auditId, name: 'memory-store', properties: [{ name: 'agentshield:adapter', value: report.adapter }, { name: 'agentshield:target', value: report.target }] }],
    vulnerabilities: report.findings.filter((item) => item.status !== 'suppressed').map((finding) => ({
      id: finding.id, source: { name: 'AgentShield Memory Rulepack', url: `urn:agentshield:rule:${finding.ruleId}` },
      ratings: [{ severity: finding.severity, score: severityScore(finding.severity), method: 'other' }],
      description: finding.description, recommendation: finding.remediation, affects: [{ ref: report.auditId }],
      properties: [{ name: 'agentshield:memoryId', value: String(finding.metadata.memoryId ?? 'unknown') }]
    }))
  };
}
