import { useState } from 'react';
import { Icon } from './App.js';

interface MemoryEvidence { path: string; excerpt: string; redacted?: boolean }
interface MemoryFinding { id: string; ruleId: string; title: string; description: string; severity: string; category: string; remediation: string; status: string; evidence: MemoryEvidence[]; metadata: Record<string, unknown> }
interface MemoryAssessment { memoryId: string; freshness: number; authority: number; integrity: number; corroboration: number; sensitivity: number; poisonRisk: number; suggestedTtlDays?: number }
interface MemoryReport {
  auditId: string; target: string; adapter: string; status: string; completedAt: string; privacyMode: string;
  inventory: { total: number; audited: number; quarantined: number; failed: number; byType: Record<string, number> };
  findings: MemoryFinding[]; assessments: MemoryAssessment[];
}
interface RemediationPlan { planId: string; memoryId: string; externalId: string; action: string; state: string; planned: { actor: string; reason: string }; approved?: { actor: string } }

const apiUrl = (import.meta.env.VITE_API_URL ?? 'http://127.0.0.1:4141').replace(/\/$/, '');
const dimensionNames: Array<[keyof MemoryAssessment, string]> = [
  ['freshness', 'Freshness'], ['authority', 'Authority'], ['integrity', 'Integrity'], ['corroboration', 'Corroboration'], ['sensitivity', 'Sensitivity'], ['poisonRisk', 'Poison risk']
];

export function Memory() {
  const [target, setTarget] = useState('');
  const [report, setReport] = useState<MemoryReport | null>(null);
  const [plans, setPlans] = useState<RemediationPlan[]>([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [message, setMessage] = useState('');

  async function audit() {
    if (!target.trim()) return;
    setLoading(true); setError(''); setMessage('');
    try {
      const response = await fetch(`${apiUrl}/v1/memory-audits`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ target, privacyMode: 'pii-secrets' }) });
      const data = await response.json();
      if (!response.ok) throw new Error(data.error?.message ?? 'Audit failed');
      setReport(data);
      const planResponse = await fetch(`${apiUrl}/v1/memory-audits/${data.auditId}/remediation-plans`);
      if (planResponse.ok) setPlans((await planResponse.json()).data);
    } catch (auditError) { setError(auditError instanceof Error ? auditError.message : String(auditError)); }
    finally { setLoading(false); }
  }

  async function exportBundle() {
    if (!report) return;
    const response = await fetch(`${apiUrl}/v1/memory-audits/${report.auditId}/export?format=bundle`);
    const blob = new Blob([await response.text()], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a'); a.href = url; a.download = `agentshield-memory-${report.auditId}.json`; a.click();
    URL.revokeObjectURL(url);
  }

  async function planQuarantine(finding: MemoryFinding) {
    const memoryId = String(finding.metadata.memoryId ?? finding.metadata.externalId ?? '');
    if (!memoryId || !report) return;
    const response = await fetch(`${apiUrl}/v1/remediation/plan`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ target: report.target, memoryId, action: 'quarantine', actor: 'dashboard', reason: `${finding.ruleId}: ${finding.title}` }) });
    const data = await response.json();
    if (response.ok) setMessage(`Planned quarantine ${data.planId} (state: ${data.state}). Approve and execute via /v1/remediation/approve.`);
    else setError(data.error?.message ?? 'Plan failed');
  }

  if (!report) return <section className="scanbar" aria-label="Memory audit"><div className="target"><span>Memory target</span><input aria-label="Memory target path" placeholder="path/to/memories.jsonl" value={target} onChange={(event) => setTarget(event.target.value)} onKeyDown={(event) => event.key === 'Enter' && audit()} /></div><button className="primary" onClick={audit} disabled={loading || !target.trim()}><Icon name="scan" />{loading ? 'Auditing…' : 'Run memory audit'}</button>{error && <div className="error" role="alert"><Icon name="alert" /><span>{error}</span></div>}</section>;

  const poisonFindings = report.findings.filter((item) => item.category === 'memory' && (item.ruleId === 'AS-ME-010' || item.ruleId === 'AS-ME-012' || item.ruleId === 'AS-ME-013'));
  const conflicts = report.findings.filter((item) => item.ruleId === 'AS-ME-003');

  return <section className="memory-view">
    <header className="memory-head"><div><p className="overline">{report.adapter} adapter · {report.privacyMode}</p><h2>{report.target}</h2><p className="secondary">{report.inventory.audited}/{report.inventory.total} audited · {report.inventory.quarantined} quarantined · {new Date(report.completedAt).toLocaleString()}</p></div><button className="link" onClick={exportBundle}><Icon name="policy" size={15} />Export bundle</button></header>
    {message && <div className="error" role="status"><Icon name="check" /><span>{message}</span></div>}
    {error && <div className="error" role="alert"><Icon name="alert" /><span>{error}</span></div>}
    <section className="content-grid">
      <article className="panel dimensions"><div className="section-head"><p className="overline">Trust dimensions</p><h2>Memory health</h2></div>{dimensionNames.map(([key, label]) => { const value = report.assessments.length ? Math.round(report.assessments.reduce((sum, item) => sum + Number(item[key]), 0) / report.assessments.length) : 0; return <div className="dimension" key={key}><span>{label}</span><div><i style={{ width: `${value}%` }}></i></div><b>{value}</b></div>; })}</article>
      <article className="panel"><div className="section-head"><p className="overline">Poisoning review queue</p><h2>{poisonFindings.length} suspect records</h2></div>{poisonFindings.map((finding) => <div className="permission" key={finding.id}><span className={`badge ${finding.severity}`}>{finding.severity}</span><div><strong>{finding.ruleId}</strong><small>{finding.evidence[0]?.excerpt.slice(0, 80)}</small></div><button className="link" onClick={() => planQuarantine(finding)}>Plan quarantine</button></div>)}{!poisonFindings.length && <p className="secondary">No poisoning indicators detected.</p>}</article>
    </section>
    <article className="panel"><div className="section-head"><p className="overline">Conflict explorer</p><h2>{conflicts.length} conflicting values</h2></div>{conflicts.map((finding) => <div className="finding" key={finding.id}><code>{finding.ruleId}</code><p>{finding.description}</p><code>{finding.evidence[0]?.excerpt}</code></div>)}{!conflicts.length && <p className="secondary">No conflicting memory values detected.</p>}</article>
    <article className="panel"><div className="section-head"><p className="overline">All findings · {report.findings.length}</p><h2>Memory findings</h2></div>{report.findings.map((finding) => <div className="finding" key={finding.id}><div className="finding-top"><span className={`badge ${finding.severity}`}>{finding.severity}</span><code>{finding.ruleId}</code><span>{finding.category}</span></div><h3>{finding.title}</h3><code>{finding.evidence[0]?.excerpt}</code></div>)}{!report.findings.length && <p className="secondary">No memory findings.</p>}</article>
    {plans.length > 0 && <article className="panel"><div className="section-head"><p className="overline">Remediation plans</p><h2>{plans.length} plan(s)</h2></div>{plans.map((plan) => <div className="permission" key={plan.planId}><span className={`badge ${plan.state}`}>{plan.state}</span><div><strong>{plan.action} {plan.externalId}</strong><small>by {plan.planned.actor}: {plan.planned.reason}</small></div></div>)}</article>}
  </section>;
}
