import { useEffect, useMemo, useState, type ReactNode } from 'react';

type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info';
interface Finding { id: string; ruleId: string; title: string; description: string; severity: Severity; category: string; confidence: string; remediation: string; status: string; evidence: Array<{ path: string; line?: number; excerpt: string }> }
interface Permission { resource: string; action: string; scope: string; risk: Severity; evidence: { path: string; line?: number } }
interface Report {
  scanId: string; target: string; status: string; filesScanned: number; completedAt: string; overallRisk: number;
  findings: Finding[]; permissions: Permission[]; risk: Record<string, number>;
}

const icons: Record<string, ReactNode> = {
  shield: <><path d="M12 3 5 6v5c0 4.7 2.9 8.1 7 10 4.1-1.9 7-5.3 7-10V6l-7-3Z"/><path d="m9 12 2 2 4-5"/></>,
  grid: <><rect x="4" y="4" width="6" height="6" rx="1"/><rect x="14" y="4" width="6" height="6" rx="1"/><rect x="4" y="14" width="6" height="6" rx="1"/><rect x="14" y="14" width="6" height="6" rx="1"/></>,
  scan: <><path d="M8 4H5a1 1 0 0 0-1 1v3M16 4h3a1 1 0 0 1 1 1v3M8 20H5a1 1 0 0 1-1-1v-3M16 20h3a1 1 0 0 0 1-1v-3"/><circle cx="12" cy="12" r="3"/></>,
  brain: <><path d="M9.5 4.5A3 3 0 0 0 5 7a3 3 0 0 0 0 5 3.5 3.5 0 0 0 4.5 5.3M14.5 4.5A3 3 0 0 1 19 7a3 3 0 0 1 0 5 3.5 3.5 0 0 1-4.5 5.3M12 3v18M8 9h4M12 15h4"/></>,
  trace: <><circle cx="5" cy="6" r="2"/><circle cx="19" cy="12" r="2"/><circle cx="7" cy="19" r="2"/><path d="M7 7.5 17 11M17.5 13.5 8.5 18"/></>,
  policy: <><path d="M6 3h9l3 3v15H6z"/><path d="M14 3v4h4M9 12h6M9 16h4"/></>,
  alert: <><path d="M12 3 2.8 19h18.4z"/><path d="M12 9v4M12 17h.01"/></>,
  check: <path d="m5 12 4 4L19 6"/>,
  arrow: <path d="m9 18 6-6-6-6"/>
};
function Icon({ name, size = 18 }: { name: string; size?: number }) { return <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">{icons[name]}</svg>; }

const nav: Array<[string, string]> = [['grid','Overview'], ['scan','Findings'], ['brain','Memory'], ['trace','Runtime traces'], ['policy','Policies']];
const severityOrder: Severity[] = ['critical', 'high', 'medium', 'low', 'info'];
const apiUrl = (import.meta.env.VITE_API_URL ?? 'http://127.0.0.1:4141').replace(/\/$/, '');

export function App() {
  const [active, setActive] = useState('Overview');
  const [target, setTarget] = useState('.');
  const [report, setReport] = useState<Report | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [online, setOnline] = useState(false);

  useEffect(() => { fetch(`${apiUrl}/health`).then((response) => setOnline(response.ok)).catch(() => setOnline(false)); }, []);
  const counts = useMemo(() => Object.fromEntries(severityOrder.map((severity) => [severity, report?.findings.filter((item) => item.severity === severity && item.status === 'open').length ?? 0])), [report]);

  async function scan() {
    setLoading(true); setError('');
    try {
      const response = await fetch(`${apiUrl}/v1/scans`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ target }) });
      const data = await response.json();
      if (!response.ok) throw new Error(data.error?.message ?? 'Scan failed');
      setReport(data); setActive('Overview'); setOnline(true);
    } catch (scanError) { setError(scanError instanceof Error ? scanError.message : String(scanError)); }
    finally { setLoading(false); }
  }

  return <div className="shell">
    <aside>
      <a className="brand" href="#top" aria-label="AgentShield home"><span className="brandmark"><Icon name="shield" size={21}/></span><span>Agent<span>Shield</span></span></a>
      <nav aria-label="Primary navigation">
        <div className="navlabel">Control plane</div>
        {nav.map(([icon,label]) => <button key={label} className={active === label ? 'active' : ''} onClick={() => setActive(label)}><Icon name={icon}/><span>{label}</span>{label === 'Findings' && report && <b>{report.findings.length}</b>}</button>)}
      </nav>
      <div className="privacy"><Icon name="shield"/><div><strong>Local-only mode</strong><span>Raw content stays on this machine.</span></div></div>
      <div className="operator"><span>AS</span><div><strong>Local operator</strong><small>Organization admin</small></div><i>•••</i></div>
    </aside>

    <main id="top">
      <header className="topbar"><div><div className="crumb">Workspace <span>/</span> Local project</div><h1>{active}</h1></div><div className={`service ${online ? 'online' : ''}`}><i></i>{online ? 'API connected' : 'API offline'}</div></header>
      <section className="scanbar" aria-label="Start a scan"><div className="target"><span>Target</span><input aria-label="Scan target path" value={target} onChange={(event) => setTarget(event.target.value)} onKeyDown={(event) => event.key === 'Enter' && scan()} /></div><button className="primary" onClick={scan} disabled={loading || !target.trim()}><Icon name="scan"/>{loading ? 'Scanning…' : 'Run local scan'}</button></section>
      {error && <div className="error" role="alert"><Icon name="alert"/><span>{error}. Start the API with <code>pnpm dev:api</code>.</span></div>}

      {active === 'Overview' && <Overview report={report} counts={counts} onViewFindings={() => setActive('Findings')} />}
      {active === 'Findings' && <Findings report={report} />}
      {active === 'Memory' && <Empty icon="brain" title="Memory intelligence is CLI-enabled" body="Run agentshield memory audit against JSON, JSONL, Markdown, or SQLite. The API endpoint /v1/memory-audits can feed this view in your integration." />}
      {active === 'Runtime traces' && <Empty icon="trace" title="No trace selected" body="Ingest sanitized events through /v1/runtime/events, then inspect the source-to-action evidence graph by trace ID." />}
      {active === 'Policies' && <Empty icon="policy" title="Policy-as-code is active" body="Evaluate versioned YAML policies from the CLI or POST a canonical report and policy to /v1/policies/evaluate." />}
    </main>
  </div>;
}

function Overview({ report, counts, onViewFindings }: { report: Report | null; counts: Record<string, number>; onViewFindings: () => void }) {
  if (!report) return <Empty icon="shield" title="Your local security control plane is ready" body="Choose a file or directory above. AgentShield will inspect it without executing target code and will keep the evidence on this machine." />;
  const dimensions = Object.entries(report.risk);
  return <>
    <section className="hero-grid">
      <article className="risk-card panel"><div><p className="overline">Composite risk</p><div className={`risk-number ${report.overallRisk >= 70 ? 'danger' : ''}`}>{report.overallRisk}<small>/100</small></div><p className="secondary">Six independent dimensions. Critical deterministic findings override the weighted score.</p></div><div className="risk-ring" style={{'--risk': `${report.overallRisk * 3.6}deg`} as React.CSSProperties}><span>{report.overallRisk >= 70 ? 'Review' : 'Stable'}</span></div></article>
      <article className="panel status-card"><div className="panel-title"><span><Icon name="scan"/>Latest scan</span><b className={`status ${report.status}`}>{report.status}</b></div><h2>{compactPath(report.target)}</h2><p className="secondary">{report.filesScanned} files · {new Date(report.completedAt).toLocaleString()}</p><button className="link" onClick={onViewFindings}>Open evidence <Icon name="arrow" size={15}/></button></article>
      <article className="panel finding-total"><div className="panel-title"><span><Icon name="alert"/>Open findings</span></div><strong>{report.findings.length}</strong><div className="severity-row">{severityOrder.slice(0,4).map((severity) => <span key={severity} className={severity}><i></i>{counts[severity]} {severity}</span>)}</div></article>
    </section>
    <section className="content-grid">
      <article className="panel dimensions"><div className="section-head"><div><p className="overline">Risk surface</p><h2>Independent dimensions</h2></div><span className="secondary">Evidence-first, not opaque</span></div>{dimensions.map(([name,value]) => <div className="dimension" key={name}><span>{displayName(name)}</span><div><i style={{width:`${value}%`}}></i></div><b>{value}</b></div>)}</article>
      <article className="panel permissions"><div className="section-head"><div><p className="overline">Capability map</p><h2>Observed permissions</h2></div><b>{report.permissions.length}</b></div>{report.permissions.slice(0,6).map((permission, index) => <div className="permission" key={`${permission.resource}-${permission.action}-${index}`}><span className={`permission-icon ${permission.risk}`}><Icon name={permission.resource === 'network' ? 'trace' : permission.resource === 'process' ? 'scan' : 'policy'} size={16}/></span><div><strong>{permission.resource}.{permission.action}</strong><small>{permission.scope} · {compactPath(permission.evidence.path)}</small></div><span className={`badge ${permission.risk}`}>{permission.risk}</span></div>)}{!report.permissions.length && <p className="secondary">No capabilities inferred.</p>}</article>
    </section>
  </>;
}

function Findings({ report }: { report: Report | null }) {
  const [filter, setFilter] = useState<'all' | Severity>('all');
  if (!report) return <Empty icon="scan" title="No evidence yet" body="Run a local scan first to triage deterministic findings." />;
  const list = report.findings.filter((item) => filter === 'all' || item.severity === filter);
  return <section className="findings-view"><div className="filterbar"><span>Filter by severity</span>{(['all',...severityOrder] as const).map((item) => <button key={item} className={filter === item ? 'selected' : ''} onClick={() => setFilter(item)}>{item}</button>)}</div>{list.map((finding) => <article className="panel finding" key={finding.id}><div className="finding-top"><span className={`badge ${finding.severity}`}>{finding.severity}</span><code>{finding.ruleId}</code><span>{finding.category}</span><span>{finding.confidence} confidence</span></div><h2>{finding.title}</h2><p>{finding.description}</p><div className="evidence"><div><strong>{compactPath(finding.evidence[0]?.path ?? '')}{finding.evidence[0]?.line ? `:${finding.evidence[0].line}` : ''}</strong><code>{finding.evidence[0]?.excerpt}</code></div></div><details><summary>Recommended remediation</summary><p>{finding.remediation}</p></details></article>)}{!list.length && <Empty icon="check" title="No matching findings" body="No open evidence is present for this filter." />}</section>;
}

function Empty({ icon, title, body }: { icon: string; title: string; body: string }) { return <section className="empty panel"><span><Icon name={icon} size={29}/></span><p className="overline">AgentShield</p><h2>{title}</h2><p>{body}</p></section>; }
function displayName(value: string) { return value.replace(/([A-Z])/g, ' $1').replace(/^./, (text) => text.toUpperCase()); }
function compactPath(value: string) { const parts = value.replaceAll('\\','/').split('/'); return parts.length > 3 ? `…/${parts.slice(-3).join('/')}` : value; }
