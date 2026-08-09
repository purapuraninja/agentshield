import { useState } from 'react';
import { Icon } from './App.js';
import { apiErrorMessage, apiFetch } from './api.js';

interface PolicyDecision { outcome: string; reasons: string[]; matchedRules: string[]; trace?: unknown }

export function Policies() {
  const [reportJson, setReportJson] = useState('');
  const [policyYaml, setPolicyYaml] = useState('');
  const [decision, setDecision] = useState<PolicyDecision | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');

  async function evaluate() {
    setLoading(true); setError(''); setDecision(null);
    try {
      let policy: unknown;
      try { policy = JSON.parse(policyYaml); } catch { policy = policyYaml; }
      const report = JSON.parse(reportJson);
      const response = await apiFetch('/v1/policies/evaluate', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ report, policy }) });
      const data = await response.json();
      if (!response.ok) throw new Error(await apiErrorMessage(response, 'Evaluation failed'));
      setDecision(data);
    } catch (evaluateError) { setError(evaluateError instanceof Error ? evaluateError.message : String(evaluateError)); }
    finally { setLoading(false); }
  }

  return <section className="memory-view">
    <header className="memory-head"><div><p className="overline">Policy-as-code</p><h2>Evaluate a report against a policy</h2><p className="secondary">Paste a canonical scan report (JSON) and a policy (YAML or JSON).</p></div></header>
    <section className="content-grid">
      <article className="panel"><div className="section-head"><p className="overline">Input</p><h2>Report JSON</h2></div><textarea aria-label="Report JSON" rows={10} value={reportJson} onChange={(event) => setReportJson(event.target.value)} placeholder='{ "scanId": "..." }' /></article>
      <article className="panel"><div className="section-head"><p className="overline">Input</p><h2>Policy</h2></div><textarea aria-label="Policy YAML or JSON" rows={10} value={policyYaml} onChange={(event) => setPolicyYaml(event.target.value)} placeholder="id: default" /></article>
    </section>
    <button className="primary" onClick={evaluate} disabled={loading || !reportJson.trim() || !policyYaml.trim()}><Icon name="policy" />{loading ? 'Evaluating…' : 'Evaluate policy'}</button>
    {error && <div className="error" role="alert"><Icon name="alert" /><span>{error}</span></div>}
    {decision && <article className="panel"><div className="section-head"><p className="overline">Decision</p><h2>Outcome: {decision.outcome}</h2></div>{decision.matchedRules.length > 0 && <p>Matched rules: {decision.matchedRules.join(', ')}</p>}{decision.reasons.map((reason, index) => <p key={index} className="secondary">{reason}</p>)}</article>}
  </section>;
}
