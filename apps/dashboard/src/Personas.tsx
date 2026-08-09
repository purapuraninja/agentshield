import { useCallback, useEffect, useMemo, useState } from 'react';
import { Icon } from './App.js';
import { apiErrorMessage, apiFetch } from './api.js';

interface PersonaVariable { name: string; description?: string; required?: boolean; default?: string }
interface Persona {
  id: string; name: string; version: number; description: string; author: string;
  systemPrompt: string; variables: PersonaVariable[]; contentHash: string; createdAt?: string; updatedAt?: string;
}
interface PersonaApplication {
  applicationId: string; personaId: string; version: number; promptHash: string;
  appliedAt: string; actor: string; reason?: string; receipt: string;
}
interface ModelRequestData {
  applicationId: string; receipt: string; warnings: string[];
  provider: string; model: string; systemPrompt: string; promptHash: string;
  request: Record<string, unknown>; injectedAs: string;
}

const PROVIDERS = ['openai', 'anthropic', 'gemini', 'mistral', 'ollama', 'responses', 'generic'] as const;
type Provider = (typeof PROVIDERS)[number];

const STARTER = `id: support-engineer
name: Support Engineer
description: Friendly, evidence-first support persona.
author: platform-team
systemPrompt: |
  You are the support engineer. Answer in a {{tone}} tone and always cite the
  exact command or path you recommend.
variables:
  - name: tone
    description: Response tone
    default: helpful`;

export function Personas() {
  const [personas, setPersonas] = useState<Persona[]>([]);
  const [applications, setApplications] = useState<PersonaApplication[]>([]);
  const [chain, setChain] = useState<{ valid: boolean; brokenAt?: string }>({ valid: true });
  const [definitionText, setDefinitionText] = useState(STARTER);
  const [registerActor, setRegisterActor] = useState('dashboard');
  const [selectedId, setSelectedId] = useState('');
  const [variableValues, setVariableValues] = useState<Record<string, string>>({});
  const [provider, setProvider] = useState<Provider>('openai');
  const [model, setModel] = useState('gpt-4o');
  const [maxTokens, setMaxTokens] = useState('');
  const [temperature, setTemperature] = useState('');
  const [applyActor, setApplyActor] = useState('dashboard');
  const [result, setResult] = useState<ModelRequestData | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');
  const [message, setMessage] = useState('');

  const refresh = useCallback(async () => {
    try {
      const [personaResponse, appResponse] = await Promise.all([
        apiFetch('/v1/personas'),
        apiFetch('/v1/personas/applications')
      ]);
      if (personaResponse.ok) setPersonas((await personaResponse.json()).data);
      if (appResponse.ok) {
        const data = await appResponse.json();
        setApplications(data.applications);
        setChain(data.chain);
      }
    } catch { /* API offline: keep the last known state */ }
  }, []);

  useEffect(() => { void refresh(); }, [refresh]);

  const selected = useMemo(
    () => personas.find((item) => item.id === selectedId) ?? personas[0],
    [personas, selectedId]
  );

  // Reset variable inputs and the result panel only when the selection changes; keying on the
  // persona id (not the object identity) keeps the rendered result alive across audit refreshes.
  const selectedIdKey = selected?.id ?? '';
  useEffect(() => {
    const persona = personas.find((item) => item.id === selectedIdKey);
    const next: Record<string, string> = {};
    for (const variable of persona?.variables ?? []) {
      if (variable.default !== undefined) next[variable.name] = variable.default;
    }
    setVariableValues(next);
    setResult(null);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [selectedIdKey]);

  async function register() {
    if (!definitionText.trim()) return;
    setBusy(true); setError(''); setMessage('');
    try {
      const response = await apiFetch('/v1/personas', {
        method: 'POST', headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ definitionText, actor: registerActor.trim() || 'dashboard' })
      });
      // Read the body only on success; on failure apiErrorMessage consumes it to surface the
      // server's message (reading json() twice throws and would replace it with the fallback).
      if (!response.ok) throw new Error(await apiErrorMessage(response, 'Registration failed'));
      const data = await response.json();
      setMessage(`Registered ${data.data.id} v${data.data.version} (${data.data.name}).`);
      await refresh();
      setSelectedId(data.data.id);
    } catch (registerError) { setError(registerError instanceof Error ? registerError.message : String(registerError)); }
    finally { setBusy(false); }
  }

  async function buildRequest() {
    if (!selected) return;
    setBusy(true); setError(''); setMessage('');
    try {
      const variables = Object.fromEntries(Object.entries(variableValues).filter(([, value]) => value.trim() !== ''));
      const body: Record<string, unknown> = { actor: applyActor.trim() || 'dashboard', provider, model, variables };
      if (maxTokens.trim()) body.maxTokens = Number(maxTokens);
      if (temperature.trim()) body.temperature = Number(temperature);
      const response = await apiFetch(`/v1/personas/${selected.id}/model-request`, {
        method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(body)
      });
      if (!response.ok) throw new Error(await apiErrorMessage(response, 'Model request failed'));
      const data = await response.json();
      setResult(data.data);
      setMessage(`Applied ${selected.id} v${selected.version}; receipt ${data.data.receipt.slice(0, 18)}…`);
      await refresh();
    } catch (requestError) { setError(requestError instanceof Error ? requestError.message : String(requestError)); }
    finally { setBusy(false); }
  }

  return <section className="memory-view">
    <header className="memory-head">
      <div>
        <p className="overline">Agent personas</p>
        <h2>Assign trusted behavior to your AI models</h2>
        <p className="secondary">Define, validate, apply, and build provider-native model requests. Every application is recorded in a hash-chained audit trail.</p>
      </div>
      <button className="link" onClick={() => void refresh()}><Icon name="scan" size={15} />Refresh</button>
    </header>

    {message && <div className="error" role="status"><Icon name="check" /><span>{message}</span></div>}
    {error && <div className="error" role="alert"><Icon name="alert" /><span>{error}</span></div>}

    <section className="content-grid">
      <article className="panel persona-panel">
        <div className="section-head"><div><p className="overline">Register</p><h2>New persona</h2></div><span className="secondary">YAML or JSON</span></div>
        <div className="field">
          <label htmlFor="persona-definition">Definition</label>
          <textarea id="persona-definition" className="field-textarea" rows={10} value={definitionText}
            onChange={(event) => setDefinitionText(event.target.value)} spellCheck={false} />
        </div>
        <div className="persona-row">
          <div className="field"><label htmlFor="persona-register-actor">Actor</label>
            <input id="persona-register-actor" className="field-input" value={registerActor} onChange={(event) => setRegisterActor(event.target.value)} /></div>
          <button className="primary persona-button" onClick={() => void register()} disabled={busy || !definitionText.trim()}>
            <Icon name="check" />{busy ? 'Registering…' : 'Register persona'}
          </button>
        </div>
      </article>

      <article className="panel persona-panel">
        <div className="section-head"><div><p className="overline">Apply to a model</p><h2>Build model request</h2></div></div>
        {!personas.length
          ? <p className="secondary">No personas registered yet. Register one to build a model request.</p>
          : <>
            <div className="field">
              <label htmlFor="persona-select">Persona</label>
              <select id="persona-select" className="field-input" value={selected?.id ?? ''} onChange={(event) => setSelectedId(event.target.value)}>
                {personas.map((persona) => <option key={persona.id} value={persona.id}>{persona.id} v{persona.version} — {persona.name}</option>)}
              </select>
            </div>
            {selected && <div className="persona-meta">
              <span className="badge info">{selected.author}</span>
              <span className="secondary">{selected.variables.length} variable(s) · {selected.systemPrompt.length} chars</span>
            </div>}
            {selected?.variables.map((variable) => (
              <div className="field" key={variable.name}>
                <label htmlFor={`var-${variable.name}`}>{variable.name}{variable.required ? ' *' : ''}</label>
                <input id={`var-${variable.name}`} className="field-input" placeholder={variable.default ?? (variable.required ? 'required' : 'optional')}
                  value={variableValues[variable.name] ?? ''} onChange={(event) => setVariableValues((current) => ({ ...current, [variable.name]: event.target.value }))} />
              </div>
            ))}
            <div className="persona-row">
              <div className="field"><label htmlFor="persona-provider">Provider</label>
                <select id="persona-provider" className="field-input" value={provider} onChange={(event) => setProvider(event.target.value as Provider)}>
                  {PROVIDERS.map((item) => <option key={item} value={item}>{item}</option>)}
                </select></div>
              <div className="field"><label htmlFor="persona-model">Model</label>
                <input id="persona-model" className="field-input" value={model} onChange={(event) => setModel(event.target.value)} placeholder="gpt-4o" /></div>
            </div>
            <div className="persona-row three">
              <div className="field"><label htmlFor="persona-temperature">Temperature</label>
                <input id="persona-temperature" className="field-input" value={temperature} onChange={(event) => setTemperature(event.target.value)} placeholder="optional" /></div>
              <div className="field"><label htmlFor="persona-max-tokens">Max tokens</label>
                <input id="persona-max-tokens" className="field-input" value={maxTokens} onChange={(event) => setMaxTokens(event.target.value)} placeholder="optional" /></div>
              <div className="field"><label htmlFor="persona-apply-actor">Actor</label>
                <input id="persona-apply-actor" className="field-input" value={applyActor} onChange={(event) => setApplyActor(event.target.value)} /></div>
            </div>
            <button className="primary persona-button" onClick={() => void buildRequest()} disabled={busy || !selected || !model.trim()}>
              <Icon name="arrow" />{busy ? 'Building…' : 'Apply & build request'}
            </button>
          </>}
      </article>
    </section>

    {result && <article className="panel persona-panel">
      <div className="section-head"><div><p className="overline">Provider-native request · {result.provider} · {result.model}</p><h2>Ready to inject</h2></div>
        <span className="badge info">{result.injectedAs}</span></div>
      <p className="secondary" style={{ maxWidth: 'none' }}>Prompt hash {result.promptHash} · application {result.applicationId}</p>
      {result.warnings.length > 0 && <div className="error" role="status"><Icon name="alert" /><span>Advisory: {result.warnings.join('; ')}</span></div>}
      <pre className="json-block">{JSON.stringify(result.request, null, 2)}</pre>
      <p className="secondary" style={{ maxWidth: 'none' }}>Receipt <code>{result.receipt}</code></p>
    </article>}

    <article className="panel persona-panel">
      <div className="section-head"><div><p className="overline">Audit trail</p><h2>Persona applications</h2></div>
        <span className={`badge ${chain.valid ? 'info' : 'critical'}`}>{chain.valid ? 'Chain intact' : `Chain broken at ${chain.brokenAt}`}</span></div>
      {applications.length === 0
        ? <p className="secondary">No applications recorded yet.</p>
        : <table className="app-table">
          <thead><tr><th>Applied</th><th>Persona</th><th>Actor</th><th>Reason</th><th>Receipt</th></tr></thead>
          <tbody>
            {applications.slice().reverse().map((application) => (
              <tr key={application.applicationId}>
                <td>{new Date(application.appliedAt).toLocaleString()}</td>
                <td><code>{application.personaId} v{application.version}</code></td>
                <td>{application.actor}</td>
                <td className="secondary">{application.reason ?? '—'}</td>
                <td><code>{application.receipt.slice(0, 24)}…</code></td>
              </tr>
            ))}
          </tbody>
        </table>}
    </article>
  </section>;
}
