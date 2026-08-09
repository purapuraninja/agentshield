import { useState } from 'react';
import { Icon } from './App.js';
import { apiErrorMessage, apiFetch } from './api.js';

interface RuntimeEvent { eventId: string; traceId: string; parentId?: string | null; causalityIds: string[]; type: string; actor: string; target?: string; timestamp: string; metadata: Record<string, unknown> }
interface EvidenceNode { id: string; kind: string; label: string; timestamp?: string }
interface EvidenceEdge { from: string; to: string; relation: string }
interface EvidenceGraph { traceId: string; nodes: EvidenceNode[]; edges: EvidenceEdge[]; gaps: string[] }

export function RuntimeTraces() {
  const [traceId, setTraceId] = useState('');
  const [events, setEvents] = useState<RuntimeEvent[]>([]);
  const [graph, setGraph] = useState<EvidenceGraph | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');

  async function load() {
    if (!traceId.trim()) return;
    setLoading(true); setError('');
    try {
      const eventResponse = await apiFetch(`/v1/traces/${encodeURIComponent(traceId)}`);
      if (!eventResponse.ok) throw new Error(await apiErrorMessage(eventResponse, 'Trace not found'));
      setEvents((await eventResponse.json()).events);
      const graphResponse = await apiFetch(`/v1/evidence-graphs/${encodeURIComponent(traceId)}`);
      setGraph(graphResponse.ok ? await graphResponse.json() : null);
    } catch (loadError) { setError(loadError instanceof Error ? loadError.message : String(loadError)); setEvents([]); setGraph(null); }
    finally { setLoading(false); }
  }

  if (!events.length) return <section className="scanbar" aria-label="Runtime trace"><div className="target"><span>Trace ID</span><input aria-label="Runtime trace ID" placeholder="trace_xxx" value={traceId} onChange={(event) => setTraceId(event.target.value)} onKeyDown={(event) => event.key === 'Enter' && load()} /></div><button className="primary" onClick={load} disabled={loading || !traceId.trim()}><Icon name="trace" />{loading ? 'Loading…' : 'Load trace'}</button>{error && <div className="error" role="alert"><Icon name="alert" /><span>{error}</span></div>}</section>;

  return <section className="memory-view">
    <header className="memory-head"><div><p className="overline">Runtime evidence</p><h2>Trace {traceId}</h2><p className="secondary">{events.length} events · {graph?.edges.length ?? 0} edges</p></div></header>
    {graph && graph.gaps.length > 0 && <div className="error" role="alert"><Icon name="alert" /><span>Evidence gaps: {graph.gaps.join('; ')}</span></div>}
    {graph && graph.gaps.length === 0 && <div className="error" role="status"><Icon name="check" /><span>Evidence chain complete for recorded event types.</span></div>}
    <article className="panel"><div className="section-head"><p className="overline">Events</p><h2>Sanitized runtime events</h2></div>{events.map((event) => <div className="permission" key={event.eventId}><span className={`badge ${event.type === 'persona.applied' ? 'low' : 'medium'}`}>{event.type}</span><div><strong>{event.target ?? event.actor}</strong>{event.type === 'persona.applied' && <small>persona {String(event.metadata.personaId ?? '')} v{String(event.metadata.version ?? '')} · digest {String(event.metadata.digest ?? '').slice(0, 20)}…</small>}<small>{new Date(event.timestamp).toLocaleString()} · {event.eventId}</small></div></div>)}</article>
    {graph && <article className="panel"><div className="section-head"><p className="overline">Evidence graph · {graph.edges.length} edges</p><h2>Causal links</h2></div>{graph.edges.map((edge, index) => <div className="finding" key={index}><code>{edge.from.slice(0, 16)}</code><span> →{edge.relation}→ </span><code>{edge.to.slice(0, 16)}</code></div>)}{!graph.edges.length && <p className="secondary">No causal edges recorded.</p>}</article>}
  </section>;
}
