import { describe, expect, it } from 'vitest';
import { AgentShieldGate, type RuntimePolicy } from './index.js';
import type { RuntimeEvent } from '@agentshield/core';

describe('AgentShield runtime SDK', () => {
  const policies: RuntimePolicy[] = [
    { id: 'block-shell', toolPattern: 'shell', action: 'block' },
    { id: 'review-write', memorySourcePattern: 'web', sensitivity: 'high', action: 'require_review' }
  ];

  it('blocks a high-sensitivity tool call matching a block policy', () => {
    const events: RuntimeEvent[] = [];
    const gate = new AgentShieldGate({ policies, onEvent: (event) => events.push(event) });
    const result = gate.beforeTool({ tool: 'shell_exec', sensitivity: 'high' }, { traceId: 't1', actor: 'agent' });
    expect(result.action).toBe('block');
    expect(result.approved).toBe(false);
    expect(result.receipt).toMatch(/^as1:/);
    expect(events).toHaveLength(1);
    expect(events[0]!.type).toBe('tool.requested');
  });

  it('allows a non-matching tool call and signs a receipt', () => {
    const gate = new AgentShieldGate({ policies, signingKey: 'test-key' });
    const result = gate.beforeTool({ tool: 'search', sensitivity: 'low' }, { traceId: 't2', actor: 'agent' });
    expect(result.action).toBe('allow');
    expect(result.approved).toBe(true);
    expect(result.receipt).toMatch(/^as1:/);
  });

  it('requires review for high-sensitivity memory writes from untrusted sources', () => {
    const gate = new AgentShieldGate({ policies });
    const result = gate.beforeMemoryWrite({ source: 'web_document', sensitivity: 'high' }, { traceId: 't3', actor: 'agent' });
    expect(result.action).toBe('require_review');
  });

  it('fail-closed mode upgrades unmatched high-sensitivity actions to require_review', () => {
    const gate = new AgentShieldGate({ policies, failMode: 'fail-closed' });
    const result = gate.beforeTool({ tool: 'send_email', sensitivity: 'high' }, { traceId: 't4', actor: 'agent' });
    expect(result.action).toBe('require_review');
  });

  it('requestApproval and resolveApproval emit the correct event types', () => {
    const events: RuntimeEvent[] = [];
    const gate = new AgentShieldGate({ policies, onEvent: (event) => events.push(event) });
    const request = gate.requestApproval('delete_record', { traceId: 't5', actor: 'agent' });
    expect(request.type).toBe('approval.requested');
    const resolved = gate.resolveApproval(request.eventId, true, 'human', 't5');
    expect(resolved.type).toBe('approval.resolved');
    expect(resolved.causalityIds).toContain(request.eventId);
  });

  it('records a persona application with hash-only evidence and never the raw prompt', () => {
    const events: RuntimeEvent[] = [];
    const gate = new AgentShieldGate({ policies, signingKey: 'k', onEvent: (event) => events.push(event) });
    const result = gate.recordPersona({
      personaId: 'code-reviewer', version: 2, promptHash: 'sha256:abc123',
      receipt: 'persona1:def456', reason: 'release 1.4'
    }, { traceId: 't7', actor: 'agent' });
    expect(result.event.type).toBe('persona.applied');
    expect(result.event.target).toBe('code-reviewer');
    expect(result.event.metadata.digest).toBe('sha256:abc123');
    expect(result.event.metadata.receipt).toBe('persona1:def456');
    expect(result.receipt).toMatch(/^as1:/);
    expect(result.approved).toBe(true);
    // The raw prompt text never appears anywhere in the event stream.
    expect(JSON.stringify(events)).not.toContain('system prompt');
    expect(JSON.stringify(events)).not.toContain('abc123'.repeat(2));
  });

  it('builds an evidence graph edge for a persona application', () => {
    const events: RuntimeEvent[] = [];
    const gate = new AgentShieldGate({ policies, onEvent: (event) => events.push(event) });
    const start = gate.recordPersona({ personaId: 'reviewer', version: 1, promptHash: 'sha256:aa' }, { traceId: 't8', actor: 'agent' });
    const run = gate.beforeTool({ tool: 'search' }, { traceId: 't8', actor: 'agent', parentId: start.event.eventId });
    const graph = gate.incidentEvidence([start.event, run.event], 't8');
    expect(graph.nodes.some((node) => node.kind === 'persona.applied')).toBe(true);
    expect(graph.edges.some((edge) => edge.relation === 'requested' && edge.from === start.event.eventId)).toBe(true);
  });

  it('exports a sanitized incident evidence graph with a receipt', () => {
    const gate = new AgentShieldGate({ policies, signingKey: 'k' });
    const start = gate.beforeTool({ tool: 'search' }, { traceId: 't6', actor: 'agent' });
    const incident = gate.incidentEvidence([start.event], 't6');
    expect(incident.nodes).toHaveLength(1);
    expect(incident.receipt).toMatch(/^as1:/);
  });
});
