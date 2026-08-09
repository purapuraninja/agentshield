import { mkdtemp } from 'node:fs/promises';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { describe, expect, it } from 'vitest';
import { listPersonaApplications, registerPersona } from '@agentshield/persona';
import { AgentShieldGate, applyPersonaToModel } from './index.js';
import type { RuntimeEvent } from '@agentshield/core';

async function tempStore(): Promise<string> {
  const directory = await mkdtemp(join(tmpdir(), 'agentshield-runtime-persona-'));
  return join(directory, 'agents.yaml');
}

const personaDefinition = {
  id: 'code-reviewer', name: 'Code Reviewer', author: 'platform-team',
  systemPrompt: 'You are the reviewer. Focus on {{focus}} with {{depth}} analysis.',
  variables: [
    { name: 'focus', required: true },
    { name: 'depth', default: 'deep' }
  ]
};

describe('runtime-persona bridge', () => {
  it('applies a persona, builds a provider request, and records a sanitized persona.applied event', async () => {
    const target = await tempStore();
    await registerPersona(target, personaDefinition, 'platform');
    const events: RuntimeEvent[] = [];
    const gate = new AgentShieldGate({ policies: [], signingKey: 'k', onEvent: (event) => events.push(event) });

    const result = await applyPersonaToModel(target, 'code-reviewer', {
      actor: 'deploy-bot', reason: 'release 1.4', variables: { focus: 'secrets' },
      provider: 'openai', model: 'gpt-4o', maxTokens: 512
    }, { gate, context: { traceId: 't1', actor: 'deploy-bot' } });

    expect(result.applied.prompt).toContain('Focus on secrets');
    expect(result.applied.receipt).toMatch(/^persona1:/);
    expect(result.request.request.messages).toEqual([{ role: 'system', content: result.applied.prompt }]);
    expect(result.request.request.max_tokens).toBe(512);
    expect(result.gateReceipt).toMatch(/^as1:/);
    expect(result.event?.type).toBe('persona.applied');

    // The event carries hash-only evidence; the raw prompt never enters the stream.
    const serialized = JSON.stringify(events);
    expect(serialized).toContain(result.applied.promptHash);
    expect(serialized).not.toContain('check for secrets');
    expect(events).toHaveLength(1);
  });

  it('skips gate recording when no recording is supplied', async () => {
    const target = await tempStore();
    await registerPersona(target, personaDefinition, 'platform');
    const result = await applyPersonaToModel(target, 'code-reviewer', {
      actor: 'bot', variables: { focus: 'auth' }, provider: 'anthropic', model: 'claude-3-5-sonnet'
    });
    expect(result.applied.receipt).toMatch(/^persona1:/);
    expect(result.request.request.system).toContain('auth');
    expect(result.request.request.max_tokens).toBe(1024);
    expect(result.event).toBeUndefined();
    expect(result.gateReceipt).toBeUndefined();
  });

  it('throws a render error for missing required variables before recording anything', async () => {
    const target = await tempStore();
    await registerPersona(target, personaDefinition, 'platform');
    await expect(applyPersonaToModel(target, 'code-reviewer', {
      actor: 'bot', provider: 'openai', model: 'gpt-4o'
    })).rejects.toThrow(/missing required variable/);
  });

  it('propagates provider validation errors without recording an event', async () => {
    const target = await tempStore();
    await registerPersona(target, personaDefinition, 'platform');
    const events: RuntimeEvent[] = [];
    const gate = new AgentShieldGate({ policies: [], onEvent: (event) => events.push(event) });
    await expect(applyPersonaToModel(target, 'code-reviewer', {
      actor: 'bot', variables: { focus: 'auth' }, provider: 'athena' as 'openai', model: 'x'
    }, { gate, context: { traceId: 't2', actor: 'bot' } })).rejects.toThrow(/Unsupported model provider/);
    // Options are validated before applyPersona records a receipt, and nothing reaches the gate.
    expect(events).toHaveLength(0);
    expect(await listPersonaApplications(target)).toHaveLength(0);
  });
});
