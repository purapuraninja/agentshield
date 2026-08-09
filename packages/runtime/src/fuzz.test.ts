import { describe, expect, it } from 'vitest';
import { runtimeEventSchema } from '@agentshield/core';
import { createRuntimeEvent, type CreateEventInput } from './index.js';

function createRandom(seed: number): () => number {
  let state = seed >>> 0;
  return () => {
    state ^= state << 13; state >>>= 0;
    state ^= state >>> 17;
    state ^= state << 5; state >>>= 0;
    return state / 0x1_0000_0000;
  };
}

const EVENT_TYPES = [
  'agent.run.started', 'source.read', 'model.requested', 'model.responded', 'memory.proposed',
  'memory.written', 'memory.retrieved', 'policy.evaluated', 'approval.requested', 'approval.resolved',
  'tool.requested', 'tool.executed', 'tool.failed', 'memory.quarantined', 'memory.restored',
  'persona.applied', 'agent.run.completed'
] as const;

const HOSTILE = ['\0', '\u200B', '\u202E', '\uFEFF', '\n'.repeat(20), 'x'.repeat(5_000), '${}', '`', '\\'];

function baseInput(random: () => number): CreateEventInput {
  return {
    traceId: `trace_${Math.floor(random() * 1_000)}`,
    parentId: Math.random() > 0.3 ? `event_${Math.floor(random() * 100)}` : undefined,
    causalityIds: Array.from({ length: Math.floor(random() * 5) }, () => `event_${Math.floor(random() * 100)}`),
    type: EVENT_TYPES[Math.floor(random() * EVENT_TYPES.length)]!,
    actor: HOSTILE[Math.floor(random() * HOSTILE.length)]! + 'actor',
    target: Math.random() > 0.3 ? `tool_${Math.floor(random() * 10)}` : undefined,
    payload: Math.random() > 0.5 ? { body: 'secret-content', token: 'sk-test' } : undefined,
    metadata: Math.random() > 0.3 ? {
      source: 'web_document', sensitivity: ['low', 'medium', 'high'][Math.floor(random() * 3)]!,
      content: 'raw memory text', prompt: 'system prompt', note: 'visible metadata'
    } : undefined
  };
}

function assertEventInvariants(input: CreateEventInput, corruptedKey: string | undefined): void {
  let event;
  try {
    event = createRuntimeEvent(input);
  } catch (error) {
    if (corruptedKey) {
      // A corrupted required field is a deterministic Zod validation error, never a crash
      // (TypeError/RangeError). The event type has its own dedicated 'Invalid option' message.
      const message = String(error);
      expect(message).toMatch(/Invalid|expected|too_|required/);
      if (corruptedKey === 'type') expect(message).toContain('Invalid option');
      return;
    }
    throw new Error(
      `createRuntimeEvent threw for input=${JSON.stringify(input).slice(0, 400)}\n` +
      `cause=${error instanceof Error ? error.message : String(error)}`
    );
  }
  const parsed = runtimeEventSchema.safeParse(event);
  expect(parsed.success).toBe(true);
  expect(event.payloadHash).toMatch(/^sha256:/);
  expect(event.eventId).toMatch(/^event_/);
  // Raw payload content must never survive into the sanitized event.
  const serialized = JSON.stringify(event);
  expect(serialized).not.toContain('secret-content');
  expect(serialized).not.toContain('sk-test');
  if (input.metadata && typeof input.metadata === 'object' && 'content' in input.metadata) {
    expect(serialized).not.toContain('raw memory text');
  }
}

describe('runtime event schema fuzzing', () => {
  it('never throws and always sanitizes payloads across mutated inputs', () => {
    const random = createRandom(0x5eed_7001);
    const iterations = 2_000;
    for (let iteration = 0; iteration < iterations; iteration++) {
      const input = baseInput(random);
      const keys = ['traceId', 'type', 'actor', 'metadata'] as const;
      const corruptedKey = Math.random() > 0.8 ? keys[Math.floor(random() * keys.length)] : undefined;
      if (corruptedKey) {
        (input as unknown as Record<string, unknown>)[corruptedKey] =
          random() > 0.5 ? HOSTILE[Math.floor(random() * HOSTILE.length)] : { nested: [1, 'x', null] };
      }
      try {
        assertEventInvariants(input, corruptedKey);
      } catch (error) {
        throw new Error(`Runtime fuzz invariant failed at iteration ${iteration}\n${error instanceof Error ? error.message : String(error)}`);
      }
    }
  });

  it('accepts every event type and keeps forbidden metadata keys hashed', () => {
    for (const type of EVENT_TYPES) {
      const event = createRuntimeEvent({ traceId: 't', type, actor: 'agent', metadata: { content: 'x', token: 'y', safe: 'z' } });
      expect(event.type).toBe(type);
      expect(event.metadata.contentHash).toBeDefined();
      expect(event.metadata.tokenHash).toBeDefined();
      expect(event.metadata.safe).toBe('z');
    }
  });
});
