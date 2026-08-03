import { mkdtemp } from 'node:fs/promises';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { describe, expect, it } from 'vitest';
import { EventStore, buildEvidenceGraph, createRuntimeEvent } from './index.js';

describe('runtime evidence', () => {
  it('sanitizes raw-like metadata and keeps payload hashes', () => {
    const event = createRuntimeEvent({ traceId: 'trace_test', type: 'source.read', actor: 'skill', payload: 'private source', metadata: { rawContent: 'do not persist', url: 'https://example.invalid' } });
    expect(event.metadata).not.toHaveProperty('rawContent');
    expect(event.metadata).toHaveProperty('rawContentHash');
    expect(event.payloadHash).toMatch(/^sha256:/);
  });

  it('ingests idempotently and reports evidence gaps', async () => {
    const directory = await mkdtemp(join(tmpdir(), 'agentshield-events-'));
    const store = new EventStore(join(directory, 'events.jsonl'));
    const event = createRuntimeEvent({ eventId: 'event_one', traceId: 'trace_test', parentId: 'missing', type: 'tool.executed', actor: 'agent', target: 'send_email' });
    expect((await store.ingest(event)).duplicate).toBe(false);
    expect((await store.ingest(event)).duplicate).toBe(true);
    const graph = buildEvidenceGraph(await store.trace('trace_test'));
    expect(graph.nodes).toHaveLength(1);
    expect(graph.gaps).toEqual(expect.arrayContaining([expect.stringContaining('Missing parent'), expect.stringContaining('no agent.run.started'), expect.stringContaining('no recorded policy')]));
  });
});
