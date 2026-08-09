import { describe, expect, it } from 'vitest';
import {
  retryWithBackoff, TokenBucket, withConnectorResilience,
  type MemoryAdapter, type MemoryInventoryPage
} from './index.js';

describe('retryWithBackoff', () => {
  it('succeeds after transient failures', async () => {
    let calls = 0;
    const result = await retryWithBackoff(async () => {
      calls++;
      if (calls < 3) throw new Error('transient');
      return 'ok';
    }, { baseDelayMs: 1, attempts: 5 });
    expect(result).toBe('ok');
    expect(calls).toBe(3);
  });

  it('rethrows the final error when attempts are exhausted', async () => {
    await expect(retryWithBackoff(async () => { throw new Error('always'); }, { baseDelayMs: 1, attempts: 2 }))
      .rejects.toThrow('always');
  });

  it('does not retry when the error is not retryable', async () => {
    let calls = 0;
    await expect(retryWithBackoff(async () => {
      calls++;
      throw new Error('fatal');
    }, { baseDelayMs: 1, attempts: 5, retryable: (error) => !String(error).includes('fatal') }))
      .rejects.toThrow('fatal');
    expect(calls).toBe(1);
  });

  it('requires at least one attempt', async () => {
    let calls = 0;
    await retryWithBackoff(async () => { calls++; return; }, { attempts: 0 });
    expect(calls).toBe(1);
  });
});

describe('TokenBucket', () => {
  it('allows bursts up to capacity immediately', async () => {
    const bucket = new TokenBucket(10, 5);
    const started = Date.now();
    for (let index = 0; index < 5; index++) await bucket.take();
    expect(Date.now() - started).toBeLessThan(50);
  });

  it('enforces the sustained rate after the burst is consumed', async () => {
    const bucket = new TokenBucket(50, 1); // 1 token per 20ms
    await bucket.take();
    const started = Date.now();
    await bucket.take();
    await bucket.take();
    expect(Date.now() - started).toBeGreaterThanOrEqual(19);
  });

  it('rejects invalid rates', () => {
    expect(() => new TokenBucket(0)).toThrow(/positive/);
    expect(() => new TokenBucket(Number.NaN)).toThrow(/positive/);
  });
});

function stubAdapter(overrides: Partial<MemoryAdapter>): MemoryAdapter {
  return {
    contractVersion: 1,
    id: 'test:adapter',
    target: 'memory://test',
    mode: 'audit',
    capabilities: { readOnlyAudit: true, pagination: true, checkpoints: true, sourceMutation: false, snapshotRestore: false },
    async testConnection() { return { ok: true, adapter: 'test', message: 'ok' }; },
    async inventoryPage(): Promise<MemoryInventoryPage> { return { records: [], errors: [] }; },
    async checkpoint() { return 'sha256:'.padEnd(71, '0'); },
    ...overrides
  };
}

describe('withConnectorResilience', () => {
  it('retries a failing inventoryPage and returns the successful page', async () => {
    let calls = 0;
    const wrapped = withConnectorResilience(stubAdapter({
      async inventoryPage() {
        calls++;
        if (calls < 2) throw new Error('boom');
        return { records: [], errors: [] };
      }
    }), { retry: { attempts: 4, baseDelayMs: 1 } });
    await expect(wrapped.inventoryPage()).resolves.toEqual({ records: [], errors: [] });
    expect(calls).toBe(2);
  });

  it('rate-limits reads through the bucket', async () => {
    const wrapped = withConnectorResilience(stubAdapter({}), { rateLimit: { requestsPerSecond: 100, burst: 1 } });
    await wrapped.checkpoint();
    const started = Date.now();
    await wrapped.checkpoint();
    await wrapped.checkpoint();
    expect(Date.now() - started).toBeGreaterThanOrEqual(9);
  });

  it('preserves identity, mode, and contract version of the wrapped adapter', () => {
    const adapter = stubAdapter({});
    const wrapped = withConnectorResilience(adapter, {});
    expect(wrapped.contractVersion).toBe(1);
    expect(wrapped.id).toBe(adapter.id);
    expect(wrapped.mode).toBe('audit');
    expect(wrapped.capabilities).toEqual(adapter.capabilities);
  });
});
