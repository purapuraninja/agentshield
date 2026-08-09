import type { MemoryAdapter } from './index.js';

/**
 * Connector resilience for external memory stores: retry with exponential backoff and a token-bucket
 * rate limiter. The Community adapters (files, SQLite) do not need this, but a connector backed by a
 * remote store or a throttled API should not fail a whole audit on a transient error or hammer the
 * upstream. Both policies are opt-in and off by default.
 */

export interface RetryPolicy {
  /** Total attempts including the first call; default 3. */
  attempts?: number;
  /** Base delay for the first retry; default 100ms. */
  baseDelayMs?: number;
  /** Cap on the exponential backoff delay; default 2000ms. */
  maxDelayMs?: number;
  /** Decide whether an error is retryable; default retries everything. */
  retryable?: (error: unknown) => boolean;
}

export interface RateLimitPolicy {
  /** Sustained requests per second. */
  requestsPerSecond: number;
  /** Token bucket capacity; default equals requestsPerSecond (allows short bursts). */
  burst?: number;
}

export interface ConnectorResilienceOptions {
  retry?: RetryPolicy | false;
  rateLimit?: RateLimitPolicy | false;
}

const sleep = (ms: number): Promise<void> => new Promise((resolve) => setTimeout(resolve, ms));

/**
 * Runs an operation up to `attempts` times with exponential backoff and full jitter. The caller
 * supplies an idempotent operation (reads and paginated fetches qualify; a mutation does not).
 */
export async function retryWithBackoff<T>(operation: () => Promise<T>, policy: RetryPolicy = {}): Promise<T> {
  const attempts = Math.max(1, Math.floor(policy.attempts ?? 3));
  const baseDelayMs = Math.max(0, policy.baseDelayMs ?? 100);
  const maxDelayMs = Math.max(baseDelayMs, policy.maxDelayMs ?? 2_000);
  const retryable = policy.retryable ?? (() => true);
  let lastError: unknown;
  for (let attempt = 1; attempt <= attempts; attempt++) {
    try {
      return await operation();
    } catch (error) {
      lastError = error;
      if (attempt === attempts || !retryable(error)) throw error;
      const exponential = Math.min(maxDelayMs, baseDelayMs * 2 ** (attempt - 1));
      await sleep(exponential * (0.5 + Math.random() * 0.5));
    }
  }
  throw lastError;
}

/** Token-bucket rate limiter: allows bursts up to capacity, then enforces the sustained rate. */
export class TokenBucket {
  private tokens: number;
  private readonly capacity: number;
  private readonly refillPerMs: number;
  private lastRefill: number;

  constructor(requestsPerSecond: number, burst?: number) {
    if (!Number.isFinite(requestsPerSecond) || requestsPerSecond <= 0) throw new Error('requestsPerSecond must be a positive number');
    this.capacity = Math.max(1, Math.ceil(burst ?? requestsPerSecond));
    this.tokens = this.capacity;
    this.refillPerMs = requestsPerSecond / 1000;
    this.lastRefill = Date.now();
  }

  /** Reserves one token, waiting until the bucket refills if it is empty. */
  async take(): Promise<void> {
    this.refill();
    if (this.tokens >= 1) {
      this.tokens -= 1;
      return;
    }
    const waitMs = Math.ceil((1 - this.tokens) / this.refillPerMs);
    await sleep(waitMs);
    this.lastRefill = Date.now();
    this.tokens = Math.min(this.capacity, this.tokens + waitMs * this.refillPerMs) - 1;
  }

  private refill(): void {
    const now = Date.now();
    this.tokens = Math.max(0, Math.min(this.capacity, this.tokens + (now - this.lastRefill) * this.refillPerMs));
    this.lastRefill = now;
  }
}

type AsyncMethod<A extends unknown[], R> = (...args: A) => Promise<R>;

/**
 * Wraps an adapter's read surface (testConnection, inventoryPage, checkpoint) with optional retry and
 * rate limiting. The wrapped adapter keeps the same contract version and identity so cache keys and
 * conformance checks are unaffected. Retries apply only to read methods, which are safe to re-run.
 */
export function withConnectorResilience(adapter: MemoryAdapter, options: ConnectorResilienceOptions): MemoryAdapter {
  const bucket = options.rateLimit ? new TokenBucket(options.rateLimit.requestsPerSecond, options.rateLimit.burst) : undefined;
  const policy = options.retry || undefined;
  const guard = <A extends unknown[], R>(fn: AsyncMethod<A, R>): AsyncMethod<A, R> => async (...args: A): Promise<R> => {
    if (bucket) await bucket.take();
    return policy ? retryWithBackoff(() => fn(...args), policy) : fn(...args);
  };
  return {
    ...adapter,
    testConnection: guard(adapter.testConnection.bind(adapter)),
    inventoryPage: guard(adapter.inventoryPage.bind(adapter)),
    checkpoint: guard(adapter.checkpoint.bind(adapter))
  };
}
