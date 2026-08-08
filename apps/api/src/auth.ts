import { createHash, timingSafeEqual } from 'node:crypto';

export interface AuthConfig {
  tokenHash?: string;
  enabled: boolean;
}

export interface RateLimitConfig {
  max: number;
  windowMs: number;
}

export const DEFAULT_RATE_LIMIT: RateLimitConfig = { max: 100, windowMs: 60_000 };

const PUBLIC_PATHS = new Set(['/health', '/v1/errors']);

export function hashToken(token: string): string {
  return createHash('sha256').update(token).digest('hex');
}

export function loadAuthConfig(): AuthConfig {
  const token = process.env.AGENTSHIELD_API_TOKEN;
  if (!token || !token.trim()) return { enabled: false };
  return { tokenHash: hashToken(token.trim()), enabled: true };
}

export function loadRateLimitConfig(): RateLimitConfig {
  const max = Number(process.env.AGENTSHIELD_RATE_LIMIT_MAX ?? DEFAULT_RATE_LIMIT.max);
  const windowMs = Number(process.env.AGENTSHIELD_RATE_LIMIT_WINDOW_MS ?? DEFAULT_RATE_LIMIT.windowMs);
  return { max: Number.isFinite(max) && max > 0 ? max : DEFAULT_RATE_LIMIT.max, windowMs: Number.isFinite(windowMs) && windowMs > 0 ? windowMs : DEFAULT_RATE_LIMIT.windowMs };
}

export function isPublicPath(path: string): boolean {
  return PUBLIC_PATHS.has(path);
}

/**
 * Timing-safe bearer token validation. Returns true only when the presented token matches the
 * configured hash. A missing or disabled config never authenticates.
 */
export function validateBearerToken(authHeader: string | undefined, config: AuthConfig): boolean {
  if (!config.enabled || !config.tokenHash) return false;
  if (!authHeader || !authHeader.startsWith('Bearer ')) return false;
  const presented = authHeader.slice(7).trim();
  if (!presented) return false;
  const presentedHash = hashToken(presented);
  const a = Buffer.from(presentedHash, 'hex');
  const b = Buffer.from(config.tokenHash, 'hex');
  if (a.length !== b.length) return false;
  return timingSafeEqual(a, b);
}

interface RateBucket { count: number; resetAt: number }

/**
 * Simple in-memory sliding-window rate limiter. Suitable for a single-process testing server; a
 * multi-instance deployment would need a shared store (Redis). Returns the remaining quota and the
 * retry-after seconds when the limit is exceeded.
 */
export class RateLimiter {
  private buckets = new Map<string, RateBucket>();

  constructor(private config: RateLimitConfig) {}

  check(key: string): { allowed: boolean; remaining: number; retryAfter: number } {
    const now = Date.now();
    const bucket = this.buckets.get(key);
    if (!bucket || now >= bucket.resetAt) {
      const resetAt = now + this.config.windowMs;
      this.buckets.set(key, { count: 1, resetAt });
      return { allowed: true, remaining: this.config.max - 1, retryAfter: 0 };
    }
    bucket.count++;
    if (bucket.count > this.config.max) {
      return { allowed: false, remaining: 0, retryAfter: Math.ceil((bucket.resetAt - now) / 1000) };
    }
    return { allowed: true, remaining: this.config.max - bucket.count, retryAfter: 0 };
  }

  /** Remove expired buckets to bound memory. */
  sweep(): void {
    const now = Date.now();
    for (const [key, bucket] of this.buckets) if (now >= bucket.resetAt) this.buckets.delete(key);
  }
}

export function generateToken(): string {
  return `as_${createHash('sha256').update(`${Date.now()}-${Math.random()}`).digest('hex').slice(0, 32)}`;
}
