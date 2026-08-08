import { describe, expect, it } from 'vitest';
import { hashToken, loadAuthConfig, validateBearerToken, isPublicPath, RateLimiter, generateToken } from './auth.js';

describe('authentication', () => {
  it('is disabled when no token env is set', () => {
    delete process.env.AGENTSHIELD_API_TOKEN;
    expect(loadAuthConfig().enabled).toBe(false);
  });

  it('enables auth and validates a bearer token timing-safely', () => {
    const token = 'as_test_secret_token_123';
    const config = { enabled: true, tokenHash: hashToken(token) };
    expect(validateBearerToken(`Bearer ${token}`, config)).toBe(true);
    expect(validateBearerToken('Bearer wrong_token', config)).toBe(false);
    expect(validateBearerToken(undefined, config)).toBe(false);
    expect(validateBearerToken('Bearer ', config)).toBe(false);
  });

  it('never authenticates when disabled', () => {
    expect(validateBearerToken('Bearer anything', { enabled: false })).toBe(false);
  });

  it('marks health and errors as public paths', () => {
    expect(isPublicPath('/health')).toBe(true);
    expect(isPublicPath('/v1/errors')).toBe(true);
    expect(isPublicPath('/v1/scans')).toBe(false);
  });

  it('generates a token with a recognizable prefix', () => {
    const token = generateToken();
    expect(token).toMatch(/^as_[a-f0-9]{32}$/);
  });
});

describe('rate limiter', () => {
  it('allows up to max requests per window then blocks', () => {
    const limiter = new RateLimiter({ max: 3, windowMs: 1000 });
    expect(limiter.check('key1').allowed).toBe(true);
    expect(limiter.check('key1').allowed).toBe(true);
    expect(limiter.check('key1').allowed).toBe(true);
    const blocked = limiter.check('key1');
    expect(blocked.allowed).toBe(false);
    expect(blocked.retryAfter).toBeGreaterThan(0);
  });

  it('tracks keys independently', () => {
    const limiter = new RateLimiter({ max: 1, windowMs: 1000 });
    expect(limiter.check('a').allowed).toBe(true);
    expect(limiter.check('b').allowed).toBe(true);
    expect(limiter.check('a').allowed).toBe(false);
  });

  it('resets after the window expires', async () => {
    const limiter = new RateLimiter({ max: 1, windowMs: 50 });
    expect(limiter.check('key').allowed).toBe(true);
    expect(limiter.check('key').allowed).toBe(false);
    await new Promise((resolve) => setTimeout(resolve, 60));
    expect(limiter.check('key').allowed).toBe(true);
  });

  it('sweeps expired buckets', async () => {
    const limiter = new RateLimiter({ max: 10, windowMs: 10 });
    limiter.check('expired');
    await new Promise((resolve) => setTimeout(resolve, 20));
    limiter.sweep();
    // After sweep, a new bucket is created (not reused)
    expect(limiter.check('expired').remaining).toBe(9);
  });
});
