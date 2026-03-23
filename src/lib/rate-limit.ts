import { Ratelimit } from '@upstash/ratelimit';
import { Redis } from '@upstash/redis';

let ratelimit: Ratelimit | null = null;

function getRatelimit(): Ratelimit | null {
  if (ratelimit) return ratelimit;

  const url = process.env.KV_REST_API_URL || process.env.UPSTASH_REDIS_REST_URL;
  const token = process.env.KV_REST_API_TOKEN || process.env.UPSTASH_REDIS_REST_TOKEN;

  if (!url || !token) return null;

  const redis = new Redis({ url, token });

  ratelimit = new Ratelimit({
    redis,
    limiter: Ratelimit.slidingWindow(10, '1 m'), // 10 scans per minute per IP
    analytics: false,
    prefix: 'dw:scan',
  });

  return ratelimit;
}

export interface RateLimitResult {
  allowed: boolean;
  remaining: number;
  resetAt: Date;
}

export async function checkRateLimit(ip: string): Promise<RateLimitResult> {
  const limiter = getRatelimit();

  if (!limiter) {
    // No rate limiter configured, allow all (local dev / no KV)
    return { allowed: true, remaining: 999, resetAt: new Date() };
  }

  const result = await limiter.limit(ip);
  return {
    allowed: result.success,
    remaining: result.remaining,
    resetAt: new Date(result.reset),
  };
}
