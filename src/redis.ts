import type { RateLimiter, RateLimitRequest } from "./types.js";
export interface RedisLike {
  eval(
    script: string,
    options: { keys: string[]; arguments: string[] },
  ): Promise<unknown>;
}
const SCRIPT = `
local now = tonumber(ARGV[1])
local window = tonumber(ARGV[2])
local limit = tonumber(ARGV[3])
for _, key in ipairs(KEYS) do
  redis.call('ZREMRANGEBYSCORE', key, 0, now - window)
  if redis.call('ZCARD', key) >= limit then
    local oldest = redis.call('ZRANGE', key, 0, 0, 'WITHSCORES')
    return {0, math.max(1, tonumber(oldest[2]) + window - now)}
  end
end
local nonce = ARGV[4]
for _, key in ipairs(KEYS) do
  redis.call('ZADD', key, now, tostring(now) .. ':' .. nonce)
  redis.call('PEXPIRE', key, window)
end
return {1, 0}
`;
export interface RedisRateLimiterOptions {
  prefix?: string;
  limit?: number;
  windowMs?: number;
}
export class RedisRateLimiter implements RateLimiter {
  private readonly prefix: string;
  private readonly limit: number;
  private readonly windowMs: number;
  constructor(
    private readonly client: RedisLike,
    options: RedisRateLimiterOptions = {},
  ) {
    this.prefix = options.prefix ?? "sba:rate";
    this.limit = options.limit ?? 5;
    this.windowMs = options.windowMs ?? 60_000;
  }
  async consume(input: RateLimitRequest) {
    const keys = input.keys.map(
      (key) => `${this.prefix}:${input.operation}:${key}`,
    );
    const result = await this.client.eval(SCRIPT, {
      keys,
      arguments: [
        String(input.now.getTime()),
        String(this.windowMs),
        String(this.limit),
        crypto.randomUUID(),
      ],
    });
    if (!Array.isArray(result) || result.length < 2)
      throw new Error("Unexpected Redis rate-limit response");
    return Number(result[0]) === 1
      ? { allowed: true as const }
      : { allowed: false as const, retryAfterMs: Number(result[1]) };
  }
}
