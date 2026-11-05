import { describe, expect, it } from "vitest";
import { RedisRateLimiter } from "../src/redis.js";
describe("Redis rate limiter", () => {
  it("uses one atomic script across every abuse key", async () => {
    let call: { keys: string[]; arguments: string[] } | undefined;
    const limiter = new RedisRateLimiter(
      {
        eval: async (_script, options) => {
          call = options;
          return [1, 0];
        },
      },
      { prefix: "test", limit: 3, windowMs: 5000 },
    );
    expect(
      await limiter.consume({
        operation: "request_code",
        keys: ["phone:a", "ip:b"],
        now: new Date(1000),
      }),
    ).toEqual({ allowed: true });
    expect(call?.keys).toEqual([
      "test:request_code:phone:a",
      "test:request_code:ip:b",
    ]);
    expect(call?.arguments.slice(0, 3)).toEqual(["1000", "5000", "3"]);
  });
  it("returns retry timing when Redis rejects the bucket", async () => {
    const limiter = new RedisRateLimiter({ eval: async () => [0, 2500] });
    expect(
      await limiter.consume({
        operation: "verify_code",
        keys: ["phone:a"],
        now: new Date(),
      }),
    ).toEqual({ allowed: false, retryAfterMs: 2500 });
  });
});
