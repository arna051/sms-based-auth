import { SignJWT } from "jose";
import { describe, expect, it } from "vitest";
import { createSmsBasedAuth, normalizeIranianPhone } from "../src/index.js";
import {
  MemoryChallengeStore,
  MemoryRateLimiter,
  MemorySessionStore,
} from "../src/memory.js";

const secret = new Uint8Array(32).fill(7);
const scope = "tenant-a";
function fixture(options: { clock?: () => Date; rateLimit?: number } = {}) {
  let code = "";
  const sessions = new MemorySessionStore();
  const events: string[] = [];
  const auth = createSmsBasedAuth({
    config: {
      issuer: "test",
      audience: "test",
      accessTokenKeys: [{ kid: "access-1", algorithm: "HS256", secret }],
      activeAccessTokenKid: "access-1",
      pepper: { kid: "pepper-1", algorithm: "HS256", secret },
    },
    challenges: new MemoryChallengeStore(),
    sessions,
    rateLimiter: new MemoryRateLimiter({ limit: options.rateLimit ?? 50 }),
    sms: {
      async send(_action, variables) {
        code = variables.code;
      },
    },
    smsActions: {
      login: "login",
      phone_verification: "verify",
      account_recovery: "recover",
      sensitive_action: "sensitive",
    },
    identities: {
      async resolve() {
        return { userId: "u1", roles: ["user"], claims: { plan: "pro" } };
      },
    },
    observer: {
      emit(event) {
        events.push(event.type);
      },
    },
    ...(options.clock ? { clock: options.clock } : {}),
  });
  return { auth, sessions, events, getCode: () => code };
}
async function login(f: ReturnType<typeof fixture>) {
  await f.auth.requestCode({ phone: "09123456789", purpose: "login", scope });
  const result = await f.auth.verifyCode({
    phone: "09123456789",
    purpose: "login",
    code: f.getCode(),
    scope,
  });
  if (result.kind !== "session") throw new Error("expected a session");
  return result.tokens;
}

describe("phone normalization", () => {
  it.each(["۰۹۱۲ ۳۴۵ ۶۷۸۹", "٠٩١٢٣٤٥٦٧٨٩", "0912-345-6789", "+989123456789"])(
    "normalizes %s",
    (value) => {
      expect(normalizeIranianPhone(value)).toBe("+989123456789");
    },
  );
  it("rejects invalid numbers", () =>
    expect(() => normalizeIranianPhone("123")).toThrow());
});

describe("challenge security", () => {
  it("allows a challenge only once under concurrency", async () => {
    const f = fixture();
    await f.auth.requestCode({ phone: "09123456789", purpose: "login", scope });
    const attempts = await Promise.allSettled(
      Array.from({ length: 20 }, () =>
        f.auth.verifyCode({
          phone: "09123456789",
          purpose: "login",
          code: f.getCode(),
          scope,
        }),
      ),
    );
    expect(
      attempts.filter((result) => result.status === "fulfilled"),
    ).toHaveLength(1);
  });
  it("enforces resend cooldown", async () => {
    const f = fixture();
    await f.auth.requestCode({ phone: "09123456789", purpose: "login", scope });
    await expect(
      f.auth.requestCode({ phone: "09123456789", purpose: "login", scope }),
    ).rejects.toMatchObject({ code: "CHALLENGE_COOLDOWN" });
  });
  it("requires actor binding for sensitive purposes", async () => {
    const f = fixture();
    await expect(
      f.auth.requestCode({
        phone: "09123456789",
        purpose: "sensitive_action",
        scope,
      }),
    ).rejects.toMatchObject({ code: "INVALID_INPUT" });
    await f.auth.requestCode({
      phone: "09123456789",
      purpose: "sensitive_action",
      scope,
      actor: { userId: "u1", sessionId: "s1" },
    });
    const result = await f.auth.verifyCode({
      phone: "09123456789",
      purpose: "sensitive_action",
      code: f.getCode(),
      scope,
      actor: { userId: "u1", sessionId: "s1" },
    });
    expect(result).toEqual({
      kind: "challenge_verified",
      purpose: "sensitive_action",
      userId: "u1",
    });
  });
  it("rate limits abuse buckets", async () => {
    const f = fixture({ rateLimit: 1 });
    await f.auth.requestCode({ phone: "09123456789", purpose: "login", scope });
    await expect(
      f.auth.requestCode({ phone: "09123456780", purpose: "login", scope }),
    ).rejects.toMatchObject({ code: "RATE_LIMITED" });
  });
});

describe("session and token security", () => {
  it("issues, verifies, and rotates usable refresh tokens", async () => {
    const f = fixture();
    const first = await login(f);
    const context = await f.auth.verifyAccessToken(first.accessToken);
    expect(context.userId).toBe("u1");
    const second = await f.auth.refresh({ refreshToken: first.refreshToken });
    const third = await f.auth.refresh({ refreshToken: second.refreshToken });
    expect(third.refreshToken).not.toBe(second.refreshToken);
  });
  it("detects reuse and revokes the family", async () => {
    const f = fixture();
    const first = await login(f);
    const second = await f.auth.refresh({ refreshToken: first.refreshToken });
    await expect(
      f.auth.refresh({ refreshToken: first.refreshToken }),
    ).rejects.toMatchObject({ code: "TOKEN_REUSE" });
    await expect(
      f.auth.refresh({ refreshToken: second.refreshToken }),
    ).rejects.toMatchObject({ code: "SESSION_REVOKED" });
  });
  it("permits exactly one concurrent refresh", async () => {
    const f = fixture();
    const first = await login(f);
    const results = await Promise.allSettled(
      Array.from({ length: 20 }, () =>
        f.auth.refresh({ refreshToken: first.refreshToken }),
      ),
    );
    expect(
      results.filter((result) => result.status === "fulfilled"),
    ).toHaveLength(1);
  });
  it("does not expose token hashes when listing sessions", async () => {
    const f = fixture();
    const tokens = await login(f);
    const sessions = await f.auth.listSessions({
      userId: "u1",
      currentSessionId: tokens.sessionId,
    });
    expect(sessions[0]).not.toHaveProperty("refreshHash");
    expect(sessions[0]?.current).toBe(true);
  });
  it("prevents cross-user session revocation", async () => {
    const f = fixture();
    const tokens = await login(f);
    await expect(
      f.auth.revokeSession({
        sessionId: tokens.sessionId,
        actorUserId: "attacker",
      }),
    ).rejects.toMatchObject({ code: "FORBIDDEN" });
    expect((await f.auth.verifyAccessToken(tokens.accessToken)).userId).toBe(
      "u1",
    );
  });
  it("rejects JWTs without required standard claims", async () => {
    const f = fixture();
    const token = await new SignJWT({
      sid: "s",
      roles: [],
      permissions: [],
      claims: {},
    })
      .setProtectedHeader({ alg: "HS256", typ: "JWT", kid: "access-1" })
      .setSubject("u1")
      .setIssuer("test")
      .setAudience("test")
      .sign(secret);
    await expect(f.auth.verifyAccessToken(token, false)).rejects.toMatchObject({
      code: "INVALID_TOKEN",
    });
  });
});
