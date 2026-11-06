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
function fixture(
  options: {
    clock?: () => Date;
    rateLimit?: number;
    identityFailures?: number;
  } = {},
) {
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
        if ((options.identityFailures ?? 0) > 0) {
          options.identityFailures!--;
          throw new Error("identity store unavailable");
        }
        return { userId: "u1", roles: ["user"], claims: { plan: "pro" } };
      },
    },
    authorizeScope: async (candidate) => candidate.startsWith("tenant-"),
    observer: {
      emit(event) {
        events.push(event.type);
      },
    },
    ...(options.clock ? { clock: options.clock } : {}),
  });
  return { auth, sessions, events, getCode: () => code };
}
async function login(f: ReturnType<typeof fixture>, loginScope = scope) {
  await f.auth.requestCode({
    phone: "09123456789",
    purpose: "login",
    scope: loginScope,
  });
  const result = await f.auth.verifyCode({
    phone: "09123456789",
    purpose: "login",
    code: f.getCode(),
    scope: loginScope,
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
  it("releases a correct OTP when downstream identity resolution fails", async () => {
    const f = fixture({ identityFailures: 1 });
    await f.auth.requestCode({ phone: "09123456789", purpose: "login", scope });
    const input = {
      phone: "09123456789",
      purpose: "login" as const,
      code: f.getCode(),
      scope,
    };
    await expect(f.auth.verifyCode(input)).rejects.toThrow(
      "identity store unavailable",
    );
    await expect(f.auth.verifyCode(input)).resolves.toMatchObject({
      kind: "session",
    });
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
    const actor = await login(f);
    await expect(
      f.auth.requestCode({
        phone: "09123456789",
        purpose: "sensitive_action",
        scope: "tenant-b",
        actorAccessToken: actor.accessToken,
      }),
    ).rejects.toMatchObject({ code: "FORBIDDEN" });
    await f.auth.requestCode({
      phone: "09123456789",
      purpose: "sensitive_action",
      scope,
      actorAccessToken: actor.accessToken,
    });
    const result = await f.auth.verifyCode({
      phone: "09123456789",
      purpose: "sensitive_action",
      code: f.getCode(),
      scope,
      actorAccessToken: actor.accessToken,
    });
    expect(result).toEqual({
      kind: "challenge_verified",
      purpose: "sensitive_action",
      userId: "u1",
    });
  });
  it("rate limits abuse buckets", async () => {
    const f = fixture({ rateLimit: 1 });
    await f.auth.requestCode({
      phone: "09123456789",
      purpose: "login",
      scope,
      context: { ip: "203.0.113.10" },
    });
    await expect(
      f.auth.requestCode({
        phone: "09123456780",
        purpose: "login",
        scope,
        context: { ip: "203.0.113.10" },
      }),
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
      accessToken: tokens.accessToken,
    });
    expect(sessions[0]).not.toHaveProperty("refreshHash");
    expect(sessions[0]?.current).toBe(true);
  });
  it("isolates session administration by tenant scope", async () => {
    const f = fixture();
    const tenantA = await login(f, "tenant-a");
    const tenantB = await login(f, "tenant-b");
    const contextB = await f.auth.verifyAccessToken(tenantB.accessToken);
    await expect(
      f.auth.revokeSession({
        accessToken: tenantA.accessToken,
        sessionId: contextB.sessionId,
      }),
    ).rejects.toMatchObject({ code: "FORBIDDEN" });
    expect(
      await f.auth.listSessions({ accessToken: tenantA.accessToken }),
    ).toHaveLength(1);
    expect(
      await f.auth.listSessions({ accessToken: tenantB.accessToken }),
    ).toHaveLength(1);
  });
  it("retains old peppers for live OTPs and refreshes, then migrates sessions", async () => {
    const oldSecret = new Uint8Array(32).fill(11);
    const newSecret = new Uint8Array(32).fill(12);
    const challenges = new MemoryChallengeStore();
    const sessions = new MemorySessionStore();
    let code = "";
    const build = (
      pepper: {
        kid: string;
        algorithm: "HS256";
        secret: Uint8Array<ArrayBuffer>;
      },
      verificationPeppers: Array<{
        kid: string;
        algorithm: "HS256";
        secret: Uint8Array<ArrayBuffer>;
      }> = [],
    ) =>
      createSmsBasedAuth({
        config: {
          issuer: "test",
          audience: "test",
          accessTokenKeys: [{ kid: "access-1", algorithm: "HS256", secret }],
          activeAccessTokenKid: "access-1",
          pepper,
          verificationPeppers,
          ...(verificationPeppers.length > 0
            ? {
                fingerprintPepper: {
                  kid: "fingerprint",
                  algorithm: "HS256" as const,
                  secret: oldSecret,
                },
              }
            : {}),
        },
        challenges,
        sessions,
        rateLimiter: new MemoryRateLimiter({ limit: 100 }),
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
            return { userId: "u1" };
          },
        },
        authorizeScope: async () => true,
      });
    const oldAuth = build({
      kid: "old",
      algorithm: "HS256",
      secret: oldSecret,
    });
    await oldAuth.requestCode({
      phone: "09123456789",
      purpose: "login",
      scope,
    });
    const newAuth = build(
      { kid: "new", algorithm: "HS256", secret: newSecret },
      [{ kid: "old", algorithm: "HS256", secret: oldSecret }],
    );
    await expect(
      newAuth.verifyCode({
        phone: "09123456789",
        purpose: "login",
        code,
        scope,
      }),
    ).resolves.toMatchObject({ kind: "session" });

    await oldAuth.requestCode({
      phone: "09123456780",
      purpose: "login",
      scope,
    });
    const oldLogin = await oldAuth.verifyCode({
      phone: "09123456780",
      purpose: "login",
      code,
      scope,
    });
    if (oldLogin.kind !== "session") throw new Error("expected session");
    const rotated = await newAuth.refresh({
      refreshToken: oldLogin.tokens.refreshToken,
    });
    expect(await sessions.get(rotated.sessionId)).toMatchObject({
      refreshPepperVersion: "new",
    });
    await expect(
      newAuth.refresh({ refreshToken: oldLogin.tokens.refreshToken }),
    ).rejects.toMatchObject({ code: "TOKEN_REUSE" });
  });

  it("refreshes authorization claims from the identity provider", async () => {
    let roles = ["user"];
    let code = "";
    const auth = createSmsBasedAuth({
      config: {
        issuer: "test",
        audience: "test",
        accessTokenKeys: [{ kid: "access-1", algorithm: "HS256", secret }],
        activeAccessTokenKid: "access-1",
        pepper: { kid: "pepper-1", algorithm: "HS256", secret },
      },
      challenges: new MemoryChallengeStore(),
      sessions: new MemorySessionStore(),
      rateLimiter: new MemoryRateLimiter({ limit: 100 }),
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
          return { userId: "u1", roles };
        },
        async reauthorize() {
          return { roles };
        },
      },
      authorizeScope: async () => true,
    });
    await auth.requestCode({ phone: "09123456789", purpose: "login", scope });
    const loggedIn = await auth.verifyCode({
      phone: "09123456789",
      purpose: "login",
      code,
      scope,
    });
    if (loggedIn.kind !== "session") throw new Error("expected session");
    roles = ["admin"];
    const refreshed = await auth.refresh({
      refreshToken: loggedIn.tokens.refreshToken,
    });
    expect((await auth.verifyAccessToken(refreshed.accessToken)).roles).toEqual(
      ["admin"],
    );
  });
  it("prevents cross-user session revocation", async () => {
    const f = fixture();
    const tokens = await login(f);
    await expect(
      f.auth.revokeSession({
        sessionId: "another-users-session",
        accessToken: tokens.accessToken,
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
