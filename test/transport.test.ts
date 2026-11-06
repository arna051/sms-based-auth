import { describe, expect, it } from "vitest";
import { SignJWT, generateKeyPair } from "jose";
import {
  assertCsrf,
  createCsrfTokenCookie,
  deliverTokens,
  parseCookie,
} from "../src/transport.js";
import { createAuthMiddleware, createEdgeVerifier } from "../src/edge.js";
import type { TokenPair } from "../src/types.js";
const now = new Date("2026-01-01T00:00:00Z");
const tokens: TokenPair = {
  accessToken: "access",
  refreshToken: "refresh",
  accessTokenExpiresAt: new Date(now.getTime() + 60_000),
  refreshTokenExpiresAt: new Date(now.getTime() + 3600_000),
  sessionId: "session",
};
describe("transport contracts", () => {
  it.each(["json", "cookie", "hybrid", "custom"] as const)(
    "supports %s transport",
    (mode) => {
      const result = deliverTokens(tokens, mode, { secure: true }, now);
      expect(result.cookies.length).toBe(
        mode === "cookie" ? 2 : mode === "hybrid" ? 1 : 0,
      );
    },
  );
  it("creates hardened cookies", () => {
    const result = deliverTokens(tokens, "cookie", { secure: true }, now);
    expect(result.cookies[0]).toContain("HttpOnly");
    expect(result.cookies[0]).toContain("Secure");
    expect(result.cookies[1]).toContain("Path=/auth/refresh");
    expect(result.cookies[0]).toContain("__Host-sba_access=");
    expect(result.cookies[1]).toContain("__Secure-sba_refresh=");
  });
  it("rejects insecure SameSite=None", () =>
    expect(() =>
      deliverTokens(tokens, "cookie", { secure: false, sameSite: "none" }, now),
    ).toThrow());
  it("rejects invalid __Host- cookie configurations", () => {
    expect(() =>
      deliverTokens(
        tokens,
        "cookie",
        { refreshName: "__Host-refresh", refreshPath: "/auth/refresh" },
        now,
      ),
    ).toThrow();
    expect(() => createCsrfTokenCookie({ secure: false })).toThrow();
  });
  it("parses malformed cookies safely", () =>
    expect(parseCookie("token=%E0%A4%A", "token")).toBeUndefined());
  it("checks double-submit CSRF tokens and origin", () => {
    const csrf = createCsrfTokenCookie();
    expect(csrf.cookie).toContain("__Host-sba_csrf=");
    expect(csrf.cookie).not.toContain("HttpOnly");
    expect(() =>
      assertCsrf({
        expectedOrigin: "https://app.test",
        origin: "https://evil.test",
        csrfCookie: "x",
        csrfHeader: "x",
      }),
    ).toThrow();
    expect(() =>
      assertCsrf({
        expectedOrigin: "https://app.test",
        origin: "https://app.test",
        csrfCookie: "x",
        csrfHeader: "x",
      }),
    ).not.toThrow();
  });
});
describe("edge routing boundary", () => {
  it("allows public routes and redirects protected routes without a token", async () => {
    const middleware = createAuthMiddleware({
      issuer: "i",
      audience: "a",
      keys: [{ kid: "k", algorithm: "ES256", publicKey: {} as CryptoKey }],
      publicRoutes: ["/login"],
      protectedRoutes: ["/dashboard/:path*"],
    });
    expect(
      await middleware(new Request("https://app.test/login")),
    ).toBeUndefined();
    const response = await middleware(
      new Request("https://app.test/dashboard/settings"),
    );
    expect(response?.status).toBe(307);
    expect(response?.headers.get("location")).toContain(
      "/login?returnTo=%2Fdashboard%2Fsettings",
    );
  });
  it("verifies a real asymmetric token and rejects unsafe redirects", async () => {
    const { privateKey, publicKey } = await generateKeyPair("ES256");
    const token = await new SignJWT({ sid: "s1" })
      .setProtectedHeader({ alg: "ES256", typ: "JWT", kid: "edge-1" })
      .setSubject("u1")
      .setIssuer("issuer")
      .setAudience("audience")
      .setJti("j1")
      .setIssuedAt()
      .setExpirationTime("5m")
      .sign(privateKey);
    const verify = createEdgeVerifier({
      issuer: "issuer",
      audience: "audience",
      keys: [{ kid: "edge-1", algorithm: "ES256", publicKey }],
    });
    expect((await verify(token)).sub).toBe("u1");
    expect(() =>
      createAuthMiddleware({
        issuer: "issuer",
        audience: "audience",
        keys: [{ kid: "edge-1", algorithm: "ES256", publicKey }],
        loginPath: "/\\\\evil.test",
      }),
    ).toThrow();
  });
});
