import { describe, expect, it } from "vitest";
import { assertCsrf, deliverTokens, parseCookie } from "../src/transport.js";
import { createAuthMiddleware } from "../src/edge.js";
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
  });
  it("rejects insecure SameSite=None", () =>
    expect(() =>
      deliverTokens(tokens, "cookie", { secure: false, sameSite: "none" }, now),
    ).toThrow());
  it("parses malformed cookies safely", () =>
    expect(parseCookie("token=%E0%A4%A", "token")).toBeUndefined());
  it("checks double-submit CSRF tokens and origin", () => {
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
      keys: [{ kid: "k", algorithm: "HS256", secret: new Uint8Array(32) }],
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
});
