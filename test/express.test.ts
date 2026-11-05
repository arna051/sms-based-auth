import express from "express";
import request from "supertest";
import { describe, it } from "vitest";
import { createExpressAuth } from "../src/express.js";
import { AuthError } from "../src/errors.js";

const context = {
  userId: "u1",
  sessionId: "s1",
  roles: ["admin"],
  permissions: ["orders.read"],
  claims: {},
  issuedAt: new Date(),
  expiresAt: new Date(Date.now() + 1000),
};
function appFor(verifier: (token: string) => Promise<typeof context>) {
  const app = express();
  const adapter = createExpressAuth(
    { verifyAccessToken: verifier },
    { csrf: { expectedOrigin: "https://app.test" } },
  );
  app.get("/profile", adapter.requireAuth(), (_req, res) =>
    res.json({ ok: true }),
  );
  app.get(
    "/admin",
    adapter.requireAuth(),
    adapter.requireRoles("admin"),
    adapter.requirePermissions("orders.read"),
    (_req, res) => res.json({ ok: true }),
  );
  app.post("/state", adapter.requireCsrf(), (_req, res) =>
    res.json({ ok: true }),
  );
  app.use(
    (
      error: unknown,
      _req: express.Request,
      res: express.Response,
      _next: express.NextFunction,
    ) => res.status(500).json({ error: String(error) }),
  );
  return app;
}
describe("Express adapter", () => {
  it("authenticates bearer requests and enforces authorization", async () => {
    const app = appFor(async () => context);
    await request(app)
      .get("/admin")
      .set("Authorization", "Bearer token")
      .expect(200);
    await request(app).get("/profile").expect(401);
  });
  it("maps invalid tokens to 401 and operational errors to the error handler", async () => {
    await request(
      appFor(async () => {
        throw new AuthError("INVALID_TOKEN", "bad", 401);
      }),
    )
      .get("/profile")
      .set("Authorization", "Bearer bad")
      .expect(401);
    await request(
      appFor(async () => {
        throw new Error("store unavailable");
      }),
    )
      .get("/profile")
      .set("Authorization", "Bearer token")
      .expect(500);
  });
  it("enforces CSRF origin and double-submit token", async () => {
    const app = appFor(async () => context);
    await request(app)
      .post("/state")
      .set("Origin", "https://app.test")
      .set("Cookie", "__Host-sba_csrf=abc")
      .set("x-csrf-token", "abc")
      .expect(200);
    await request(app)
      .post("/state")
      .set("Origin", "https://evil.test")
      .set("Cookie", "__Host-sba_csrf=abc")
      .set("x-csrf-token", "abc")
      .expect(403);
  });
});
