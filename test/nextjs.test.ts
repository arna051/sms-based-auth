import { describe, expect, it } from "vitest";
import { withAuth } from "../src/nextjs.js";
describe("Next.js adapter", () => {
  it("injects typed auth and handles bearer failures", async () => {
    const auth = {
      verifyAccessToken: async () => ({
        userId: "u1",
        sessionId: "s1",
        roles: [],
        permissions: [],
        claims: {},
        issuedAt: new Date(),
        expiresAt: new Date(Date.now() + 1000),
      }),
    };
    const route = withAuth(auth, (_request, context) =>
      Response.json({ userId: context.auth.userId }),
    );
    expect(
      await (
        await route(
          new Request("https://app.test", {
            headers: { authorization: "Bearer token" },
          }),
        )
      ).json(),
    ).toEqual({ userId: "u1" });
    expect((await route(new Request("https://app.test"))).status).toBe(401);
  });
});
