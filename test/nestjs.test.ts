import "reflect-metadata";
import { Controller, Get, UseGuards } from "@nestjs/common";
import { Reflector } from "@nestjs/core";
import { Test } from "@nestjs/testing";
import { describe, expect, it } from "vitest";
import {
  CurrentAuth,
  RequirePermissions,
  SMS_BASED_AUTH,
  SmsAuthController,
  SmsAuthGuard,
  SmsBasedAuthModule,
  type NestAuthService,
} from "../src/nestjs.js";

@Controller()
class ProtectedController {
  @Get()
  @UseGuards(SmsAuthGuard)
  @RequirePermissions("orders.read")
  route(@CurrentAuth() auth: unknown) {
    return auth;
  }
}
const auth: NestAuthService = {
  async verifyAccessToken() {
    return {
      userId: "u1",
      scope: "tenant",
      sessionId: "s1",
      roles: [],
      permissions: ["orders.read"],
      claims: {},
      issuedAt: new Date(),
      expiresAt: new Date(Date.now() + 1000),
    };
  },
  async requestCode() {
    return {};
  },
  async verifyCode() {
    return {};
  },
  async refresh() {
    return {};
  },
  async logout() {
    return {};
  },
  async listSessions() {
    return [];
  },
  async revokeSession() {
    return {};
  },
  async revokeAllSessions() {
    return 0;
  },
};
describe("NestJS adapter", () => {
  it("registers forRoot without hidden connections", async () => {
    const module = await Test.createTestingModule({
      imports: [SmsBasedAuthModule.forRoot({ auth, controllers: false })],
    }).compile();
    expect(module.get(SMS_BASED_AUTH)).toBe(auth);
    expect(module.get(SmsAuthGuard)).toBeInstanceOf(SmsAuthGuard);
    await module.close();
  });
  it("guard authenticates and enforces metadata", async () => {
    const guard = new SmsAuthGuard(auth, { auth }, new Reflector());
    const handler = ProtectedController.prototype.route;
    const request: { headers: Record<string, string>; smsAuth?: unknown } = {
      headers: { authorization: "Bearer token" },
    };
    const context = {
      switchToHttp: () => ({ getRequest: () => request }),
      getHandler: () => handler,
      getClass: () => ProtectedController,
    } as never;
    expect(await guard.canActivate(context)).toBe(true);
    expect(request.smsAuth).toMatchObject({ userId: "u1" });
  });
  it("requires CSRF validation for unsafe cookie-authenticated requests", async () => {
    const guard = new SmsAuthGuard(
      auth,
      { auth, csrf: { expectedOrigin: "https://app.test" } },
      new Reflector(),
    );
    const handler = ProtectedController.prototype.route;
    const request = {
      method: "POST",
      headers: {
        cookie: "__Host-sba_access=token; __Host-sba_csrf=csrf",
        origin: "https://app.test",
        "x-csrf-token": "csrf",
      },
    };
    const context = {
      switchToHttp: () => ({ getRequest: () => request }),
      getHandler: () => handler,
      getClass: () => ProtectedController,
    } as never;
    expect(await guard.canActivate(context)).toBe(true);
    delete (request.headers as { "x-csrf-token"?: string })["x-csrf-token"];
    await expect(guard.canActivate(context)).rejects.toMatchObject({
      code: "FORBIDDEN",
    });
  });
  it("requires CSRF for refresh-cookie fallback", async () => {
    const controller = new SmsAuthController(auth, {
      auth,
      transport: { mode: "cookie" },
      csrf: { expectedOrigin: "https://app.test" },
    });
    const response = {
      setHeader() {},
      appendHeader() {},
    };
    await expect(
      controller.refresh(
        {},
        { headers: { cookie: "__Secure-sba_refresh=refresh" } },
        response,
      ),
    ).rejects.toMatchObject({ code: "FORBIDDEN" });
  });
  it("requires CSRF before establishing a cookie session", async () => {
    const cookieAuth: NestAuthService = {
      ...auth,
      async verifyCode() {
        return {
          kind: "session",
          tokens: {
            accessToken: "access",
            refreshToken: "refresh",
            accessTokenExpiresAt: new Date(Date.now() + 60_000),
            refreshTokenExpiresAt: new Date(Date.now() + 3_600_000),
            sessionId: "s1",
          },
        };
      },
    };
    const controller = new SmsAuthController(cookieAuth, {
      auth: cookieAuth,
      transport: { mode: "cookie" },
      csrf: { expectedOrigin: "https://app.test" },
    });
    const cookies: string[] = [];
    const response = {
      setHeader() {},
      appendHeader(_name: string, value: string) {
        cookies.push(value);
      },
    };
    await expect(
      controller.verify({}, { headers: {} }, response),
    ).rejects.toMatchObject({ code: "FORBIDDEN" });
    await controller.verify(
      {},
      {
        headers: {
          Origin: "https://app.test",
          Cookie: "__Host-sba_csrf=csrf",
          "X-CSRF-Token": "csrf",
        },
      },
      response,
    );
    expect(cookies).toHaveLength(2);
  });
});
