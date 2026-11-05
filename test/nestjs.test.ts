import "reflect-metadata";
import { Controller, Get, UseGuards } from "@nestjs/common";
import { Reflector } from "@nestjs/core";
import { Test } from "@nestjs/testing";
import { describe, expect, it } from "vitest";
import {
  CurrentAuth,
  RequirePermissions,
  SMS_BASED_AUTH,
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
});
