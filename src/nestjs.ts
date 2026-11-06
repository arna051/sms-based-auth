import "reflect-metadata";
import {
  Body,
  CanActivate,
  Catch,
  Controller,
  createParamDecorator,
  Delete,
  DynamicModule,
  ExecutionContext,
  type ArgumentsHost,
  type ExceptionFilter,
  Get,
  Inject,
  Injectable,
  Module,
  Param,
  Post,
  Req,
  Res,
  SetMetadata,
  UseGuards,
  type Provider,
} from "@nestjs/common";
import { APP_FILTER, Reflector } from "@nestjs/core";
import { AuthError, toAuthProblem } from "./errors.js";
import {
  assertCsrf,
  clearTokenCookies,
  deliverTokens,
  parseCookie,
  type CookieOptions,
  type TransportMode,
} from "./transport.js";
import type { AuthContext, TokenPair } from "./types.js";

export const SMS_BASED_AUTH = Symbol("SMS_BASED_AUTH");
export const SMS_AUTH_OPTIONS = Symbol("SMS_AUTH_OPTIONS");
interface NestRequest {
  headers: Record<string, string | undefined>;
}
interface NestResponse {
  setHeader(name: string, value: string): void;
  appendHeader(name: string, value: string): void;
}
function requestHeader(request: NestRequest, name: string) {
  const expected = name.toLowerCase();
  return Object.entries(request.headers).find(
    ([candidate]) => candidate.toLowerCase() === expected,
  )?.[1];
}
export interface NestAuthService {
  verifyAccessToken(
    token: string,
    checkSession?: boolean,
  ): Promise<AuthContext>;
  requestCode(input: unknown): Promise<unknown>;
  verifyCode(input: unknown): Promise<unknown>;
  refresh(input: unknown): Promise<unknown>;
  logout(input: { accessToken: string }): Promise<unknown>;
  listSessions(input: { accessToken: string }): Promise<unknown>;
  revokeSession(input: {
    sessionId: string;
    accessToken: string;
  }): Promise<unknown>;
  revokeAllSessions(input: { accessToken: string }): Promise<unknown>;
}
export interface NestAuthOptions {
  auth: NestAuthService;
  controllers?: boolean;
  cookieName?: string;
  checkSession?: boolean;
  transport?: { mode: TransportMode; cookies?: CookieOptions };
  csrf?: { expectedOrigin: string; cookieName?: string; headerName?: string };
  policy?: (
    context: AuthContext,
    request: unknown,
  ) => boolean | Promise<boolean>;
}
export interface NestAuthAsyncOptions {
  imports?: DynamicModule["imports"];
  inject?: any[];
  useFactory: (
    ...dependencies: any[]
  ) => NestAuthOptions | Promise<NestAuthOptions>;
  providers?: Provider[];
  controllers?: boolean;
}
const ROLES = Symbol("SMS_AUTH_ROLES");
const PERMISSIONS = Symbol("SMS_AUTH_PERMISSIONS");
export const RequireRoles = (...roles: string[]) => SetMetadata(ROLES, roles);
export const RequirePermissions = (...permissions: string[]) =>
  SetMetadata(PERMISSIONS, permissions);
export const CurrentAuth = createParamDecorator(
  (_data: unknown, context: ExecutionContext) =>
    context.switchToHttp().getRequest<{ smsAuth?: AuthContext }>().smsAuth,
);
export const CurrentAccessToken = createParamDecorator(
  (_data: unknown, context: ExecutionContext) =>
    context.switchToHttp().getRequest<{ smsAuthToken?: string }>().smsAuthToken,
);

@Catch(AuthError)
export class SmsAuthExceptionFilter implements ExceptionFilter {
  catch(error: AuthError, host: ArgumentsHost) {
    const response = host.switchToHttp().getResponse<{
      status(code: number): {
        type(value: string): { json(body: unknown): void };
      };
      setHeader(name: string, value: string): void;
    }>();
    if (error.retryAfterMs)
      response.setHeader(
        "Retry-After",
        String(Math.max(1, Math.ceil(error.retryAfterMs / 1000))),
      );
    response
      .status(error.status)
      .type("application/problem+json")
      .json(toAuthProblem(error));
  }
}

@Injectable()
export class SmsAuthGuard implements CanActivate {
  constructor(
    @Inject(SMS_BASED_AUTH) private readonly auth: NestAuthService,
    @Inject(SMS_AUTH_OPTIONS) private readonly options: NestAuthOptions,
    @Inject(Reflector) private readonly reflector: Reflector,
  ) {}
  async canActivate(context: ExecutionContext) {
    const request = context.switchToHttp().getRequest<{
      headers: Record<string, string | undefined>;
      method?: string;
      smsAuth?: AuthContext;
      smsAuthToken?: string;
    }>();
    const bearer = requestHeader(request, "authorization")?.match(
      /^Bearer ([^\s]+)$/i,
    )?.[1];
    const token =
      bearer ??
      parseCookie(
        requestHeader(request, "cookie"),
        this.options.cookieName ?? "__Host-sba_access",
      );
    if (!token) throw new AuthError("INVALID_TOKEN", "Unauthorized", 401);
    if (
      !bearer &&
      this.options.csrf &&
      !["GET", "HEAD", "OPTIONS"].includes(request.method ?? "GET")
    ) {
      try {
        const csrfCookie = parseCookie(
          requestHeader(request, "cookie"),
          this.options.csrf.cookieName ?? "__Host-sba_csrf",
        );
        const csrfHeader = requestHeader(
          request,
          this.options.csrf.headerName ?? "x-csrf-token",
        );
        const origin = requestHeader(request, "origin");
        assertCsrf({
          expectedOrigin: this.options.csrf.expectedOrigin,
          ...(origin ? { origin } : {}),
          ...(csrfCookie ? { csrfCookie } : {}),
          ...(csrfHeader ? { csrfHeader } : {}),
        });
      } catch {
        throw new AuthError("FORBIDDEN", "CSRF validation failed", 403);
      }
    }
    let authContext: AuthContext;
    try {
      authContext = await this.auth.verifyAccessToken(
        token,
        this.options.checkSession ?? true,
      );
      request.smsAuth = authContext;
      request.smsAuthToken = token;
    } catch {
      throw new AuthError("INVALID_TOKEN", "Unauthorized", 401);
    }
    const roles =
      this.reflector.getAllAndOverride<string[]>(ROLES, [
        context.getHandler(),
        context.getClass(),
      ]) ?? [];
    const permissions =
      this.reflector.getAllAndOverride<string[]>(PERMISSIONS, [
        context.getHandler(),
        context.getClass(),
      ]) ?? [];
    if (
      !roles.every((role) => authContext.roles.includes(role)) ||
      !permissions.every((permission) =>
        authContext.permissions.includes(permission),
      )
    )
      throw new AuthError("FORBIDDEN", "Forbidden", 403);
    if (
      this.options.policy &&
      !(await this.options.policy(authContext, request))
    )
      throw new AuthError("FORBIDDEN", "Forbidden", 403);
    return true;
  }
}
@Controller("auth")
export class SmsAuthController {
  constructor(
    @Inject(SMS_BASED_AUTH) private readonly auth: NestAuthService,
    @Inject(SMS_AUTH_OPTIONS) private readonly options: NestAuthOptions,
  ) {}
  private deliver(result: unknown, response: NestResponse) {
    if (
      !result ||
      typeof result !== "object" ||
      !("kind" in result) ||
      result.kind !== "session" ||
      !("tokens" in result)
    )
      return result;
    const delivered = deliverTokens(
      result.tokens as TokenPair,
      this.options.transport?.mode ?? "json",
      this.options.transport?.cookies,
    );
    response.setHeader("Cache-Control", "no-store");
    for (const cookie of delivered.cookies)
      response.appendHeader("Set-Cookie", cookie);
    return delivered.body;
  }
  private assertRequestCsrf(request: NestRequest) {
    if (!this.options.csrf)
      throw new AuthError(
        "MISCONFIGURED",
        "CSRF options are required for cookie refresh",
        500,
      );
    const csrfCookie = parseCookie(
      requestHeader(request, "cookie"),
      this.options.csrf.cookieName ?? "__Host-sba_csrf",
    );
    const csrfHeader = requestHeader(
      request,
      this.options.csrf.headerName ?? "x-csrf-token",
    );
    const origin = requestHeader(request, "origin");
    try {
      assertCsrf({
        expectedOrigin: this.options.csrf.expectedOrigin,
        ...(origin ? { origin } : {}),
        ...(csrfCookie ? { csrfCookie } : {}),
        ...(csrfHeader ? { csrfHeader } : {}),
      });
    } catch {
      throw new AuthError("FORBIDDEN", "CSRF validation failed", 403);
    }
  }
  private assertSessionEstablishmentCsrf(request: NestRequest) {
    const mode = this.options.transport?.mode ?? "json";
    if (mode === "cookie" || mode === "hybrid") this.assertRequestCsrf(request);
  }
  @Post("request-code") requestCode(
    @Body() body: unknown,
    @Req() request: NestRequest,
  ) {
    this.assertSessionEstablishmentCsrf(request);
    return this.auth.requestCode(body);
  }
  @Post("verify") async verify(
    @Body() body: unknown,
    @Req() request: NestRequest,
    @Res({ passthrough: true }) response: NestResponse,
  ) {
    this.assertSessionEstablishmentCsrf(request);
    return this.deliver(await this.auth.verifyCode(body), response);
  }
  @Post("refresh") async refresh(
    @Body() body: Record<string, unknown>,
    @Req() request: NestRequest,
    @Res({ passthrough: true }) response: NestResponse,
  ) {
    const bodyRefreshToken =
      typeof body?.refreshToken === "string" ? body.refreshToken : undefined;
    const cookieRefreshToken = parseCookie(
      requestHeader(request, "cookie"),
      this.options.transport?.cookies?.refreshName ?? "__Secure-sba_refresh",
    );
    const refreshToken = bodyRefreshToken ?? cookieRefreshToken;
    if (!refreshToken)
      throw new AuthError("INVALID_TOKEN", "Refresh token is required", 401);
    if (cookieRefreshToken) this.assertRequestCsrf(request);
    const tokens = (await this.auth.refresh({
      ...body,
      refreshToken,
    })) as TokenPair;
    const delivered = deliverTokens(
      tokens,
      this.options.transport?.mode ?? "json",
      this.options.transport?.cookies,
    );
    response.setHeader("Cache-Control", "no-store");
    for (const cookie of delivered.cookies)
      response.appendHeader("Set-Cookie", cookie);
    return delivered.body;
  }
  @UseGuards(SmsAuthGuard)
  @Post("logout")
  async logout(
    @CurrentAccessToken() accessToken: string,
    @Res({ passthrough: true }) response: NestResponse,
  ) {
    await this.auth.logout({ accessToken });
    if (this.options.transport?.mode !== "json")
      for (const cookie of clearTokenCookies(this.options.transport?.cookies))
        response.appendHeader("Set-Cookie", cookie);
  }
  @UseGuards(SmsAuthGuard)
  @Get("sessions")
  sessions(@CurrentAccessToken() accessToken: string) {
    return this.auth.listSessions({ accessToken });
  }
  @UseGuards(SmsAuthGuard)
  @Delete("sessions/:sessionId")
  revoke(
    @Param("sessionId") sessionId: string,
    @CurrentAccessToken() accessToken: string,
  ) {
    return this.auth.revokeSession({ sessionId, accessToken });
  }
  @UseGuards(SmsAuthGuard)
  @Post("sessions/revoke-all")
  revokeAll(@CurrentAccessToken() accessToken: string) {
    return this.auth.revokeAllSessions({ accessToken });
  }
}
@Module({})
export class SmsBasedAuthModule {
  static forRoot(options: NestAuthOptions): DynamicModule {
    return {
      module: SmsBasedAuthModule,
      providers: [
        { provide: SMS_AUTH_OPTIONS, useValue: options },
        { provide: SMS_BASED_AUTH, useValue: options.auth },
        SmsAuthGuard,
        { provide: APP_FILTER, useClass: SmsAuthExceptionFilter },
      ],
      controllers: options.controllers === false ? [] : [SmsAuthController],
      exports: [SMS_BASED_AUTH, SMS_AUTH_OPTIONS, SmsAuthGuard],
    };
  }
  static forRootAsync(options: NestAuthAsyncOptions): DynamicModule {
    const optionsProvider: Provider = {
      provide: SMS_AUTH_OPTIONS,
      useFactory: options.useFactory,
      ...(options.inject ? { inject: options.inject } : {}),
    };
    const authProvider: Provider = {
      provide: SMS_BASED_AUTH,
      useFactory: (resolved: NestAuthOptions) => resolved.auth,
      inject: [SMS_AUTH_OPTIONS],
    };
    return {
      module: SmsBasedAuthModule,
      ...(options.imports ? { imports: options.imports } : {}),
      providers: [
        ...(options.providers ?? []),
        optionsProvider,
        authProvider,
        SmsAuthGuard,
        { provide: APP_FILTER, useClass: SmsAuthExceptionFilter },
      ],
      controllers: options.controllers === false ? [] : [SmsAuthController],
      exports: [SMS_BASED_AUTH, SMS_AUTH_OPTIONS, SmsAuthGuard],
    };
  }
}
