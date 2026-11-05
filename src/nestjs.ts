import "reflect-metadata";
import {
  Body,
  CanActivate,
  Controller,
  createParamDecorator,
  Delete,
  DynamicModule,
  ExecutionContext,
  ForbiddenException,
  Get,
  Inject,
  Injectable,
  Module,
  Param,
  Post,
  SetMetadata,
  UnauthorizedException,
  UseGuards,
  type Provider,
} from "@nestjs/common";
import { Reflector } from "@nestjs/core";
import { parseCookie } from "./transport.js";
import type { AuthContext } from "./types.js";

export const SMS_BASED_AUTH = Symbol("SMS_BASED_AUTH");
export const SMS_AUTH_OPTIONS = Symbol("SMS_AUTH_OPTIONS");
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
      smsAuth?: AuthContext;
      smsAuthToken?: string;
    }>();
    const bearer =
      request.headers.authorization?.match(/^Bearer ([^\s]+)$/i)?.[1];
    const token =
      bearer ??
      parseCookie(
        request.headers.cookie,
        this.options.cookieName ?? "__Host-sba_access",
      );
    if (!token) throw new UnauthorizedException();
    let authContext: AuthContext;
    try {
      authContext = await this.auth.verifyAccessToken(
        token,
        this.options.checkSession ?? true,
      );
      request.smsAuth = authContext;
      request.smsAuthToken = token;
    } catch {
      throw new UnauthorizedException();
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
      throw new ForbiddenException();
    if (
      this.options.policy &&
      !(await this.options.policy(authContext, request))
    )
      throw new ForbiddenException();
    return true;
  }
}
@Controller("auth")
export class SmsAuthController {
  constructor(@Inject(SMS_BASED_AUTH) private readonly auth: NestAuthService) {}
  @Post("request-code") requestCode(@Body() body: unknown) {
    return this.auth.requestCode(body);
  }
  @Post("verify") verify(@Body() body: unknown) {
    return this.auth.verifyCode(body);
  }
  @Post("refresh") refresh(@Body() body: unknown) {
    return this.auth.refresh(body);
  }
  @UseGuards(SmsAuthGuard)
  @Post("logout")
  logout(@CurrentAccessToken() accessToken: string) {
    return this.auth.logout({ accessToken });
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
      ],
      controllers: options.controllers === false ? [] : [SmsAuthController],
      exports: [SMS_BASED_AUTH, SMS_AUTH_OPTIONS, SmsAuthGuard],
    };
  }
}
