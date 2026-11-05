import "reflect-metadata";
import {
  Body,
  CanActivate,
  Controller,
  createParamDecorator,
  DynamicModule,
  ExecutionContext,
  ForbiddenException,
  Inject,
  Injectable,
  Module,
  Post,
  SetMetadata,
  UnauthorizedException,
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
  inject?: unknown[];
  useFactory: (
    ...dependencies: never[]
  ) => NestAuthOptions | Promise<NestAuthOptions>;
  providers?: Provider[];
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

@Injectable()
export class SmsAuthGuard implements CanActivate {
  constructor(
    @Inject(SMS_BASED_AUTH) private readonly auth: NestAuthService,
    @Inject(SMS_AUTH_OPTIONS) private readonly options: NestAuthOptions,
    @Inject(Reflector) private readonly reflector: Reflector,
  ) {}
  async canActivate(context: ExecutionContext) {
    const request = context
      .switchToHttp()
      .getRequest<{
        headers: Record<string, string | undefined>;
        smsAuth?: AuthContext;
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
      exports: [SMS_BASED_AUTH, SmsAuthGuard],
    };
  }
  static forRootAsync(options: NestAuthAsyncOptions): DynamicModule {
    const optionsProvider: Provider = {
      provide: SMS_AUTH_OPTIONS,
      useFactory: options.useFactory,
      ...(options.inject ? { inject: options.inject as never[] } : {}),
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
      exports: [SMS_BASED_AUTH, SmsAuthGuard],
    };
  }
}
