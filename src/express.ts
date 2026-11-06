import type { Request, RequestHandler, Response } from "express";
import { AuthError, toAuthProblem } from "./errors.js";
import {
  assertCsrf,
  parseCookie,
  type CookieOptions,
  type TransportMode,
  deliverTokens,
} from "./transport.js";
import type { AuthContext, TokenPair } from "./types.js";
type Verifier<T extends Record<string, unknown>> = {
  verifyAccessToken(
    token: string,
    checkSession?: boolean,
  ): Promise<AuthContext<T>>;
};
export interface ExpressAuthOptions {
  cookieName?: string;
  checkSession?: boolean;
  transport?: { mode: TransportMode; cookies?: CookieOptions };
  onUnauthorized?: (
    request: Request,
    response: Response,
    error?: unknown,
  ) => void;
  onForbidden?: (request: Request, response: Response) => void;
  csrf?: { expectedOrigin: string; cookieName?: string; headerName?: string };
}
export function createExpressAuth<T extends Record<string, unknown>>(
  auth: Verifier<T>,
  options: ExpressAuthOptions = {},
) {
  const contexts = new WeakMap<Request, AuthContext<T>>();
  const unauthorized = (req: Request, res: Response, error?: unknown) => {
    if (options.onUnauthorized) return options.onUnauthorized(req, res, error);
    res
      .status(401)
      .type("application/problem+json")
      .json(toAuthProblem(new AuthError("INVALID_TOKEN", "Unauthorized", 401)));
  };
  const forbidden = (req: Request, res: Response) => {
    if (options.onForbidden) return options.onForbidden(req, res);
    res
      .status(403)
      .type("application/problem+json")
      .json(toAuthProblem(new AuthError("FORBIDDEN", "Forbidden", 403)));
  };
  const requireAuth = (): RequestHandler => async (req, res, next) => {
    try {
      const bearer =
        req.headers.authorization?.match(/^Bearer ([^\s]+)$/i)?.[1];
      const cookie = parseCookie(
        req.headers.cookie,
        options.cookieName ?? "__Host-sba_access",
      );
      const token = bearer ?? cookie;
      if (!token) return unauthorized(req, res);
      contexts.set(
        req,
        await auth.verifyAccessToken(token, options.checkSession ?? true),
      );
      next();
    } catch (error) {
      if (error instanceof AuthError) return unauthorized(req, res, error);
      next(error);
    }
  };
  const requireRoles =
    (...roles: string[]): RequestHandler =>
    (req, res, next) => {
      const context = contexts.get(req);
      if (!context) return unauthorized(req, res);
      if (!roles.every((role) => context.roles.includes(role)))
        return forbidden(req, res);
      next();
    };
  const requireCsrf = (): RequestHandler => (req, res, next) => {
    try {
      if (!options.csrf) throw new Error("CSRF options are required");
      const header = req.get(options.csrf.headerName ?? "x-csrf-token");
      const csrfCookie = parseCookie(
        req.headers.cookie,
        options.csrf.cookieName ?? "__Host-sba_csrf",
      );
      assertCsrf({
        expectedOrigin: options.csrf.expectedOrigin,
        ...(req.headers.origin ? { origin: req.headers.origin } : {}),
        ...(csrfCookie ? { csrfCookie } : {}),
        ...(header ? { csrfHeader: header } : {}),
      });
      next();
    } catch {
      res
        .status(403)
        .type("application/problem+json")
        .json(
          toAuthProblem(
            new AuthError("FORBIDDEN", "CSRF validation failed", 403),
          ),
        );
    }
  };
  const requirePermissions =
    (...permissions: string[]): RequestHandler =>
    (req, res, next) => {
      const context = contexts.get(req);
      if (!context) return unauthorized(req, res);
      if (
        !permissions.every((permission) =>
          context.permissions.includes(permission),
        )
      )
        return forbidden(req, res);
      next();
    };
  const requirePolicy =
    (
      policy: (
        context: AuthContext<T>,
        request: Request,
      ) => boolean | Promise<boolean>,
    ): RequestHandler =>
    async (req, res, next) => {
      const context = contexts.get(req);
      if (!context) return unauthorized(req, res);
      try {
        if (!(await policy(context, req))) return forbidden(req, res);
        next();
      } catch (error) {
        next(error);
      }
    };
  const sendTokens = (
    res: Response,
    tokens: TokenPair,
    mode = options.transport?.mode ?? "json",
  ) => {
    const delivered = deliverTokens(tokens, mode, options.transport?.cookies);
    res.set("Cache-Control", "no-store");
    for (const cookie of delivered.cookies) res.append("Set-Cookie", cookie);
    if (delivered.body) res.json(delivered.body);
    else res.status(204).end();
  };
  return {
    requireAuth,
    requireRoles,
    requirePermissions,
    requirePolicy,
    requireCsrf,
    getAuth: (request: Request) => contexts.get(request),
    sendTokens,
  };
}
