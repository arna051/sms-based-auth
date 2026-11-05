import { decodeProtectedHeader, jwtVerify } from "jose";
import { z } from "zod";
import { parseCookie } from "./transport.js";
const claims = z.object({
  sub: z.string().min(1),
  sid: z.string().min(1),
  jti: z.string().min(1),
  iat: z.number().int().positive(),
  exp: z.number().int().positive(),
});
export interface EdgeAuthOptions {
  issuer: string;
  audience: string;
  keys: Array<{
    kid: string;
    algorithm: "ES256" | "RS256" | "EdDSA";
    publicKey: CryptoKey;
  }>;
  publicRoutes?: string[];
  protectedRoutes?: string[];
  loginPath?: string;
  cookieName?: string;
}
function matches(pathname: string, pattern: string) {
  const prefix = pattern.endsWith("/:path*") ? pattern.slice(0, -7) : undefined;
  return prefix === undefined
    ? pathname === pattern
    : pathname === prefix || pathname.startsWith(prefix + "/");
}
export function createEdgeVerifier(
  options: Pick<EdgeAuthOptions, "issuer" | "audience" | "keys">,
) {
  const keys = new Map(options.keys.map((key) => [key.kid, key]));
  return async (token: string) => {
    const header = decodeProtectedHeader(token);
    if (
      typeof header.alg !== "string" ||
      !["ES256", "RS256", "EdDSA"].includes(header.alg) ||
      typeof header.kid !== "string"
    )
      throw new Error("Invalid token header");
    const key = keys.get(header.kid);
    if (!key) throw new Error("Unknown key");
    if (header.alg !== key.algorithm) throw new Error("Algorithm mismatch");
    const result = await jwtVerify(token, key.publicKey, {
      algorithms: [key.algorithm],
      issuer: options.issuer,
      audience: options.audience,
      typ: "JWT",
    });
    return claims.parse(result.payload);
  };
}
export function createAuthMiddleware(options: EdgeAuthOptions) {
  const verify = createEdgeVerifier(options);
  const loginPath = options.loginPath ?? "/login";
  const validationBase = new URL("https://sms-based-auth.invalid");
  const configuredLogin = new URL(loginPath, validationBase);
  if (configuredLogin.origin !== validationBase.origin)
    throw new Error("loginPath must be a local absolute path");
  return async (request: Request) => {
    const url = new URL(request.url);
    if (options.publicRoutes?.some((route) => matches(url.pathname, route)))
      return;
    if (
      options.protectedRoutes &&
      !options.protectedRoutes.some((route) => matches(url.pathname, route))
    )
      return;
    const bearer = request.headers
      .get("authorization")
      ?.match(/^Bearer ([^\s]+)$/i)?.[1];
    const token =
      bearer ??
      parseCookie(
        request.headers.get("cookie"),
        options.cookieName ?? "__Host-sba_access",
      );
    try {
      if (!token) throw new Error("Missing token");
      await verify(token);
      return;
    } catch {
      const login = new URL(loginPath, url.origin);
      login.searchParams.set("returnTo", url.pathname);
      return Response.redirect(login, 307);
    }
  };
}
