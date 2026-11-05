import type { TokenPair } from "./types.js";
export type TransportMode = "cookie" | "json" | "hybrid" | "custom";
export interface CookieOptions {
  accessName?: string;
  refreshName?: string;
  secure?: boolean;
  sameSite?: "strict" | "lax" | "none";
  domain?: string;
  accessPath?: string;
  refreshPath?: string;
}
export interface TransportResult {
  body?: Record<string, unknown>;
  cookies: string[];
}
function serializeCookie(
  name: string,
  value: string,
  options: {
    maxAge: number;
    secure: boolean;
    sameSite: string;
    path: string;
    domain?: string;
  },
) {
  const parts = [
    `${name}=${encodeURIComponent(value)}`,
    `Max-Age=${Math.max(0, Math.floor(options.maxAge))}`,
    `Path=${options.path}`,
    "HttpOnly",
    `SameSite=${options.sameSite[0]!.toUpperCase()}${options.sameSite.slice(1)}`,
  ];
  if (options.secure) parts.push("Secure");
  if (options.domain) parts.push(`Domain=${options.domain}`);
  return parts.join("; ");
}
export function deliverTokens(
  tokens: TokenPair,
  mode: TransportMode,
  options: CookieOptions = {},
  at = new Date(),
): TransportResult {
  if (options.sameSite === "none" && options.secure === false)
    throw new Error("SameSite=None cookies must be Secure");
  const secure = options.secure ?? process.env.NODE_ENV === "production";
  const sameSite = options.sameSite ?? "lax";
  const access = serializeCookie(
    options.accessName ?? "__Host-sba_access",
    tokens.accessToken,
    {
      maxAge: (tokens.accessTokenExpiresAt.getTime() - at.getTime()) / 1000,
      secure,
      sameSite,
      path: options.accessPath ?? "/",
      ...(options.domain ? { domain: options.domain } : {}),
    },
  );
  const refresh = serializeCookie(
    options.refreshName ?? "__Host-sba_refresh",
    tokens.refreshToken,
    {
      maxAge: (tokens.refreshTokenExpiresAt.getTime() - at.getTime()) / 1000,
      secure,
      sameSite,
      path: options.refreshPath ?? "/auth/refresh",
      ...(options.domain ? { domain: options.domain } : {}),
    },
  );
  if (mode === "json") return { body: { ...tokens }, cookies: [] };
  if (mode === "cookie")
    return {
      body: {
        sessionId: tokens.sessionId,
        accessTokenExpiresAt: tokens.accessTokenExpiresAt,
        refreshTokenExpiresAt: tokens.refreshTokenExpiresAt,
      },
      cookies: [access, refresh],
    };
  if (mode === "hybrid")
    return {
      body: {
        accessToken: tokens.accessToken,
        accessTokenExpiresAt: tokens.accessTokenExpiresAt,
        sessionId: tokens.sessionId,
      },
      cookies: [refresh],
    };
  return { cookies: [] };
}
export function clearTokenCookies(options: CookieOptions = {}) {
  const secure = options.secure ?? process.env.NODE_ENV === "production";
  const sameSite = options.sameSite ?? "lax";
  return [
    serializeCookie(options.accessName ?? "__Host-sba_access", "", {
      maxAge: 0,
      secure,
      sameSite,
      path: options.accessPath ?? "/",
      ...(options.domain ? { domain: options.domain } : {}),
    }),
    serializeCookie(options.refreshName ?? "__Host-sba_refresh", "", {
      maxAge: 0,
      secure,
      sameSite,
      path: options.refreshPath ?? "/auth/refresh",
      ...(options.domain ? { domain: options.domain } : {}),
    }),
  ];
}
export function parseCookie(
  header: string | null | undefined,
  name: string,
): string | undefined {
  if (!header) return undefined;
  for (const part of header.split(";")) {
    const separator = part.indexOf("=");
    if (separator < 0) continue;
    if (part.slice(0, separator).trim() !== name) continue;
    try {
      return decodeURIComponent(part.slice(separator + 1).trim());
    } catch {
      return undefined;
    }
  }
  return undefined;
}
export function assertCsrf(input: {
  expectedOrigin: string;
  origin?: string;
  csrfCookie?: string;
  csrfHeader?: string;
}) {
  if (
    input.origin !== input.expectedOrigin ||
    !input.csrfCookie ||
    input.csrfCookie !== input.csrfHeader
  )
    throw new Error("CSRF validation failed");
}
