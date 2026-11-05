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
interface SerializeOptions {
  maxAge: number;
  secure: boolean;
  sameSite: string;
  path: string;
  httpOnly: boolean;
  domain?: string;
}
function serializeCookie(
  name: string,
  value: string,
  options: SerializeOptions,
) {
  const parts = [
    `${name}=${encodeURIComponent(value)}`,
    `Max-Age=${Math.max(0, Math.floor(options.maxAge))}`,
    `Path=${options.path}`,
    `SameSite=${options.sameSite[0]!.toUpperCase()}${options.sameSite.slice(1)}`,
  ];
  if (options.httpOnly) parts.push("HttpOnly");
  if (options.secure) parts.push("Secure");
  if (options.domain) parts.push(`Domain=${options.domain}`);
  return parts.join("; ");
}
function resolveCookieOptions(options: CookieOptions) {
  const secure = options.secure ?? true;
  const sameSite = options.sameSite ?? "lax";
  if (sameSite === "none" && !secure)
    throw new Error("SameSite=None cookies must be Secure");
  const accessName = options.accessName ?? "__Host-sba_access";
  const refreshName = options.refreshName ?? "__Secure-sba_refresh";
  const accessPath = options.accessPath ?? "/";
  const refreshPath = options.refreshPath ?? "/auth/refresh";
  if (
    accessName.startsWith("__Host-") &&
    (!secure || options.domain || accessPath !== "/")
  )
    throw new Error(
      "__Host- access cookies require Secure, Path=/, and no Domain",
    );
  if (
    (accessName.startsWith("__Secure-") ||
      refreshName.startsWith("__Secure-")) &&
    !secure
  )
    throw new Error("__Secure- cookies require Secure");
  return { secure, sameSite, accessName, refreshName, accessPath, refreshPath };
}
export function deliverTokens(
  tokens: TokenPair,
  mode: TransportMode,
  options: CookieOptions = {},
  at = new Date(),
): TransportResult {
  const resolved = resolveCookieOptions(options);
  const access = serializeCookie(resolved.accessName, tokens.accessToken, {
    maxAge: (tokens.accessTokenExpiresAt.getTime() - at.getTime()) / 1000,
    secure: resolved.secure,
    sameSite: resolved.sameSite,
    path: resolved.accessPath,
    httpOnly: true,
    ...(options.domain ? { domain: options.domain } : {}),
  });
  const refresh = serializeCookie(resolved.refreshName, tokens.refreshToken, {
    maxAge: (tokens.refreshTokenExpiresAt.getTime() - at.getTime()) / 1000,
    secure: resolved.secure,
    sameSite: resolved.sameSite,
    path: resolved.refreshPath,
    httpOnly: true,
    ...(options.domain ? { domain: options.domain } : {}),
  });
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
  return { body: { ...tokens }, cookies: [] };
}
export function createCsrfTokenCookie(
  options: {
    name?: string;
    secure?: boolean;
    sameSite?: "strict" | "lax";
    path?: string;
    maxAgeSeconds?: number;
  } = {},
) {
  const bytes = crypto.getRandomValues(new Uint8Array(32));
  const token = Array.from(bytes, (byte) =>
    byte.toString(16).padStart(2, "0"),
  ).join("");
  const cookie = serializeCookie(options.name ?? "__Host-sba_csrf", token, {
    maxAge: options.maxAgeSeconds ?? 3600,
    secure: options.secure ?? true,
    sameSite: options.sameSite ?? "strict",
    path: options.path ?? "/",
    httpOnly: false,
  });
  return { token, cookie };
}
export function clearTokenCookies(options: CookieOptions = {}) {
  const resolved = resolveCookieOptions(options);
  return [
    serializeCookie(resolved.accessName, "", {
      maxAge: 0,
      secure: resolved.secure,
      sameSite: resolved.sameSite,
      path: resolved.accessPath,
      httpOnly: true,
      ...(options.domain ? { domain: options.domain } : {}),
    }),
    serializeCookie(resolved.refreshName, "", {
      maxAge: 0,
      secure: resolved.secure,
      sameSite: resolved.sameSite,
      path: resolved.refreshPath,
      httpOnly: true,
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
