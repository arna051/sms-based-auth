import { SignJWT, decodeProtectedHeader, jwtVerify } from "jose";
import { z } from "zod";
import { resolveConfig, type SecurityConfig } from "./config.js";
import { generateCode, keyedHash, randomId, randomToken } from "./crypto.js";
import { AuthError } from "./errors.js";
import { normalizeIranianPhone } from "./phone.js";
import {
  AUTH_PURPOSES,
  type AuthContext,
  type AuthPurpose,
  type ChallengeRecord,
  type ChallengeStore,
  type IdentityProvider,
  type Observer,
  type RateLimiter,
  type RequestContext,
  type SessionRecord,
  type SessionStore,
  type SessionSummary,
  type SmsSender,
  type TokenPair,
  type VerifyCodeResult,
} from "./types.js";

const requestCodeSchema = z.object({
  phone: z.string().min(1).max(64),
  purpose: z.enum(AUTH_PURPOSES),
  scope: z.string().min(1).max(128).optional(),
  actorAccessToken: z.string().min(1).max(4096).optional(),
});
const verifyCodeSchema = requestCodeSchema.extend({
  code: z.string().regex(/^\d{6,10}$/),
});
const accessClaims = z.object({
  sub: z.string().min(1),
  sid: z.string().min(1),
  jti: z.string().min(1),
  iat: z.number().int().positive(),
  exp: z.number().int().positive(),
  iss: z.string().min(1),
  aud: z.union([z.string(), z.array(z.string())]),
  roles: z.array(z.string()),
  permissions: z.array(z.string()),
  claims: z.record(z.string(), z.unknown()),
});

export interface CreateAuthOptions<
  TClaims extends Record<string, unknown>,
  TAction extends string,
> {
  config: SecurityConfig;
  challenges: ChallengeStore;
  sessions: SessionStore<TClaims>;
  rateLimiter: RateLimiter;
  sms: SmsSender<TAction>;
  smsActions: Record<AuthPurpose, TAction>;
  identities: IdentityProvider<TClaims>;
  authorizeScope: (
    scope: string,
    context?: RequestContext,
  ) => boolean | Promise<boolean>;
  observer?: Observer;
  clock?: () => Date;
}
async function safelyObserve(
  observer: Observer | undefined,
  event: Parameters<Observer["emit"]>[0],
) {
  try {
    await observer?.emit(event);
  } catch {
    /* observers cannot break authentication */
  }
}

export function createSmsBasedAuth<
  TClaims extends Record<string, unknown> = Record<string, unknown>,
  TAction extends string = string,
>(options: CreateAuthOptions<TClaims, TAction>) {
  const cfg = resolveConfig(options.config);
  const now = options.clock ?? (() => new Date());
  const pepper = cfg.pepper.secret;
  const accessKeys = new Map(cfg.accessTokenKeys.map((key) => [key.kid, key]));
  const activeKey = accessKeys.get(cfg.activeAccessTokenKid)!;
  const scopeOf = (scope: string | undefined) => {
    if (cfg.requireScope && !scope)
      throw new AuthError("INVALID_INPUT", "A tenant scope is required", 400);
    return scope ?? "default";
  };
  const fingerprint = (phone: string) =>
    keyedHash(pepper, "phone-fingerprint", phone);
  const challengeKey = (
    phone: string,
    purpose: AuthPurpose,
    scope: string,
    actorUserId?: string,
    actorSessionId?: string,
  ) =>
    keyedHash(
      pepper,
      "challenge-key",
      `${scope}\0${purpose}\0${phone}\0${actorUserId ?? ""}\0${actorSessionId ?? ""}`,
    );
  const rateKeys = (
    phoneFingerprint: string,
    scope: string,
    context?: RequestContext,
  ) => [
    `phone:${phoneFingerprint}`,
    `scope:${scope}`,
    ...(context?.ip
      ? [`ip:${keyedHash(pepper, "ip-fingerprint", context.ip)}`]
      : []),
    ...(context?.deviceId
      ? [`device:${keyedHash(pepper, "device-fingerprint", context.deviceId)}`]
      : []),
  ];
  const checkRate = async (
    operation: "request_code" | "verify_code" | "refresh",
    keys: string[],
    at: Date,
  ) => {
    const result = await options.rateLimiter.consume({
      operation,
      keys,
      now: at,
    });
    if (!result.allowed)
      throw new AuthError(
        "RATE_LIMITED",
        "Too many requests",
        429,
        result.retryAfterMs,
      );
  };
  async function mintAccess(record: SessionRecord<TClaims>, at: Date) {
    return new SignJWT({
      sid: record.id,
      roles: record.roles,
      permissions: record.permissions,
      claims: record.claims,
    })
      .setProtectedHeader({
        alg: activeKey.algorithm,
        typ: "JWT",
        kid: activeKey.kid,
      })
      .setSubject(record.userId)
      .setIssuer(cfg.issuer)
      .setAudience(cfg.audience)
      .setJti(randomId())
      .setIssuedAt(Math.floor(at.getTime() / 1000))
      .setExpirationTime(Math.floor(at.getTime() / 1000) + cfg.accessTtlSeconds)
      .sign(
        activeKey.algorithm === "HS256"
          ? activeKey.secret
          : activeKey.privateKey,
      );
  }
  async function tokenPair(
    record: SessionRecord<TClaims>,
    refresh: string,
    at: Date,
  ): Promise<TokenPair> {
    return {
      accessToken: await mintAccess(record, at),
      refreshToken: `${record.id}.${refresh}`,
      accessTokenExpiresAt: new Date(
        at.getTime() + cfg.accessTtlSeconds * 1000,
      ),
      refreshTokenExpiresAt: record.expiresAt,
      sessionId: record.id,
    };
  }

  async function verifyAccessToken(
    token: string,
    checkSession = true,
  ): Promise<AuthContext<TClaims>> {
    try {
      const header = decodeProtectedHeader(token);
      if (
        typeof header.alg !== "string" ||
        !["HS256", "ES256", "RS256", "EdDSA"].includes(header.alg) ||
        typeof header.kid !== "string"
      )
        throw new Error("invalid protected header");
      const key = accessKeys.get(header.kid);
      if (!key) throw new Error("unknown key ID");
      if (header.alg !== key.algorithm) throw new Error("algorithm mismatch");
      const verificationKey =
        key.algorithm === "HS256" ? key.secret : key.publicKey;
      const verified = await jwtVerify(token, verificationKey, {
        algorithms: [key.algorithm],
        issuer: cfg.issuer,
        audience: cfg.audience,
        clockTolerance: cfg.clockToleranceSeconds,
        typ: "JWT",
      });
      const parsed = accessClaims.parse(verified.payload);
      if (checkSession) {
        const session = await options.sessions.get(parsed.sid);
        if (
          !session ||
          session.status !== "active" ||
          session.expiresAt <= now() ||
          session.userId !== parsed.sub
        )
          throw new AuthError("SESSION_REVOKED", "Session revoked", 401);
      }
      return {
        userId: parsed.sub,
        sessionId: parsed.sid,
        roles: parsed.roles,
        permissions: parsed.permissions,
        claims: parsed.claims as TClaims,
        issuedAt: new Date(parsed.iat * 1000),
        expiresAt: new Date(parsed.exp * 1000),
      };
    } catch (error) {
      if (error instanceof AuthError) throw error;
      throw new AuthError("INVALID_TOKEN", "Invalid access token", 401);
    }
  }

  return {
    async requestCode(raw: {
      phone: string;
      purpose: AuthPurpose;
      scope?: string;
      actorAccessToken?: string;
      context?: RequestContext;
    }) {
      const input = requestCodeSchema.parse(raw);
      const scope = scopeOf(input.scope);
      const phone = normalizeIranianPhone(input.phone);
      const at = now();
      const phoneFingerprint = fingerprint(phone);
      await checkRate(
        "request_code",
        rateKeys(phoneFingerprint, scope, raw.context),
        at,
      );
      if (!(await options.authorizeScope(scope, raw.context)))
        throw new AuthError(
          "INVALID_INPUT",
          "Invalid authentication request",
          400,
        );
      const requiresActor =
        input.purpose === "phone_verification" ||
        input.purpose === "sensitive_action";
      if (requiresActor && !input.actorAccessToken)
        throw new AuthError(
          "INVALID_INPUT",
          "This purpose requires an authenticated actor",
          400,
        );
      if (!requiresActor && input.actorAccessToken)
        throw new AuthError(
          "INVALID_INPUT",
          "Actor token is not valid for this purpose",
          400,
        );
      const actor = input.actorAccessToken
        ? await verifyAccessToken(input.actorAccessToken, true)
        : undefined;
      const code = generateCode(cfg.codeLength);
      const key = challengeKey(
        phone,
        input.purpose,
        scope,
        actor?.userId,
        actor?.sessionId,
      );
      const record: ChallengeRecord = {
        id: randomId(),
        key,
        phone,
        phoneFingerprint,
        purpose: input.purpose,
        scope,
        ...(actor
          ? { actorUserId: actor.userId, actorSessionId: actor.sessionId }
          : {}),
        codeHash: keyedHash(pepper, `otp:${cfg.pepper.kid}`, `${key}\0${code}`),
        pepperVersion: cfg.pepper.kid,
        state: "dispatching",
        attempts: 0,
        maxAttempts: cfg.maxAttempts,
        createdAt: at,
        expiresAt: new Date(at.getTime() + cfg.challengeTtlMs),
        cleanupAt: new Date(at.getTime() + cfg.challengeTtlMs + 86_400_000),
        resendAvailableAt: new Date(at.getTime() + cfg.resendCooldownMs),
      };
      const reservation = await options.challenges.reserve(record, at);
      if (reservation.status === "cooldown")
        throw new AuthError(
          "CHALLENGE_COOLDOWN",
          "A challenge was recently sent",
          429,
          reservation.retryAfterMs,
        );
      await safelyObserve(options.observer, {
        type: "challenge.requested",
        occurredAt: at,
        phoneFingerprint,
        purpose: input.purpose,
        ...(raw.context?.correlationId
          ? { correlationId: raw.context.correlationId }
          : {}),
      });
      try {
        await options.sms.send(
          options.smsActions[input.purpose],
          { recipient: phone, code },
          raw.context?.signal ? { signal: raw.context.signal } : undefined,
        );
      } catch {
        await options.challenges.fail(record.id);
        await safelyObserve(options.observer, {
          type: "challenge.failed",
          occurredAt: now(),
          phoneFingerprint,
          purpose: input.purpose,
          ...(raw.context?.correlationId
            ? { correlationId: raw.context.correlationId }
            : {}),
        });
        throw new AuthError(
          "SMS_DELIVERY_FAILED",
          "Unable to dispatch authentication challenge",
          503,
        );
      }
      if (!(await options.challenges.activate(record.id)))
        throw new AuthError(
          "INVALID_CHALLENGE",
          "Challenge was superseded",
          409,
        );
      await safelyObserve(options.observer, {
        type: "challenge.dispatched",
        occurredAt: now(),
        phoneFingerprint,
        purpose: input.purpose,
        ...(raw.context?.correlationId
          ? { correlationId: raw.context.correlationId }
          : {}),
      });
      return { accepted: true as const, expiresAt: record.expiresAt };
    },

    async verifyCode(raw: {
      phone: string;
      purpose: AuthPurpose;
      code: string;
      scope?: string;
      actorAccessToken?: string;
      context?: RequestContext;
    }): Promise<VerifyCodeResult> {
      const input = verifyCodeSchema.parse(raw);
      const scope = scopeOf(input.scope);
      const phone = normalizeIranianPhone(input.phone);
      const at = now();
      const phoneFingerprint = fingerprint(phone);
      await checkRate(
        "verify_code",
        rateKeys(phoneFingerprint, scope, raw.context),
        at,
      );
      if (!(await options.authorizeScope(scope, raw.context)))
        throw new AuthError(
          "INVALID_INPUT",
          "Invalid authentication request",
          400,
        );
      const requiresActor =
        input.purpose === "phone_verification" ||
        input.purpose === "sensitive_action";
      if (requiresActor && !input.actorAccessToken)
        throw new AuthError(
          "INVALID_INPUT",
          "This purpose requires an authenticated actor",
          400,
        );
      if (!requiresActor && input.actorAccessToken)
        throw new AuthError(
          "INVALID_INPUT",
          "Actor token is not valid for this purpose",
          400,
        );
      const actor = input.actorAccessToken
        ? await verifyAccessToken(input.actorAccessToken, true)
        : undefined;
      const key = challengeKey(
        phone,
        input.purpose,
        scope,
        actor?.userId,
        actor?.sessionId,
      );
      const result = await options.challenges.consumeAttempt(
        key,
        keyedHash(pepper, `otp:${cfg.pepper.kid}`, `${key}\0${input.code}`),
        at,
      );
      if (result.status !== "verified") {
        await safelyObserve(options.observer, {
          type: "challenge.rejected",
          occurredAt: at,
          phoneFingerprint,
          purpose: input.purpose,
          ...(raw.context?.correlationId
            ? { correlationId: raw.context.correlationId }
            : {}),
        });
        throw new AuthError(
          "INVALID_CHALLENGE",
          "Invalid or expired code",
          401,
        );
      }
      if (
        input.purpose === "phone_verification" ||
        input.purpose === "sensitive_action"
      ) {
        await safelyObserve(options.observer, {
          type: "challenge.verified",
          occurredAt: at,
          phoneFingerprint,
          purpose: input.purpose,
          userId: actor!.userId,
        });
        return {
          kind: "challenge_verified",
          purpose: input.purpose,
          userId: actor!.userId,
        };
      }
      const identity = await options.identities.resolve({
        phone,
        purpose: input.purpose,
        scope,
        createIfMissing: input.purpose === "login",
      });
      if (!identity)
        throw new AuthError(
          "ACCOUNT_NOT_FOUND",
          "Account is not eligible",
          403,
        );
      if (identity.eligible === false)
        throw new AuthError(
          "ACCOUNT_INELIGIBLE",
          "Account is not eligible",
          403,
        );
      const rawRefresh = randomToken();
      const session: SessionRecord<TClaims> = {
        id: randomId(),
        familyId: randomId(),
        userId: identity.userId,
        scope,
        refreshHash: keyedHash(pepper, `refresh:${cfg.pepper.kid}`, rawRefresh),
        spentRefreshHashes: [],
        status: "active",
        roles: identity.roles ?? [],
        permissions: identity.permissions ?? [],
        claims: identity.claims ?? ({} as TClaims),
        createdAt: at,
        lastUsedAt: at,
        expiresAt: new Date(at.getTime() + cfg.refreshTtlSeconds * 1000),
        ...(raw.context?.userAgent ? { userAgent: raw.context.userAgent } : {}),
        ...(cfg.retainIpFingerprint && raw.context?.ip
          ? {
              ipFingerprint: keyedHash(
                pepper,
                "ip-fingerprint",
                raw.context.ip,
              ),
            }
          : {}),
      };
      await options.sessions.create(session);
      await safelyObserve(options.observer, {
        type: "session.created",
        occurredAt: at,
        sessionId: session.id,
        userId: session.userId,
        phoneFingerprint,
      });
      return {
        kind: "session",
        tokens: await tokenPair(session, rawRefresh, at),
      };
    },

    async refresh(input: { refreshToken: string; context?: RequestContext }) {
      const parts = input.refreshToken.split(".");
      if (parts.length !== 2 || !parts[0] || !parts[1])
        throw new AuthError("INVALID_TOKEN", "Invalid refresh token", 401);
      const [sessionId, presented] = parts as [string, string];
      const at = now();
      const currentSession = await options.sessions.get(sessionId);
      if (!currentSession)
        throw new AuthError("SESSION_REVOKED", "Session is invalid", 401);
      if (
        options.identities.checkEligibility &&
        !(await options.identities.checkEligibility(
          currentSession.userId,
          currentSession.scope,
        ))
      ) {
        await options.sessions.revokeAll(currentSession.userId);
        throw new AuthError("ACCOUNT_INELIGIBLE", "Session is invalid", 401);
      }
      await checkRate(
        "refresh",
        [
          `session:${sessionId}`,
          ...(input.context?.ip
            ? [`ip:${keyedHash(pepper, "ip-fingerprint", input.context.ip)}`]
            : []),
        ],
        at,
      );
      const next = randomToken();
      const result = await options.sessions.rotate(
        sessionId,
        keyedHash(pepper, `refresh:${cfg.pepper.kid}`, presented),
        keyedHash(pepper, `refresh:${cfg.pepper.kid}`, next),
        at,
      );
      if (result.status === "reused") {
        await safelyObserve(options.observer, {
          type: "session.reuse_detected",
          occurredAt: at,
          sessionId,
        });
        throw new AuthError("TOKEN_REUSE", "Refresh token reuse detected", 401);
      }
      if (result.status !== "rotated")
        throw new AuthError("SESSION_REVOKED", "Session is invalid", 401);
      await safelyObserve(options.observer, {
        type: "session.refreshed",
        occurredAt: at,
        sessionId,
        userId: result.record.userId,
      });
      return tokenPair(result.record, next, at);
    },

    verifyAccessToken,

    async listSessions(input: {
      accessToken: string;
    }): Promise<SessionSummary[]> {
      const actor = await verifyAccessToken(input.accessToken, true);
      return (await options.sessions.list(actor.userId)).map((session) => ({
        id: session.id,
        current: session.id === actor.sessionId,
        status: session.status,
        createdAt: session.createdAt,
        expiresAt: session.expiresAt,
        lastUsedAt: session.lastUsedAt,
        ...(session.userAgent ? { userAgent: session.userAgent } : {}),
      }));
    },
    async revokeSession(input: { sessionId: string; accessToken: string }) {
      const actor = await verifyAccessToken(input.accessToken, true);
      if (!(await options.sessions.revokeOwned(input.sessionId, actor.userId)))
        throw new AuthError(
          "FORBIDDEN",
          "Session does not belong to the actor",
          403,
        );
      await safelyObserve(options.observer, {
        type: "session.revoked",
        occurredAt: now(),
        sessionId: input.sessionId,
        userId: actor.userId,
      });
    },
    async logout(input: { accessToken: string }) {
      const actor = await verifyAccessToken(input.accessToken, true);
      if (!(await options.sessions.revokeOwned(actor.sessionId, actor.userId)))
        throw new AuthError("SESSION_REVOKED", "Session is invalid", 401);
      await safelyObserve(options.observer, {
        type: "session.revoked",
        occurredAt: now(),
        sessionId: actor.sessionId,
        userId: actor.userId,
      });
    },
    async revokeAllSessions(input: { accessToken: string }) {
      const actor = await verifyAccessToken(input.accessToken, true);
      const count = await options.sessions.revokeAll(actor.userId);
      await safelyObserve(options.observer, {
        type: "session.all_revoked",
        occurredAt: now(),
        userId: actor.userId,
        metadata: { count },
      });
      return count;
    },
  };
}
