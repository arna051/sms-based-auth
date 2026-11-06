export const AUTH_PURPOSES = [
  "login",
  "phone_verification",
  "account_recovery",
  "sensitive_action",
] as const;
export type AuthPurpose = (typeof AUTH_PURPOSES)[number];
export type SessionPurpose = "login" | "account_recovery";
export type ChallengeState =
  | "dispatching"
  | "active"
  | "verifying"
  | "verified"
  | "failed"
  | "expired"
  | "locked"
  | "superseded";
export type SessionStatus = "active" | "revoked" | "compromised" | "expired";

export interface RequestContext {
  ip?: string;
  userAgent?: string;
  deviceId?: string;
  correlationId?: string;
  signal?: AbortSignal;
}
export interface AuthContext<
  TClaims extends Record<string, unknown> = Record<string, unknown>,
> {
  userId: string;
  scope: string;
  sessionId: string;
  roles: string[];
  permissions: string[];
  claims: TClaims;
  issuedAt: Date;
  expiresAt: Date;
}
export interface ChallengeRecord {
  id: string;
  key: string;
  phone: string;
  phoneFingerprint: string;
  purpose: AuthPurpose;
  scope: string;
  actorUserId?: string;
  actorSessionId?: string;
  codeHash: string;
  pepperVersion: string;
  state: ChallengeState;
  attempts: number;
  maxAttempts: number;
  expiresAt: Date;
  cleanupAt: Date;
  resendAvailableAt: Date;
  createdAt: Date;
}
export interface ChallengeReservation {
  status: "reserved" | "cooldown";
  retryAfterMs?: number;
}
export interface ChallengeStore {
  reserve(record: ChallengeRecord, now: Date): Promise<ChallengeReservation>;
  activate(id: string): Promise<boolean>;
  fail(id: string): Promise<void>;
  completeVerification(id: string): Promise<boolean>;
  releaseVerification(id: string): Promise<void>;
  consumeAttempt(
    key: string,
    candidateHash: string,
    now: Date,
  ): Promise<{
    status: "verified" | "invalid" | "expired" | "locked" | "missing";
    record?: ChallengeRecord;
  }>;
  consumeAttemptVersioned?(
    candidates: ReadonlyArray<{
      pepperVersion: string;
      key: string;
      candidateHash: string;
    }>,
    now: Date,
  ): Promise<{
    status: "verified" | "invalid" | "expired" | "locked" | "missing";
    record?: ChallengeRecord;
  }>;
}
export interface SessionRecord<
  TClaims extends Record<string, unknown> = Record<string, unknown>,
> {
  id: string;
  familyId: string;
  userId: string;
  scope: string;
  refreshHash: string;
  refreshPepperVersion?: string;
  spentRefreshHashes: string[];
  status: SessionStatus;
  roles: string[];
  permissions: string[];
  claims: TClaims;
  createdAt: Date;
  expiresAt: Date;
  lastUsedAt: Date;
  userAgent?: string;
  ipFingerprint?: string;
}
export interface SessionSummary {
  id: string;
  current: boolean;
  status: SessionStatus;
  createdAt: Date;
  expiresAt: Date;
  lastUsedAt: Date;
  userAgent?: string;
}
export interface SessionStore<
  TClaims extends Record<string, unknown> = Record<string, unknown>,
> {
  create(record: SessionRecord<TClaims>): Promise<void>;
  rotate(
    sessionId: string,
    presentedHash: string,
    nextHash: string,
    now: Date,
    update?: {
      nextPepperVersion?: string;
      presentedHashes?: string[];
      authorization?: {
        roles: string[];
        permissions: string[];
        claims: TClaims;
      };
    },
  ): Promise<
    | { status: "rotated"; record: SessionRecord<TClaims> }
    | { status: "reused" | "invalid" }
  >;
  get(sessionId: string): Promise<SessionRecord<TClaims> | undefined>;
  list(scope: string, userId: string): Promise<SessionRecord<TClaims>[]>;
  revokeOwned(
    sessionId: string,
    scope: string,
    userId: string,
  ): Promise<boolean>;
  revokeFamily(familyId: string): Promise<number>;
  revokeAll(scope: string, userId: string): Promise<number>;
}
export interface SmsSender<TAction extends string = string> {
  send(
    action: TAction,
    variables: { recipient: string; code: string },
    options?: { signal?: AbortSignal },
  ): Promise<void>;
}
export interface Identity<TClaims extends Record<string, unknown>> {
  userId: string;
  roles?: string[];
  permissions?: string[];
  claims?: TClaims;
  eligible?: boolean;
}
export interface IdentityProvider<TClaims extends Record<string, unknown>> {
  resolve(input: {
    phone: string;
    purpose: SessionPurpose;
    scope: string;
    createIfMissing: boolean;
  }): Promise<Identity<TClaims> | undefined>;
  checkEligibility?(userId: string, scope: string): Promise<boolean>;
  reauthorize?(input: {
    userId: string;
    scope: string;
    sessionId: string;
  }): Promise<
    | {
        roles?: string[];
        permissions?: string[];
        claims?: TClaims;
        eligible?: boolean;
      }
    | undefined
  >;
}
export interface RateLimitRequest {
  operation: "request_code" | "verify_code" | "refresh";
  keys: string[];
  now: Date;
}
export interface RateLimiter {
  consume(
    input: RateLimitRequest,
  ): Promise<{ allowed: true } | { allowed: false; retryAfterMs: number }>;
}
export type AuditEventType =
  | "challenge.requested"
  | "challenge.dispatched"
  | "challenge.failed"
  | "challenge.rejected"
  | "challenge.verified"
  | "session.created"
  | "session.refreshed"
  | "session.reuse_detected"
  | "session.revoked"
  | "session.all_revoked";
export interface AuditEvent {
  type: AuditEventType;
  occurredAt: Date;
  correlationId?: string;
  userId?: string;
  sessionId?: string;
  phoneFingerprint?: string;
  purpose?: AuthPurpose;
  metadata?: Record<string, string | number | boolean>;
}
export interface Observer {
  emit(event: AuditEvent): void | Promise<void>;
}
export type AccessTokenKey =
  | { kid: string; algorithm: "HS256"; secret: Uint8Array }
  | {
      kid: string;
      algorithm: "ES256" | "RS256" | "EdDSA";
      privateKey: CryptoKey;
      publicKey: CryptoKey;
    };
export interface TokenPair {
  accessToken: string;
  refreshToken: string;
  accessTokenExpiresAt: Date;
  refreshTokenExpiresAt: Date;
  sessionId: string;
}
export type VerifyCodeResult =
  | { kind: "session"; tokens: TokenPair }
  | {
      kind: "challenge_verified";
      purpose: "phone_verification" | "sensitive_action";
      userId: string;
    };
