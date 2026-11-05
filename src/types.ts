export type AuthPurpose = 'login' | 'phone_verification' | 'account_recovery' | 'sensitive_action';
export type ChallengeState = 'dispatching' | 'active' | 'verified' | 'failed' | 'expired' | 'locked' | 'superseded';
export type SessionStatus = 'active' | 'revoked' | 'compromised' | 'expired';

export interface RequestContext { ip?: string; userAgent?: string; deviceId?: string; signal?: AbortSignal }
export interface AuthContext<TClaims extends Record<string, unknown> = Record<string, unknown>> {
  userId: string; sessionId: string; roles: string[]; permissions: string[]; claims: TClaims; issuedAt: Date; expiresAt: Date;
}
export interface ChallengeRecord {
  id: string; key: string; phone: string; purpose: AuthPurpose; scope: string; codeHash: string;
  state: ChallengeState; attempts: number; maxAttempts: number; expiresAt: Date; createdAt: Date;
}
export interface SessionRecord<TClaims extends Record<string, unknown> = Record<string, unknown>> {
  id: string; familyId: string; userId: string; refreshHash: string; spentRefreshHashes: string[];
  status: SessionStatus; roles: string[]; permissions: string[]; claims: TClaims;
  createdAt: Date; expiresAt: Date; lastUsedAt: Date; userAgent?: string; ip?: string;
}
export interface ChallengeStore {
  createReplacing(record: ChallengeRecord): Promise<void>;
  consumeAttempt(key: string, candidateHash: string, now: Date): Promise<{ status: 'verified' | 'invalid' | 'expired' | 'locked' | 'missing'; record?: ChallengeRecord }>;
}
export interface SessionStore<TClaims extends Record<string, unknown> = Record<string, unknown>> {
  create(record: SessionRecord<TClaims>): Promise<void>;
  rotate(sessionId: string, presentedHash: string, nextHash: string, now: Date): Promise<'rotated' | 'reused' | 'invalid'>;
  get(sessionId: string): Promise<SessionRecord<TClaims> | undefined>;
  list(userId: string): Promise<SessionRecord<TClaims>[]>;
  revoke(sessionId: string): Promise<void>;
  revokeAll(userId: string): Promise<number>;
}
export interface SmsSender<TAction extends string = string> { send(action: TAction, variables: { recipient: string; code: string }, options?: { signal?: AbortSignal }): Promise<void> }
export interface Identity<TClaims extends Record<string, unknown>> { userId: string; roles?: string[]; permissions?: string[]; claims?: TClaims; eligible?: boolean }
export interface IdentityProvider<TClaims extends Record<string, unknown>> { resolve(input: { phone: string; purpose: AuthPurpose; scope: string }): Promise<Identity<TClaims>> }
export interface TokenPair { accessToken: string; refreshToken: string; accessTokenExpiresAt: Date; refreshTokenExpiresAt: Date; sessionId: string }
