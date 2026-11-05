export type AuthErrorCode = 'INVALID_INPUT' | 'RATE_LIMITED' | 'INVALID_CHALLENGE' | 'ACCOUNT_INELIGIBLE' | 'INVALID_TOKEN' | 'TOKEN_REUSE' | 'SESSION_REVOKED' | 'MISCONFIGURED';
export class AuthError extends Error {
  constructor(public readonly code: AuthErrorCode, message: string, public readonly status: number, public readonly cause?: unknown) { super(message); this.name = 'AuthError'; }
}
