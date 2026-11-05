export type AuthErrorCode =
  | "INVALID_INPUT"
  | "RATE_LIMITED"
  | "CHALLENGE_COOLDOWN"
  | "INVALID_CHALLENGE"
  | "ACCOUNT_NOT_FOUND"
  | "ACCOUNT_INELIGIBLE"
  | "INVALID_TOKEN"
  | "TOKEN_REUSE"
  | "SESSION_REVOKED"
  | "FORBIDDEN"
  | "SMS_DELIVERY_FAILED"
  | "MISCONFIGURED";
export class AuthError extends Error {
  constructor(
    public readonly code: AuthErrorCode,
    message: string,
    public readonly status: number,
    public readonly retryAfterMs?: number,
  ) {
    super(message);
    this.name = "AuthError";
  }
}
export interface AuthProblem {
  type: string;
  title: string;
  status: number;
  code: AuthErrorCode;
}
export function toAuthProblem(error: AuthError): AuthProblem {
  return {
    type: `https://sms-based-auth.dev/problems/${error.code.toLowerCase()}`,
    title: error.message,
    status: error.status,
    code: error.code,
  };
}
