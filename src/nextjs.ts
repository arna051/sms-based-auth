import { AuthError, toAuthProblem } from "./errors.js";
import { parseCookie } from "./transport.js";
import type { AuthContext } from "./types.js";
type Verifier<T extends Record<string, unknown>> = {
  verifyAccessToken(
    token: string,
    checkSession?: boolean,
  ): Promise<AuthContext<T>>;
};
export interface NextAuthContext<T extends Record<string, unknown>> {
  auth: AuthContext<T>;
  params?: Record<string, string | string[]>;
}
export function withAuth<T extends Record<string, unknown>>(
  auth: Verifier<T>,
  handler: (
    request: Request,
    context: NextAuthContext<T>,
  ) => Response | Promise<Response>,
  options: { cookieName?: string; checkSession?: boolean } = {},
) {
  return async (
    request: Request,
    routeContext: { params?: Record<string, string | string[]> } = {},
  ) => {
    const bearer = request.headers
      .get("authorization")
      ?.match(/^Bearer ([^\s]+)$/i)?.[1];
    const token =
      bearer ??
      parseCookie(
        request.headers.get("cookie"),
        options.cookieName ?? "__Host-sba_access",
      );
    if (!token)
      return Response.json(
        toAuthProblem(new AuthError("INVALID_TOKEN", "Unauthorized", 401)),
        { status: 401 },
      );
    try {
      const context = await auth.verifyAccessToken(
        token,
        options.checkSession ?? true,
      );
      return await handler(request, {
        auth: context,
        ...(routeContext.params ? { params: routeContext.params } : {}),
      });
    } catch (error) {
      if (error instanceof AuthError)
        return Response.json(toAuthProblem(error), { status: error.status });
      throw error;
    }
  };
}
