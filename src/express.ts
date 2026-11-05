import type { NextFunction, Request, RequestHandler, Response } from 'express';
import type { AuthContext } from './types.js';
type Verifier<T extends Record<string, unknown>> = { verifyAccessToken(token: string, checkSession?: boolean): Promise<AuthContext<T>> };
export function createExpressAuth<T extends Record<string, unknown>>(auth: Verifier<T>, options: { cookieName?: string; checkSession?: boolean } = {}) {
  const contexts = new WeakMap<Request, AuthContext<T>>();
  const requireAuth = (): RequestHandler => async (req,res,next) => { try { const bearer=req.headers.authorization?.match(/^Bearer (.+)$/i)?.[1]; const cookie=options.cookieName && req.headers.cookie?.split(';').map(v=>v.trim()).find(v=>v.startsWith(`${options.cookieName}=`))?.slice(options.cookieName.length+1); const token=bearer??cookie; if(!token){res.status(401).json({error:'unauthorized'});return;} contexts.set(req,await auth.verifyAccessToken(decodeURIComponent(token),options.checkSession)); next(); } catch(error){ next(error); } };
  const requireRoles = (...roles: string[]): RequestHandler => (req,res,next) => { const ctx=contexts.get(req); if(!ctx){res.status(401).json({error:'unauthorized'});return;} if(!roles.every(r=>ctx.roles.includes(r))){res.status(403).json({error:'forbidden'});return;} next(); };
  return { requireAuth, requireRoles, getAuth: (request: Request) => contexts.get(request) };
}
