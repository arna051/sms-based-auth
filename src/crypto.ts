import { createHmac, randomBytes, randomInt, timingSafeEqual } from 'node:crypto';
export const randomId = () => randomBytes(18).toString('base64url');
export const randomToken = () => randomBytes(32).toString('base64url');
export function generateCode(length: number): string { let out = ''; for (let i = 0; i < length; i++) out += randomInt(0, 10); return out; }
export function keyedHash(secret: Uint8Array, domain: string, value: string): string { return createHmac('sha256', secret).update(domain).update('\0').update(value).digest('base64url'); }
export function safeEqual(a: string, b: string): boolean { const x = Buffer.from(a); const y = Buffer.from(b); return x.length === y.length && timingSafeEqual(x, y); }
