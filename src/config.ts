import { z } from 'zod';
const schema = z.object({
  issuer: z.string().min(1), audience: z.string().min(1), secret: z.instanceof(Uint8Array).refine(v => v.byteLength >= 32, 'secret must be at least 32 bytes'),
  codeLength: z.number().int().min(6).max(10).default(6), challengeTtlMs: z.number().int().min(30_000).max(900_000).default(300_000),
  maxAttempts: z.number().int().min(1).max(10).default(5), accessTtlSeconds: z.number().int().min(60).max(3600).default(600),
  refreshTtlSeconds: z.number().int().min(3600).max(31_536_000).default(2_592_000), clockToleranceSeconds: z.number().int().min(0).max(120).default(5)
});
export type SecurityConfig = z.input<typeof schema>;
export type ResolvedSecurityConfig = z.output<typeof schema>;
export const resolveConfig = (value: SecurityConfig): ResolvedSecurityConfig => schema.parse(value);
