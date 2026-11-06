import { z } from "zod";

const hmacKeySchema = z.object({
  kid: z.string().min(1).max(64),
  algorithm: z.literal("HS256"),
  secret: z
    .instanceof(Uint8Array)
    .refine(
      (value) => value.byteLength >= 32,
      "key secret must be at least 32 bytes",
    ),
});
const asymmetricKeySchema = z.object({
  kid: z.string().min(1).max(64),
  algorithm: z.enum(["ES256", "RS256", "EdDSA"]),
  privateKey: z.custom<CryptoKey>(
    (value) => typeof CryptoKey !== "undefined" && value instanceof CryptoKey,
  ),
  publicKey: z.custom<CryptoKey>(
    (value) => typeof CryptoKey !== "undefined" && value instanceof CryptoKey,
  ),
});
const accessTokenKeySchema = z.discriminatedUnion("algorithm", [
  hmacKeySchema,
  asymmetricKeySchema,
]);
const schema = z.object({
  issuer: z.string().min(1),
  audience: z.string().min(1),
  accessTokenKeys: z.array(accessTokenKeySchema).min(1),
  activeAccessTokenKid: z.string().min(1),
  pepper: hmacKeySchema,
  verificationPeppers: z.array(hmacKeySchema).max(8).default([]),
  fingerprintPepper: hmacKeySchema.optional(),
  codeLength: z.number().int().min(6).max(10).default(6),
  challengeTtlMs: z.number().int().min(30_000).max(900_000).default(300_000),
  resendCooldownMs: z.number().int().min(5_000).max(900_000).default(60_000),
  maxAttempts: z.number().int().min(1).max(10).default(5),
  accessTtlSeconds: z.number().int().min(60).max(3600).default(600),
  refreshTtlSeconds: z
    .number()
    .int()
    .min(3600)
    .max(31_536_000)
    .default(2_592_000),
  clockToleranceSeconds: z.number().int().min(0).max(120).default(5),
  requireScope: z.boolean().default(true),
  retainIpFingerprint: z.boolean().default(false),
});
export type SecurityConfig = z.input<typeof schema>;
export type ResolvedSecurityConfig = z.output<typeof schema> & {
  pepperRing: z.output<typeof hmacKeySchema>[];
};
export function resolveConfig(value: SecurityConfig): ResolvedSecurityConfig {
  const config = schema.parse(value);
  if (
    !config.accessTokenKeys.some(
      (key) => key.kid === config.activeAccessTokenKid,
    )
  )
    throw new Error(
      "activeAccessTokenKid must identify a configured access-token key",
    );
  if (
    new Set(config.accessTokenKeys.map((key) => key.kid)).size !==
    config.accessTokenKeys.length
  )
    throw new Error("access-token key IDs must be unique");
  const pepperRing = [config.pepper, ...config.verificationPeppers];
  if (new Set(pepperRing.map((key) => key.kid)).size !== pepperRing.length)
    throw new Error("pepper key IDs must be unique");
  if (pepperRing.length > 1 && !config.fingerprintPepper)
    throw new Error(
      "fingerprintPepper is required during pepper rotation to preserve stable challenge and abuse keys",
    );
  return { ...config, pepperRing };
}
