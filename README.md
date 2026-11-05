# sms-based-auth

Security-first, framework-neutral SMS authentication for Node.js. It generates purpose-bound OTP challenges, delegates delivery to a typed host SMS manager, and manages short-lived access tokens plus rotating opaque refresh sessions.

> SMS OTP is not phishing-resistant and is not strong MFA. Use a phishing-resistant factor for high-value operations.

## Features

- Iranian mobile normalization to E.164, including Persian and Arabic-Indic digits
- Explicit isolated purposes: `login`, `phone_verification`, `account_recovery`, and `sensitive_action`
- CSPRNG OTPs, keyed hashes, attempt limits, resend cooldown, abuse buckets, atomic single use
- Actor/session-bound sensitive challenges
- Rotating refresh tokens, family reuse detection, session listing and revocation
- HS256 for single-service deployments and ES256/RS256/EdDSA for multi-service or Edge verification
- JSON, hardened cookie, hybrid, and custom delivery
- Express, NestJS, Next.js App Router, and Web-Crypto Edge exports
- Caller-supplied Mongoose and Redis clients; no hidden connections
- ESM, CommonJS, and declarations for every subpath

## Install

```sh
npm install sms-based-auth jose zod
```

Install only the optional peers you use: `express`, `mongoose`, `redis`, `@nestjs/common`, `@nestjs/core`, `reflect-metadata`, and `rxjs`.

## Core setup

```ts
import { randomBytes } from "node:crypto";
import { createSmsBasedAuth } from "sms-based-auth";
import {
  MemoryChallengeStore,
  MemoryRateLimiter,
  MemorySessionStore,
} from "sms-based-auth/memory";

const signingSecret = randomBytes(32);
const pepperSecret = randomBytes(32);

const auth = createSmsBasedAuth({
  config: {
    issuer: "https://api.example.com",
    audience: "example-app",
    accessTokenKeys: [
      { kid: "access-2026-01", algorithm: "HS256", secret: signingSecret },
    ],
    activeAccessTokenKid: "access-2026-01",
    pepper: { kid: "pepper-2026-01", algorithm: "HS256", secret: pepperSecret },
  },
  challenges: new MemoryChallengeStore(),
  sessions: new MemorySessionStore(),
  rateLimiter: new MemoryRateLimiter(),
  sms: smsManager,
  smsActions: {
    login: "auth",
    phone_verification: "verify",
    account_recovery: "recover",
    sensitive_action: "sensitive",
  },
  authorizeScope: async (scope, context) => tenantPolicy.allows(scope, context),
  identities: {
    resolve: ({ phone, purpose, scope, createIfMissing }) =>
      userRepository.resolvePhone({ phone, purpose, scope, createIfMissing }),
  },
});
```

Memory stores are single-process development references, not production stores.

```ts
await auth.requestCode({
  phone: "09123456789",
  purpose: "login",
  scope: "tenant-id",
  context: { ip, userAgent },
});

const result = await auth.verifyCode({
  phone: "09123456789",
  purpose: "login",
  code: "483291",
  scope: "tenant-id",
  context: { ip, userAgent },
});
```

For `phone_verification` and `sensitive_action`, provide `actorAccessToken`. The core verifies the token and active session and binds both user and session IDs into the challenge. Never accept a client-provided user ID as the actor.

## Production persistence

Use `createAuthModels`, `MongooseChallengeStore`, and `MongooseSessionStore` from `sms-based-auth/mongoose`. A MongoDB replica set is mandatory because security transitions use transactions. Run `syncIndexes()` during a controlled migration, not on every application start. Challenges use a grace-period cleanup TTL and a partial unique active-challenge index.

Use `RedisRateLimiter` from `sms-based-auth/redis` with a caller-owned connected Redis client. Rate-limit context IPs must come only from a correctly configured trusted-proxy chain. Device IDs and user agents are hints, not identities.

## Token delivery

`deliverTokens(tokens, mode, cookieOptions)` supports:

- `cookie`: HttpOnly access and refresh cookies
- `json`: response-body tokens for native, CLI, or trusted non-browser clients
- `hybrid`: access token in memory/JSON and refresh token in HttpOnly cookie
- `custom`: transport-neutral token result for host delivery

Defaults are `__Host-sba_access` (`Secure; Path=/`) and `__Secure-sba_refresh` with the narrow `/auth/refresh` path. Cookie-authenticated state changes must use allowed origins and `createCsrfTokenCookie` plus the adapter CSRF guard. Never store durable browser secrets in `localStorage`.

## Framework adapters

```ts
import { createExpressAuth } from "sms-based-auth/express";
const expressAuth = createExpressAuth(auth, {
  csrf: { expectedOrigin: "https://app.example.com" },
});
app.get("/profile", expressAuth.requireAuth(), handler);
app.get(
  "/orders",
  expressAuth.requireAuth(),
  expressAuth.requirePermissions("orders.read"),
  handler,
);
app.post("/settings", expressAuth.requireCsrf(), handler);
```

NestJS exports `SmsBasedAuthModule`, `SmsAuthGuard`, `CurrentAuth`, `RequireRoles`, and `RequirePermissions`, with `forRoot` and `forRootAsync`. Controllers can be disabled.

Next.js exports `withAuth` for Node App Router handlers. Pages Router is deferred. Mark routes using database/session checks as `runtime = "nodejs"`.

The `edge` export only verifies short-lived asymmetric tokens and makes routing decisions. It contains no signing/private key or stateful revocation check. Re-check sensitive authorization in a trusted Node backend.

## Security and operations

Read [THREAT_MODEL.md](THREAT_MODEL.md), [DEPLOYMENT.md](DEPLOYMENT.md), [SECURITY.md](SECURITY.md), and [MIGRATION.md](MIGRATION.md) before production use. Keep access-token signing keys, OTP peppers, refresh hashes, OTPs, cookies, and provider secrets out of logs.

## Validation

```sh
npm run check
npm run package:check
npm run integration:up
npm run test:integration
npm run integration:down
npm audit
```

The integration suite uses a real MongoDB replica set and Redis instance.
