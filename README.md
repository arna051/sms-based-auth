# sms-based-auth

Security-first, framework-neutral phone/SMS authentication for Node.js. The package generates purpose-bound OTP challenges, delegates delivery to a caller-supplied SMS manager, and provides short-lived access JWTs with rotating opaque refresh tokens.

> **Status:** pre-1.0 foundation. The included memory stores are for development and single-process tests. Production deployments must supply durable stores whose transition methods are atomic across all application instances.

## Security model

- Iranian mobile numbers are canonicalized to E.164.
- OTPs and refresh tokens are never persisted in plaintext; keyed HMAC hashes use a caller-owned 256-bit secret.
- OTPs are purpose- and scope-bound, short-lived, attempt-limited, superseded on resend, and single-use.
- Refresh tokens rotate on every use. Reuse of the previous token marks the session family compromised.
- Access JWT validation pins `HS256`, issuer, audience, expiry, and claims. Use a unique secret per environment and rotate it through a coordinated deployment.
- Responses should remain generic at the HTTP boundary to reduce account enumeration.

The host remains responsible for trusted-proxy configuration, distributed rate limiting, CSRF/CORS policy, user eligibility, authorization policy, secrets management, audit retention, and transactional production stores.

## Example

```ts
import { createSmsBasedAuth } from 'sms-based-auth';
import { MemoryChallengeStore, MemorySessionStore } from 'sms-based-auth/memory';

const auth = createSmsBasedAuth({
  config: { issuer: 'https://api.example.com', audience: 'example-app', secret: crypto.getRandomValues(new Uint8Array(32)) },
  challenges: new MemoryChallengeStore(), sessions: new MemorySessionStore(),
  sms: smsManager,
  smsActions: { login: 'auth', phone_verification: 'verify', account_recovery: 'recover', sensitive_action: 'sensitive' },
  identities: { resolve: async ({ phone }) => userRepository.findOrCreateByPhone(phone) }
});
```

Never put durable browser tokens in `localStorage`. Prefer an `HttpOnly`, `Secure`, appropriately scoped refresh cookie with CSRF protection, or use an OS credential store on native clients.

## Planned adapters

The core ports intentionally allow MongoDB/Redis, NestJS, Next.js Node route handlers, and an isolated Web-Crypto Edge verifier without pulling those dependencies into the core. These integrations require their own concurrency and runtime test suites before being advertised as production-ready.
