# Deployment guide

## Required infrastructure

Node.js 20 or newer is supported. Production Mongoose stores require a MongoDB replica set; standalone MongoDB is intentionally unsupported because transactions cannot be guaranteed. Redis is recommended for distributed rate limiting. Both clients are created, configured, monitored, and closed by the host.

Create/synchronize indexes during a controlled deployment. The challenge collection needs the partial unique active-key index and cleanup TTL; the session collection needs user/family indexes and an expiry TTL. Review index changes before calling `syncIndexes()`.

## Secrets and key rotation

Use independent secrets for access signing, OTP/refresh peppering, and SMS providers. Store them in a secret manager. Never expose private or symmetric signing keys to browsers or Edge bundles.

To rotate access keys:

1. Add the new key while retaining old verification keys.
2. Set `activeAccessTokenKid` to the new key.
3. Deploy all issuers, then all verifiers.
4. Wait longer than access-token TTL plus clock tolerance.
5. Remove the retired verification key.

To rotate OTP and refresh peppers, deploy the new key as `pepper` and keep old
keys in `verificationPeppers`. New refresh rotations migrate sessions to the
active key automatically. Retain every old key through the longest live refresh
session (or explicitly revoke those sessions), then remove it. Use a separate,
stable `fingerprintPepper` across rotations so phone/IP/device abuse buckets and
privacy-preserving metadata remain comparable.

Implement `identities.reauthorize` when authorization may change during a
refresh session. Its result is written atomically with refresh rotation before
the new access token is minted.

## HTTP

Configure trusted proxies explicitly before deriving `context.ip`. For cookie mode, terminate TLS correctly, allow only explicit origins, use credentialed CORS narrowly, and require CSRF on state changes. Set `Cache-Control: no-store` on token responses. Native clients should use OS credential storage.

## Privacy and retention

Raw IP retention is disabled by default; optional IP values are keyed fingerprints. Define retention for challenges, sessions, and audit events. User agents can contain identifying data. Keep audit metadata allowlisted and append-oriented.

## Observability

Alert on rate-limit spikes, SMS failure rate, OTP lockouts, refresh reuse, family revocation, abnormal tenant volume, and store failures. Observers must not receive secrets and cannot change authentication outcomes.

## Release verification

Run `npm run check`, `npm run package:check`, real integration tests, `npm audit`, secret scanning, and an independent security review. Normal CI uses a fake SMS sender and never sends messages.
