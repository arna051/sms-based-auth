# Threat model

## Assets and attackers

Assets are OTPs, signing keys, refresh tokens, authenticated sessions, phone-to-user bindings, authorization claims, SMS spend, and audit evidence. Attackers include remote unauthenticated clients, compromised browsers, malicious tenants, leaked-database readers, replay attackers, provider/network failures, and operators with partial infrastructure access.

## Trust boundaries

```text
untrusted client
  -> host HTTP adapter (origin, proxy and input policy)
  -> sms-based-auth core
       -> challenge/session store (atomic trusted state)
       -> rate limiter (distributed abuse state)
       -> identity callbacks (host-owned user truth)
       -> sms-panel-manager -> external provider
```

The host derives tenant scope and trusted client IP. Phone numbers, codes, user agents, device identifiers, headers, roles, permissions, scope strings, and redirect targets supplied by clients are untrusted.

## State machines

```text
challenge: dispatching -> active -> verified
                         |-> expired | locked | superseded
             |-> failed

session: active -> revoked | expired | compromised
refresh: current -> spent + new current
         replay of any spent token -> family compromised
```

Store transitions must be atomic. Implementations that cannot meet the contracts must fail closed.

## Key controls

- Purpose, tenant scope, phone, actor user, and actor session are included in the challenge key.
- OTP and refresh values are never stored; HMAC hashes use a separately rotated pepper.
- Access-token verification pins algorithm, key ID, issuer, audience, subject, session ID, JTI, issue time, and expiry.
- Edge uses public asymmetric verification keys only.
- Generic HTTP responses should avoid revealing identity existence or eligibility.
- Per-phone limits alone can cause victim lockout; deployments must combine IP/device/tenant/global risk controls and escalation hooks.
- Cookie transports require Secure/HttpOnly attributes, allowed origins, credentialed CORS policy, and CSRF protection.
- Logs must redact Authorization, Cookie, Set-Cookie, OTPs, phone numbers, tokens, and provider errors.

## Residual risks

SMS is vulnerable to SIM swap, SS7/provider compromise, malware, phishing, number recycling, and delivery interception. Short-lived stateless access tokens cannot be immediately revoked unless Node routes enable session checks. Edge routing is not authorization. Device fingerprints are weak signals. Host authorization and resource ownership checks remain mandatory.
