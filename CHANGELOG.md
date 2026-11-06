# Changelog

All notable changes follow Keep a Changelog. The project uses Semantic Versioning.

## [Unreleased]

- Added tenant-bound access contexts and tenant-isolated session administration.
- Added retry-safe OTP verification leases and downstream failure recovery.
- Added versioned OTP/refresh pepper rotation and refresh-time authorization reloads.
- Added NestJS cookie/hybrid transport, CSRF enforcement, and problem responses.

### Added

- Security-first OTP, session rotation, transport, framework, Mongoose, Redis, Edge, audit-observer, packaging, CI, and integration-test foundations.

### Security

- Purpose/scope isolation, authenticated actor-session binding, attempt and resend limits, HMAC secret storage, refresh-family replay detection, algorithm/key-ID pinning, hardened cookies, CSRF helpers, and Edge public-key verification.
