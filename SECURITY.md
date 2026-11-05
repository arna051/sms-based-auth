# Security policy

## Supported versions

Until 1.0, only the latest published minor release receives security fixes.

## Reporting

Use GitHub private vulnerability reporting for this repository. Do not open a public issue. Include affected version, impact, a minimal reproduction, and mitigations. Never include real phone numbers, OTPs, tokens, cookies, signing keys, provider credentials, or private user data.

We aim to acknowledge reports within three business days, provide an initial assessment within seven business days, and coordinate disclosure after a fix is available.

## Security assumptions

SMS OTP is not phishing-resistant and is not strong MFA. Hosts own tenant derivation, identity uniqueness, account eligibility, authorization, proxy trust, CORS, CSRF wiring, secret management, retention, monitoring, and production store operation. Edge middleware is routing assistance, not stateful authorization.
