# Contributing

Use Node.js 20 or newer and `npm ci`. Do not use real SMS credentials or personal phone numbers.

Before submitting changes:

```sh
npm run check
npm run package:check
npm run integration:up
npm run test:integration
npm run integration:down
npm audit
```

Security-sensitive store changes need concurrency tests. Public API changes need declaration and clean-consumer tests. Edge changes must pass the browser bundle graph test. Report vulnerabilities through the private process in SECURITY.md.
