# Migration guide

## Pre-1.0 policy

The public API may change before 1.0. Every release records breaking changes in CHANGELOG.md.

## Store migrations

Never rely on automatic index creation in application startup. Back up data, inspect generated indexes, deploy schema-compatible code, synchronize indexes in a maintenance step, and verify replica-set transactions. Removing an old TTL index is an explicit operator migration.

## Key migrations

Access keys are selected by trusted configured `kid`; attacker-selected URLs are never fetched. Follow the overlap sequence in DEPLOYMENT.md. Pepper changes may invalidate OTPs and refresh sessions unless a store implementation supports old pepper versions.

## Transport migrations

Cookie names, domain, path, SameSite, and Secure attributes are part of the session contract. During a rename, clear both old and new cookie names at their original paths. Do not change from JSON to cookie mode without adding CSRF and CORS controls.
