# Platform parity fixture — `field-commitment.json`

**Source:** `server/services/ledger/__fixtures__/field-commitments.json` in
the TrueTake platform repository.

**Source commit:** `9f23844d` — *feat(aul): single-field Merkle disclosure
PoC (TRU-657) (#510)*. Platform repo `HEAD` at copy time:
`767d44824f51997748f189e3765fd63d71088247`.

**Copied:** 2026-04-20.

## Purpose

Pins cross-implementation byte equality between the TrueTake platform's
commit-side field-commitment service (`field-commitment.service.ts`, uses
`node:crypto`) and this package's verifier-side primitives
(`src/field-commitment.ts`, uses `@noble/hashes`). `src/platform-parity.test.ts`
loads this file and asserts OSS `computeLeafHash` reproduces each
`expected_leaf_hashes` entry byte-for-byte, and `verifyFieldProof` accepts
each `proofs[].path` against the declared `expected_root`.

The two implementations have no shared code. This fixture — plus the
§10.9 disclosure vectors — is the contract.

## Refresh policy

Refresh on any change to:

- `server/services/ledger/field-commitment.service.ts`
- `server/services/ledger/canonicalize.ts`
- `server/services/ledger/__fixtures__/field-commitments.json`

When refreshing, update `Source commit:` and `Copied:` above and re-run
`npm test`. A byte-equality failure after a refresh means the two
implementations have drifted; investigate before merging.

The long-term forcing function is the downstream platform PR that
regenerates platform's gold file against the OSS implementation and reruns
`field-commitment.fixtures.test.ts`. This fixture is the short-term guard
against OSS-side drift before that downstream PR lands.

## Schema

This file uses the platform fixture schema (not
`schema/disclosure.v1.json`). `scripts/check-schema-vectors.ts`
deliberately skips the `platform-parity/` subdirectory — its
`readdirSync(VECTORS_DIR)` call is non-recursive, so nested directories
are not walked. Do not switch that call to recursive without adding an
explicit skip path for this file.
