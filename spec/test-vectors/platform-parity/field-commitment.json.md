# Platform parity fixture — `field-commitment.json`

**Copied:** 2026-04-20 from TrueTake's internal commit-side
field-commitment implementation, which is not distributed with this
package.

## Purpose

Pins cross-implementation byte equality between two independent
implementations of spec §10's leaf-hash and Merkle-walk primitives:

- Commit side — internal, uses `node:crypto`.
- Verifier side — this package (`src/field-commitment.ts`), uses
  `@noble/hashes`.

`src/platform-parity.test.ts` loads this file and asserts
`computeLeafHash` reproduces each `expected_leaf_hashes` entry
byte-for-byte, and `verifyFieldProof` accepts each `proofs[].path`
against the declared `expected_root`.

The two implementations have no shared code. This fixture — plus the
§10.9 disclosure vectors — is the contract.

## Refresh policy

Refresh whenever the internal commit-side canonicalization rules, leaf
encoding, or Merkle construction change. When refreshing, update the
`Copied:` date above and re-run `npm test`. A byte-equality failure
after a refresh means the two implementations have drifted;
investigate before merging.

## Schema

This file uses a bespoke fixture schema (not `schema/disclosure.v1.json`)
because it exposes commit-side internals (explicit `salt_hex` values,
multi-leaf layouts) that are not part of the disclosure wire format.
`scripts/check-schema-vectors.ts` deliberately skips the
`platform-parity/` subdirectory — its `readdirSync(VECTORS_DIR)` call
is non-recursive, so nested directories are not walked. Do not switch
that call to recursive without adding an explicit skip path for this
file.
