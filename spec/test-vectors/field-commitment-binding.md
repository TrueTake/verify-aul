# `field-commitment-binding` — end-to-end binding vector

**Expected verdict (full CLI):** `pass`.

**Scope:** Exercises the full §10.8 verification algorithm —
`verifyBundle` → `checkBinding` → `canonicalizeCandidate` →
`computeLeafHash` → `verifyMerkleProof` — and specifically pins the
binding rule between a field-disclosure bundle and its referenced
verification bundle.

## Binding to `tier2-pass.json`

`event_hash` in this disclosure equals the `event_hash` in
[`tier2-pass.json`](./tier2-pass.json). The binding is derived
deterministically from the canonical `TIER2_PASS_EVENT` object in
`spec/generate-fixtures.ts`, so any change to that event's shape
automatically propagates here.

The field-commitment tree is **separate** from the bundle's
`merkle_proof` tree. There is no coupling between the two roots — a
real commit side would anchor the bundle's Merkle root to Solana and
persist the field-commitment root as a per-event database column
(`ledger_events.field_commitment_root` in platform). This vector uses a
single-leaf field-commitment tree, so the walk is a no-op (`root ===
leaf_hash`, `merkle_path: []`).

## Using this vector in tests

Run `runVerifyFieldCommand(...)` against this disclosure + the
`tier2-pass.json` bundle, with `verifyBundle` mocked to return a `pass`
verdict (so the test does not require network access). See
`src/spec-vectors.field-commitment.test.ts`.

## Candidate that should verify against this disclosure

`alice@example.com` (the canonical form — also `Alice@Example.COM `,
`  alice@EXAMPLE.com  `, etc. — all canonicalize to the same bytes).

## Regeneration

Run `npm run fixtures:generate:offline`. CI gates byte-equality via
`git diff --exit-code`.
