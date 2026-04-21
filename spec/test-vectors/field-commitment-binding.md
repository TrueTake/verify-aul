# `field-commitment-binding` — end-to-end binding vector

**Expected verdict (full CLI):** `pass`.

**Scope:** Exercises the full §10.8 verification algorithm —
`verifyBundle` → `checkBindingEventHash` → `checkBindingRoot` →
`canonicalizeCandidate` → `computeLeafHash` → `verifyMerkleProof` —
and specifically pins both §10.7 bindings between a field-disclosure
bundle and its referenced verification bundle.

## Two bindings to `tier2-pass`

**Binding A (`event_hash`).** `disclosure.event_hash` equals the
`event_hash` in [`tier2-pass.json`](./tier2-pass.json). The binding is
derived deterministically from the canonical `TIER2_PASS_EVENT` object
in `spec/generate-fixtures.ts`, so any change to that event's shape
automatically propagates here.

**Binding B (`event_root`).** A Tier 2 bundle that supports field
disclosure MUST carry `event.metadata.event_root` (§10.7); the verifier
asserts `disclosure.root === bundle.event.metadata.event_root`. Without
this check, a fabricated disclosure paired with an attacker-chosen
candidate (fresh salt, `merkle_path=[]`, `root` set to
`computeLeafHash(candidate, salt)`) produces a self-consistent Merkle
walk — a critical forgery.

Because this repo's `tier2-pass.json` is regenerated via network (TSA +
Ed25519) and does not include `event.metadata.event_root`, the
end-to-end test in `spec-vectors.field-commitment.test.ts` constructs a
synthetic Tier 2 bundle with matching `event_hash` and `event_root` at
test time rather than using the crypto-bearing fixture directly. The
binding disclosure vector is the source of truth for both values.

The field-commitment tree is **separate** from the bundle's
`merkle_proof` tree. This vector uses a single-leaf field-commitment
tree, so the walk is a no-op (`root === leaf_hash`, `merkle_path: []`).

## Using this vector in tests

Run `runVerifyFieldCommand(...)` against this disclosure + a Tier 2
bundle whose `event_hash` equals `disclosure.event_hash` and whose
`event.metadata.event_root` equals `disclosure.root`. Mock
`verifyBundle` to return a `pass` verdict so the test does not require
network access. See `src/spec-vectors.field-commitment.test.ts`.

## Candidate that should verify against this disclosure

`alice@example.com` (the canonical form — also `Alice@Example.COM `,
`  alice@EXAMPLE.com  `, etc. — all canonicalize to the same bytes).

## Regeneration

Run `npm run fixtures:generate:offline`. CI gates byte-equality via
`git diff --exit-code`.
