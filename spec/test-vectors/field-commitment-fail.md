# `field-commitment-fail` — tampered root

**Expected verdict (primitives):** `fail`.

**Scope:** External verifier implementations use this vector to confirm
they correctly **reject** a field-disclosure bundle whose `root` does
not match the reconstructed Merkle walk.

## What was tampered

The `root` here is the `field-commitment-pass` root with its final two
hex characters flipped. The leaf hash, canonicalization, and sibling
path are all unchanged — the only difference is the advertised root.

A conformant verifier MUST emit verdict `fail` with a reason pointing at
the Merkle walk mismatch. It MUST NOT "repair" the root or emit `pass`
for a re-derived leaf that matches the walk but not the advertised
root.

## Candidate

Same as `field-commitment-pass`: `alice@example.com`. The walk itself
is a purely mechanical check — it fails regardless of candidate.

## Regeneration

Run `npm run fixtures:generate:offline`. CI gates byte-equality via
`git diff --exit-code`.
