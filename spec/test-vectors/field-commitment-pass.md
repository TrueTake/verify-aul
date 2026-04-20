# `field-commitment-pass` — primitives happy path

**Expected verdict (primitives):** `pass`.

**Scope:** Exercises the field-commitment **primitives** — canonicalization,
leaf hashing, and two-sibling Merkle walk — in isolation. This vector is
**not** bound to any bundle; its `event_hash` is a synthetic placeholder
(all-`a` hex). CLI end-to-end coverage lives in `field-commitment-binding`.

## What it verifies

- `canonicalizeFieldValue('approver.email', ...)` applied to a mixed-case
  candidate produces the same canonical bytes as `field_value`.
- `computeLeafHash(...)` with the 16-byte salt `0x2a…2a` (16 repetitions)
  produces the leaf that walks to `root` under the given `merkle_path`.
- The walk exercises **both** sibling directions (`left` then `right`).

## Candidate that should verify against this disclosure

`Alice@Example.COM ` — mixed case plus a trailing space. After the v1
rule (`NFC + trim + lowercase`) it canonicalizes to `alice@example.com`,
which equals `field_value`.

## Regeneration

Run `npm run fixtures:generate:offline`. CI gates byte-equality of this
file via `git diff --exit-code`.
