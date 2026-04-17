# `fail-bad-merkle.json`

**Expected verdict:** `fail`

**Exercises:** Check 4 — `merkle_inclusion`. Tier 1 proof with a single-leaf tree. The declared `merkle_proof.root` is all-zero, which cannot match the actual leaf hash of `SHA-256(0x00 || hex_decode(event_hash))`.

**Why this vector is deterministic:** RFC 6962 leaf-hash computation is deterministic; the verifier reproduces it from `event_hash` and compares against `merkle_proof.root`.

**Expected check records:**

- `bundle_schema_version` → `pass`
- `merkle_inclusion` → `fail` (reconstructed root ≠ declared root)
- `anchors` → `fail` (confirmed bundle with empty anchors list — structural rule)

**Verdict:** `fail`.

**Note on multiple failures:** this vector intentionally surfaces two failures so both the Merkle-arithmetic defense and the "confirmed-bundle-must-carry-anchors" structural defense are exercised. A production bundle would never emit an empty `anchors` array on a confirmed status.
