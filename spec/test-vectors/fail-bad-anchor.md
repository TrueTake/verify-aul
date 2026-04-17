# `fail-bad-anchor.json`

**Expected verdict:** `fail`

**Exercises:** Check 5 — per-anchor TSA token verification, specifically the DER parse path.

**Why this vector is deterministic:** the vector's `anchors[0].token` is a trivially malformed 4-character base64 string (`"AAAA"` → 3 null bytes). The verifier's ASN.1 parser rejects it as not a valid `ContentInfo`, records the anchor check as `fail`, and short-circuits without ever touching CMS signature verification or the pinned trust-anchor set.

**Expected check records:**

- `bundle_schema_version` → `pass`
- `merkle_inclusion` → `pass` (single-leaf tree: `root = SHA-256(0x00 || event_hash_bytes)` — computable deterministically)
- `anchor:tsa_freetsa` → `fail` (error: `Failed to parse TimeStampToken DER` or equivalent)

**Verdict:** `fail`.

**Note:** a stronger `fail-bad-anchor` vector would ship a structurally-well-formed token signed by a *different* CA whose fingerprint is not in the verifier's pin set — exercising the CMS signature-verification path. That vector requires the fixtures CA (Unit 4b). Until the generator lands, this deterministic "bad-parse" variant fills the slot by exercising the same error-surface from a different angle.
