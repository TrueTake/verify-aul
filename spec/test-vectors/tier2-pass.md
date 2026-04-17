# `tier2-pass.json`

**Status:** **PLACEHOLDER** — the JSON in this file is shape-only and will **not** pass the verifier. Unit 4b regenerates it with real crypto.

**Expected verdict (once generated):** `pass`

**Exercises:** the end-to-end success path for a Tier 2 bundle — all five check categories fire and all return `pass`.

- Check 1 — `bundle_schema_version` → pass.
- Check 2 — `canonical_recompute` → pass (`SHA-256(canonicalize(event)) === event_hash`).
- Check 3 — `server_signature` → pass (Ed25519 verify succeeds over `hex_decode(event_hash)`).
- Check 4 — `merkle_inclusion` → pass.
- Check 5 — per-anchor → pass.

**Blocker:** the fixtures Ed25519 signing key + real RFC 3161 TimeStampToken generation. Both tracked in Unit 4b.
