# `tier1-pass.json`

**Status:** **PLACEHOLDER** — the JSON in this file is shape-only and will **not** pass the verifier. Unit 4b of the TRU-625 plan regenerates it with real crypto via `spec/generate-fixtures.ts`.

**Expected verdict (once generated):** `pass`

**Exercises:** the end-to-end success path for a Tier 1 proof.

- Check 1 — `bundle_schema_version` → pass.
- Check 4 — `merkle_inclusion` → pass (proof reproduces the declared root).
- Check 5 — `anchor:tsa_freetsa` → pass (TSA token validly signed by the fixtures CA; messageImprint matches `SHA-256(hex_decode(merkle_proof.root))`).
- Check 5 — `anchor:solana` → pass (mocked RPC response includes the Merkle root in `meta.logMessages`).

**Blocker:** the TSA token must be a well-formed RFC 3161 TimeStampToken signed by a cert whose CA is in the `TRUST_ANCHOR_FINGERPRINTS_FIXTURES` pin set. The generator is tracked as Unit 4b.
