# `tier1-pass.json`

**Expected verdict:** `pass`

**Exercises:** the end-to-end success path for a Tier 1 proof.

- Check 1 — `bundle_schema_version` → pass.
- Check 4 — `merkle_inclusion` → pass (single-leaf tree; `root = SHA-256(0x00 || hex_decode(event_hash))`).
- Check 5 — `anchor:tsa_freetsa` → pass (real RFC 3161 TimeStampToken from FreeTSA).
- Check 5 — `anchor:tsa_digicert` → pass (real RFC 3161 TimeStampToken from DigiCert).

**Generation:** `npm run fixtures:generate` contacts FreeTSA and DigiCert and mints fresh tokens over this vector's Merkle root. Both CAs are pinned in `src/trust-anchors/fingerprints.ts`, so the tokens verify against the same trust set an end user has bundled with the package.

**Solana anchors are intentionally omitted.** Static vectors can't include real Solana transactions without devnet round-trips. The Solana code path is covered by unit tests under `src/core.test.ts` with mocked `fetch`.
