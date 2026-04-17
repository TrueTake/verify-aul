# `tier2-pass.json`

**Expected verdict:** `pass`

**Exercises:** the end-to-end success path for a Tier 2 bundle — all five check categories fire and all return `pass`.

- Check 1 — `bundle_schema_version` → pass.
- Check 2 — `canonical_recompute` → pass. `SHA-256(canonicalize(event)) === event_hash`.
- Check 3 — `server_signature` → pass. Fresh Ed25519 key pair signs `hex_decode(event_hash)` at generation time; the public key lands in `signing_keys[0]`.
- Check 4 — `merkle_inclusion` → pass.
- Check 5 — per-anchor → pass on both FreeTSA and DigiCert tokens.

**Generation:** `npm run fixtures:generate` runs:

1. `canonicalize(event)` → SHA-256 → `event_hash`.
2. `getPublicKeyAsync(ed25519.utils.randomSecretKey())` → `signing_keys[0].public_key_base64url`, with fingerprint `base64url(SHA-256(publicKey)).slice(0, 16)`.
3. `signAsync(hex_decode(event_hash), privateKey)` → `server_signature`.
4. FreeTSA + DigiCert TSA requests against the Merkle root.
