# `fail-tampered-event.json`

**Expected verdict:** `fail`

**Exercises:** Check 2 — `canonical_recompute`. The declared `event_hash` was computed from an *untampered* version of the event (`foo: "bar"`), but the bundle ships the *tampered* event (`foo: "TAMPERED"`). The verifier recomputes `SHA-256(canonicalize(event))`, gets a different hash, and records `canonical_recompute` as `fail`.

**Why this vector is deterministic:** RFC 8785 canonicalization is deterministic; SHA-256 is deterministic; no cryptographic fixtures are required to exercise the detection.

**Expected check records:**

- `bundle_schema_version` → `pass`
- `canonical_recompute` → `fail` (hash mismatch)
- `server_signature` → `fail` (attempt is made but the placeholder Ed25519 signature doesn't verify either — both failures are surfaced in the result.)
- No Merkle/anchor checks because `status: "pending"` has no proof / anchors.

**Verdict:** `fail` (because any check fail → fail, even on a pending bundle).

**Note:** the bundle's `server_signature` and `signing_keys[0].public_key_base64url` are zero-byte placeholders. They exist to satisfy the JSON Schema's `if event then server_signature+signing_*` requirement. A conformant verifier would attempt Ed25519 verification, fail, and record it as a second failure — this vector intentionally exercises both Check 2 and Check 3 failing in the same bundle.
