# `fail-unsupported-version.json`

**Expected verdict:** `fail`

**Exercises:** Check 1 — `bundle_schema_version` rejection. The verifier is required to short-circuit and record a single `bundle_schema_version` failure; no downstream checks are attempted.

**What's in the bundle:**

- `bundle_schema_version: 99` — not in the verifier's `SUPPORTED_BUNDLE_VERSIONS` list.
- `status: "confirmed"` — structurally a confirmed bundle.
- `event_hash` — placeholder (never read because the version check fails first).

**Why this vector is deterministic:** No cryptographic fixtures required. The check is a simple numeric membership test against a compile-time constant.

**Verifier behavior:** `checks = [{ check: "bundle_schema_version", status: "fail" }]`.

**Note:** this vector intentionally omits `event`, `merkle_proof`, and `anchors` — since the version check short-circuits, those fields are never consulted. The vector will still validate against `schema/bundle.v1.json` because the schema's `allOf` conditionals only require those fields when `status` is confirmed/partial *and* the vector has `status: "confirmed"`. That's a deliberate schema mismatch: the schema rejects the bundle (missing `merkle_proof`), but the verifier never gets that far because Check 1 fails first. Both outcomes are acceptable; they exercise different layers of defense.
