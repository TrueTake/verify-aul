# `fail-unsupported-version.json`

**Expected verdict:** `fail`

**Exercises:** Check 1 — `bundle_schema_version` rejection. The verifier is required to short-circuit and record a single `bundle_schema_version` failure; no downstream checks are attempted.

**What's in the bundle:**

- `bundle_schema_version: 99` — not in the verifier's `SUPPORTED_BUNDLE_VERSIONS` list.
- `status: "pending"` — keeps the vector structurally minimal (no required `merkle_proof` / `anchors`).
- `event_hash` — placeholder (never read because the version check fails first).

**Why this vector is deterministic:** No cryptographic fixtures required. The check is a simple numeric membership test against a compile-time constant.

**Verifier behavior:** `checks = [{ check: "bundle_schema_version", status: "fail" }]` and an immediate `fail` verdict — Check 1 short-circuits the rest of the pipeline.

**Note:** status is `pending` rather than `confirmed` so the vector is structurally valid against `schema/bundle.v1.json` (the schema's `allOf` conditional requires `merkle_proof` + `anchors` only for confirmed/partial). The version mismatch is what drives the verdict; `status` is incidental.
