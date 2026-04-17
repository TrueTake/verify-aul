# `spec/` — Bundle format specification

This directory holds the normative artifacts for `@truetake/verify-aul`.

| Path | Purpose |
|---|---|
| [`v1.0-rc.1.md`](./v1.0-rc.1.md) | Normative prose. Defines the bundle format, verification algorithm, and verdict truth table. |
| [`schema/bundle.v1.json`](./schema/bundle.v1.json) | JSON Schema — source of truth for structural validation. |
| [`fixtures-trust-anchors/`](./fixtures-trust-anchors/) | **Fixtures-only** CA fingerprints and PEMs. Never ship with a production verifier. |
| [`test-vectors/`](./test-vectors/) | Eight reference test vectors (four deterministic, four crypto-bearing). Each JSON vector has a co-located `.md` sibling describing intent. |
| [`generate-fixtures.ts`](./generate-fixtures.ts) | Script that regenerates the fixtures CA, signs TimeStampTokens, and produces the crypto-bearing vectors. |

## Fixtures vs. production anchors

- **Production anchors** (`src/trust-anchors/`) ship with the published package. They are real public CAs (FreeTSA, DigiCert SHA2 Timestamping CA). Their SKI SHA-256s are pinned in `src/trust-anchors/fingerprints.ts`. The pinning protects against silent substitution.
- **Fixtures anchors** (`spec/fixtures-trust-anchors/`) are local-only. They sign the crypto-bearing test vectors and are referenced by `TRUST_ANCHOR_FINGERPRINTS_FIXTURES`. A CI check (see Unit 6) enforces that production and fixtures fingerprint sets have **empty set-intersection**.

Test vectors are consumed by the verifier test suite via `verifyBundleForTesting`, which accepts a `trustAnchorFingerprints` override — this is how a vector signed by a fixtures CA passes without polluting the production pin set.

## Spec authoring conventions

- **Versioning.** The spec document's filename tracks the RC cycle (`v1.0-rc.1.md`, `v1.0-rc.2.md`, ...). When stable, rename to `v1.md`. The JSON Schema's filename tracks `bundle_schema_version` in the bundle itself, independent of the spec doc version (`bundle.v1.json` → `bundle.v2.json` only on a breaking bundle change).
- **Prose vs. schema normativity.** The JSON Schema is normative for structural validation; the prose is normative for semantics (what the fields mean, how to compute verdicts). In case of conflict, fix both — never let them drift.
- **Test vectors are part of the spec.** A change to the verdict truth table, the algorithm order, or any field's semantics **MUST** include updated vectors with expected-verdict annotations in the `.md` sibling.
