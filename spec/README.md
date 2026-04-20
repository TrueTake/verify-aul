# `spec/` — Bundle format specification

This directory holds the normative artifacts for `@truetake/verify-aul`.

| Path | Purpose |
|---|---|
| [`v1.md`](./v1.md) | Normative prose. Defines the bundle format, verification algorithm, verdict truth table, and (§10) the field-disclosure bundle format. |
| [`schema/bundle.v1.json`](./schema/bundle.v1.json) | JSON Schema — source of truth for structural validation of verification bundles. |
| [`schema/disclosure.v1.json`](./schema/disclosure.v1.json) | JSON Schema — source of truth for structural validation of field-disclosure bundles (§10). |
| [`fixtures-trust-anchors/`](./fixtures-trust-anchors/) | **Fixtures-only** CA fingerprints and PEMs. Never ship with a production verifier. |
| [`test-vectors/`](./test-vectors/) | Reference test vectors — bundle vectors plus field-disclosure vectors (§10.9). Each JSON vector has a co-located `.md` sibling describing intent. |
| [`test-vectors/platform-parity/`](./test-vectors/platform-parity/) | Frozen cross-implementation byte-equality fixture copied from TrueTake's internal commit-side implementation (§10.9). |
| [`generate-fixtures.ts`](./generate-fixtures.ts) | Script that regenerates the fixtures CA, signs TimeStampTokens, and produces the crypto-bearing vectors. The offline-only phase is suitable for CI byte-equality gates. |

## Fixtures vs. production anchors

- **Production anchors** (`src/trust-anchors/`) ship with the published package. They are real public CAs (FreeTSA, DigiCert SHA2 Timestamping CA). Their SKI SHA-256s are pinned in `src/trust-anchors/fingerprints.ts`. The pinning protects against silent substitution.
- **Fixtures anchors** (`spec/fixtures-trust-anchors/`) are local-only. They sign the crypto-bearing test vectors and are referenced by `TRUST_ANCHOR_FINGERPRINTS_FIXTURES`. A CI check (see Unit 6) enforces that production and fixtures fingerprint sets have **empty set-intersection**.

Test vectors are consumed by the verifier test suite via `verifyBundleForTesting`, which accepts a `trustAnchorFingerprints` override — this is how a vector signed by a fixtures CA passes without polluting the production pin set.

## Spec authoring conventions

- **Versioning.** The spec document's filename tracks `bundle_schema_version` (`v1.md`, `v2.md`, ...); a new major version is cut only when a breaking change to the bundle format or verification algorithm lands. Minor clarifications amend the current spec in place with a dated changelog entry. The JSON Schema's filename tracks the same number (`bundle.v1.json` → `bundle.v2.json` only on a breaking bundle change).
- **Prose vs. schema normativity.** The JSON Schema is normative for structural validation; the prose is normative for semantics (what the fields mean, how to compute verdicts). In case of conflict, fix both — never let them drift.
- **Test vectors are part of the spec.** A change to the verdict truth table, the algorithm order, or any field's semantics **MUST** include updated vectors with expected-verdict annotations in the `.md` sibling.
