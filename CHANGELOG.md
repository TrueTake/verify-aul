# Changelog

All notable changes to `@truetake/verify-aul` are documented here.

This project follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [1.1.0] — 2026-04-21

**Field-disclosure support.** Stable promotion of the `1.1.0-alpha.{0,1,2}`
development train. The full alpha sequence landed upstream integration
(TrueTake platform commit side; see TrueTake/platform#544) with
cross-implementation byte-equality verified end-to-end before this
promotion. No behavioral differences versus `1.1.0-alpha.2`.

### Added

- **`verify-field` CLI subcommand** — verifies a single-field Merkle
  disclosure against its companion verification bundle. Flags:
  `--disclosure <path>`, `--bundle <path>`, `--candidate <VALUE>`, and
  `--candidate-file <path>` (mutually exclusive with `--candidate`;
  prefer it for sensitive values to avoid argv leakage). Mandatory
  `verifyBundle` step, strict 64-char lowercase hex `event_hash`
  binding, and `event_root` binding
  (`disclosure.root === bundle.event.metadata.event_root`) — no escape
  hatch. The two bindings together anchor the disclosure's Merkle root
  to the signed + Solana-anchored event; without Binding B, a forged
  disclosure paired with an attacker-chosen candidate would walk
  self-consistently.
- **Field-commitment primitives** in `src/field-commitment.ts` —
  `canonicalizeFieldValue`, `computeLeafHash`, `verifyFieldProof`,
  `DISCLOSABLE_FIELDS`, `ENCODING_VERSION`, `FieldCommitmentError`.
  Used by the CLI handler internally and re-exported on the `./testing`
  subpath (`import { … } from '@truetake/verify-aul/testing'`) for
  cross-implementation parity fixture generation. Not on the `.` entry
  point — external verifier implementations should work from spec §10
  and the disclosure test vectors, not from package imports.
- **Spec §10** — *Field-disclosure bundles (v1)*. Normative prose for
  leaf / node prefixes, 16-byte salt, per-field canonicalization
  (`approver.email` → NFC + trim + lowercase; other paths reserved),
  disclosure payload shape, the two §10.7 bindings (`event_hash`
  identity + `root` tree commitment), and the §10.8 verification
  algorithm. Includes §10.10 operational guidance (Solana RPC trust,
  10 MB payload cap, argv-leak caveat, release cadence for new
  `field_path` values).
- **`spec/schema/disclosure.v1.json`** — JSON Schema for the
  field-disclosure payload. Five required fields (`field_path`, `salt`,
  `merkle_path`, `root`, `event_hash`), `additionalProperties: false`
  so unspecified keys cause schema validation to fail.
  `scripts/check-schema-vectors.ts` routes vectors to the bundle or
  disclosure schema based on the presence of `field_path`.
- **Four disclosure test vectors** under `spec/test-vectors/`:
  `field-commitment-pass` (primitives happy path), `-binding` (bound
  to `tier2-pass.json`'s `event_hash` — exercises the CLI end-to-end),
  `-nfc` (NFD → NFC invariant pin), `-fail` (tampered root). External
  verifier implementations MUST use all four.
- **Cross-implementation byte-equality fixture** at
  `spec/test-vectors/platform-parity/field-commitment.json` — copied
  from a parallel commit-side implementation (not distributed with this
  package). `src/platform-parity.test.ts` asserts this package's
  `computeLeafHash` reproduces the committed `expected_leaf_hashes`
  byte-for-byte, catching drift between the two implementations.
- **Split fixtures generator** — `npm run fixtures:generate:offline`
  emits only the deterministic field-commitment vectors (no network,
  no fresh CA keys). CI gates byte-equality on the offline outputs via
  `git diff --exit-code`. `npm run fixtures:generate` retains the full
  behavior (offline + network).

### Design notes

- **Disclosures never carry the committed value on the wire.** The
  spec deliberately omits a `field_value` field and the schema's
  `additionalProperties: false` rejects it. Verification works by the
  verifier supplying a candidate out-of-band (e.g. `--candidate`) and
  folding via `computeLeafHash`; a wrong candidate produces a leaf that
  does not fold to `root`. A disclosure at rest therefore leaks nothing
  beyond an opaque salt + hash, preserving the commit side's "row-level
  DB compromise never leaks committed values directly" guarantee.
- **Mandatory `verifyBundle` step in the CLI** — pins the active
  TrueTake public key via the package's embedded trust anchor, validates
  the Ed25519 signature, confirms `event_hash` is included in a
  Solana-confirmed batch Merkle root. Without it, a hostile actor could
  fabricate a bundle + disclosure pair whose internal arithmetic is
  self-consistent.

### Migration from `1.0.0`

No breaking changes to existing public API (`verifyBundle`, bundle
verification types, trust-anchor fingerprints). The `verify-field`
subcommand and the `./testing` subpath are purely additive. The alpha
train during development briefly required a `field_value` field on
disclosure payloads, but that was never released as stable — `1.0.0`
consumers have nothing to migrate.

### Notes

- **Release cadence for `field_path`.** Adding a new supported
  `field_path` to spec §10.4 requires a minor-version bump here —
  verifiers older than the bump MUST reject the new path. A future
  release MAY adopt a declarative `canonicalization` field inside the
  disclosure payload to decouple field additions from verifier release
  cadence; not in scope for v1.
- **Alpha history.** The development train `1.1.0-alpha.{0,1,2}` was
  published during downstream integration; those versions are preserved
  on npm under the `next` dist-tag and in git tags but are superseded
  by this release. Git log and GitHub Releases carry the alpha-by-alpha
  diff for anyone needing that history.

## [1.0.0] — 2026-04-20

**First stable release.** The API, CLI flags, and bundle format (`bundle_schema_version: 1`) are now covered by semver — no breaking changes until a new major version.

### Added

- `spec/v1.md` — stable specification, promoted from `spec/v1.0-rc.1.md`. The RC window closed without substantive external feedback; the normative text is unchanged from `rc.1`. Future breaking changes bump `bundle_schema_version` and land in a new `spec/v2.md` document.

### Changed

- `package.json.version` → `1.0.0`. Workflow's `dist-tag` logic routes this to `latest` automatically.
- Spec filename renamed `spec/v1.0-rc.1.md` → `spec/v1.md`. All repo references (README, `src/index.ts` header, JSON Schema description, `spec/README.md`) updated in lockstep.
- `spec/README.md` § Versioning rewritten: spec filename tracks `bundle_schema_version` (v1, v2, ...) rather than the RC cycle.

### Migration

No migration needed for consumers pinned at `0.1.0-alpha.4` — the API surface and bundle shape are identical. Bump the pin to `1.0.0` at your convenience. A `next` dist-tag release channel remains for future pre-release testing.

## [0.1.0-alpha.4] — 2026-04-17

**First OIDC-provenance alpha to land on npm.** [Sigstore transparency entry 1331751100](https://search.sigstore.dev/?logIndex=1331751100). Repository visibility flipped to public as a Unit 9 side-effect — `npm publish --provenance` rejects private-repo provenance. `github-pages` deploy branch policy updated to allow `v*` tag refs. Hosted UI live at https://truetake.github.io/verify-aul/.

### Added (between alpha.0 and 1.0.0, rolled up)

- **Unit 4b: all four crypto-bearing reference test vectors** (`tier1-pass`, `tier2-pass`, `partial-missing-anchor`, `fail-trust-anchor-mismatch`) now contain real cryptographic material and verify end-to-end against the production trust anchors. Pass / partial vectors carry real RFC 3161 TimeStampTokens minted against FreeTSA + DigiCert by `spec/generate-fixtures.ts`. The mismatch vector's token is signed by a local fixtures CA (new, under `spec/fixtures-trust-anchors/`) whose SHA-256(SKI) is pinned in `spec/fixtures-trust-anchors/fingerprints.ts` and asserted disjoint from production by `scripts/check-fingerprints-disjoint.ts`.
- `spec/tools/fetch-tsa.ts` — RFC 3161 `TimeStampReq` issuer that POSTs to a TSA and unwraps the returned `TimeStampToken`. Pure pkijs; no external TSA client dep.
- `spec/tools/fixtures-ca.ts` — local CA + TSA signing cert generator plus a `TimeStampToken` signer that wraps a `TSTInfo` in CMS `SignedData`. Used only for the mismatch vector; never ships in the npm tarball.
- `npm run fixtures:generate` — orchestrates the above. Requires network (contacts FreeTSA + DigiCert). Regenerated vectors end up with fresh TSA `genTime` + fresh RSA signatures; their verdicts stay stable.

### Changed (between alpha.0 and 1.0.0, rolled up)

- `src/spec-vectors.test.ts` now asserts a concrete verdict on every vector (was: 4 deterministic + 4 placeholder-marker-only). Uses `verifyBundle` from the production API — no test-only override needed, because the pass / partial vectors are signed by real pinned CAs.
- `scripts/check-schema-vectors.ts` no longer skips placeholder vectors; it validates all eight.
- Removed the OIDC debug step from `release.yml`. It served its purpose during the alpha.0–alpha.3 troubleshooting; production publishes don't need it.

### Plan delta

- Static vectors intentionally omit Solana anchors. The static-vector format can't carry a real Solana tx signature without every test run round-tripping to a devnet RPC; the Solana verification code path is exercised by `src/core.test.ts` with mocked `fetch`.

## [0.1.0-alpha.4] — 2026-04-17

**First OIDC-provenance alpha to land on npm.** [Sigstore transparency entry 1331751100](https://search.sigstore.dev/?logIndex=1331751100). Repository visibility flipped to public as a Unit 9 side-effect — `npm publish --provenance` rejects private-repo provenance. `github-pages` deploy branch policy updated to allow `v*` tag refs. Hosted UI live at https://truetake.github.io/verify-aul/.

### Fixed

- **Release workflow now uses Node 24** in the publish job. The alpha.3 attempt to `npm install -g npm@latest` under Node 22 failed with `Cannot find module 'promise-retry'` (a known mid-swap glitch when npm 10 upgrades itself to npm 11+). Node 24 ships with npm 11+ by default, sidestepping the self-upgrade entirely. CI (`ci.yml`) continues to test the published package against Node 20 and Node 22 — only the publish job lifts to 24.
- **Pages actions downgraded to v4 SHAs.** `upload-pages-artifact@v5` consumed `upload-artifact@v7`'s new immutable blob storage; `deploy-pages@v5` couldn't download the resulting blob across jobs (produced `BlobNotFound` in the deploy step). Rolling both back to v4 restores the cross-job artifact handoff.

## [0.1.0-alpha.3] — 2026-04-17

### Fixed

- **npm Trusted Publishing.** Node 22 LTS ships with npm 10.x; npm Trusted Publishing (OIDC) requires npm ≥ 11.5.1. Without the upgrade, `npm publish` sends an unauthenticated PUT (the registry answers 404 — npm's opaque "not found or not authorized" response — without even attempting the OIDC token exchange). The release workflow now runs `npm install -g npm@latest` before `npm publish`, and logs the resolved `npm --version` so future regressions surface in logs. This was the root cause of the 404s on alpha.0 / alpha.1 / alpha.2; the TP config was correct the whole time.
- **Pages deploy BlobNotFound.** `actions/configure-pages` moved back into the `build` job. The two Pages actions (`configure-pages` and `upload-pages-artifact`) must share a job because `upload-pages-artifact` writes configuration that `deploy-pages` later reads. Splitting them broke that handoff. Build gains `pages: read` + `id-token: write`; the compromise-containment split still holds because `deploy` retains the actual `pages: write` (deployment) privilege and `build` cannot call `deploy-pages`.

## [0.1.0-alpha.2] — 2026-04-17

### Fixed

- `pages.yml` moved `actions/configure-pages` from the `build` job (which had only `contents: read`) to the `deploy` job (`pages: write`). The `Resource not accessible by integration` error from alpha.1 is gone.

### Added (temporary — will be reverted)

- Debug step in `release.yml` that prints OIDC token claims for npm Trusted Publishing troubleshooting. Remove once we confirm the first OIDC publish lands.

## [0.1.0-alpha.1] — 2026-04-17

### Fixed

- `web/index.html` CSP meta tag collapsed to a single line so the `pages.yml` verbatim-grep check passes. The policy content is unchanged.

### Notes

- `v0.1.0-alpha.0` was tagged and its provenance statement was signed + published to the Sigstore transparency log ([entry 1331465970](https://search.sigstore.dev/?logIndex=1331465970)), but the subsequent npm `PUT` returned 404 — likely because the Trusted Publisher configuration was saved to npmjs.com a moment after the workflow had already started. The `0.1.0-alpha.0` version was never published to the npm registry and the tag is effectively dead. `0.1.0-alpha.1` is the first version to land on npm via OIDC.

## [0.1.0-alpha.0] — 2026-04-17

### Added

- **Library.** ES module `verifyBundle` port from platform `lib/verify-aul/`. Isomorphic — runs under Node ≥20 and in modern browsers via WebCrypto. Pinned CA trust anchors (FreeTSA, DigiCert) validated by SubjectKeyIdentifier SHA-256 at module load.
- **Testing subpath.** `verifyBundleForTesting` reachable only via `@truetake/verify-aul/testing`. Accepts a `trustAnchorFingerprints` override so fixtures-CA test vectors can be exercised without polluting the production pin set.
- **CLI.** `npx @truetake/verify-aul bundle <file>` / `proof <file>`. Flags `--trust-anchors`, `--solana-rpc`, `--json`, `--verbose`. Exit codes 0 pass, 1 fail/partial, 2 usage error.
- **Bundle format spec.** [`spec/v1.0-rc.1.md`](./spec/v1.0-rc.1.md) — normative prose, verdict truth table, trust-anchor pinning mechanism, RFC 2119/8174/8785/6962/3161/5652 cited normatively. 60-day RC window from publish date.
- **JSON Schema.** [`spec/schema/bundle.v1.json`](./spec/schema/bundle.v1.json) — source of truth for structural validation.
- **Test vectors.** Four deterministic reference vectors in `spec/test-vectors/` — `fail-unsupported-version`, `fail-tampered-event`, `fail-bad-merkle`, `fail-bad-anchor`. Four placeholder vectors (marked `_TODO_unit_4b`) pending the fixtures CA generator.
- **Static verifier UI.** Vanilla-DOM + esbuild page hosted at [truetake.github.io/verify-aul/](https://truetake.github.io/verify-aul/). Strict CSP meta, no framework, no telemetry. Ships `MANIFEST.sha256` for reproducible-build verification.
- **MIT license.**
- **Supply-chain posture.** `npm publish --provenance` via GitHub Actions OIDC Trusted Publishing; tag-ancestor-of-main guard; `repository.url` drift guard; all third-party Actions SHA-pinned; `npm ci --ignore-scripts` on every CI job; CI-enforced inline-PEM vs file-PEM sync + fingerprint disjointness + spec-schema-vector coherence checks.
- **Solo-maintainer Ruleset on `main`.** PR required, `ci` status check, no force-push / deletion, no admin bypass. See [`SECURITY.md`](./SECURITY.md) §4 for the posture details and deferred controls that activate when a second maintainer onboards.

### Known gaps (tracked toward `v1.0.0`)

- Four crypto-bearing test vectors in `spec/test-vectors/` (the `*_pass` and `partial-missing-anchor` and `fail-trust-anchor-mismatch` ones) are shape-only placeholders. A fixtures-CA generator in `spec/generate-fixtures.ts` is the blocker. Deterministic vectors cover the remaining four verdict paths.
- Repository is currently private during the alpha window; will flip public before `v1.0.0`.

## [0.0.0-rc.0] — 2026-04-17

### Added

- **Scope-claim publish.** One-time manual publish to own the `@truetake/verify-aul` name on npm before Trusted Publishing could be configured (npm requires the package to exist before Trusted Publisher config is available). No provenance attestation on this version. Not recommended for use — install `0.1.0-alpha.0` or later.
