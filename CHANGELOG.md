# Changelog

All notable changes to `@truetake/verify-aul` are documented here.

This project follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Changed

- Removed the OIDC debug step from `release.yml`. It served its purpose during the alpha.0–alpha.3 troubleshooting; production publishes don't need it.

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
