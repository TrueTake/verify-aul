# Changelog

All notable changes to `@truetake/verify-aul` are documented here.

This project follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Initial repository scaffolding: README, SECURITY, CODEOWNERS, solo-maintainer Ruleset, `package.json` skeleton.

### Planned for `0.1.0-alpha.0`

- ES module library surface (`verifyBundle`, types) ported from platform's `lib/verify-aul/`.
- CLI (`npx @truetake/verify-aul`) ported from platform's `scripts/verify-aul/`.
- Bundle-format spec `v1.0-rc.1` + JSON Schema + 8 reference test vectors.
- Static HTML verifier UI hosted at `truetake.github.io/verify-aul/`.
- npm Trusted Publishing (OIDC) with Sigstore provenance.
