# Security Policy

## 1. Contact

Report security issues privately to **security@truetake.com**.

PGP key: TODO — publish key fingerprint here before the repository goes public. Until then, encrypted reports can be coordinated via the email address above.

Please do **not** file a GitHub issue for security-sensitive reports.

## 2. Supported versions

Only the most recently published version on npm is supported. Older versions are unsupported and may be deprecated via `npm deprecate` without further notice when a security patch ships.

| Version | Supported |
|---|---|
| Latest published on npm | Yes |
| All earlier versions | No |

## 3. Response SLA

- **Acknowledge** receipt of a report within 48 hours.
- **Initial assessment** and coordinated-disclosure timeline within 5 business days.
- **Fix window** depends on severity and complexity; communicated in the initial assessment.

## 4. Security posture (v1, solo maintainer)

This repository operates with a **single maintainer** during initial release. Supply-chain integrity rests on the following controls, all of which work with one human in the loop:

- **npm Trusted Publishing (OIDC provenance)** — every tarball carries a Sigstore attestation binding it to a specific commit + workflow + build log. No long-lived `NPM_TOKEN`.
- **SHA-pinned GitHub Actions** — every third-party Action is pinned to a 40-character SHA (not a tag). Tag mutation attacks (e.g. `tj-actions/changed-files`, Trivy/TeamPCP) are neutralized by pinning.
- **`npm ci --ignore-scripts` in CI** — neutralizes the most common supply-chain vector (lifecycle scripts in transitive deps).
- **Public commit visibility** — once the repository goes public, every change is auditable by anyone.
- **Split Pages build/deploy with scoped permissions** — the `build` job has `contents: read` only and cannot deploy; the `deploy` job has `pages: write` + `id-token: write` only and does not run arbitrary build code.
- **Environment-level tag restriction on publish** — the `npm-publish` environment's deployment-branch rule restricts workflow runs to tag refs (`refs/tags/v*`), so a `main`-triggered rogue workflow cannot satisfy the OIDC environment claim.
- **CI-enforced trust-anchor checks** — inline-PEM vs. file-PEM byte equality, fingerprint validity, and disjointness between production and fixtures anchor sets (see `scripts/check-trust-anchor-fingerprints.ts` and `scripts/check-fingerprints-disjoint.ts`).

### Controls deferred until a second maintainer onboards

The following controls require **two humans** to be meaningful and are intentionally **not enforced in v1**:

- `required_approving_review_count: 1` + `require_code_owner_review: true` on the `main` Ruleset.
- `required_signatures: true` (enforced signed commits + tags at merge).
- `.github/allowed-signers.txt` maintained as a tag-signing identity allowlist.
- A second human added to `CODEOWNERS` for `src/trust-anchors/`, `src/core.ts`, `.github/`, `web/`, `spec/schema/`.
- Hardware-key (WebAuthn) requirement enforced at GitHub-org and npm-org admin level.
- Repository-deletion webhook alerting to a maintainer-controlled channel.

Activation is a one-line Ruleset edit + a CODEOWNERS commit — no code changes.

### Accepted residual risks (v1)

- **A consistent same-PR substitution of both inline PEM and file PEM by the sole maintainer is not prevented.** The CI check catches *inconsistent* updates (file vs. inline drift) but cannot distinguish a malicious consistent edit from a legitimate rotation. Detection relies on downstream diff review after the fact; downstream consumers should pin exact versions (`0.1.0-alpha.0`, not `^0.1.0`) and review release notes on every bump.
- **The maintainer's GitHub account credentials are a single point of failure.** 2FA alone does not defeat real-time proxy phishing. **Recommended** (not mandated): enable WebAuthn/hardware-key as the sole 2FA method on the maintainer's GitHub account and on any npm-org admin. Low cost; closes the realistic credential-theft vector.

## 5. Emergency revocation outline

If a pinned CA fingerprint must be revoked (for example, because a CA is compromised or a pinned certificate is misissued):

1. Maintainer publishes a patch release that removes the fingerprint from `TRUST_ANCHOR_FINGERPRINTS` and the associated `.pem` file from `src/trust-anchors/`.
2. `npm deprecate` is used to mark all prior versions as unsafe, with a link to the advisory.
3. `spec/v1.md` is updated with the revocation rationale and the affected fingerprint's retirement window.
4. A GitHub Security Advisory is filed, cross-referenced from the npm deprecation notes.

**Asymmetry note:** the hosted UI at `truetake.github.io/verify-aul/` is force-repointed on the next Pages deploy. Exact-pin downstream consumers are stuck on the revoked version until they bump — the advisory is the forcing function. Consumers who pin `^0.1.x` will pick up the fix automatically but are exposed to the wider risks of loose pinning on a security-critical dependency.

The detailed rotation runbook is maintained internally; this one-page outline is the public-facing commitment.
