# @truetake/verify-aul

Open-source verifier for TrueTake [Authorized Use Ledger](https://www.truetake.com) (AUL) bundles.

## What this verifies

A **verification bundle** is the full evidence envelope for a single AUL event:

- Canonical event fields (who did what, when, with which artifact hashes).
- The server's Ed25519 signature over the event hash.
- A Merkle inclusion proof tying the event to a batch root.
- RFC 3161 TSA tokens from two independent timestamping authorities (FreeTSA + DigiCert) over the batch root.
- A Solana memo transaction over the batch root.
- The public key used for signing (inlined — no network lookup required).

This package runs the five verification checks locally, pinning CA trust anchors by SubjectKeyIdentifier SHA-256, and returns a `pass` / `partial` / `fail` verdict.

## Install

```bash
npm install @truetake/verify-aul
```

```typescript
import { verifyBundle } from '@truetake/verify-aul';

const result = await verifyBundle(bundle);
console.log(result.verdict); // 'pass' | 'partial' | 'fail'
```

## CLI

```bash
npx @truetake/verify-aul bundle ./some-bundle.json
```

Exit codes: `0` pass, `1` fail/partial, `2` usage error.

## Hosted UI

A self-hostable static verifier is published at [truetake.github.io/verify-aul/](https://truetake.github.io/verify-aul/). Drop a bundle file onto the page and read the report — no platform round-trip required.

## Trust model

The verifier trusts **only** the CA fingerprints pinned in `src/trust-anchors/fingerprints.ts` and the Solana + TSA endpoints the caller points it at. Rotation is shipped as a patch release; consumers should pin exact versions (`0.1.0-alpha.0`, not `^0.1.0`) and review release notes on every bump.

## Spec

The bundle format is documented in [`spec/v1.md`](./spec/v1.md). JSON Schema: [`spec/schema/bundle.v1.json`](./spec/schema/bundle.v1.json). Eight reference test vectors live in [`spec/test-vectors/`](./spec/test-vectors/).

## Reproducible build

The hosted UI can be rebuilt from this repository and compared against the deployed artifact:

```bash
git checkout <tag>
npm ci
npm run build
npm run build:web
diff <(sort web/dist/MANIFEST.sha256) <(sort <downloaded-dist-dir>/MANIFEST.sha256)
```

Byte-identical diffs are unreliable across OS / filesystem / locale, so the build emits a per-file SHA-256 manifest (`web/dist/MANIFEST.sha256`, also shipped alongside the deployed Pages artifact at `/MANIFEST.sha256`) for comparison instead.

## License

[MIT](./LICENSE).

## Security

See [`SECURITY.md`](./SECURITY.md) for disclosure contact and threat-model notes.
