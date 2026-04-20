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
# Verify a Tier 2 bundle (event + signature + anchors).
npx @truetake/verify-aul bundle ./some-bundle.json

# Verify a Tier 1 proof (anchors only, no event/signature).
npx @truetake/verify-aul proof ./some-proof.json

# Verify a single-field Merkle disclosure against its companion bundle (spec §10).
npx @truetake/verify-aul verify-field \
  --bundle ./bundle.json --disclosure ./disclosure.json \
  --candidate alice@example.com
```

Exit codes: `0` pass, `1` fail/partial/error, `2` usage error.

### `verify-field` — sensitive candidate values

`--candidate <VALUE>` leaks the disclosed value to argv (`/proc`, `ps`, shell
history, CI logs). For anything resembling PII, prefer `--candidate-file`,
which reads UTF-8 file contents (minus a single trailing newline):

```bash
npx @truetake/verify-aul verify-field \
  --bundle ./bundle.json --disclosure ./disclosure.json \
  --candidate-file ./candidate.txt
```

### Operational notes

- **Solana RPC trust.** Bundle verification trusts the Solana RPC endpoint
  for transaction confirmation data. Operators SHOULD pin a known-good
  endpoint via `--solana-rpc <url>` or query multiple endpoints and
  compare. See [spec §10.10](./spec/v1.md#1010-trust-model-and-operational-constraints).
- **Payload size.** The CLI refuses bundle / disclosure files larger than
  10 MB to mitigate DoS against automated verification pipelines.

## Hosted UI

A self-hostable static verifier is published at [truetake.github.io/verify-aul/](https://truetake.github.io/verify-aul/). Drop a bundle file onto the page and read the report — no platform round-trip required.

## Trust model

The verifier trusts **only** the CA fingerprints pinned in `src/trust-anchors/fingerprints.ts` and the Solana + TSA endpoints the caller points it at. Rotation is shipped as a patch release; consumers should pin exact versions (`0.1.0-alpha.0`, not `^0.1.0`) and review release notes on every bump.

## Spec

The bundle format is documented in [`spec/v1.md`](./spec/v1.md). Field-disclosure payloads are documented in [`spec/v1.md` §10](./spec/v1.md#10-field-disclosure-bundles-v1). JSON Schemas: [`spec/schema/bundle.v1.json`](./spec/schema/bundle.v1.json), [`spec/schema/disclosure.v1.json`](./spec/schema/disclosure.v1.json). Reference test vectors — including four disclosure vectors and a platform-parity fixture — live in [`spec/test-vectors/`](./spec/test-vectors/).

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
