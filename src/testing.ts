/**
 * Test-only surface — reached via `import { ... } from '@truetake/verify-aul/testing'`.
 *
 * The production API (`verifyBundle` from `@truetake/verify-aul`) enforces the
 * pinned production trust anchors at load time. That means tests cannot
 * exercise the trust-anchor-mismatch path, and cannot verify pass vectors
 * signed under a fixtures CA, without an alternative entry point.
 *
 * `verifyBundleForTesting` accepts a `trustAnchorFingerprints` override.
 * Third-party implementers reading the spec never see this on the main API
 * surface; it's reached only through the `./testing` subpath export declared
 * in `package.json.exports`.
 *
 * Field-commitment primitives (`canonicalizeFieldValue`, `computeLeafHash`,
 * `verifyFieldProof`, `ENCODING_VERSION`, `DISCLOSABLE_FIELDS`) are re-exported
 * here so cross-implementation parity fixtures — most notably the commit-side
 * gold file at `server/services/ledger/__fixtures__/field-commitments.json` in
 * the TrueTake platform repo — can be regenerated from this package's
 * `@noble/hashes`-based implementation instead of the commit-side `node:crypto`
 * one. Keeping the surface on `./testing` (not on `.`) preserves the "external
 * verifiers implement from the spec, not from imports" stance for production
 * consumers.
 */

import type { VerificationBundle, VerificationResult, VerifyOptions } from './types.js';
import { _verifyBundleWithTestingOverrides } from './core.js';

export interface VerifyForTestingOptions extends VerifyOptions {
  /**
   * Map of `<filename>.pem` → SHA-256(SKI bytes), hex-encoded. Overrides the
   * production `TRUST_ANCHOR_FINGERPRINTS` pin set used at load time. Used
   * exclusively by the reference test-vector runner in `spec/test-vectors/`
   * and by consumers writing fixture-driven integration tests.
   */
  trustAnchorFingerprints?: Record<string, string>;
}

export function verifyBundleForTesting(
  bundle: VerificationBundle,
  options?: VerifyForTestingOptions,
): Promise<VerificationResult> {
  return _verifyBundleWithTestingOverrides(bundle, options);
}

export {
  DISCLOSABLE_FIELDS,
  ENCODING_VERSION,
  FieldCommitmentError,
  canonicalizeFieldValue,
  computeLeafHash,
  verifyFieldProof,
} from './field-commitment.js';
export type { DisclosableField, FieldCommitmentErrorCode } from './field-commitment.js';
