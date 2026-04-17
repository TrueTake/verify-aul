/**
 * `@truetake/verify-aul` — public entry point.
 *
 * Isomorphic: runs under Node >=20 and in modern browsers via WebCrypto.
 *
 * See spec/v1.0-rc.1.md for the bundle format, verdict truth table, and the
 * five verification checks.
 */

export { verifyBundle } from './core.js';

export type {
  Anchor,
  BundleSigningKey,
  Check,
  CheckStatus,
  MerkleProof,
  MerkleSibling,
  SolanaAnchor,
  TsaAnchor,
  Verdict,
  VerificationBundle,
  VerificationResult,
  VerifyOptions,
} from './types.js';

export { TRUST_ANCHOR_FINGERPRINTS } from './trust-anchors/fingerprints.js';
