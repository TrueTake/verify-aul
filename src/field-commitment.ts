/**
 * AUL field-commitment primitives — verifier side.
 *
 * Mirrors `server/services/ledger/field-commitment.service.ts` in the platform
 * repo. The two implementations are intentionally independent (no shared code,
 * no cross-imports); byte-level agreement is pinned by the frozen platform-
 * parity fixture under `spec/test-vectors/platform-parity/` plus the disclosure
 * vectors under `spec/test-vectors/field-commitment-*.json`.
 *
 * Algorithm (spec §10):
 *   leaf_input = UTF-8( rfc8785_canonicalize( {
 *                  "encoding_version": <version>,
 *                  "field_name":       <field_path>,
 *                  "value":            <canonicalized value per §10.4>
 *                } ) )
 *   leaf       = SHA-256( 0x00 || salt || leaf_input )
 *   node       = SHA-256( 0x01 || left || right )
 *
 * CLI-internal: these symbols are NOT re-exported from `./index.ts` or
 * `./testing.ts` in this release. External verifiers implement from spec §10
 * and the test vectors. Re-expose via `./testing` in a future release if an
 * external verifier asks for programmatic access.
 */

import { sha256 } from '@noble/hashes/sha2.js';
import { bytesToHex, hexToBytes } from '@noble/hashes/utils.js';
import canonicalize from 'canonicalize';

import type { MerkleSibling } from './types.js';

// ---------------------------------------------------------------------------
// Allowlist + version (§10.4)
// ---------------------------------------------------------------------------

/** v1 allowlist — exactly one field (`approver.email`). See spec §10.4. */
export const DISCLOSABLE_FIELDS = ['approver.email'] as const;
export type DisclosableField = (typeof DISCLOSABLE_FIELDS)[number];

/** Leaf-input encoding version. Bumped if canonicalization rules ever change. */
export const ENCODING_VERSION = 'v1';

// ---------------------------------------------------------------------------
// Domain separators (RFC 6962 §2.1) — identical to src/merkle.ts
// ---------------------------------------------------------------------------

const LEAF_PREFIX = new Uint8Array([0x00]);
const NODE_PREFIX = new Uint8Array([0x01]);

// ---------------------------------------------------------------------------
// Canonicalization (§10.4)
// ---------------------------------------------------------------------------

/**
 * Canonicalize a field value per its per-version rule. Returns a UTF-8 string;
 * the caller feeds it into the JCS-wrapped leaf input (see `computeLeafHash`).
 *
 * v1 rules:
 *   `approver.email`: NFC → trim ASCII whitespace → lowercase.
 *
 * Throws with stable error codes on unknown encoding versions and unknown
 * field names. Error messages MUST NOT include the candidate value (PII
 * hygiene — mirrors platform's rule).
 */
export function canonicalizeFieldValue(
  name: string,
  value: string,
  encodingVersion: string = ENCODING_VERSION,
): string {
  switch (encodingVersion) {
    case 'v1':
      switch (name) {
        case 'approver.email':
          return value.normalize('NFC').trim().toLowerCase();
        default: {
          const err = new Error(`unknown field_name for encoding v1: ${name}`);
          (err as Error & { code?: string }).code = 'E_UNKNOWN_FIELD_PATH';
          throw err;
        }
      }
    default: {
      const err = new Error(`unknown encoding_version: ${encodingVersion}`);
      (err as Error & { code?: string }).code = 'E_UNKNOWN_ENCODING_VERSION';
      throw err;
    }
  }
}

// ---------------------------------------------------------------------------
// Leaf hash (§10.5)
// ---------------------------------------------------------------------------

/**
 * Compute the salted leaf hash for a field commitment.
 *
 * The raw `value` is canonicalized per §10.4 before being embedded in the
 * JCS-encoded leaf input object. Callers pass the candidate value as received
 * (from `--candidate` or a disclosure payload); this function is responsible
 * for applying the canonicalization rule so callers cannot accidentally skip
 * it.
 *
 * @param fieldPath      Disclosable field name (e.g., `"approver.email"`).
 * @param value          Raw candidate value as a UTF-8 string.
 * @param salt           16-byte salt.
 * @param encodingVersion Defaults to `'v1'`. Accepted for future-compatibility
 *                        with stored rows that carry their own version tag.
 * @returns 64-char lowercase hex leaf hash.
 */
export function computeLeafHash(
  fieldPath: string,
  value: string,
  salt: Uint8Array,
  encodingVersion: string = ENCODING_VERSION,
): string {
  if (salt.length !== 16) {
    throw new Error(`salt must be 16 bytes; got ${salt.length}`);
  }
  const canonical = canonicalizeFieldValue(fieldPath, value, encodingVersion);
  const leafInput = canonicalize({
    encoding_version: encodingVersion,
    field_name: fieldPath,
    value: canonical,
  });
  if (leafInput === undefined) {
    throw new Error('rfc8785 canonicalization returned undefined for leaf input');
  }
  const leafBytes = new TextEncoder().encode(leafInput);

  const h = sha256.create();
  h.update(LEAF_PREFIX);
  h.update(salt);
  h.update(leafBytes);
  return bytesToHex(h.digest());
}

// ---------------------------------------------------------------------------
// Merkle proof verification (§10.6)
// ---------------------------------------------------------------------------

/** SHA-256(0x01 || left_bytes || right_bytes), returned as 64-char lowercase hex. */
function computeNodeHash(left: string, right: string): string {
  const h = sha256.create();
  h.update(NODE_PREFIX);
  h.update(hexToBytes(left));
  h.update(hexToBytes(right));
  return bytesToHex(h.digest());
}

/**
 * Verify a field-commitment Merkle inclusion proof.
 *
 * Takes the leaf hash directly (field-commitment leaves are not event hashes,
 * so there is no event-hash → leaf re-hashing step; that's what `computeLeafHash`
 * is for). Walks siblings leaf-to-root combining under RFC 6962 internal-hash
 * rules with `direction`-respecting order.
 *
 * Single-leaf trees (empty `siblings`) verify when `leafHash === root`.
 *
 * @param leafHash 64-char lowercase hex leaf hash.
 * @param siblings Sibling path leaf-to-root.
 * @param root     64-char lowercase hex expected root.
 * @returns true if the reconstructed root matches `root`; false otherwise.
 */
export function verifyFieldProof(
  leafHash: string,
  siblings: MerkleSibling[],
  root: string,
): boolean {
  let current = leafHash;
  for (const sibling of siblings) {
    if (sibling.direction === 'right') {
      current = computeNodeHash(current, sibling.hash);
    } else {
      current = computeNodeHash(sibling.hash, current);
    }
  }
  return current === root;
}
