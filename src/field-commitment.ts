/**
 * AUL field-commitment primitives (spec §10). CLI-internal — not re-exported
 * from `./index.ts` or `./testing.ts`. External verifiers implement from the
 * spec + the disclosure test vectors. Byte-level agreement with the platform
 * commit-side implementation is pinned by `src/platform-parity.test.ts`.
 *
 *   leaf = SHA-256( 0x00 || salt || utf8( rfc8785( {
 *            encoding_version, field_name, value: canonical
 *          } ) ) )
 *   node = SHA-256( 0x01 || left || right )
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
 *   `approver.email`: NFC → trim whitespace (WHATWG) → lowercase.
 *
 * Throws a `FieldCommitmentError` on unknown encoding versions and unknown
 * field names. Error messages MUST NOT include the candidate value (PII
 * hygiene — mirrors platform's rule).
 */
export type FieldCommitmentErrorCode =
  | 'E_UNKNOWN_FIELD_PATH'
  | 'E_UNKNOWN_ENCODING_VERSION';

export class FieldCommitmentError extends Error {
  readonly code: FieldCommitmentErrorCode;
  constructor(message: string, code: FieldCommitmentErrorCode) {
    super(message);
    this.name = 'FieldCommitmentError';
    this.code = code;
  }
}

export function canonicalizeFieldValue(
  name: string,
  value: string,
  encodingVersion: string = ENCODING_VERSION,
): string {
  if (encodingVersion !== 'v1') {
    throw new FieldCommitmentError(
      `unknown encoding_version: ${encodingVersion}`,
      'E_UNKNOWN_ENCODING_VERSION',
    );
  }
  if (name === 'approver.email') {
    return value.normalize('NFC').trim().toLowerCase();
  }
  throw new FieldCommitmentError(
    `unknown field_name for encoding v1: ${name}`,
    'E_UNKNOWN_FIELD_PATH',
  );
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
