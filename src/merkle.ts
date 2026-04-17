/**
 * RFC 6962-compliant Merkle inclusion proof verification.
 *
 * Isomorphic — runs identically in Node and browser. Uses @noble/hashes/sha256
 * instead of node:crypto so it works without a polyfill in the browser.
 *
 * Algorithm mirrors server/services/ledger/anchor/merkle.ts exactly:
 * - Leaf:     SHA-256(0x00 || event_hash_bytes)
 * - Internal: SHA-256(0x01 || left || right)
 * - Odd-node: promote without duplication (RFC 6962 §2.1)
 * - Siblings: { hash: string, direction: 'left' | 'right' }
 */

import { sha256 } from '@noble/hashes/sha2.js';
import { bytesToHex, hexToBytes } from '@noble/hashes/utils.js';

// ---------------------------------------------------------------------------
// Domain separators (RFC 6962 §2.1)
// ---------------------------------------------------------------------------

const LEAF_PREFIX = new Uint8Array([0x00]);
const NODE_PREFIX = new Uint8Array([0x01]);

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/** SHA-256 of concatenated byte arrays, returned as 64-char lowercase hex. */
function hashConcat(...parts: Uint8Array[]): string {
  const h = sha256.create();
  for (const p of parts) h.update(p);
  return bytesToHex(h.digest());
}

/**
 * Compute the RFC 6962 leaf hash for an event hash.
 * SHA-256(0x00 || event_hash_bytes)
 */
function computeLeafHash(eventHash: string): string {
  return hashConcat(LEAF_PREFIX, hexToBytes(eventHash));
}

/**
 * Compute an internal node hash from two child hashes.
 * SHA-256(0x01 || left_bytes || right_bytes)
 */
function computeNodeHash(left: string, right: string): string {
  return hashConcat(NODE_PREFIX, hexToBytes(left), hexToBytes(right));
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

export interface MerkleProofInput {
  siblings: Array<{ hash: string; direction: 'left' | 'right' }>;
  root: string;
}

/**
 * Verify an RFC 6962 Merkle inclusion proof for a given event hash.
 *
 * Recomputes the leaf hash from the event hash, walks the sibling path
 * combining with RFC 6962 domain separators, and checks that the computed
 * root matches the proof root.
 *
 * @param eventHash - 64-char hex event hash (the leaf data before leaf-hashing)
 * @param proof - Siblings (ordered leaf-to-root) and expected root
 * @returns true if the proof is valid; false otherwise
 */
export function verifyMerkleInclusion(eventHash: string, proof: MerkleProofInput): boolean {
  let current = computeLeafHash(eventHash);

  for (const sibling of proof.siblings) {
    if (sibling.direction === 'right') {
      // current is left child; sibling is right child
      current = computeNodeHash(current, sibling.hash);
    } else {
      // current is right child; sibling is left child
      current = computeNodeHash(sibling.hash, current);
    }
  }

  return current === proof.root;
}
