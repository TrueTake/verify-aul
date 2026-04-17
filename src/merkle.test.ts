/**
 * Merkle inclusion proof verification tests.
 *
 * Validates the RFC 6962 Merkle proof verification logic in isolation,
 * exercising leaf hash computation, sibling directions, single-leaf trees,
 * and odd-node promotion.
 */

import { describe, it, expect } from 'vitest';

import { verifyMerkleInclusion } from './merkle.js';
import { sha256 } from '@noble/hashes/sha2.js';
import { bytesToHex, hexToBytes } from '@noble/hashes/utils.js';

// ---------------------------------------------------------------------------
// Test helpers mirroring the production algorithm
// ---------------------------------------------------------------------------

function hashConcat(...parts: Uint8Array[]): string {
  const h = sha256.create();
  for (const p of parts) h.update(p);
  return bytesToHex(h.digest());
}

function computeLeafHash(eventHash: string): string {
  return hashConcat(new Uint8Array([0x00]), hexToBytes(eventHash));
}

function computeNodeHash(left: string, right: string): string {
  return hashConcat(new Uint8Array([0x01]), hexToBytes(left), hexToBytes(right));
}

// Build a Merkle tree and return root + leaves (mirrors server algorithm)
function buildTree(eventHashes: string[]): { root: string; leaves: string[] } {
  const leaves = eventHashes.map(computeLeafHash);
  let level = leaves;
  while (level.length > 1) {
    const next: string[] = [];
    for (let i = 0; i < level.length; i += 2) {
      if (i + 1 < level.length) {
        next.push(computeNodeHash(level[i]!, level[i + 1]!));
      } else {
        next.push(level[i]!); // odd node promotion
      }
    }
    level = next;
  }
  return { root: level[0]!, leaves };
}

// Generate a proof for a leaf at leafIndex
function buildProof(
  eventHashes: string[],
  leafIndex: number,
): { siblings: Array<{ hash: string; direction: 'left' | 'right' }>; root: string } {
  const { leaves, root } = buildTree(eventHashes);
  const siblings: Array<{ hash: string; direction: 'left' | 'right' }> = [];

  let level = leaves;
  let idx = leafIndex;

  while (level.length > 1) {
    const next: string[] = [];
    let newIdx = -1;

    for (let i = 0; i < level.length; i += 2) {
      const parentIdx = next.length;
      if (i + 1 < level.length) {
        next.push(computeNodeHash(level[i]!, level[i + 1]!));
        if (i === idx) {
          siblings.push({ hash: level[i + 1]!, direction: 'right' });
          newIdx = parentIdx;
        } else if (i + 1 === idx) {
          siblings.push({ hash: level[i]!, direction: 'left' });
          newIdx = parentIdx;
        }
      } else {
        next.push(level[i]!);
        if (i === idx) newIdx = parentIdx;
      }
    }

    level = next;
    idx = newIdx;
  }

  return { siblings, root };
}

// ---------------------------------------------------------------------------
// Test fixtures — deterministic values
// ---------------------------------------------------------------------------

const EH1 = 'a'.repeat(64); // aaaa...aaaa (64 chars)
const EH2 = 'b'.repeat(64);
const EH3 = 'c'.repeat(64);
const EH4 = 'd'.repeat(64);

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe('verifyMerkleInclusion', () => {
  it('single-leaf tree (batch of 1) passes with empty siblings', () => {
    const { root } = buildTree([EH1]);
    // Single leaf: root = leafHash(EH1), no siblings
    const proof = { siblings: [], root };
    expect(verifyMerkleInclusion(EH1, proof)).toBe(true);
  });

  it('verifies leaf 0 in a two-leaf tree (right sibling)', () => {
    const proof = buildProof([EH1, EH2], 0);
    // leaf 0 is left child; its sibling should be 'right'
    expect(proof.siblings).toHaveLength(1);
    expect(proof.siblings[0]!.direction).toBe('right');
    expect(verifyMerkleInclusion(EH1, proof)).toBe(true);
  });

  it('verifies leaf 1 in a two-leaf tree (left sibling)', () => {
    const proof = buildProof([EH1, EH2], 1);
    // leaf 1 is right child; its sibling should be 'left'
    expect(proof.siblings).toHaveLength(1);
    expect(proof.siblings[0]!.direction).toBe('left');
    expect(verifyMerkleInclusion(EH2, proof)).toBe(true);
  });

  it('verifies leaves in a four-leaf tree (two levels)', () => {
    for (let i = 0; i < 4; i++) {
      const eventHashes = [EH1, EH2, EH3, EH4];
      const proof = buildProof(eventHashes, i);
      expect(verifyMerkleInclusion(eventHashes[i]!, proof)).toBe(true);
    }
  });

  it('verifies leaves in a three-leaf tree with odd-node promotion', () => {
    // tree: [leaf1, leaf2, leaf3]
    // level 0: leaf1, leaf2, leaf3 (odd → leaf3 promoted)
    // level 1: node(leaf1,leaf2), leaf3
    // level 2 (root): node(node12, leaf3)
    for (let i = 0; i < 3; i++) {
      const proof = buildProof([EH1, EH2, EH3], i);
      const eventHashes = [EH1, EH2, EH3];
      expect(verifyMerkleInclusion(eventHashes[i]!, proof)).toBe(true);
    }
  });

  it('exercises both left and right sibling directions', () => {
    const rightProof = buildProof([EH1, EH2], 0); // leaf 0 has right sibling
    const leftProof = buildProof([EH1, EH2], 1); // leaf 1 has left sibling

    expect(rightProof.siblings[0]!.direction).toBe('right');
    expect(leftProof.siblings[0]!.direction).toBe('left');

    expect(verifyMerkleInclusion(EH1, rightProof)).toBe(true);
    expect(verifyMerkleInclusion(EH2, leftProof)).toBe(true);
  });

  it('returns false for a tampered event hash', () => {
    const proof = buildProof([EH1, EH2], 0);
    const tamperedHash = 'f'.repeat(64);
    expect(verifyMerkleInclusion(tamperedHash, proof)).toBe(false);
  });

  it('returns false for a tampered sibling hash', () => {
    const proof = buildProof([EH1, EH2], 0);
    const tamperedProof = {
      ...proof,
      siblings: [{ hash: 'f'.repeat(64), direction: 'right' as const }],
    };
    expect(verifyMerkleInclusion(EH1, tamperedProof)).toBe(false);
  });

  it('returns false when the root is wrong', () => {
    const proof = buildProof([EH1, EH2], 0);
    const wrongRootProof = { ...proof, root: 'f'.repeat(64) };
    expect(verifyMerkleInclusion(EH1, wrongRootProof)).toBe(false);
  });

  it('correctly handles a single-leaf "wrong hash" case', () => {
    const { root } = buildTree([EH1]);
    const proof = { siblings: [], root };
    // Wrong event hash
    expect(verifyMerkleInclusion(EH2, proof)).toBe(false);
  });
});
