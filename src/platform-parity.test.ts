/**
 * Cross-implementation byte-equality test.
 *
 * Loads `spec/test-vectors/platform-parity/field-commitment.json` — a frozen
 * fixture copied from the TrueTake platform repo — and asserts that this
 * package's `computeLeafHash` reproduces each `expected_leaf_hashes` entry
 * byte-for-byte, and that `verifyFieldProof` accepts each recorded proof
 * against the declared `expected_root`.
 *
 * The platform uses `node:crypto`; this package uses `@noble/hashes`. Byte
 * equality under identical inputs is the signal that the spec is
 * re-implementable in any language. See the sibling `.md` for source
 * provenance and refresh policy.
 */

import { describe, expect, it } from 'vitest';
import { readFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { sha256 } from '@noble/hashes/sha2.js';
import { bytesToHex, hexToBytes } from '@noble/hashes/utils.js';

import { computeLeafHash, verifyFieldProof } from './field-commitment.js';
import type { MerkleSibling } from './types.js';

const __dirname = dirname(fileURLToPath(import.meta.url));
const FIXTURE_PATH = resolve(
  __dirname,
  '..',
  'spec',
  'test-vectors',
  'platform-parity',
  'field-commitment.json',
);

interface FixtureInput {
  field_name: string;
  value: string;
  salt_hex: string;
}

interface FixtureProof {
  leaf_index: number;
  path: Array<{ hash: string; direction: 'left' | 'right' }>;
}

interface FixtureEntry {
  description: string;
  inputs: FixtureInput[];
  expected_leaf_hashes: string[];
  expected_root: string;
  proofs: FixtureProof[];
}

interface FixtureFile {
  encoding_version: string;
  fixtures: FixtureEntry[];
}

function loadFixture(): FixtureFile {
  const raw = readFileSync(FIXTURE_PATH, 'utf-8');
  return JSON.parse(raw) as FixtureFile;
}

/** Rebuild the Merkle root from pre-hashed leaves using RFC 6962 rules.
 *  Mirrors platform's `buildMerkleTree` without duplicating odd-leaf nodes. */
function buildRootFromLeaves(leafHashesHex: string[]): string {
  if (leafHashesHex.length === 0) throw new Error('empty leaves');
  let level = leafHashesHex.slice();
  while (level.length > 1) {
    const next: string[] = [];
    for (let i = 0; i < level.length; i += 2) {
      if (i + 1 < level.length) {
        const h = sha256.create();
        h.update(new Uint8Array([0x01]));
        h.update(hexToBytes(level[i]!));
        h.update(hexToBytes(level[i + 1]!));
        next.push(bytesToHex(h.digest()));
      } else {
        next.push(level[i]!);
      }
    }
    level = next;
  }
  return level[0]!;
}

describe('platform-parity fixture', () => {
  const fixtureFile = loadFixture();

  it('fixture declares encoding_version v1', () => {
    expect(fixtureFile.encoding_version).toBe('v1');
  });

  for (const fixture of fixtureFile.fixtures) {
    describe(fixture.description, () => {
      const actualLeafHashes = fixture.inputs.map((inp) =>
        computeLeafHash(
          inp.field_name,
          inp.value,
          hexToBytes(inp.salt_hex),
          fixtureFile.encoding_version,
        ),
      );

      it('leaf hashes match platform byte-for-byte', () => {
        expect(actualLeafHashes).toEqual(fixture.expected_leaf_hashes);
      });

      it('reconstructed root matches platform byte-for-byte', () => {
        const actualRoot = buildRootFromLeaves(actualLeafHashes);
        expect(actualRoot).toBe(fixture.expected_root);
      });

      for (const expectedProof of fixture.proofs) {
        it(`proof for leaf_index ${expectedProof.leaf_index} verifies against expected_root`, () => {
          const leafHash = actualLeafHashes[expectedProof.leaf_index]!;
          const siblings: MerkleSibling[] = expectedProof.path;
          expect(verifyFieldProof(leafHash, siblings, fixture.expected_root)).toBe(true);
        });
      }
    });
  }
});
