/**
 * Spec-vector coherence tests.
 *
 * Loads each `spec/test-vectors/*.json` file, runs it through the verifier,
 * and asserts the verdict matches what the co-located `.md` sibling
 * documents. The vectors are part of the specification — divergence between
 * the verifier and the spec is caught here as a test failure, not as silent
 * drift.
 *
 * All eight reference vectors verify end-to-end against the production
 * trust anchors pinned in `src/trust-anchors/`. Pass / partial vectors
 * contain real FreeTSA + DigiCert TimeStampTokens (minted by
 * `spec/generate-fixtures.ts`, which contacts both TSAs at generation
 * time). The mismatch vector's token is signed by a local fixtures CA
 * whose cert is not in any pinned trust set, so CMS signature verification
 * fails deterministically and the verdict is `fail`.
 */

import { describe, expect, it } from 'vitest';
import { readFile } from 'node:fs/promises';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { hexToBytes } from '@noble/hashes/utils.js';

import { verifyBundle } from './core.js';
import { computeLeafHash, verifyFieldProof } from './field-commitment.js';
import type { MerkleSibling, VerificationBundle } from './types.js';

const __dirname = dirname(fileURLToPath(import.meta.url));
const VECTORS_DIR = resolve(__dirname, '..', 'spec', 'test-vectors');

interface Vector {
  filename: string;
  expectedVerdict: 'pass' | 'partial' | 'fail';
}

const VECTORS: Vector[] = [
  { filename: 'fail-unsupported-version.json', expectedVerdict: 'fail' },
  { filename: 'fail-tampered-event.json', expectedVerdict: 'fail' },
  { filename: 'fail-bad-merkle.json', expectedVerdict: 'fail' },
  { filename: 'fail-bad-anchor.json', expectedVerdict: 'fail' },
  { filename: 'tier1-pass.json', expectedVerdict: 'pass' },
  { filename: 'tier2-pass.json', expectedVerdict: 'pass' },
  { filename: 'partial-missing-anchor.json', expectedVerdict: 'partial' },
  { filename: 'fail-trust-anchor-mismatch.json', expectedVerdict: 'fail' },
];

async function loadVector(filename: string): Promise<VerificationBundle> {
  const path = resolve(VECTORS_DIR, filename);
  const raw = await readFile(path, 'utf-8');
  return JSON.parse(raw) as VerificationBundle;
}

describe('spec vectors', () => {
  for (const vector of VECTORS) {
    it(`${vector.filename} → verdict ${vector.expectedVerdict}`, async () => {
      const bundle = await loadVector(vector.filename);
      const result = await verifyBundle(bundle);
      expect(result.verdict).toBe(vector.expectedVerdict);
    });
  }
});

// ---------------------------------------------------------------------------
// Field-commitment vectors (§10.9) — primitives only
//
// These vectors do not flow through `verifyBundle`; they exercise the
// field-commitment primitives directly. The end-to-end CLI binding vector
// (`field-commitment-binding`) lives in `spec-vectors.field-commitment.test.ts`
// because it requires `vi.mock('./core.js')`, which is module-hoisted and
// would silently stub the real `verifyBundle` for the bundle vectors above
// if declared in this file.
// ---------------------------------------------------------------------------

interface DisclosureVector {
  field_path: string;
  salt: string;
  merkle_path: MerkleSibling[];
  root: string;
  event_hash: string;
}

// The canonical committed value for each vector. These are NOT on the wire
// (the disclosure format deliberately omits them — §10.2). They are known
// out-of-band to anyone regenerating the vectors via `spec/generate-fixtures.ts`
// and are inlined here so the parity test below can assert that a specific
// candidate folds to the same leaf as the value the commit side hashed.
const COMMITTED_VALUES: Record<string, string> = {
  'field-commitment-pass.json': 'alice@example.com',
  'field-commitment-nfc.json': 'caf\u00e9@example.com',
  'field-commitment-fail.json': 'alice@example.com',
};

async function loadDisclosure(filename: string): Promise<DisclosureVector> {
  const path = resolve(VECTORS_DIR, filename);
  const raw = await readFile(path, 'utf-8');
  return JSON.parse(raw) as DisclosureVector;
}

function base64UrlToBytes(b64url: string): Uint8Array {
  return Uint8Array.from(Buffer.from(b64url, 'base64url'));
}

describe('field-commitment primitives vectors (spec §10.9)', () => {
  it('field-commitment-pass: candidate canonicalizes to the committed value and proof verifies', async () => {
    const v = await loadDisclosure('field-commitment-pass.json');
    const salt = base64UrlToBytes(v.salt);
    const committed = COMMITTED_VALUES['field-commitment-pass.json']!;
    // Candidate in mixed case + trailing space canonicalizes to the committed value.
    const candidate = 'Alice@Example.COM ';
    const leafHash = computeLeafHash(v.field_path, candidate, salt);
    // Cross-check: the canonical form produces the same leaf.
    expect(computeLeafHash(v.field_path, committed, salt)).toBe(leafHash);
    expect(verifyFieldProof(leafHash, v.merkle_path, v.root)).toBe(true);
  });

  it('field-commitment-nfc: NFD candidate produces same leaf as the NFC committed value', async () => {
    const v = await loadDisclosure('field-commitment-nfc.json');
    const salt = base64UrlToBytes(v.salt);
    const committed = COMMITTED_VALUES['field-commitment-nfc.json']!;
    const nfdCandidate = 'cafe\u0301@example.com'; // decomposed
    const nfcLeaf = computeLeafHash(v.field_path, committed, salt);
    const nfdLeaf = computeLeafHash(v.field_path, nfdCandidate, salt);
    expect(nfdLeaf).toBe(nfcLeaf);
    expect(verifyFieldProof(nfdLeaf, v.merkle_path, v.root)).toBe(true);
  });

  it('field-commitment-fail: proof verification returns false (tampered root)', async () => {
    const v = await loadDisclosure('field-commitment-fail.json');
    const salt = base64UrlToBytes(v.salt);
    const committed = COMMITTED_VALUES['field-commitment-fail.json']!;
    const leafHash = computeLeafHash(v.field_path, committed, salt);
    expect(verifyFieldProof(leafHash, v.merkle_path, v.root)).toBe(false);
  });

  it('salt fields are 16 bytes after base64url decode', async () => {
    for (const filename of [
      'field-commitment-pass.json',
      'field-commitment-binding.json',
      'field-commitment-nfc.json',
      'field-commitment-fail.json',
    ]) {
      const v = await loadDisclosure(filename);
      expect(base64UrlToBytes(v.salt).length, `${filename} salt bytes`).toBe(16);
    }
  });

  it('root and event_hash fields are 64-char lowercase hex', async () => {
    for (const filename of [
      'field-commitment-pass.json',
      'field-commitment-binding.json',
      'field-commitment-nfc.json',
      'field-commitment-fail.json',
    ]) {
      const v = await loadDisclosure(filename);
      expect(v.root, `${filename} root`).toMatch(/^[0-9a-f]{64}$/);
      expect(v.event_hash, `${filename} event_hash`).toMatch(/^[0-9a-f]{64}$/);
      // Ensure hex is decodable as bytes.
      expect(hexToBytes(v.root).length).toBe(32);
    }
  });
});
