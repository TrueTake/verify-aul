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

import { verifyBundle } from './core.js';
import type { VerificationBundle } from './types.js';

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
