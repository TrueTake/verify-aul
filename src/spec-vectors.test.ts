/**
 * Spec-vector coherence tests.
 *
 * Loads each `spec/test-vectors/*.json` file, runs it through
 * `verifyBundleForTesting`, and asserts the verdict matches what the
 * co-located `.md` sibling documents. The vectors are part of the
 * specification — divergence between the verifier and the spec is caught
 * here as a test failure, not as silent drift.
 *
 * **v1.0-rc.1 scope:** only the four deterministic vectors run to a concrete
 * verdict assertion. The four crypto-bearing vectors are shape-only placeholders
 * (marked with `_TODO_unit_4b`); they are only exercised for schema validity
 * until `spec/generate-fixtures.ts` regenerates them with real fixtures-CA
 * signatures (Unit 4b).
 */

import { describe, expect, it } from 'vitest';
import { readFile } from 'node:fs/promises';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

import { verifyBundleForTesting } from './testing.js';
import type { VerificationBundle } from './types.js';

const __dirname = dirname(fileURLToPath(import.meta.url));
const VECTORS_DIR = resolve(__dirname, '..', 'spec', 'test-vectors');

interface Vector {
  filename: string;
  expectedVerdict: 'pass' | 'partial' | 'fail';
  deterministic: boolean;
}

const VECTORS: Vector[] = [
  { filename: 'fail-unsupported-version.json', expectedVerdict: 'fail', deterministic: true },
  { filename: 'fail-tampered-event.json', expectedVerdict: 'fail', deterministic: true },
  { filename: 'fail-bad-merkle.json', expectedVerdict: 'fail', deterministic: true },
  { filename: 'fail-bad-anchor.json', expectedVerdict: 'fail', deterministic: true },
  { filename: 'tier1-pass.json', expectedVerdict: 'pass', deterministic: false },
  { filename: 'tier2-pass.json', expectedVerdict: 'pass', deterministic: false },
  { filename: 'partial-missing-anchor.json', expectedVerdict: 'partial', deterministic: false },
  { filename: 'fail-trust-anchor-mismatch.json', expectedVerdict: 'fail', deterministic: false },
];

async function loadVector(filename: string): Promise<VerificationBundle> {
  const path = resolve(VECTORS_DIR, filename);
  const raw = await readFile(path, 'utf-8');
  return JSON.parse(raw) as VerificationBundle;
}

describe('spec vectors — deterministic', () => {
  for (const vector of VECTORS.filter((v) => v.deterministic)) {
    it(`${vector.filename} → verdict ${vector.expectedVerdict}`, async () => {
      const bundle = await loadVector(vector.filename);
      const result = await verifyBundleForTesting(bundle);
      expect(result.verdict).toBe(vector.expectedVerdict);
    });
  }
});

describe('spec vectors — placeholders (Unit 4b)', () => {
  for (const vector of VECTORS.filter((v) => !v.deterministic)) {
    it(`${vector.filename} is flagged for Unit 4b regeneration`, async () => {
      const raw = await readFile(resolve(VECTORS_DIR, vector.filename), 'utf-8');
      const parsed = JSON.parse(raw) as Record<string, unknown>;
      // Explicit contract: placeholder vectors carry the `_TODO_unit_4b` marker.
      // When Unit 4b lands, the generator writes real vectors without this key
      // and the assertion below flips to a verdict check in a follow-up PR.
      expect(parsed['_TODO_unit_4b']).toBeDefined();
    });
  }
});
