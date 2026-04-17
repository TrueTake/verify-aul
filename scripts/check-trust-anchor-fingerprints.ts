#!/usr/bin/env node
/**
 * Trust-anchor sync + fingerprint check.
 *
 * Runs two independent assertions:
 *
 *   1. **Inline-file sync** — the PEM template literals in `src/core.ts`
 *      (`FREETSA_PEM`, `DIGICERT_PEM`) must match `src/trust-anchors/*.pem`
 *      byte-for-byte after block-extraction and LF-normalization.
 *
 *   2. **SKI fingerprint validity** — for each `.pem` under
 *      `src/trust-anchors/`, parse the cert, extract the
 *      SubjectKeyIdentifier bytes, compute SHA-256, and check the value
 *      matches `TRUST_ANCHOR_FINGERPRINTS[<filename>]`. A `.pem` without a
 *      matching fingerprint entry fails with "unpinned trust anchor".
 *
 * CI enforces this on every PR (Unit 6). Honest defense note: this catches
 * *inconsistent* edits but not a consistent same-PR substitution by a sole
 * maintainer. The structural defense against that (≥2 codeowner approvals)
 * is deferred until a second maintainer onboards — see SECURITY.md §4.
 */

import { readFileSync, readdirSync } from 'node:fs';
import { resolve, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { sha256 } from '@noble/hashes/sha2.js';
import { bytesToHex } from '@noble/hashes/utils.js';

import { extractSkiBytes, parsePemCert } from '../src/tsa.js';
import { TRUST_ANCHOR_FINGERPRINTS } from '../src/trust-anchors/fingerprints.js';

const __dirname = dirname(fileURLToPath(import.meta.url));
const ROOT = resolve(__dirname, '..');
const CORE_PATH = resolve(ROOT, 'src/core.ts');
const ANCHORS_DIR = resolve(ROOT, 'src/trust-anchors');

const INLINE_CONSTANTS: Array<{ file: string; constantName: string }> = [
  { file: 'freetsa.pem', constantName: 'FREETSA_PEM' },
  { file: 'digicert.pem', constantName: 'DIGICERT_PEM' },
];

// ---------------------------------------------------------------------------
// Normalize + extract helpers (exported for unit tests)
// ---------------------------------------------------------------------------

export function normalizePem(pem: string): string {
  const match = pem.match(/-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----/);
  if (!match) throw new Error('No PEM block found');
  return match[0].trim().replace(/\r\n/g, '\n');
}

export function extractInlineConstant(source: string, name: string): string {
  const re = new RegExp(`const\\s+${name}\\s*=\\s*\`([\\s\\S]*?)\`\\s*;`, 'm');
  const m = source.match(re);
  if (!m || !m[1]) throw new Error(`Could not find inline constant ${name} in core.ts`);
  return m[1];
}

// ---------------------------------------------------------------------------
// Main — executed when invoked as a script
// ---------------------------------------------------------------------------

function main(): number {
  let failures = 0;
  const coreSource = readFileSync(CORE_PATH, 'utf8');

  // Check 1: inline vs file sync
  for (const { file, constantName } of INLINE_CONSTANTS) {
    const filePath = resolve(ANCHORS_DIR, file);
    let fileContent: string;
    let inlineContent: string;
    try {
      fileContent = normalizePem(readFileSync(filePath, 'utf8'));
      inlineContent = normalizePem(extractInlineConstant(coreSource, constantName));
    } catch (err) {
      console.error(`✗ [inline-sync] ${file}: ${(err as Error).message}`);
      failures++;
      continue;
    }
    if (fileContent !== inlineContent) {
      console.error(`✗ [inline-sync] ${file} does not match inline ${constantName} in src/core.ts`);
      failures++;
    } else {
      console.log(`✓ [inline-sync] ${file} matches inline ${constantName}`);
    }
  }

  // Check 2: SKI fingerprint validity + unpinned-anchor detection
  const pemFiles = readdirSync(ANCHORS_DIR).filter((f) => f.endsWith('.pem'));
  for (const file of pemFiles) {
    if (!TRUST_ANCHOR_FINGERPRINTS[file]) {
      console.error(
        `✗ [unpinned-anchor] ${file} has no entry in TRUST_ANCHOR_FINGERPRINTS — add one or remove the PEM`,
      );
      failures++;
      continue;
    }
    const pem = readFileSync(resolve(ANCHORS_DIR, file), 'utf8');
    const der = parsePemCert(pem);
    const ski = extractSkiBytes(der);
    if (!ski) {
      console.error(`✗ [ski-missing] ${file}: cert has no SubjectKeyIdentifier extension`);
      failures++;
      continue;
    }
    const actual = bytesToHex(sha256(ski));
    const expected = TRUST_ANCHOR_FINGERPRINTS[file];
    if (actual !== expected) {
      console.error(
        `✗ [fingerprint-mismatch] ${file}\n  expected ${expected}\n  actual   ${actual}`,
      );
      failures++;
    } else {
      console.log(`✓ [fingerprint] ${file} SKI SHA-256 matches pin`);
    }
  }

  if (failures > 0) {
    console.error(`\n${failures} trust-anchor check(s) failed.`);
    return 1;
  }
  console.log('\nAll trust-anchor checks passed.');
  return 0;
}

// Only run when executed directly, not when imported by tests.
const isDirectInvocation = import.meta.url === `file://${process.argv[1]}`;
if (isDirectInvocation) {
  process.exit(main());
}
