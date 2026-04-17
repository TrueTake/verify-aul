#!/usr/bin/env node
/**
 * Fingerprint-set disjointness check.
 *
 * Asserts that the production trust-anchor fingerprint set and the fixtures
 * fingerprint set have empty intersection. Defends against a silent bug
 * where a fixtures fingerprint accidentally bleeds into the production pin
 * map — a verifier running the test suite would otherwise pollute its
 * production trust set.
 *
 * Runs programmatically, not via grep.
 */

import { TRUST_ANCHOR_FINGERPRINTS } from '../src/trust-anchors/fingerprints.js';
import { TRUST_ANCHOR_FINGERPRINTS_FIXTURES } from '../spec/fixtures-trust-anchors/fingerprints.js';

function main(): number {
  const prodValues = new Set(Object.values(TRUST_ANCHOR_FINGERPRINTS));
  const fixturesValues = new Set(Object.values(TRUST_ANCHOR_FINGERPRINTS_FIXTURES));

  const intersection = [...fixturesValues].filter((v) => prodValues.has(v));

  if (intersection.length > 0) {
    console.error('✗ Fingerprint sets are NOT disjoint. Overlapping values:');
    for (const v of intersection) {
      console.error(`  ${v}`);
    }
    console.error(
      '\nThis is a critical bug: a fixtures anchor must never be in the production pin set.',
    );
    return 1;
  }

  const prodCount = Object.keys(TRUST_ANCHOR_FINGERPRINTS).length;
  const fixturesCount = Object.keys(TRUST_ANCHOR_FINGERPRINTS_FIXTURES).length;
  console.log(
    `✓ Fingerprint sets are disjoint (production: ${prodCount}, fixtures: ${fixturesCount}).`,
  );
  return 0;
}

const isDirectInvocation = import.meta.url === `file://${process.argv[1]}`;
if (isDirectInvocation) {
  process.exit(main());
}
