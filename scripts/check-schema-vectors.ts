#!/usr/bin/env node
/**
 * Spec-schema-vector coherence check.
 *
 * Loads `spec/schema/bundle.v1.json` and validates every non-placeholder
 * vector under `spec/test-vectors/` against it. Placeholders (vectors with
 * the `_TODO_unit_4b` marker) are skipped because they're shape-documented
 * stubs, not real vectors.
 *
 * This runs in CI alongside the verifier-level `spec-vectors.test.ts` so
 * that schema drift is caught separately from verdict drift.
 */

import { Ajv2020 } from 'ajv/dist/2020.js';
import addFormats from 'ajv-formats';
import { readFileSync, readdirSync } from 'node:fs';
import { resolve, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = dirname(fileURLToPath(import.meta.url));
const ROOT = resolve(__dirname, '..');
const SCHEMA_PATH = resolve(ROOT, 'spec/schema/bundle.v1.json');
const VECTORS_DIR = resolve(ROOT, 'spec/test-vectors');

function main(): number {
  const schema = JSON.parse(readFileSync(SCHEMA_PATH, 'utf8')) as Record<string, unknown>;
  const ajv = new Ajv2020({ strict: false, allErrors: true });
  // ajv-formats ships with wonky ESM/CJS interop; the default export is the initializer.
  (addFormats as unknown as (a: unknown) => void)(ajv);
  const validate = ajv.compile(schema);

  const files = readdirSync(VECTORS_DIR)
    .filter((f) => f.endsWith('.json'))
    .sort();

  let failures = 0;
  for (const file of files) {
    const path = resolve(VECTORS_DIR, file);
    const raw = JSON.parse(readFileSync(path, 'utf8')) as Record<string, unknown>;
    if ('_TODO_unit_4b' in raw) {
      console.log(`- [placeholder] ${file}: skipped until Unit 4b regenerates it`);
      continue;
    }
    const ok = validate(raw);
    if (!ok) {
      console.error(`✗ ${file} failed schema validation:`);
      for (const err of validate.errors ?? []) {
        console.error(`    ${err.instancePath || '(root)'} ${err.message}`);
      }
      failures++;
    } else {
      console.log(`✓ ${file} validates against schema`);
    }
  }

  if (failures > 0) {
    console.error(`\n${failures} vector(s) failed schema validation.`);
    return 1;
  }
  return 0;
}

const isDirectInvocation = import.meta.url === `file://${process.argv[1]}`;
if (isDirectInvocation) {
  process.exit(main());
}
