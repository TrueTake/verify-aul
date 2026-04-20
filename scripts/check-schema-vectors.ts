#!/usr/bin/env node
/**
 * Spec-schema-vector coherence check.
 *
 * Loads both `spec/schema/bundle.v1.json` and `spec/schema/disclosure.v1.json`
 * and validates every non-placeholder vector under `spec/test-vectors/`
 * against the matching schema. The shape discriminator is the presence of
 * the `field_path` property — disclosure vectors have it, bundle vectors
 * don't. Placeholders (vectors with the `_TODO_unit_4b` marker) are skipped.
 *
 * `readdirSync(VECTORS_DIR)` is deliberately non-recursive. The
 * `platform-parity/` subdirectory uses a different, non-normative fixture
 * shape and is validated programmatically by `src/platform-parity.test.ts`
 * rather than by this schema check — keeping it out of this walk is
 * load-bearing.
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
const BUNDLE_SCHEMA_PATH = resolve(ROOT, 'spec/schema/bundle.v1.json');
const DISCLOSURE_SCHEMA_PATH = resolve(ROOT, 'spec/schema/disclosure.v1.json');
const VECTORS_DIR = resolve(ROOT, 'spec/test-vectors');

function main(): number {
  const bundleSchema = JSON.parse(readFileSync(BUNDLE_SCHEMA_PATH, 'utf8')) as Record<
    string,
    unknown
  >;
  const disclosureSchema = JSON.parse(readFileSync(DISCLOSURE_SCHEMA_PATH, 'utf8')) as Record<
    string,
    unknown
  >;

  const ajv = new Ajv2020({ strict: false, allErrors: true });
  // ajv-formats ships with wonky ESM/CJS interop; the default export is the initializer.
  (addFormats as unknown as (a: unknown) => void)(ajv);
  const validateBundle = ajv.compile(bundleSchema);
  const validateDisclosure = ajv.compile(disclosureSchema);

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
    const isDisclosure = 'field_path' in raw;
    const validate = isDisclosure ? validateDisclosure : validateBundle;
    const kind = isDisclosure ? 'disclosure' : 'bundle';
    const ok = validate(raw);
    if (!ok) {
      console.error(`✗ ${file} failed ${kind} schema validation:`);
      for (const err of validate.errors ?? []) {
        console.error(`    ${err.instancePath || '(root)'} ${err.message}`);
      }
      failures++;
    } else {
      console.log(`✓ ${file} validates against ${kind} schema`);
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
