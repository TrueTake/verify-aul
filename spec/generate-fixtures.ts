#!/usr/bin/env node
/**
 * Regenerate the reference test vectors under `spec/test-vectors/`, plus
 * the fixtures CA PEM + its pinned SHA-256 SKI fingerprint.
 *
 * Two phases:
 *
 *   **Offline-deterministic phase** — emits the four field-commitment
 *   disclosure vectors (`field-commitment-*.json`). No network, no
 *   wall-clock, no non-deterministic key generation. Suitable for CI
 *   byte-equality gating with `git diff --exit-code`.
 *
 *   **Network phase** — emits the crypto-bearing bundle vectors
 *   (`tier1-pass`, `tier2-pass`, `partial-missing-anchor`,
 *   `fail-trust-anchor-mismatch`) and the fixtures CA artifacts.
 *   Contacts FreeTSA + DigiCert for real RFC 3161 TimeStampTokens and
 *   generates a fresh fixtures CA via `webcrypto.subtle.generateKey()`
 *   — the CA PEM and the mismatch vector are NOT byte-deterministic
 *   across runs. Do not gate CI on byte-equality of outputs from this
 *   phase.
 *
 * Run:
 *     npm run fixtures:generate            # both phases
 *     npm run fixtures:generate:offline    # offline phase only
 *
 * The `fail-trust-anchor-mismatch` vector uses a TimeStampToken signed
 * by the local fixtures CA; its issuer chain does not terminate at any
 * PEM pinned in `src/`, so CMS signature verification fails and the
 * verdict is `fail`.
 */

import * as ed25519 from '@noble/ed25519';
import { sha256 } from '@noble/hashes/sha2.js';
import { bytesToHex, hexToBytes } from '@noble/hashes/utils.js';
import canonicalize from 'canonicalize';
import { writeFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

import { computeLeafHash } from '../src/field-commitment.js';
import type { MerkleSibling } from '../src/types.js';

import { DIGICERT, FREETSA, fetchTsaToken } from './tools/fetch-tsa.js';
import { buildFixturesCa, signFixturesTimeStampToken } from './tools/fixtures-ca.js';

const __dirname = dirname(fileURLToPath(import.meta.url));
const VECTORS_DIR = resolve(__dirname, 'test-vectors');
const FIXTURES_DIR = resolve(__dirname, 'fixtures-trust-anchors');

// ---------------------------------------------------------------------------
// Helpers — RFC 6962 Merkle (mirrors src/merkle.ts exactly)
// ---------------------------------------------------------------------------

function leafHash(eventHash: string): string {
  const h = sha256.create();
  h.update(Uint8Array.from([0x00]));
  h.update(hexToBytes(eventHash));
  return bytesToHex(h.digest());
}

/** Compute the Merkle root for a single-leaf tree. */
function singleLeafRoot(eventHash: string): string {
  return leafHash(eventHash);
}

/** Compute SHA-256(canonicalize(event)) — the event_hash production rule. */
function eventHashFor(event: Record<string, unknown>): string {
  const canonical = canonicalize(event);
  if (canonical === undefined) throw new Error('canonicalize returned undefined');
  return bytesToHex(sha256(new TextEncoder().encode(canonical)));
}

// ---------------------------------------------------------------------------
// Ed25519 helpers (for tier2-pass server_signature)
// ---------------------------------------------------------------------------

function toBase64Url(bytes: Uint8Array): string {
  return Buffer.from(bytes).toString('base64url');
}

async function generateSigningKey() {
  const privateKey = ed25519.utils.randomSecretKey();
  const publicKey = await ed25519.getPublicKeyAsync(privateKey);
  // Matches `computeFingerprint` in the platform: base64url(SHA-256(publicKey))[:16].
  const fingerprint = toBase64Url(sha256(publicKey)).slice(0, 16);
  return { privateKey, publicKey, fingerprint };
}

// ---------------------------------------------------------------------------
// Vector specifications
// ---------------------------------------------------------------------------

interface TsaAnchor {
  type: 'tsa_freetsa' | 'tsa_digicert';
  token: string;
  external_timestamp: string;
}

/**
 * The tier2-pass event object. Lifted to a module constant so the
 * field-commitment `binding` vector can bind to this event's hash
 * without re-declaring it.
 */
const TIER2_PASS_EVENT = {
  deal_id: 'deal-spec-vector',
  event_type: 'ACCEPT_TERMS',
  actor_user_id: 'user-spec-vector',
  actor_org_id: 'org-spec-vector',
  actor_role: 'talent',
  timestamp: '2026-04-17T00:00:00.000Z',
  prev_event_hash: null,
  metadata: { note: 'spec-vector: tier2-pass' },
  artifact_references: [],
} as const;

async function generateTier2Pass(fixturesInfo: { caSkiSha256Hex: string }): Promise<void> {
  console.log('[tier2-pass] building event + Merkle root');
  const event = TIER2_PASS_EVENT;
  const eventHash = eventHashFor(event);
  const root = singleLeafRoot(eventHash);

  console.log('[tier2-pass] generating Ed25519 signing key');
  const { privateKey, publicKey, fingerprint } = await generateSigningKey();
  const signature = await ed25519.signAsync(hexToBytes(eventHash), privateKey);

  console.log('[tier2-pass] requesting FreeTSA token…');
  const freetsa = await fetchTsaToken(FREETSA, root);
  console.log('[tier2-pass] requesting DigiCert token…');
  const digicert = await fetchTsaToken(DIGICERT, root);

  const bundle = {
    bundle_schema_version: 1,
    status: 'confirmed',
    event_hash: eventHash,
    event,
    server_signature: bytesToHex(signature),
    signing_key_id: fingerprint,
    signing_keys: [
      {
        fingerprint,
        public_key_base64url: toBase64Url(publicKey),
        status: 'active',
      },
    ],
    merkle_proof: { leaf_index: 0, siblings: [], root },
    anchors: [
      {
        type: 'tsa_freetsa',
        token: freetsa.tokenBase64Der,
        external_timestamp: freetsa.externalTimestamp,
      } as TsaAnchor,
      {
        type: 'tsa_digicert',
        token: digicert.tokenBase64Der,
        external_timestamp: digicert.externalTimestamp,
      } as TsaAnchor,
    ],
    partial_anchors_reason: [],
  };

  writeVector('tier2-pass.json', bundle);
}

async function generateTier1Pass(): Promise<void> {
  console.log('[tier1-pass] building Tier 1 proof');
  // Tier 1 has only event_hash, merkle_proof, anchors — no event / sig / keys.
  // Use a deterministic synthetic hash so the committed vector's Merkle root
  // is reproducible without needing to share real event data.
  const eventHash = bytesToHex(sha256(new TextEncoder().encode('spec-vector:tier1-pass'))); // 64-char hex
  const root = singleLeafRoot(eventHash);

  console.log('[tier1-pass] requesting FreeTSA token…');
  const freetsa = await fetchTsaToken(FREETSA, root);
  console.log('[tier1-pass] requesting DigiCert token…');
  const digicert = await fetchTsaToken(DIGICERT, root);

  const bundle = {
    bundle_schema_version: 1,
    status: 'confirmed',
    event_hash: eventHash,
    merkle_proof: { leaf_index: 0, siblings: [], root },
    anchors: [
      {
        type: 'tsa_freetsa',
        token: freetsa.tokenBase64Der,
        external_timestamp: freetsa.externalTimestamp,
      } as TsaAnchor,
      {
        type: 'tsa_digicert',
        token: digicert.tokenBase64Der,
        external_timestamp: digicert.externalTimestamp,
      } as TsaAnchor,
    ],
    partial_anchors_reason: [],
  };

  writeVector('tier1-pass.json', bundle);
}

async function generatePartialMissingAnchor(): Promise<void> {
  console.log('[partial-missing-anchor] building Tier 1 with only DigiCert present');
  const eventHash = bytesToHex(sha256(new TextEncoder().encode('spec-vector:partial-missing-anchor')));
  const root = singleLeafRoot(eventHash);

  console.log('[partial-missing-anchor] requesting DigiCert token (FreeTSA declared missing)…');
  const digicert = await fetchTsaToken(DIGICERT, root);

  const bundle = {
    bundle_schema_version: 1,
    status: 'partial',
    event_hash: eventHash,
    merkle_proof: { leaf_index: 0, siblings: [], root },
    anchors: [
      {
        type: 'tsa_digicert',
        token: digicert.tokenBase64Der,
        external_timestamp: digicert.externalTimestamp,
      } as TsaAnchor,
    ],
    // Non-empty partial_anchors_reason with all checks passing triggers the
    // "partial" row in the verdict truth table (§5 of the spec).
    partial_anchors_reason: ['tsa_freetsa'],
  };

  writeVector('partial-missing-anchor.json', bundle);
}

async function generateTrustAnchorMismatch(fixturesCa: {
  fixtures: Awaited<ReturnType<typeof buildFixturesCa>>;
}): Promise<void> {
  console.log('[fail-trust-anchor-mismatch] signing token with local fixtures CA');
  const eventHash = bytesToHex(
    sha256(new TextEncoder().encode('spec-vector:fail-trust-anchor-mismatch')),
  );
  const root = singleLeafRoot(eventHash);

  const fixturesToken = await signFixturesTimeStampToken(fixturesCa.fixtures, root);

  const bundle = {
    bundle_schema_version: 1,
    status: 'confirmed',
    event_hash: eventHash,
    merkle_proof: { leaf_index: 0, siblings: [], root },
    anchors: [
      // Claim this is a FreeTSA anchor so the verifier routes it through the
      // TSA verification path. The embedded token is signed by the local
      // fixtures CA, which is not pinned — CMS sig verification fails.
      {
        type: 'tsa_freetsa',
        token: fixturesToken.tokenBase64Der,
        external_timestamp: fixturesToken.genTime.toISOString(),
      } as TsaAnchor,
    ],
    partial_anchors_reason: [],
  };

  writeVector('fail-trust-anchor-mismatch.json', bundle);
}

// ---------------------------------------------------------------------------
// Field-commitment vectors (offline, deterministic) — spec §10.9
// ---------------------------------------------------------------------------

/** SHA-256(0x01 || left_bytes || right_bytes), returned as 64-char hex. */
function fieldNodeHash(left: string, right: string): string {
  const h = sha256.create();
  h.update(Uint8Array.from([0x01]));
  h.update(hexToBytes(left));
  h.update(hexToBytes(right));
  return bytesToHex(h.digest());
}

/** Walk siblings leaf-to-root, returning the reconstructed root. */
function walkRoot(leafHash: string, siblings: MerkleSibling[]): string {
  let current = leafHash;
  for (const s of siblings) {
    current = s.direction === 'right' ? fieldNodeHash(current, s.hash) : fieldNodeHash(s.hash, current);
  }
  return current;
}

function generateFieldCommitmentPass(): void {
  console.log('[field-commitment-pass] building ASCII primitives happy path');
  const saltBytes = new Uint8Array(16).fill(0x2a);
  const salt = Buffer.from(saltBytes).toString('base64url');
  const fieldValue = 'alice@example.com';
  const eventHash = 'a'.repeat(64); // placeholder — this vector tests primitives only

  const leaf = computeLeafHash('approver.email', fieldValue, saltBytes);
  // Two-sibling path exercising both directions. Siblings are arbitrary
  // 32-byte values — this vector validates the walk mechanics, not any
  // specific tree shape.
  const sibL = '11'.repeat(32);
  const sibR = '22'.repeat(32);
  const merkle: MerkleSibling[] = [
    { hash: sibL, direction: 'left' },
    { hash: sibR, direction: 'right' },
  ];
  const root = walkRoot(leaf, merkle);

  writeVector('field-commitment-pass.json', {
    field_path: 'approver.email',
    field_value: fieldValue,
    salt,
    merkle_path: merkle,
    root,
    event_hash: eventHash,
  });
}

function generateFieldCommitmentBinding(): void {
  console.log('[field-commitment-binding] binding to tier2-pass event_hash');
  const saltBytes = new Uint8Array(16).fill(0x42);
  const salt = Buffer.from(saltBytes).toString('base64url');
  const fieldValue = 'alice@example.com';
  const eventHash = eventHashFor(TIER2_PASS_EVENT);

  const leaf = computeLeafHash('approver.email', fieldValue, saltBytes);
  // Single-leaf tree: empty siblings, root === leaf.
  writeVector('field-commitment-binding.json', {
    field_path: 'approver.email',
    field_value: fieldValue,
    salt,
    merkle_path: [],
    root: leaf,
    event_hash: eventHash,
  });
}

function generateFieldCommitmentNfc(): void {
  console.log('[field-commitment-nfc] non-ASCII NFC invariant');
  // salt pattern: 0x55 x 16 (recognisable in base64url as "VVVVVVVVVVVVVVVVVVVVVQ")
  const saltBytes = new Uint8Array(16).fill(0x55);
  const salt = Buffer.from(saltBytes).toString('base64url');
  // Commit the NFC-canonicalized value. The co-located .md documents the
  // NFD form of the plain candidate that canonicalizes to match.
  const fieldValue = 'caf\u00e9@example.com';
  const eventHash = 'c'.repeat(64);

  const leaf = computeLeafHash('approver.email', fieldValue, saltBytes);
  writeVector('field-commitment-nfc.json', {
    field_path: 'approver.email',
    field_value: fieldValue,
    salt,
    merkle_path: [],
    root: leaf,
    event_hash: eventHash,
  });
}

function generateFieldCommitmentFail(): void {
  console.log('[field-commitment-fail] tampered root (expected verdict: fail)');
  const saltBytes = new Uint8Array(16).fill(0x2a);
  const salt = Buffer.from(saltBytes).toString('base64url');
  const fieldValue = 'alice@example.com';
  const eventHash = 'a'.repeat(64);

  const leaf = computeLeafHash('approver.email', fieldValue, saltBytes);
  const sibL = '11'.repeat(32);
  const sibR = '22'.repeat(32);
  const merkle: MerkleSibling[] = [
    { hash: sibL, direction: 'left' },
    { hash: sibR, direction: 'right' },
  ];
  const realRoot = walkRoot(leaf, merkle);
  // Flip the last two hex chars to tamper the root.
  const tamperedRoot = realRoot.slice(0, -2) + (realRoot.slice(-2) === 'ff' ? '00' : 'ff');

  writeVector('field-commitment-fail.json', {
    field_path: 'approver.email',
    field_value: fieldValue,
    salt,
    merkle_path: merkle,
    root: tamperedRoot,
    event_hash: eventHash,
  });
}

async function runOfflinePhase(): Promise<void> {
  console.log('\n[offline] regenerating deterministic field-commitment vectors');
  generateFieldCommitmentPass();
  generateFieldCommitmentBinding();
  generateFieldCommitmentNfc();
  generateFieldCommitmentFail();
  console.log('[offline] done');
}

async function runNetworkPhase(): Promise<void> {
  console.log('[fixtures] building local CA + TSA signing cert');
  const fixtures = await buildFixturesCa();

  // Write the fixtures CA PEM + fingerprints file.
  writeFileSync(resolve(FIXTURES_DIR, 'test-ca.pem'), fixtures.caCertPem);
  console.log(`  wrote fixtures-trust-anchors/test-ca.pem`);
  writeFileSync(
    resolve(FIXTURES_DIR, 'fingerprints.ts'),
    `/**
 * Fixtures-only trust anchor fingerprint map.
 *
 * **Not for production use.** The fixtures CA under \`test-ca.pem\` is
 * generated by \`spec/tools/fixtures-ca.ts\` and is only referenced by the
 * \`fail-trust-anchor-mismatch\` test vector. A CI check asserts this map
 * has empty set-intersection with \`src/trust-anchors/fingerprints.ts\`
 * so a fixtures anchor cannot leak into a production verifier's trust set.
 *
 * Regenerated by \`npm run fixtures:generate\`. Do not hand-edit.
 */
export const TRUST_ANCHOR_FINGERPRINTS_FIXTURES: Record<string, string> = {
  'test-ca.pem': '${fixtures.caSkiSha256Hex}',
};
`,
  );
  console.log(`  wrote fixtures-trust-anchors/fingerprints.ts`);

  console.log('\n[vectors] regenerating crypto-bearing reference test vectors');
  await generateTier1Pass();
  await generateTier2Pass({ caSkiSha256Hex: fixtures.caSkiSha256Hex });
  await generatePartialMissingAnchor();
  await generateTrustAnchorMismatch({ fixtures });

  console.log('[network] done');
}

// ---------------------------------------------------------------------------
// I/O
// ---------------------------------------------------------------------------

function writeVector(filename: string, bundle: Record<string, unknown>): void {
  const path = resolve(VECTORS_DIR, filename);
  writeFileSync(path, JSON.stringify(bundle, null, 2) + '\n');
  console.log(`  wrote ${filename}`);
}

async function main(): Promise<void> {
  const args = process.argv.slice(2);
  const offlineOnly = args.includes('--offline');

  await runOfflinePhase();
  if (!offlineOnly) {
    await runNetworkPhase();
  }

  console.log('\n[done] Run `npm test` to verify.');
}

const isDirectInvocation = import.meta.url === `file://${process.argv[1]}`;
if (isDirectInvocation) {
  main().catch((err) => {
    console.error(err);
    process.exit(1);
  });
}

