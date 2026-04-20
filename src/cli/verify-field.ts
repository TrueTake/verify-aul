/**
 * `verify-field` subcommand handler — single-field Merkle disclosure
 * verification (spec §10).
 *
 * Takes three inputs:
 *
 *   `--disclosure <path>`   Path to a disclosure payload (spec §10.2).
 *   `--bundle <path>`       Path to the verification bundle the disclosure binds to.
 *   `--candidate <VALUE>`   Raw candidate value (e.g., `alice@example.com`).
 *   or
 *   `--candidate-file <path>` File whose UTF-8 contents (minus a single trailing
 *                           newline) are the candidate value.
 *
 * The handler runs the §10.8 algorithm:
 *
 *   1. verifyBundle (mandatory) — short-circuits to `error` on non-`pass`.
 *   2. checkBinding — disclosure.event_hash === bundle.event_hash, strict
 *      64-char lowercase hex on both sides; reject non-conforming encodings.
 *   3. canonicalizeCandidate — apply the §10.4 rule for disclosure.field_path.
 *   4. computeLeafHash — SHA-256 over the JCS-wrapped leaf input with salt.
 *   5. verifyMerkleProof — walk disclosure.merkle_path to disclosure.root.
 *
 * Pass invariant: the handler refuses to emit verdict `pass` unless the
 * bundle verdict is `pass`. This is a code-level guard against a future
 * `--skip-bundle-check` regression.
 *
 * Exit codes match the `bundle` / `proof` contract:
 *   0 — verdict `pass`.
 *   1 — verdict `fail` or `error`.
 *   2 — usage error (missing flag, malformed JSON, oversized file, etc.).
 */

import { readFile, stat } from 'node:fs/promises';
import { resolve } from 'node:path';

import { verifyBundle } from '../core.js';
import {
  computeLeafHash,
  canonicalizeFieldValue,
  DISCLOSABLE_FIELDS,
  ENCODING_VERSION,
  verifyFieldProof,
} from '../field-commitment.js';
import type {
  MerkleSibling,
  VerificationBundle,
  VerificationResult,
  Verdict,
} from '../types.js';

// ---------------------------------------------------------------------------
// Option surface
// ---------------------------------------------------------------------------

export interface VerifyFieldCommandOptions {
  disclosurePath: string;
  bundlePath: string;
  /** Raw candidate value; mutually exclusive with `candidateFile`. */
  candidate: string | null;
  /** Path to candidate file; mutually exclusive with `candidate`. */
  candidateFile: string | null;
  trustAnchorsDer?: Uint8Array[];
  solanaRpcUrl?: string;
  json: boolean;
  verbose: boolean;
}

/** Disclosure payload shape — mirrors spec §10.2 / schema/disclosure.v1.json. */
interface DisclosurePayload {
  field_path: string;
  field_value: string;
  salt: string;
  merkle_path: MerkleSibling[];
  root: string;
  event_hash: string;
}

export type FieldVerdict = 'pass' | 'fail' | 'error';

/** Verdict record emitted by `runVerifyFieldCommand` (via `--json`). */
interface FieldVerdictReport {
  subcommand: 'verify-field';
  disclosure: string;
  bundle: string;
  verdict: FieldVerdict;
  bundle_verdict: Verdict | null;
  reason: string | null;
  rpc_endpoint_used: string | null;
}

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/** 10 MB cap on bundle + disclosure JSON reads (spec §10.10). */
const MAX_FILE_SIZE_BYTES = 10 * 1024 * 1024;
const HEX64_RE = /^[0-9a-f]{64}$/;
const BASE64URL_SALT_RE = /^[A-Za-z0-9_-]{22}$/;

// ---------------------------------------------------------------------------
// Small I/O helpers
// ---------------------------------------------------------------------------

async function readJsonFile(
  label: string,
  path: string,
): Promise<{ raw: Record<string, unknown> } | { error: string; exitCode: 1 | 2 }> {
  const absPath = resolve(path);
  let stats: Awaited<ReturnType<typeof stat>>;
  try {
    stats = await stat(absPath);
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    return { error: `could not stat ${label} file: ${msg}`, exitCode: 2 };
  }
  if (stats.size > MAX_FILE_SIZE_BYTES) {
    return {
      error: `${label} file exceeds 10 MB cap (${stats.size} bytes); refusing to read`,
      exitCode: 2,
    };
  }
  let body: string;
  try {
    body = await readFile(absPath, 'utf-8');
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    return { error: `could not read ${label} file: ${msg}`, exitCode: 2 };
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse(body);
  } catch {
    return { error: `${label} file is not valid JSON: ${absPath}`, exitCode: 2 };
  }
  if (parsed === null || typeof parsed !== 'object' || Array.isArray(parsed)) {
    return { error: `${label} file must contain a JSON object`, exitCode: 2 };
  }
  return { raw: parsed as Record<string, unknown> };
}

function base64UrlToBytes(b64url: string): Uint8Array {
  return Uint8Array.from(Buffer.from(b64url, 'base64url'));
}

// ---------------------------------------------------------------------------
// Disclosure shape validation
// ---------------------------------------------------------------------------

function validateDisclosureShape(
  raw: Record<string, unknown>,
): { disclosure: DisclosurePayload } | { error: string } {
  const requiredStringFields = ['field_path', 'field_value', 'salt', 'root', 'event_hash'] as const;
  for (const f of requiredStringFields) {
    if (typeof raw[f] !== 'string') {
      return { error: `disclosure missing or invalid '${f}' (expected string)` };
    }
  }
  if (!Array.isArray(raw.merkle_path)) {
    return { error: `disclosure missing or invalid 'merkle_path' (expected array)` };
  }
  const fieldPath = raw.field_path as string;
  if (!(DISCLOSABLE_FIELDS as readonly string[]).includes(fieldPath)) {
    return { error: `unknown field_path: ${fieldPath}` };
  }
  const root = raw.root as string;
  if (!HEX64_RE.test(root)) {
    return { error: `disclosure.root must be 64-char lowercase hex` };
  }
  const eventHash = raw.event_hash as string;
  if (!HEX64_RE.test(eventHash)) {
    return {
      error: `disclosure.event_hash must be 64-char lowercase hex (got: ${eventHash})`,
    };
  }
  const salt = raw.salt as string;
  if (!BASE64URL_SALT_RE.test(salt)) {
    return { error: `disclosure.salt must be 22-char unpadded base64url (16 raw bytes)` };
  }
  // salt already matches BASE64URL_SALT_RE (22 chars, 16 raw bytes);
  // Buffer.from('<22 base64url chars>', 'base64url') never throws, and the
  // decoded length is always 16. No further runtime check needed.
  const siblings: MerkleSibling[] = [];
  for (let i = 0; i < raw.merkle_path.length; i += 1) {
    const s = raw.merkle_path[i];
    if (s === null || typeof s !== 'object' || Array.isArray(s)) {
      return { error: `disclosure.merkle_path[${i}] must be an object` };
    }
    const sibling = s as Record<string, unknown>;
    if (typeof sibling.hash !== 'string' || !HEX64_RE.test(sibling.hash)) {
      return { error: `disclosure.merkle_path[${i}].hash must be 64-char lowercase hex` };
    }
    if (sibling.direction !== 'left' && sibling.direction !== 'right') {
      return { error: `disclosure.merkle_path[${i}].direction must be 'left' or 'right'` };
    }
    siblings.push({ hash: sibling.hash, direction: sibling.direction });
  }

  return {
    disclosure: {
      field_path: fieldPath,
      field_value: raw.field_value as string,
      salt,
      merkle_path: siblings,
      root,
      event_hash: eventHash,
    },
  };
}

// ---------------------------------------------------------------------------
// Verdict formatter — constructs the report object; enforces pass invariant.
// ---------------------------------------------------------------------------

/**
 * Construct a verdict report, enforcing the §10.8 step-7 pass invariant:
 * a verifier MUST NOT emit `pass` unless the bundle verdict is `pass`.
 *
 * Exported so tests can exercise the invariant directly (without relying on
 * the earlier short-circuit in `runVerifyFieldCommand` that catches the same
 * condition). This is the load-bearing guard against a hypothetical future
 * regression that loosens the earlier check (e.g., `--skip-bundle-check`).
 */
export function buildReport(params: {
  disclosure: string;
  bundle: string;
  verdict: FieldVerdict;
  bundleVerdict: Verdict | null;
  reason: string | null;
  rpcEndpoint: string | null;
}): FieldVerdictReport {
  const { disclosure, bundle, bundleVerdict, reason, rpcEndpoint } = params;
  let verdict = params.verdict;
  // Code-level pass invariant (spec §10.8 step 6): a verifier MUST NOT
  // emit `pass` unless the bundle verdict is `pass`.
  if (verdict === 'pass' && bundleVerdict !== 'pass') {
    verdict = 'error';
  }
  return {
    subcommand: 'verify-field',
    disclosure,
    bundle,
    verdict,
    bundle_verdict: bundleVerdict,
    reason,
    rpc_endpoint_used: rpcEndpoint,
  };
}

// ---------------------------------------------------------------------------
// Output
// ---------------------------------------------------------------------------

function formatHuman(report: FieldVerdictReport): string {
  const lines: string[] = [];
  lines.push('AUL Verification Report — verify-field');
  lines.push(`  disclosure: ${report.disclosure}`);
  lines.push(`  bundle:     ${report.bundle}`);
  if (report.rpc_endpoint_used) {
    lines.push(`  rpc:        ${report.rpc_endpoint_used}`);
  }
  lines.push(`  verdict:    ${report.verdict.toUpperCase()}`);
  if (report.bundle_verdict) {
    lines.push(`  bundle:     ${report.bundle_verdict}`);
  }
  if (report.reason) {
    lines.push(`  reason:     ${report.reason}`);
  }
  return lines.join('\n');
}

function emitReport(report: FieldVerdictReport, asJson: boolean): void {
  if (asJson) {
    process.stdout.write(JSON.stringify(report, null, 2) + '\n');
  } else {
    process.stdout.write(formatHuman(report) + '\n');
  }
}

function exitFor(verdict: FieldVerdict): 0 | 1 {
  return verdict === 'pass' ? 0 : 1;
}

// ---------------------------------------------------------------------------
// Main entry point
// ---------------------------------------------------------------------------

export async function runVerifyFieldCommand(opts: VerifyFieldCommandOptions): Promise<void> {
  // Input option arbitration.
  if (opts.candidate !== null && opts.candidateFile !== null) {
    process.stderr.write(
      `Error: --candidate and --candidate-file are mutually exclusive. Use one.\n`,
    );
    process.exit(2);
  }
  if (opts.candidate === null && opts.candidateFile === null) {
    process.stderr.write(
      `Error: one of --candidate <VALUE> or --candidate-file <path> is required\n`,
    );
    process.exit(2);
  }
  if (opts.candidateFile !== null && opts.candidateFile === '') {
    process.stderr.write(`Error: --candidate-file requires a non-empty path\n`);
    process.exit(2);
  }

  // Resolve candidate string.
  let candidate: string;
  if (opts.candidateFile !== null) {
    const absPath = resolve(opts.candidateFile);
    let stats: Awaited<ReturnType<typeof stat>>;
    try {
      stats = await stat(absPath);
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      process.stderr.write(`Error: could not stat candidate file: ${msg}\n`);
      process.exit(2);
    }
    if (stats.size > MAX_FILE_SIZE_BYTES) {
      process.stderr.write(
        `Error: candidate file exceeds 10 MB cap (${stats.size} bytes)\n`,
      );
      process.exit(2);
    }
    let body: string;
    try {
      body = await readFile(absPath, 'utf-8');
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      process.stderr.write(`Error: could not read candidate file: ${msg}\n`);
      process.exit(2);
    }
    // Strip a single trailing newline (\n or \r\n), not all whitespace.
    candidate = body.endsWith('\r\n')
      ? body.slice(0, -2)
      : body.endsWith('\n')
        ? body.slice(0, -1)
        : body;
  } else {
    candidate = opts.candidate!;
  }

  // Read disclosure + bundle JSON.
  const disclosureRead = await readJsonFile('disclosure', opts.disclosurePath);
  if ('error' in disclosureRead) {
    process.stderr.write(`Error: ${disclosureRead.error}\n`);
    process.exit(disclosureRead.exitCode);
  }
  const bundleRead = await readJsonFile('bundle', opts.bundlePath);
  if ('error' in bundleRead) {
    process.stderr.write(`Error: ${bundleRead.error}\n`);
    process.exit(bundleRead.exitCode);
  }

  // Validate disclosure shape.
  const shape = validateDisclosureShape(disclosureRead.raw);
  if ('error' in shape) {
    const report = buildReport({
      disclosure: opts.disclosurePath,
      bundle: opts.bundlePath,
      verdict: 'error',
      bundleVerdict: null,
      reason: shape.error,
      rpcEndpoint: null,
    });
    emitReport(report, opts.json);
    process.exit(exitFor(report.verdict));
  }
  const disclosure = shape.disclosure;

  // Step 1: verifyBundle (mandatory).
  const bundleRaw = bundleRead.raw as unknown as VerificationBundle;
  const verifyOpts: Parameters<typeof verifyBundle>[1] = {};
  if (opts.trustAnchorsDer && opts.trustAnchorsDer.length > 0) {
    verifyOpts.trustAnchors = opts.trustAnchorsDer;
  }
  if (opts.solanaRpcUrl) {
    verifyOpts.solanaRpcUrl = opts.solanaRpcUrl;
  }
  let bundleResult: VerificationResult;
  try {
    bundleResult = await verifyBundle(bundleRaw, verifyOpts);
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    const report = buildReport({
      disclosure: opts.disclosurePath,
      bundle: opts.bundlePath,
      verdict: 'error',
      bundleVerdict: null,
      reason: `bundle verification threw: ${msg}`,
      rpcEndpoint: null,
    });
    emitReport(report, opts.json);
    process.exit(exitFor(report.verdict));
  }

  if (bundleResult.verdict !== 'pass') {
    const report = buildReport({
      disclosure: opts.disclosurePath,
      bundle: opts.bundlePath,
      verdict: 'error',
      bundleVerdict: bundleResult.verdict,
      reason: 'bundle verification did not pass',
      rpcEndpoint: bundleResult.rpc_endpoint_used,
    });
    emitReport(report, opts.json);
    process.exit(exitFor(report.verdict));
  }

  // Step 2: checkBinding.
  if (typeof bundleRaw.event_hash !== 'string') {
    const report = buildReport({
      disclosure: opts.disclosurePath,
      bundle: opts.bundlePath,
      verdict: 'error',
      bundleVerdict: bundleResult.verdict,
      reason: 'bundle.event_hash missing or not a string',
      rpcEndpoint: bundleResult.rpc_endpoint_used,
    });
    emitReport(report, opts.json);
    process.exit(exitFor(report.verdict));
  }
  if (!HEX64_RE.test(bundleRaw.event_hash)) {
    const report = buildReport({
      disclosure: opts.disclosurePath,
      bundle: opts.bundlePath,
      verdict: 'error',
      bundleVerdict: bundleResult.verdict,
      reason: `bundle.event_hash must be 64-char lowercase hex (got: ${bundleRaw.event_hash})`,
      rpcEndpoint: bundleResult.rpc_endpoint_used,
    });
    emitReport(report, opts.json);
    process.exit(exitFor(report.verdict));
  }
  if (disclosure.event_hash !== bundleRaw.event_hash) {
    const report = buildReport({
      disclosure: opts.disclosurePath,
      bundle: opts.bundlePath,
      verdict: 'error',
      bundleVerdict: bundleResult.verdict,
      reason: `event_hash mismatch: disclosure=${disclosure.event_hash} bundle=${bundleRaw.event_hash}`,
      rpcEndpoint: bundleResult.rpc_endpoint_used,
    });
    emitReport(report, opts.json);
    process.exit(exitFor(report.verdict));
  }

  // Step 3: checkBindingRoot (spec §10.7 Binding B).
  //
  // disclosure.root MUST equal bundle.event.metadata.event_root. Without this
  // check, an attacker with any legitimate bundle can forge a disclosure for
  // an attacker-chosen field_value: fresh salt + merkle_path=[] +
  // root=computeLeafHash(attackerValue, salt) produces a self-consistent walk.
  // The event_root binding closes the gap because event_root lives inside
  // bundle.event, which is transitively committed by event_hash (verified in
  // step 1 via verifyBundle's canonical_recompute check).
  //
  // Tier 1 proofs (§3.1) omit `event` and therefore cannot support
  // field-disclosure verification — we reject them explicitly here.
  if (bundleRaw.event === undefined || bundleRaw.event === null) {
    const report = buildReport({
      disclosure: opts.disclosurePath,
      bundle: opts.bundlePath,
      verdict: 'error',
      bundleVerdict: bundleResult.verdict,
      reason: 'bundle.event missing — field-disclosure verification requires a Tier 2 bundle',
      rpcEndpoint: bundleResult.rpc_endpoint_used,
    });
    emitReport(report, opts.json);
    process.exit(exitFor(report.verdict));
  }
  const bundleEvent = bundleRaw.event as Record<string, unknown>;
  const bundleMetadata = bundleEvent.metadata;
  if (bundleMetadata === null || typeof bundleMetadata !== 'object' || Array.isArray(bundleMetadata)) {
    const report = buildReport({
      disclosure: opts.disclosurePath,
      bundle: opts.bundlePath,
      verdict: 'error',
      bundleVerdict: bundleResult.verdict,
      reason: 'bundle.event.metadata missing or not an object',
      rpcEndpoint: bundleResult.rpc_endpoint_used,
    });
    emitReport(report, opts.json);
    process.exit(exitFor(report.verdict));
  }
  const bundleEventRoot = (bundleMetadata as Record<string, unknown>).event_root;
  if (typeof bundleEventRoot !== 'string' || !HEX64_RE.test(bundleEventRoot)) {
    const report = buildReport({
      disclosure: opts.disclosurePath,
      bundle: opts.bundlePath,
      verdict: 'error',
      bundleVerdict: bundleResult.verdict,
      reason: 'bundle.event.metadata.event_root missing or not 64-char lowercase hex',
      rpcEndpoint: bundleResult.rpc_endpoint_used,
    });
    emitReport(report, opts.json);
    process.exit(exitFor(report.verdict));
  }
  if (disclosure.root !== bundleEventRoot) {
    const report = buildReport({
      disclosure: opts.disclosurePath,
      bundle: opts.bundlePath,
      verdict: 'error',
      bundleVerdict: bundleResult.verdict,
      reason: `event_root mismatch: disclosure.root=${disclosure.root} bundle.event.metadata.event_root=${bundleEventRoot}`,
      rpcEndpoint: bundleResult.rpc_endpoint_used,
    });
    emitReport(report, opts.json);
    process.exit(exitFor(report.verdict));
  }

  // Steps 4-6: canonicalizeCandidate, computeLeafHash, verifyMerkleProof.
  //
  // The primitive throws on unknown field_path / encoding_version. Shape
  // validation above already rejects unknown paths, but we still wrap for
  // defence in depth.
  let leafHash: string;
  try {
    // Pin to spec §10.4's encoding version for disclosures; field-path
    // lookup inside the primitive applies the §10.4 canonicalization rule.
    canonicalizeFieldValue(disclosure.field_path, candidate, ENCODING_VERSION);
    leafHash = computeLeafHash(
      disclosure.field_path,
      candidate,
      base64UrlToBytes(disclosure.salt),
      ENCODING_VERSION,
    );
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    const report = buildReport({
      disclosure: opts.disclosurePath,
      bundle: opts.bundlePath,
      verdict: 'error',
      bundleVerdict: bundleResult.verdict,
      reason: `canonicalization failed: ${msg}`,
      rpcEndpoint: bundleResult.rpc_endpoint_used,
    });
    emitReport(report, opts.json);
    process.exit(exitFor(report.verdict));
  }

  const proofOk = verifyFieldProof(leafHash, disclosure.merkle_path, disclosure.root);
  if (!proofOk) {
    const report = buildReport({
      disclosure: opts.disclosurePath,
      bundle: opts.bundlePath,
      verdict: 'fail',
      bundleVerdict: bundleResult.verdict,
      reason: 'field proof verification failed',
      rpcEndpoint: bundleResult.rpc_endpoint_used,
    });
    emitReport(report, opts.json);
    process.exit(exitFor(report.verdict));
  }

  // All five steps cleared. buildReport applies the pass invariant.
  const report = buildReport({
    disclosure: opts.disclosurePath,
    bundle: opts.bundlePath,
    verdict: 'pass',
    bundleVerdict: bundleResult.verdict,
    reason: null,
    rpcEndpoint: bundleResult.rpc_endpoint_used,
  });
  emitReport(report, opts.json);
  process.exit(exitFor(report.verdict));
}
