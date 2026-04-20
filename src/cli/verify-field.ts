/**
 * `verify-field` subcommand handler — single-field Merkle disclosure
 * verification. Implements the §10.8 algorithm end-to-end. See spec §10 for
 * the normative contract; the handler body is numbered to match the spec's
 * step names.
 */

import { readFile, stat } from 'node:fs/promises';
import { resolve } from 'node:path';

import { verifyBundle } from '../core.js';
import {
  computeLeafHash,
  DISCLOSABLE_FIELDS,
  ENCODING_VERSION,
  verifyFieldProof,
} from '../field-commitment.js';
import type {
  Disclosure,
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

type ReadError = { error: string; exitCode: 1 | 2 };

/** Stat + read a UTF-8 text file, enforcing the 10 MB size cap per §10.10. */
async function readCappedTextFile(
  label: string,
  path: string,
): Promise<{ body: string } | ReadError> {
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
  try {
    return { body: await readFile(absPath, 'utf-8') };
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    return { error: `could not read ${label} file: ${msg}`, exitCode: 2 };
  }
}

async function readJsonFile(
  label: string,
  path: string,
): Promise<{ raw: Record<string, unknown> } | ReadError> {
  const read = await readCappedTextFile(label, path);
  if ('error' in read) return read;
  let parsed: unknown;
  try {
    parsed = JSON.parse(read.body);
  } catch {
    return { error: `${label} file is not valid JSON: ${resolve(path)}`, exitCode: 2 };
  }
  if (parsed === null || typeof parsed !== 'object' || Array.isArray(parsed)) {
    return { error: `${label} file must contain a JSON object`, exitCode: 2 };
  }
  return { raw: parsed as Record<string, unknown> };
}

function base64UrlToBytes(b64url: string): Uint8Array {
  return Uint8Array.from(Buffer.from(b64url, 'base64url'));
}

/** Strip exactly one trailing newline (LF or CRLF), not all whitespace. */
function stripTrailingNewline(s: string): string {
  if (s.endsWith('\r\n')) return s.slice(0, -2);
  if (s.endsWith('\n')) return s.slice(0, -1);
  return s;
}

// ---------------------------------------------------------------------------
// Disclosure shape validation
// ---------------------------------------------------------------------------

function validateDisclosureShape(
  raw: Record<string, unknown>,
): { disclosure: Disclosure } | { error: string } {
  const requiredStringFields = ['field_path', 'salt', 'root', 'event_hash'] as const;
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
  const siblings: Disclosure['merkle_path'] = [];
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
  // Input option arbitration — usage errors precede any verdict output.
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
  if (opts.candidateFile === '') {
    process.stderr.write(`Error: --candidate-file requires a non-empty path\n`);
    process.exit(2);
  }

  // Emit a verdict report and exit. All non-usage errors flow through here;
  // this is the single point that enforces the §10.8 step-7 pass invariant
  // via buildReport.
  const emitAndExit = (params: {
    verdict: FieldVerdict;
    reason: string | null;
    bundleVerdict?: Verdict | null;
    rpcEndpoint?: string | null;
  }): never => {
    const report = buildReport({
      disclosure: opts.disclosurePath,
      bundle: opts.bundlePath,
      verdict: params.verdict,
      reason: params.reason,
      bundleVerdict: params.bundleVerdict ?? null,
      rpcEndpoint: params.rpcEndpoint ?? null,
    });
    emitReport(report, opts.json);
    process.exit(exitFor(report.verdict));
  };

  // Resolve candidate string.
  let candidate: string;
  if (opts.candidateFile !== null) {
    const read = await readCappedTextFile('candidate', opts.candidateFile);
    if ('error' in read) {
      process.stderr.write(`Error: ${read.error}\n`);
      process.exit(read.exitCode);
    }
    candidate = stripTrailingNewline(read.body);
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

  const shape = validateDisclosureShape(disclosureRead.raw);
  if ('error' in shape) {
    return emitAndExit({ verdict: 'error', reason: shape.error });
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
    return emitAndExit({ verdict: 'error', reason: `bundle verification threw: ${msg}` });
  }
  const bv = bundleResult!.verdict;
  const rpc = bundleResult!.rpc_endpoint_used;
  if (bv !== 'pass') {
    return emitAndExit({
      verdict: 'error',
      reason: 'bundle verification did not pass',
      bundleVerdict: bv,
      rpcEndpoint: rpc,
    });
  }

  // Step 2: checkBindingEventHash (spec §10.7 Binding A).
  if (typeof bundleRaw.event_hash !== 'string') {
    return emitAndExit({
      verdict: 'error',
      reason: 'bundle.event_hash missing or not a string',
      bundleVerdict: bv,
      rpcEndpoint: rpc,
    });
  }
  if (!HEX64_RE.test(bundleRaw.event_hash)) {
    return emitAndExit({
      verdict: 'error',
      reason: `bundle.event_hash must be 64-char lowercase hex (got: ${bundleRaw.event_hash})`,
      bundleVerdict: bv,
      rpcEndpoint: rpc,
    });
  }
  if (disclosure.event_hash !== bundleRaw.event_hash) {
    return emitAndExit({
      verdict: 'error',
      reason: `event_hash mismatch: disclosure=${disclosure.event_hash} bundle=${bundleRaw.event_hash}`,
      bundleVerdict: bv,
      rpcEndpoint: rpc,
    });
  }

  // Step 3: checkBindingRoot (spec §10.7 Binding B) — disclosure.root MUST
  // equal bundle.event.metadata.event_root. Without this check, an attacker
  // with any legitimate bundle can forge a disclosure for an attacker-chosen
  // candidate (fresh salt + merkle_path=[] + root=computeLeafHash(candidate, salt)).
  // event_root is committed transitively by event_hash via verifyBundle's
  // canonical_recompute, so Binding A + Binding B together anchor the
  // disclosed Merkle root to the signed + Solana-anchored event.
  if (bundleRaw.event === undefined || bundleRaw.event === null) {
    return emitAndExit({
      verdict: 'error',
      reason: 'bundle.event missing — field-disclosure verification requires a Tier 2 bundle',
      bundleVerdict: bv,
      rpcEndpoint: rpc,
    });
  }
  const bundleEvent = bundleRaw.event as Record<string, unknown>;
  const bundleMetadata = bundleEvent.metadata;
  if (bundleMetadata === null || typeof bundleMetadata !== 'object' || Array.isArray(bundleMetadata)) {
    return emitAndExit({
      verdict: 'error',
      reason: 'bundle.event.metadata missing or not an object',
      bundleVerdict: bv,
      rpcEndpoint: rpc,
    });
  }
  const bundleEventRoot = (bundleMetadata as Record<string, unknown>).event_root;
  if (typeof bundleEventRoot !== 'string' || !HEX64_RE.test(bundleEventRoot)) {
    return emitAndExit({
      verdict: 'error',
      reason: 'bundle.event.metadata.event_root missing or not 64-char lowercase hex',
      bundleVerdict: bv,
      rpcEndpoint: rpc,
    });
  }
  if (disclosure.root !== bundleEventRoot) {
    return emitAndExit({
      verdict: 'error',
      reason: `event_root mismatch: disclosure.root=${disclosure.root} bundle.event.metadata.event_root=${bundleEventRoot}`,
      bundleVerdict: bv,
      rpcEndpoint: rpc,
    });
  }

  // Steps 4–6: canonicalizeCandidate, computeLeafHash, verifyMerkleProof.
  let leafHash: string;
  try {
    leafHash = computeLeafHash(
      disclosure.field_path,
      candidate,
      base64UrlToBytes(disclosure.salt),
      ENCODING_VERSION,
    );
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    return emitAndExit({
      verdict: 'error',
      reason: `canonicalization failed: ${msg}`,
      bundleVerdict: bv,
      rpcEndpoint: rpc,
    });
  }
  if (!verifyFieldProof(leafHash!, disclosure.merkle_path, disclosure.root)) {
    return emitAndExit({
      verdict: 'fail',
      reason: 'field proof verification failed',
      bundleVerdict: bv,
      rpcEndpoint: rpc,
    });
  }
  return emitAndExit({
    verdict: 'pass',
    reason: null,
    bundleVerdict: bv,
    rpcEndpoint: rpc,
  });
}
