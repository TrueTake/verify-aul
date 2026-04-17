/**
 * Shared entry point for the `bundle` and `proof` subcommands.
 *
 * Tier 1 proofs and Tier 2 bundles flow through the same verifier core; the
 * label ("bundle" / "proof") is only used to style the report output and the
 * usage hint in error messages.
 */

import { readFile } from 'node:fs/promises';
import { resolve } from 'node:path';

import { verifyBundle } from '../core.js';
import type { VerificationBundle, VerifyOptions } from '../types.js';

import { formatJson, formatText } from './report.js';

export interface VerifyCommandOptions {
  filePath: string;
  trustAnchorsDer?: Uint8Array[];
  solanaRpcUrl?: string;
  json: boolean;
  verbose: boolean;
}

export async function runVerifyCommand(
  label: 'bundle' | 'proof',
  opts: VerifyCommandOptions,
): Promise<void> {
  const absPath = resolve(opts.filePath);

  let raw: string;
  try {
    raw = await readFile(absPath, 'utf-8');
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    process.stderr.write(
      `Error: could not read file: ${msg}\nUsage: verify-aul ${label} <file.json> [--trust-anchors <path>] [--solana-rpc <url>] [--json] [--verbose]\n`,
    );
    process.exit(2);
  }

  let bundle: VerificationBundle;
  try {
    bundle = JSON.parse(raw) as VerificationBundle;
  } catch {
    process.stderr.write(
      `Error: file is not valid JSON: ${absPath}\nUsage: verify-aul ${label} <file.json>\n`,
    );
    process.exit(2);
  }

  const verifyOptions: VerifyOptions = {};
  if (opts.trustAnchorsDer && opts.trustAnchorsDer.length > 0) {
    verifyOptions.trustAnchors = opts.trustAnchorsDer;
  }
  if (opts.solanaRpcUrl) {
    verifyOptions.solanaRpcUrl = opts.solanaRpcUrl;
  }

  let result;
  try {
    result = await verifyBundle(bundle, verifyOptions);
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    process.stderr.write(`Error: verification failed unexpectedly: ${msg}\n`);
    process.exit(1);
  }

  const useTty = !opts.json && !!process.stdout.isTTY;
  if (opts.json) {
    process.stdout.write(formatJson(label, opts.filePath, result) + '\n');
  } else {
    process.stdout.write(
      formatText(label, opts.filePath, result, { useTty, verbose: opts.verbose }) + '\n',
    );
  }

  process.exit(result.verdict === 'pass' ? 0 : 1);
}
