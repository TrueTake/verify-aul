/**
 * `bundle` subcommand handler — Tier 2 verification bundle entry point.
 *
 * Delegates to the shared `runVerifyCommand`; Tier 1 vs Tier 2 is determined
 * structurally by field presence in the verifier core, not by this subcommand.
 */

import { runVerifyCommand, type VerifyCommandOptions } from './run-verify.js';

export type BundleCommandOptions = VerifyCommandOptions;

export function runBundleCommand(opts: BundleCommandOptions): Promise<void> {
  return runVerifyCommand('bundle', opts);
}
