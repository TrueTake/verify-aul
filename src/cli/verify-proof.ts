/**
 * `proof` subcommand handler — Tier 1 anchor proof entry point.
 *
 * Delegates to the shared `runVerifyCommand`; Tier 1 vs Tier 2 is determined
 * structurally by field presence in the verifier core, not by this subcommand.
 */

import { runVerifyCommand, type VerifyCommandOptions } from './run-verify.js';

export type ProofCommandOptions = VerifyCommandOptions;

export function runProofCommand(opts: ProofCommandOptions): Promise<void> {
  return runVerifyCommand('proof', opts);
}
