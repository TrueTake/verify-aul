#!/usr/bin/env node
/**
 * AUL verification CLI
 *
 * Usage:
 *   npx @truetake/verify-aul bundle       <file.json> [--trust-anchors <path>] [--solana-rpc <url>] [--json] [--verbose]
 *   npx @truetake/verify-aul proof        <file.json> [--trust-anchors <path>] [--solana-rpc <url>] [--json] [--verbose]
 *   npx @truetake/verify-aul verify-field --disclosure <path> --bundle <path> (--candidate <VAL> | --candidate-file <path>) [options]
 *
 * Or after install:
 *   verify-aul bundle path/to/bundle.json
 *
 * Exit codes:
 *   0 — verdict pass
 *   1 — verdict fail, partial, or error
 *   2 — usage error (missing file, malformed JSON, unknown flag)
 */

import { readFile } from 'node:fs/promises';
import { resolve } from 'node:path';

import { runBundleCommand } from './verify-bundle.js';
import { runProofCommand } from './verify-proof.js';
import { runVerifyFieldCommand } from './verify-field.js';

// ---------------------------------------------------------------------------
// PEM → DER helper (multi-cert files)
// ---------------------------------------------------------------------------

/**
 * Parse one or more PEM certificates from a PEM string.
 * Returns DER bytes (Uint8Array) for each certificate found.
 * Handles files with multiple concatenated PEM blocks.
 */
function parsePemCerts(pem: string): Uint8Array[] {
  const ders: Uint8Array[] = [];
  const regex = /-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----/g;
  let match: RegExpExecArray | null;

  while ((match = regex.exec(pem)) !== null) {
    const block = match[0];
    // Extract base64 lines between the headers
    const base64 = block
      .replace('-----BEGIN CERTIFICATE-----', '')
      .replace('-----END CERTIFICATE-----', '')
      .replace(/\s+/g, '');

    // Decode base64 to bytes
    const binary = atob(base64);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) {
      bytes[i] = binary.charCodeAt(i);
    }
    ders.push(bytes);
  }

  return ders;
}

// ---------------------------------------------------------------------------
// Minimal argv parser
// ---------------------------------------------------------------------------

interface ParsedArgs {
  subcommand: string | null;
  filePath: string | null;
  trustAnchorsPath: string | null;
  solanaRpcUrl: string | null;
  /** verify-field: path to disclosure JSON. */
  disclosurePath: string | null;
  /** verify-field: path to bundle JSON. */
  bundlePath: string | null;
  /** verify-field: raw candidate value. */
  candidate: string | null;
  /** verify-field: path to file whose UTF-8 contents are the candidate. */
  candidateFile: string | null;
  json: boolean;
  verbose: boolean;
  help: boolean;
  unknown: string[];
}

function parseArgs(argv: string[]): ParsedArgs {
  // argv = process.argv.slice(2)
  const result: ParsedArgs = {
    subcommand: null,
    filePath: null,
    trustAnchorsPath: null,
    solanaRpcUrl: null,
    disclosurePath: null,
    bundlePath: null,
    candidate: null,
    candidateFile: null,
    json: false,
    verbose: false,
    help: false,
    unknown: [],
  };

  let i = 0;

  // First positional = subcommand
  const first = argv[i];
  if (first !== undefined && !first.startsWith('-')) {
    result.subcommand = first;
    i++;
  }

  // Second positional = file path (bundle / proof only; verify-field uses --bundle)
  if (result.subcommand !== 'verify-field') {
    const second = argv[i];
    if (second !== undefined && !second.startsWith('-')) {
      result.filePath = second;
      i++;
    }
  }

  // Flags
  while (i < argv.length) {
    const arg = argv[i];
    if (arg === undefined) break;
    if (arg === '--json') {
      result.json = true;
      i++;
    } else if (arg === '--verbose' || arg === '-v') {
      result.verbose = true;
      i++;
    } else if (arg === '--help' || arg === '-h') {
      result.help = true;
      i++;
    } else if (arg === '--trust-anchors') {
      const next = argv[i + 1];
      if (next === undefined) {
        process.stderr.write('Error: --trust-anchors requires a path argument\n');
        process.exit(2);
      }
      result.trustAnchorsPath = next;
      i += 2;
    } else if (arg.startsWith('--trust-anchors=')) {
      result.trustAnchorsPath = arg.slice('--trust-anchors='.length);
      i++;
    } else if (arg === '--solana-rpc') {
      const next = argv[i + 1];
      if (next === undefined) {
        process.stderr.write('Error: --solana-rpc requires a URL argument\n');
        process.exit(2);
      }
      result.solanaRpcUrl = next;
      i += 2;
    } else if (arg.startsWith('--solana-rpc=')) {
      result.solanaRpcUrl = arg.slice('--solana-rpc='.length);
      i++;
    } else if (arg === '--disclosure') {
      const next = argv[i + 1];
      if (next === undefined) {
        process.stderr.write('Error: --disclosure requires a path argument\n');
        process.exit(2);
      }
      result.disclosurePath = next;
      i += 2;
    } else if (arg.startsWith('--disclosure=')) {
      result.disclosurePath = arg.slice('--disclosure='.length);
      i++;
    } else if (arg === '--bundle') {
      const next = argv[i + 1];
      if (next === undefined) {
        process.stderr.write('Error: --bundle requires a path argument\n');
        process.exit(2);
      }
      result.bundlePath = next;
      i += 2;
    } else if (arg.startsWith('--bundle=')) {
      result.bundlePath = arg.slice('--bundle='.length);
      i++;
    } else if (arg === '--candidate') {
      const next = argv[i + 1];
      if (next === undefined) {
        process.stderr.write('Error: --candidate requires a value argument\n');
        process.exit(2);
      }
      result.candidate = next;
      i += 2;
    } else if (arg.startsWith('--candidate=')) {
      result.candidate = arg.slice('--candidate='.length);
      i++;
    } else if (arg === '--candidate-file') {
      const next = argv[i + 1];
      if (next === undefined) {
        process.stderr.write('Error: --candidate-file requires a path argument\n');
        process.exit(2);
      }
      result.candidateFile = next;
      i += 2;
    } else if (arg.startsWith('--candidate-file=')) {
      result.candidateFile = arg.slice('--candidate-file='.length);
      i++;
    } else {
      result.unknown.push(arg);
      i++;
    }
  }

  return result;
}

// ---------------------------------------------------------------------------
// Usage text
// ---------------------------------------------------------------------------

const USAGE = `
AUL Verification CLI (@truetake/verify-aul)

Usage:
  verify-aul bundle       <file.json> [options]
  verify-aul proof        <file.json> [options]
  verify-aul verify-field --disclosure <path> --bundle <path>
                          (--candidate <VALUE> | --candidate-file <path>) [options]

  Also reachable as: npx @truetake/verify-aul bundle ...

Subcommands:
  bundle <file.json>       Verify a Tier 2 bundle (event + server signature + anchors)
  proof  <file.json>       Verify a Tier 1 proof (anchors only, no event/signature)
  verify-field             Verify a single-field Merkle disclosure (spec §10)
                           against its companion bundle

Options:
  --trust-anchors <path>   Path to PEM file with additional trust anchor certs
                           (additive to bundled anchors; may contain multiple certs)
  --solana-rpc <url>       Override the Solana RPC endpoint
  --json                   Output machine-parseable JSON to stdout
  --verbose                Include full details for each check (no truncation)
  -h, --help               Show this help message

Subcommand-specific options (verify-field):
  --disclosure <path>      Path to disclosure payload JSON (spec §10.2)
  --bundle <path>          Path to the verification bundle the disclosure binds to
  --candidate <VALUE>      Raw candidate value (leaks to argv; prefer --candidate-file
                           for sensitive values — see §10.10)
  --candidate-file <path>  File whose UTF-8 contents (minus one trailing newline)
                           are the candidate value

Exit codes:
  0   Verdict: PASS
  1   Verdict: FAIL, PARTIAL, or ERROR (not fully verified)
  2   Usage error (missing file, malformed JSON, unknown flag)

Examples:
  verify-aul bundle ./verification-evt_123.json
  verify-aul bundle ./verification-evt_123.json --json | jq .verdict
  verify-aul bundle ./bundle.json --trust-anchors ./my-ca.pem --verbose
  verify-aul proof ./proof.json --solana-rpc https://api.devnet.solana.com
  verify-aul verify-field --bundle ./b.json --disclosure ./d.json --candidate alice@example.com
  verify-aul verify-field --bundle ./b.json --disclosure ./d.json --candidate-file ./candidate.txt
`.trim();

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

async function main(): Promise<void> {
  const args = parseArgs(process.argv.slice(2));

  // --help prints USAGE and exits 0, regardless of subcommand. This is the
  // agent-readiness contract: `verify-aul verify-field --help` MUST NOT be
  // treated as a usage error (missing --disclosure / --bundle), because the
  // caller hasn't yet learned what those flags are.
  if (args.help) {
    process.stdout.write(USAGE + '\n');
    process.exit(0);
  }

  // Unknown flags
  if (args.unknown.length > 0) {
    process.stderr.write(`Error: unknown flag(s): ${args.unknown.join(', ')}\n\n${USAGE}\n`);
    process.exit(2);
  }

  // Subcommand required
  if (!args.subcommand) {
    process.stderr.write(
      `Error: subcommand required (bundle, proof, or verify-field)\n\n${USAGE}\n`,
    );
    process.exit(2);
  }

  if (
    args.subcommand !== 'bundle' &&
    args.subcommand !== 'proof' &&
    args.subcommand !== 'verify-field'
  ) {
    process.stderr.write(
      `Error: unknown subcommand '${args.subcommand}' (expected bundle, proof, or verify-field)\n\n${USAGE}\n`,
    );
    process.exit(2);
  }

  // File path required for bundle / proof (verify-field uses --bundle)
  if ((args.subcommand === 'bundle' || args.subcommand === 'proof') && !args.filePath) {
    process.stderr.write(
      `Error: file path required\nUsage: verify-aul ${args.subcommand} <file.json>\n`,
    );
    process.exit(2);
  }

  // Load trust anchors if specified
  let trustAnchorsDer: Uint8Array[] | undefined;
  if (args.trustAnchorsPath) {
    const absPath = resolve(args.trustAnchorsPath);
    let pemContent: string;
    try {
      pemContent = await readFile(absPath, 'utf-8');
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      process.stderr.write(`Error: could not read trust anchors file: ${msg}\n`);
      process.exit(2);
    }
    const ders = parsePemCerts(pemContent);
    if (ders.length === 0) {
      process.stderr.write(`Error: no valid PEM certificates found in ${args.trustAnchorsPath}\n`);
      process.exit(2);
    }
    trustAnchorsDer = ders;
  }

  if (args.subcommand === 'verify-field') {
    if (!args.disclosurePath) {
      process.stderr.write(
        `Error: --disclosure <path> is required for verify-field\n\n${USAGE}\n`,
      );
      process.exit(2);
    }
    if (!args.bundlePath) {
      process.stderr.write(
        `Error: --bundle <path> is required for verify-field\n\n${USAGE}\n`,
      );
      process.exit(2);
    }
    await runVerifyFieldCommand({
      disclosurePath: args.disclosurePath,
      bundlePath: args.bundlePath,
      candidate: args.candidate,
      candidateFile: args.candidateFile,
      trustAnchorsDer,
      solanaRpcUrl: args.solanaRpcUrl ?? undefined,
      json: args.json,
      verbose: args.verbose,
    });
    return;
  }

  const commonOpts = {
    filePath: args.filePath!,
    trustAnchorsDer,
    solanaRpcUrl: args.solanaRpcUrl ?? undefined,
    json: args.json,
    verbose: args.verbose,
  };

  if (args.subcommand === 'bundle') {
    await runBundleCommand(commonOpts);
  } else {
    await runProofCommand(commonOpts);
  }
}

main().catch((err) => {
  process.stderr.write(`Unexpected error: ${err instanceof Error ? err.message : String(err)}\n`);
  process.exit(1);
});
