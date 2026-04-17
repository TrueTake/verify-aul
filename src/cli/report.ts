/**
 * Formats a VerificationResult as either pretty human-readable text or
 * machine-parseable JSON.
 *
 * ANSI colors are emitted only when writing to a TTY (process.stdout.isTTY).
 * Colors are suppressed with --json.
 */

import type { Check, VerificationResult } from '../types.js';

// ---------------------------------------------------------------------------
// ANSI helpers
// ---------------------------------------------------------------------------

const RESET = '\x1b[0m';
const GREEN = '\x1b[32m';
const RED = '\x1b[31m';
const YELLOW = '\x1b[33m';
const BOLD = '\x1b[1m';
const DIM = '\x1b[2m';

function colorize(text: string, code: string, useTty: boolean): string {
  if (!useTty) return text;
  return `${code}${text}${RESET}`;
}

// ---------------------------------------------------------------------------
// JSON output
// ---------------------------------------------------------------------------

export interface JsonReport {
  subcommand: string;
  input: string;
  verdict: string;
  rpc_endpoint_used: string;
  checks: Array<{ check: string; status: string; details?: string }>;
}

export function formatJson(
  subcommand: string,
  inputPath: string,
  result: VerificationResult,
): string {
  const report: JsonReport = {
    subcommand,
    input: inputPath,
    verdict: result.verdict,
    rpc_endpoint_used: result.rpc_endpoint_used,
    checks: result.checks.map((c) => {
      const entry: { check: string; status: string; details?: string } = {
        check: c.check,
        status: c.status,
      };
      if (c.details !== undefined) entry.details = c.details;
      return entry;
    }),
  };
  return JSON.stringify(report, null, 2);
}

// ---------------------------------------------------------------------------
// Text output
// ---------------------------------------------------------------------------

function verdictLabel(verdict: string, useTty: boolean): string {
  switch (verdict) {
    case 'pass':
      return colorize('PASS', GREEN + BOLD, useTty);
    case 'fail':
      return colorize('FAIL', RED + BOLD, useTty);
    case 'partial':
      return colorize('PARTIAL', YELLOW + BOLD, useTty);
    default:
      return verdict.toUpperCase();
  }
}

function checkIcon(status: string, useTty: boolean): string {
  switch (status) {
    case 'pass':
      return colorize('✓', GREEN, useTty);
    case 'fail':
      return colorize('✗', RED, useTty);
    case 'skip':
      return colorize('–', DIM, useTty);
    default:
      return '?';
  }
}

function formatCheck(check: Check, useTty: boolean, verbose: boolean): string {
  const icon = checkIcon(check.status, useTty);
  let line = `  ${icon} ${check.check}`;
  if (check.details) {
    if (verbose) {
      line += colorize(` — ${check.details}`, DIM, useTty);
    } else {
      // Truncate long detail strings when not verbose
      const detail = check.details.length > 80 ? check.details.slice(0, 77) + '...' : check.details;
      line += colorize(` — ${detail}`, DIM, useTty);
    }
  }
  return line;
}

export function formatText(
  subcommand: string,
  inputPath: string,
  result: VerificationResult,
  options: { useTty: boolean; verbose: boolean },
): string {
  const { useTty, verbose } = options;
  const lines: string[] = [];

  lines.push(colorize(`AUL Verification Report — ${subcommand}`, BOLD, useTty));
  lines.push(`Input:   ${inputPath}`);
  lines.push(`Verdict: ${verdictLabel(result.verdict, useTty)}`);
  lines.push(`RPC:     ${result.rpc_endpoint_used}`);
  lines.push('');
  lines.push('Checks:');

  for (const check of result.checks) {
    lines.push(formatCheck(check, useTty, verbose));
  }

  if (result.checks.length === 0) {
    lines.push('  (no checks recorded)');
  }

  return lines.join('\n');
}
