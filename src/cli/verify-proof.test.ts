/**
 * CLI integration tests for the `proof` subcommand.
 *
 * Tests verify CLI behavior using a mocked verifyBundle. The verifier math
 * is Unit 1's job.
 *
 * Tier 1 proofs are structurally distinguished from Tier 2 bundles by the
 * absence of event / server_signature fields — the verifier core handles
 * this automatically. The CLI subcommand only affects the report label.
 */

import { resolve, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

const __dirname = dirname(fileURLToPath(import.meta.url));
const FIXTURES_DIR = resolve(__dirname, 'fixtures');

// ---------------------------------------------------------------------------
// Mock verifyBundle before importing the handler
// ---------------------------------------------------------------------------

vi.mock('../core.js', () => ({
  verifyBundle: vi.fn(),
}));

import { verifyBundle } from '../core.js';
import type { VerificationResult } from '../types.js';
import { runProofCommand } from './verify-proof.js';

// ---------------------------------------------------------------------------
// Result fixtures
// ---------------------------------------------------------------------------

/** Tier 1: no canonical_recompute or server_signature checks */
const TIER1_PASS_RESULT: VerificationResult = {
  verdict: 'pass',
  rpc_endpoint_used: 'https://api.mainnet-beta.solana.com',
  checks: [
    { check: 'bundle_schema_version', status: 'pass', details: 'supported (1)' },
    { check: 'merkle_inclusion', status: 'pass', details: 'root reconstructed from 0 siblings' },
  ],
};

const TIER1_FAIL_RESULT: VerificationResult = {
  verdict: 'fail',
  rpc_endpoint_used: 'https://api.mainnet-beta.solana.com',
  checks: [
    { check: 'bundle_schema_version', status: 'pass' },
    {
      check: 'merkle_inclusion',
      status: 'fail',
      details: 'event hash abc123... not included in Merkle root def456...',
    },
  ],
};

// ---------------------------------------------------------------------------
// Process capture helper (same pattern as verify-bundle.test.ts)
// ---------------------------------------------------------------------------

interface RunResult {
  stdout: string;
  stderr: string;
  exitCode: number;
}

async function captureRun(fn: () => Promise<void>): Promise<RunResult> {
  let stdoutOutput = '';
  let stderrOutput = '';
  let capturedExitCode = 0;

  vi.spyOn(process.stdout, 'write').mockImplementation((chunk: unknown) => {
    stdoutOutput += String(chunk);
    return true;
  });

  vi.spyOn(process.stderr, 'write').mockImplementation((chunk: unknown) => {
    stderrOutput += String(chunk);
    return true;
  });

  vi.spyOn(process, 'exit').mockImplementation((code?: number) => {
    capturedExitCode = code ?? 0;
    throw { __isExit: true, code: capturedExitCode };
  });

  try {
    await fn();
    capturedExitCode = 0;
  } catch (err) {
    if (err && typeof err === 'object' && '__isExit' in err) {
      capturedExitCode = (err as { __isExit: true; code: number }).code;
    } else {
      throw err;
    }
  } finally {
    vi.mocked(process.stdout.write).mockRestore();
    vi.mocked(process.stderr.write).mockRestore();
    vi.mocked(process.exit).mockRestore();
  }

  return { stdout: stdoutOutput, stderr: stderrOutput, exitCode: capturedExitCode };
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe('verify-proof CLI', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  describe('Happy path — Tier 1 proof', () => {
    it('exits 0 when verdict is pass', async () => {
      vi.mocked(verifyBundle).mockResolvedValue(TIER1_PASS_RESULT);

      const result = await captureRun(() =>
        runProofCommand({
          filePath: resolve(FIXTURES_DIR, 'tier1-proof-pass.json'),
          json: false,
          verbose: false,
        }),
      );

      expect(result.exitCode).toBe(0);
      expect(result.stdout).toContain('PASS');
      expect(result.stderr).toBe('');
    });

    it('uses "proof" as the subcommand label in the report', async () => {
      vi.mocked(verifyBundle).mockResolvedValue(TIER1_PASS_RESULT);

      const result = await captureRun(() =>
        runProofCommand({
          filePath: resolve(FIXTURES_DIR, 'tier1-proof-pass.json'),
          json: false,
          verbose: false,
        }),
      );

      expect(result.stdout).toContain('AUL Verification Report — proof');
    });

    it('does NOT include canonical_recompute or server_signature checks for Tier 1', async () => {
      vi.mocked(verifyBundle).mockResolvedValue(TIER1_PASS_RESULT);

      const result = await captureRun(() =>
        runProofCommand({
          filePath: resolve(FIXTURES_DIR, 'tier1-proof-pass.json'),
          json: false,
          verbose: false,
        }),
      );

      // Tier 1 pass result has no canonical/server checks
      expect(result.stdout).not.toContain('canonical_recompute');
      expect(result.stdout).not.toContain('server_signature');
      expect(result.stdout).toContain('merkle_inclusion');
    });
  });

  describe('--json flag', () => {
    it('outputs JSON-parseable stdout', async () => {
      vi.mocked(verifyBundle).mockResolvedValue(TIER1_PASS_RESULT);

      const result = await captureRun(() =>
        runProofCommand({
          filePath: resolve(FIXTURES_DIR, 'tier1-proof-pass.json'),
          json: true,
          verbose: false,
        }),
      );

      expect(result.exitCode).toBe(0);

      const parsed = JSON.parse(result.stdout);
      expect(parsed.subcommand).toBe('proof');
      expect(parsed.verdict).toBe('pass');
      expect(Array.isArray(parsed.checks)).toBe(true);
    });

    it('JSON does not contain canonical_recompute or server_signature for Tier 1', async () => {
      vi.mocked(verifyBundle).mockResolvedValue(TIER1_PASS_RESULT);

      const result = await captureRun(() =>
        runProofCommand({
          filePath: resolve(FIXTURES_DIR, 'tier1-proof-pass.json'),
          json: true,
          verbose: false,
        }),
      );

      const parsed = JSON.parse(result.stdout);
      const checkNames = parsed.checks.map((c: { check: string }) => c.check);
      expect(checkNames).not.toContain('canonical_recompute');
      expect(checkNames).not.toContain('server_signature');
    });
  });

  describe('Tampered fixture → exit 1', () => {
    it('exits 1 when verification fails', async () => {
      vi.mocked(verifyBundle).mockResolvedValue(TIER1_FAIL_RESULT);

      const result = await captureRun(() =>
        runProofCommand({
          filePath: resolve(FIXTURES_DIR, 'tier1-proof-pass.json'),
          json: false,
          verbose: false,
        }),
      );

      expect(result.exitCode).toBe(1);
      expect(result.stdout).toContain('FAIL');
    });

    it('names the failing check in text output', async () => {
      vi.mocked(verifyBundle).mockResolvedValue(TIER1_FAIL_RESULT);

      const result = await captureRun(() =>
        runProofCommand({
          filePath: resolve(FIXTURES_DIR, 'tier1-proof-pass.json'),
          json: false,
          verbose: false,
        }),
      );

      expect(result.stdout).toContain('merkle_inclusion');
    });
  });

  describe('Missing input file → exit 2', () => {
    it('exits 2 with usage hint when file is not found', async () => {
      const result = await captureRun(() =>
        runProofCommand({
          filePath: '/nonexistent/path/proof.json',
          json: false,
          verbose: false,
        }),
      );

      expect(result.exitCode).toBe(2);
      expect(result.stderr).toContain('Error');
      expect(result.stderr).toContain('Usage');
    });
  });

  describe('Malformed JSON → exit 2', () => {
    it('exits 2 when file is not valid JSON', async () => {
      const { writeFile, unlink } = await import('node:fs/promises');
      const { tmpdir } = await import('node:os');
      const { join } = await import('node:path');
      const tmpFile = join(tmpdir(), 'verify-aul-test-proof-malformed.json');

      await writeFile(tmpFile, '{ not valid json', 'utf-8');

      try {
        const result = await captureRun(() =>
          runProofCommand({ filePath: tmpFile, json: false, verbose: false }),
        );

        expect(result.exitCode).toBe(2);
        expect(result.stderr).toContain('not valid JSON');
      } finally {
        await unlink(tmpFile).catch(() => undefined);
      }
    });
  });

  describe('Unsupported bundle schema version → exit 1', () => {
    it('exits 1 with unsupported version in report', async () => {
      const unsupportedResult: VerificationResult = {
        verdict: 'fail',
        rpc_endpoint_used: 'https://api.mainnet-beta.solana.com',
        checks: [
          {
            check: 'bundle_schema_version',
            status: 'fail',
            details: 'unsupported bundle version: 99',
          },
        ],
      };
      vi.mocked(verifyBundle).mockResolvedValue(unsupportedResult);

      const result = await captureRun(() =>
        runProofCommand({
          filePath: resolve(FIXTURES_DIR, 'unsupported-version.json'),
          json: false,
          verbose: false,
        }),
      );

      expect(result.exitCode).toBe(1);
      expect(result.stdout).toContain('unsupported bundle version');
    });
  });

  describe('--trust-anchors flag', () => {
    it('passes trust anchor DER bytes to verifyBundle', async () => {
      vi.mocked(verifyBundle).mockResolvedValue(TIER1_PASS_RESULT);

      await captureRun(() =>
        runProofCommand({
          filePath: resolve(FIXTURES_DIR, 'tier1-proof-pass.json'),
          trustAnchorsDer: [new Uint8Array([0x30, 0x82, 0x01, 0x00])],
          json: false,
          verbose: false,
        }),
      );

      expect(vi.mocked(verifyBundle)).toHaveBeenCalledWith(
        expect.any(Object),
        expect.objectContaining({ trustAnchors: expect.any(Array) }),
      );
    });
  });

  describe('--solana-rpc flag', () => {
    it('passes custom solanaRpcUrl to verifyBundle', async () => {
      vi.mocked(verifyBundle).mockResolvedValue(TIER1_PASS_RESULT);
      const customRpc = 'https://api.devnet.solana.com';

      await captureRun(() =>
        runProofCommand({
          filePath: resolve(FIXTURES_DIR, 'tier1-proof-pass.json'),
          solanaRpcUrl: customRpc,
          json: false,
          verbose: false,
        }),
      );

      expect(vi.mocked(verifyBundle)).toHaveBeenCalledWith(
        expect.any(Object),
        expect.objectContaining({ solanaRpcUrl: customRpc }),
      );
    });
  });
});
