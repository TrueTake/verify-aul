/**
 * CLI integration tests for the `bundle` subcommand.
 *
 * Tests verify CLI behavior (argv parsing, exit codes, formatting, flag
 * handling) using a mocked verifyBundle. The verifier math is Unit 1's job.
 *
 * Strategy: import the handler function directly and stub process.exit /
 * process.stdout to capture output + exit codes without spawning subprocesses.
 */

import { readFile } from 'node:fs/promises';
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
import { runBundleCommand } from './verify-bundle.js';

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

const PASS_RESULT: VerificationResult = {
  verdict: 'pass',
  rpc_endpoint_used: 'https://api.mainnet-beta.solana.com',
  checks: [
    { check: 'bundle_schema_version', status: 'pass', details: 'supported (1)' },
    { check: 'canonical_recompute', status: 'pass', details: 'hash matches' },
    { check: 'server_signature', status: 'pass', details: 'Ed25519 verified' },
    { check: 'merkle_inclusion', status: 'pass', details: 'root reconstructed' },
  ],
};

const FAIL_RESULT: VerificationResult = {
  verdict: 'fail',
  rpc_endpoint_used: 'https://api.mainnet-beta.solana.com',
  checks: [
    { check: 'bundle_schema_version', status: 'pass' },
    {
      check: 'canonical_recompute',
      status: 'fail',
      details: 'hash mismatch: recomputed abc123, bundle has def456',
    },
  ],
};

const PARTIAL_RESULT: VerificationResult = {
  verdict: 'partial',
  rpc_endpoint_used: 'https://api.mainnet-beta.solana.com',
  checks: [
    { check: 'bundle_schema_version', status: 'pass' },
    { check: 'merkle_inclusion', status: 'pass' },
  ],
};

// ---------------------------------------------------------------------------
// Process capture helpers
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

describe('verify-bundle CLI', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  describe('Happy path — Tier 2 bundle', () => {
    it('exit 0 when verdict is pass', async () => {
      vi.mocked(verifyBundle).mockResolvedValue(PASS_RESULT);

      const result = await captureRun(() =>
        runBundleCommand({
          filePath: resolve(FIXTURES_DIR, 'tier2-bundle-pass.json'),
          json: false,
          verbose: false,
        }),
      );

      expect(result.exitCode).toBe(0);
      expect(result.stdout).toContain('PASS');
      expect(result.stdout).toContain('bundle_schema_version');
      expect(result.stderr).toBe('');
    });

    it('outputs AUL Verification Report header for bundle subcommand', async () => {
      vi.mocked(verifyBundle).mockResolvedValue(PASS_RESULT);

      const result = await captureRun(() =>
        runBundleCommand({
          filePath: resolve(FIXTURES_DIR, 'tier2-bundle-pass.json'),
          json: false,
          verbose: false,
        }),
      );

      expect(result.stdout).toContain('AUL Verification Report — bundle');
      expect(result.stdout).toContain('Checks:');
    });
  });

  describe('--json flag', () => {
    it('outputs JSON-parseable stdout', async () => {
      vi.mocked(verifyBundle).mockResolvedValue(PASS_RESULT);

      const result = await captureRun(() =>
        runBundleCommand({
          filePath: resolve(FIXTURES_DIR, 'tier2-bundle-pass.json'),
          json: true,
          verbose: false,
        }),
      );

      expect(result.exitCode).toBe(0);

      const parsed = JSON.parse(result.stdout);
      expect(parsed.subcommand).toBe('bundle');
      expect(parsed.verdict).toBe('pass');
      expect(parsed.rpc_endpoint_used).toBe('https://api.mainnet-beta.solana.com');
      expect(Array.isArray(parsed.checks)).toBe(true);
    });

    it('JSON includes input path', async () => {
      vi.mocked(verifyBundle).mockResolvedValue(PASS_RESULT);
      const filePath = resolve(FIXTURES_DIR, 'tier2-bundle-pass.json');

      const result = await captureRun(() =>
        runBundleCommand({ filePath, json: true, verbose: false }),
      );

      const parsed = JSON.parse(result.stdout);
      expect(parsed.input).toBe(filePath);
    });
  });

  describe('Tampered fixture → exit 1', () => {
    it('exits 1 when verdict is fail', async () => {
      vi.mocked(verifyBundle).mockResolvedValue(FAIL_RESULT);

      const result = await captureRun(() =>
        runBundleCommand({
          filePath: resolve(FIXTURES_DIR, 'tier2-bundle-tampered.json'),
          json: false,
          verbose: false,
        }),
      );

      expect(result.exitCode).toBe(1);
      expect(result.stdout).toContain('FAIL');
    });

    it('names the failing check in text output', async () => {
      vi.mocked(verifyBundle).mockResolvedValue(FAIL_RESULT);

      const result = await captureRun(() =>
        runBundleCommand({
          filePath: resolve(FIXTURES_DIR, 'tier2-bundle-tampered.json'),
          json: false,
          verbose: false,
        }),
      );

      expect(result.stdout).toContain('canonical_recompute');
    });
  });

  describe('Partial verdict → exit 1', () => {
    it('exits 1 for partial verdict (not fully verified)', async () => {
      vi.mocked(verifyBundle).mockResolvedValue(PARTIAL_RESULT);

      const result = await captureRun(() =>
        runBundleCommand({
          filePath: resolve(FIXTURES_DIR, 'tier2-bundle-pass.json'),
          json: false,
          verbose: false,
        }),
      );

      expect(result.exitCode).toBe(1);
      expect(result.stdout).toContain('PARTIAL');
    });
  });

  describe('Missing input file → exit 2', () => {
    it('exits 2 with usage hint when file is not found', async () => {
      const result = await captureRun(() =>
        runBundleCommand({
          filePath: '/nonexistent/path/bundle.json',
          json: false,
          verbose: false,
        }),
      );

      expect(result.exitCode).toBe(2);
      expect(result.stderr).toContain('Error');
      expect(result.stderr).toContain('could not read file');
      expect(result.stderr).toContain('Usage');
    });
  });

  describe('Malformed JSON → exit 2', () => {
    it('exits 2 when file is not valid JSON', async () => {
      // Create a temp file with invalid JSON content using the fixtures approach
      // We'll write inline by creating a file in the OS tmp dir
      const { writeFile, unlink } = await import('node:fs/promises');
      const { tmpdir } = await import('node:os');
      const { join } = await import('node:path');
      const tmpFile = join(tmpdir(), 'verify-aul-test-malformed.json');

      await writeFile(tmpFile, '{ this is not json }', 'utf-8');

      try {
        const result = await captureRun(() =>
          runBundleCommand({ filePath: tmpFile, json: false, verbose: false }),
        );

        expect(result.exitCode).toBe(2);
        expect(result.stderr).toContain('not valid JSON');
      } finally {
        await unlink(tmpFile).catch(() => undefined);
      }
    });
  });

  describe('Unsupported bundle schema version → exit 1', () => {
    it('exits 1 and mentions unsupported bundle version', async () => {
      const UNSUPPORTED_RESULT: VerificationResult = {
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
      vi.mocked(verifyBundle).mockResolvedValue(UNSUPPORTED_RESULT);

      const result = await captureRun(() =>
        runBundleCommand({
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
      vi.mocked(verifyBundle).mockResolvedValue(PASS_RESULT);

      // Use the FreeTSA PEM from core.ts as a stand-in test cert
      const testPem = `-----BEGIN CERTIFICATE-----
MIIFMTCCBBmgAwIBAgIQCqEl1tYyG35B5AXaNpfCFTANBgkqhkiG9w0BAQsFADBl
MQswCQYDVQQGEwJVUzEVMBMGA1UEChMMRGlnaUNlcnQgSW5jMRkwFwYDVQQLExB3
d3cuZGlnaWNlcnQuY29tMSQwIgYDVQQDExtEaWdpQ2VydCBBc3N1cmVkIElEIFJv
b3QgQ0EwHhcNMTYwMTA3MTIwMDAwWhcNMzEwMTA3MTIwMDAwWjByMQswCQYDVQQG
-----END CERTIFICATE-----`;

      const { writeFile, unlink } = await import('node:fs/promises');
      const { tmpdir } = await import('node:os');
      const { join } = await import('node:path');
      const tmpPem = join(tmpdir(), 'verify-aul-test-trust-anchors.pem');

      await writeFile(tmpPem, testPem, 'utf-8');

      try {
        await captureRun(() =>
          runBundleCommand({
            filePath: resolve(FIXTURES_DIR, 'tier2-bundle-pass.json'),
            trustAnchorsDer: [new Uint8Array([0x30, 0x82])], // fake DER stub
            json: false,
            verbose: false,
          }),
        );

        // Verify that verifyBundle was called with trustAnchors in options
        expect(vi.mocked(verifyBundle)).toHaveBeenCalledWith(
          expect.any(Object),
          expect.objectContaining({ trustAnchors: expect.any(Array) }),
        );
      } finally {
        await unlink(tmpPem).catch(() => undefined);
      }
    });
  });

  describe('--solana-rpc flag', () => {
    it('passes custom solanaRpcUrl to verifyBundle', async () => {
      vi.mocked(verifyBundle).mockResolvedValue(PASS_RESULT);
      const customRpc = 'https://api.devnet.solana.com';

      await captureRun(() =>
        runBundleCommand({
          filePath: resolve(FIXTURES_DIR, 'tier2-bundle-pass.json'),
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

  describe('--verbose flag', () => {
    it('includes full details in text output', async () => {
      const longDetails = 'a'.repeat(120);
      const resultWithLongDetails: VerificationResult = {
        verdict: 'pass',
        rpc_endpoint_used: 'https://api.mainnet-beta.solana.com',
        checks: [{ check: 'bundle_schema_version', status: 'pass', details: longDetails }],
      };
      vi.mocked(verifyBundle).mockResolvedValue(resultWithLongDetails);

      const verboseResult = await captureRun(() =>
        runBundleCommand({
          filePath: resolve(FIXTURES_DIR, 'tier2-bundle-pass.json'),
          json: false,
          verbose: true,
        }),
      );

      // With verbose, the full details should appear (not truncated)
      expect(verboseResult.stdout).toContain(longDetails);
    });

    it('truncates long details without --verbose', async () => {
      const longDetails = 'a'.repeat(120);
      const resultWithLongDetails: VerificationResult = {
        verdict: 'pass',
        rpc_endpoint_used: 'https://api.mainnet-beta.solana.com',
        checks: [{ check: 'bundle_schema_version', status: 'pass', details: longDetails }],
      };
      vi.mocked(verifyBundle).mockResolvedValue(resultWithLongDetails);

      const nonVerboseResult = await captureRun(() =>
        runBundleCommand({
          filePath: resolve(FIXTURES_DIR, 'tier2-bundle-pass.json'),
          json: false,
          verbose: false,
        }),
      );

      // Without verbose, long details get truncated with '...'
      expect(nonVerboseResult.stdout).toContain('...');
      expect(nonVerboseResult.stdout).not.toContain(longDetails);
    });
  });

  describe('verifyBundle is called with parsed bundle', () => {
    it('reads and parses the bundle file before calling verifyBundle', async () => {
      vi.mocked(verifyBundle).mockResolvedValue(PASS_RESULT);
      const filePath = resolve(FIXTURES_DIR, 'tier2-bundle-pass.json');

      await captureRun(() => runBundleCommand({ filePath, json: false, verbose: false }));

      // Read the fixture to get the expected bundle shape
      const raw = await readFile(filePath, 'utf-8');
      const expected = JSON.parse(raw);

      expect(vi.mocked(verifyBundle)).toHaveBeenCalledWith(
        expect.objectContaining({ bundle_schema_version: expected.bundle_schema_version }),
        expect.anything(),
      );
    });
  });
});
