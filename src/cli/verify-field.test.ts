/**
 * CLI integration tests for the `verify-field` subcommand.
 *
 * Uses `vi.mock('../core.js')` to substitute a fake `verifyBundle` — tests
 * assert the CLI handler's binding / shape-validation / proof-walk
 * behavior without requiring network access or real trust anchors. This
 * mirrors the pattern in `verify-bundle.test.ts`.
 *
 * Fixtures are generated per-test into the OS tmp dir so each test is
 * self-contained and readable.
 */

import { writeFile, unlink, mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import { computeLeafHash } from '../field-commitment.js';

vi.mock('../core.js', () => ({
  verifyBundle: vi.fn(),
}));

import { verifyBundle } from '../core.js';
import type { VerificationResult } from '../types.js';
import { runVerifyFieldCommand } from './verify-field.js';

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

const PASS_BUNDLE_RESULT: VerificationResult = {
  verdict: 'pass',
  rpc_endpoint_used: 'https://api.mainnet-beta.solana.com',
  checks: [{ check: 'bundle_schema_version', status: 'pass' }],
};

const PARTIAL_BUNDLE_RESULT: VerificationResult = {
  verdict: 'partial',
  rpc_endpoint_used: 'https://api.mainnet-beta.solana.com',
  checks: [{ check: 'bundle_schema_version', status: 'pass' }],
};

const FAIL_BUNDLE_RESULT: VerificationResult = {
  verdict: 'fail',
  rpc_endpoint_used: 'https://api.mainnet-beta.solana.com',
  checks: [{ check: 'server_signature', status: 'fail', details: 'Ed25519 verify failed' }],
};

/** Build a disclosure + matching bundle pair that verifies cleanly. */
function makePassFixtures(overrides: {
  bundleEventHash?: string;
  disclosureEventHash?: string;
  fieldValue?: string;
  tamperRoot?: boolean;
} = {}): {
  bundle: Record<string, unknown>;
  disclosure: Record<string, unknown>;
  candidate: string;
} {
  const salt = new Uint8Array(16).fill(0x99);
  const saltB64 = Buffer.from(salt).toString('base64url');
  const fieldValue = overrides.fieldValue ?? 'alice@example.com';
  const candidate = 'Alice@Example.COM '; // trims + lowercases to fieldValue
  const leafHash = computeLeafHash('approver.email', fieldValue, salt);
  const eventHash = '0'.repeat(64).replace(/0/g, 'a'); // 64 'a's

  const root = overrides.tamperRoot
    ? leafHash.slice(0, -2) + (leafHash.slice(-2) === 'ff' ? '00' : 'ff')
    : leafHash;

  const bundle = {
    bundle_schema_version: 1,
    status: 'confirmed',
    event_hash: overrides.bundleEventHash ?? eventHash,
    merkle_proof: { leaf_index: 0, siblings: [], root: '0'.repeat(64) },
    anchors: [],
    partial_anchors_reason: [],
  };
  const disclosure = {
    field_path: 'approver.email',
    field_value: fieldValue,
    salt: saltB64,
    merkle_path: [],
    root,
    event_hash: overrides.disclosureEventHash ?? eventHash,
  };
  return { bundle, disclosure, candidate };
}

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

/** Write bundle + disclosure JSON to a fresh tmp dir, return paths. */
async function writeFixtures(
  bundle: unknown,
  disclosure: unknown,
): Promise<{ dir: string; bundlePath: string; disclosurePath: string }> {
  const dir = await mkdtemp(join(tmpdir(), 'verify-aul-vf-'));
  const bundlePath = join(dir, 'bundle.json');
  const disclosurePath = join(dir, 'disclosure.json');
  await writeFile(bundlePath, JSON.stringify(bundle), 'utf-8');
  await writeFile(disclosurePath, JSON.stringify(disclosure), 'utf-8');
  return { dir, bundlePath, disclosurePath };
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe('verify-field CLI', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  describe('Happy path', () => {
    it('well-formed inputs + matching candidate → verdict pass, exit 0', async () => {
      vi.mocked(verifyBundle).mockResolvedValue(PASS_BUNDLE_RESULT);
      const { bundle, disclosure, candidate } = makePassFixtures();
      const { bundlePath, disclosurePath, dir } = await writeFixtures(bundle, disclosure);

      const result = await captureRun(() =>
        runVerifyFieldCommand({
          bundlePath,
          disclosurePath,
          candidate,
          candidateFile: null,
          json: true,
          verbose: false,
        }),
      );

      expect(result.exitCode).toBe(0);
      const report = JSON.parse(result.stdout);
      expect(report.verdict).toBe('pass');
      expect(report.bundle_verdict).toBe('pass');
      expect(report.reason).toBeNull();

      await rm(dir, { recursive: true });
    });

    it('canonicalizes mixed-case candidate to match field_value', async () => {
      vi.mocked(verifyBundle).mockResolvedValue(PASS_BUNDLE_RESULT);
      const { bundle, disclosure } = makePassFixtures();
      const { bundlePath, disclosurePath, dir } = await writeFixtures(bundle, disclosure);

      const result = await captureRun(() =>
        runVerifyFieldCommand({
          bundlePath,
          disclosurePath,
          candidate: '  ALICE@example.com  ', // different casing + whitespace
          candidateFile: null,
          json: true,
          verbose: false,
        }),
      );

      expect(result.exitCode).toBe(0);
      expect(JSON.parse(result.stdout).verdict).toBe('pass');
      await rm(dir, { recursive: true });
    });

    it('human-mode output includes verdict label', async () => {
      vi.mocked(verifyBundle).mockResolvedValue(PASS_BUNDLE_RESULT);
      const { bundle, disclosure, candidate } = makePassFixtures();
      const { bundlePath, disclosurePath, dir } = await writeFixtures(bundle, disclosure);

      const result = await captureRun(() =>
        runVerifyFieldCommand({
          bundlePath,
          disclosurePath,
          candidate,
          candidateFile: null,
          json: false,
          verbose: false,
        }),
      );

      expect(result.exitCode).toBe(0);
      expect(result.stdout).toContain('AUL Verification Report — verify-field');
      expect(result.stdout).toContain('verdict:');
      expect(result.stdout).toContain('PASS');
      await rm(dir, { recursive: true });
    });
  });

  describe('--candidate-file', () => {
    it('reads candidate from file (strips trailing \\n)', async () => {
      vi.mocked(verifyBundle).mockResolvedValue(PASS_BUNDLE_RESULT);
      const { bundle, disclosure } = makePassFixtures();
      const { bundlePath, disclosurePath, dir } = await writeFixtures(bundle, disclosure);
      const candidatePath = join(dir, 'candidate.txt');
      await writeFile(candidatePath, 'alice@example.com\n', 'utf-8');

      const result = await captureRun(() =>
        runVerifyFieldCommand({
          bundlePath,
          disclosurePath,
          candidate: null,
          candidateFile: candidatePath,
          json: true,
          verbose: false,
        }),
      );

      expect(result.exitCode).toBe(0);
      expect(JSON.parse(result.stdout).verdict).toBe('pass');
      await rm(dir, { recursive: true });
    });

    it('strips trailing \\r\\n', async () => {
      vi.mocked(verifyBundle).mockResolvedValue(PASS_BUNDLE_RESULT);
      const { bundle, disclosure } = makePassFixtures();
      const { bundlePath, disclosurePath, dir } = await writeFixtures(bundle, disclosure);
      const candidatePath = join(dir, 'candidate.txt');
      await writeFile(candidatePath, 'alice@example.com\r\n', 'utf-8');

      const result = await captureRun(() =>
        runVerifyFieldCommand({
          bundlePath,
          disclosurePath,
          candidate: null,
          candidateFile: candidatePath,
          json: true,
          verbose: false,
        }),
      );

      expect(result.exitCode).toBe(0);
      await rm(dir, { recursive: true });
    });
  });

  describe('Candidate input arbitration', () => {
    it('both --candidate and --candidate-file set → exit 2', async () => {
      const { bundle, disclosure } = makePassFixtures();
      const { bundlePath, disclosurePath, dir } = await writeFixtures(bundle, disclosure);

      const result = await captureRun(() =>
        runVerifyFieldCommand({
          bundlePath,
          disclosurePath,
          candidate: 'alice@example.com',
          candidateFile: '/tmp/nonexistent',
          json: false,
          verbose: false,
        }),
      );

      expect(result.exitCode).toBe(2);
      expect(result.stderr).toContain('mutually exclusive');
      await rm(dir, { recursive: true });
    });

    it('neither --candidate nor --candidate-file set → exit 2', async () => {
      const { bundle, disclosure } = makePassFixtures();
      const { bundlePath, disclosurePath, dir } = await writeFixtures(bundle, disclosure);

      const result = await captureRun(() =>
        runVerifyFieldCommand({
          bundlePath,
          disclosurePath,
          candidate: null,
          candidateFile: null,
          json: false,
          verbose: false,
        }),
      );

      expect(result.exitCode).toBe(2);
      expect(result.stderr).toContain('required');
      await rm(dir, { recursive: true });
    });
  });

  describe('Proof-walk failure paths', () => {
    it('candidate does not canonicalize to committed leaf → verdict fail, exit 1', async () => {
      vi.mocked(verifyBundle).mockResolvedValue(PASS_BUNDLE_RESULT);
      const { bundle, disclosure } = makePassFixtures();
      const { bundlePath, disclosurePath, dir } = await writeFixtures(bundle, disclosure);

      const result = await captureRun(() =>
        runVerifyFieldCommand({
          bundlePath,
          disclosurePath,
          candidate: 'different@example.com',
          candidateFile: null,
          json: true,
          verbose: false,
        }),
      );

      expect(result.exitCode).toBe(1);
      const report = JSON.parse(result.stdout);
      expect(report.verdict).toBe('fail');
      expect(report.reason).toBe('field proof verification failed');
      await rm(dir, { recursive: true });
    });

    it('tampered root → verdict fail, exit 1', async () => {
      vi.mocked(verifyBundle).mockResolvedValue(PASS_BUNDLE_RESULT);
      const { bundle, disclosure, candidate } = makePassFixtures({ tamperRoot: true });
      const { bundlePath, disclosurePath, dir } = await writeFixtures(bundle, disclosure);

      const result = await captureRun(() =>
        runVerifyFieldCommand({
          bundlePath,
          disclosurePath,
          candidate,
          candidateFile: null,
          json: true,
          verbose: false,
        }),
      );

      expect(result.exitCode).toBe(1);
      expect(JSON.parse(result.stdout).verdict).toBe('fail');
      await rm(dir, { recursive: true });
    });
  });

  describe('Pass invariant (F19)', () => {
    it('Merkle walk succeeds but bundle verdict is partial → verdict error (NOT pass)', async () => {
      vi.mocked(verifyBundle).mockResolvedValue(PARTIAL_BUNDLE_RESULT);
      const { bundle, disclosure, candidate } = makePassFixtures();
      const { bundlePath, disclosurePath, dir } = await writeFixtures(bundle, disclosure);

      const result = await captureRun(() =>
        runVerifyFieldCommand({
          bundlePath,
          disclosurePath,
          candidate,
          candidateFile: null,
          json: true,
          verbose: false,
        }),
      );

      expect(result.exitCode).toBe(1);
      const report = JSON.parse(result.stdout);
      expect(report.verdict).toBe('error');
      expect(report.verdict).not.toBe('pass');
      expect(report.bundle_verdict).toBe('partial');
      await rm(dir, { recursive: true });
    });

    it('Bundle verdict fail → verdict error, exit 1', async () => {
      vi.mocked(verifyBundle).mockResolvedValue(FAIL_BUNDLE_RESULT);
      const { bundle, disclosure, candidate } = makePassFixtures();
      const { bundlePath, disclosurePath, dir } = await writeFixtures(bundle, disclosure);

      const result = await captureRun(() =>
        runVerifyFieldCommand({
          bundlePath,
          disclosurePath,
          candidate,
          candidateFile: null,
          json: true,
          verbose: false,
        }),
      );

      expect(result.exitCode).toBe(1);
      const report = JSON.parse(result.stdout);
      expect(report.verdict).toBe('error');
      expect(report.bundle_verdict).toBe('fail');
      expect(report.reason).toBe('bundle verification did not pass');
      await rm(dir, { recursive: true });
    });
  });

  describe('Disclosure shape validation', () => {
    it('missing root field → verdict error, exit 1', async () => {
      vi.mocked(verifyBundle).mockResolvedValue(PASS_BUNDLE_RESULT);
      const { bundle, disclosure, candidate } = makePassFixtures();
      delete (disclosure as Record<string, unknown>).root;
      const { bundlePath, disclosurePath, dir } = await writeFixtures(bundle, disclosure);

      const result = await captureRun(() =>
        runVerifyFieldCommand({
          bundlePath,
          disclosurePath,
          candidate,
          candidateFile: null,
          json: true,
          verbose: false,
        }),
      );

      expect(result.exitCode).toBe(1);
      const report = JSON.parse(result.stdout);
      expect(report.verdict).toBe('error');
      expect(report.reason).toMatch(/root/);
      await rm(dir, { recursive: true });
    });

    it('missing event_hash field → verdict error, exit 1', async () => {
      vi.mocked(verifyBundle).mockResolvedValue(PASS_BUNDLE_RESULT);
      const { bundle, disclosure, candidate } = makePassFixtures();
      delete (disclosure as Record<string, unknown>).event_hash;
      const { bundlePath, disclosurePath, dir } = await writeFixtures(bundle, disclosure);

      const result = await captureRun(() =>
        runVerifyFieldCommand({
          bundlePath,
          disclosurePath,
          candidate,
          candidateFile: null,
          json: true,
          verbose: false,
        }),
      );

      expect(result.exitCode).toBe(1);
      expect(JSON.parse(result.stdout).verdict).toBe('error');
      await rm(dir, { recursive: true });
    });

    it('salt is not valid base64url → verdict error, exit 1', async () => {
      vi.mocked(verifyBundle).mockResolvedValue(PASS_BUNDLE_RESULT);
      const { bundle, disclosure, candidate } = makePassFixtures();
      (disclosure as Record<string, unknown>).salt = 'NOT_BASE64URL!!';
      const { bundlePath, disclosurePath, dir } = await writeFixtures(bundle, disclosure);

      const result = await captureRun(() =>
        runVerifyFieldCommand({
          bundlePath,
          disclosurePath,
          candidate,
          candidateFile: null,
          json: true,
          verbose: false,
        }),
      );

      expect(result.exitCode).toBe(1);
      expect(JSON.parse(result.stdout).reason).toMatch(/salt/);
      await rm(dir, { recursive: true });
    });

    it('salt does not decode to 16 bytes → verdict error, exit 1', async () => {
      vi.mocked(verifyBundle).mockResolvedValue(PASS_BUNDLE_RESULT);
      const { bundle, disclosure, candidate } = makePassFixtures();
      // 20 base64url chars (not 22) → won't match the length pattern.
      (disclosure as Record<string, unknown>).salt = 'A'.repeat(20);
      const { bundlePath, disclosurePath, dir } = await writeFixtures(bundle, disclosure);

      const result = await captureRun(() =>
        runVerifyFieldCommand({
          bundlePath,
          disclosurePath,
          candidate,
          candidateFile: null,
          json: true,
          verbose: false,
        }),
      );

      expect(result.exitCode).toBe(1);
      expect(JSON.parse(result.stdout).reason).toMatch(/salt/);
      await rm(dir, { recursive: true });
    });

    it('malformed merkle_path sibling → verdict error, exit 1', async () => {
      vi.mocked(verifyBundle).mockResolvedValue(PASS_BUNDLE_RESULT);
      const { bundle, disclosure, candidate } = makePassFixtures();
      (disclosure as Record<string, unknown>).merkle_path = [{ hash: 'not-hex', direction: 'right' }];
      const { bundlePath, disclosurePath, dir } = await writeFixtures(bundle, disclosure);

      const result = await captureRun(() =>
        runVerifyFieldCommand({
          bundlePath,
          disclosurePath,
          candidate,
          candidateFile: null,
          json: true,
          verbose: false,
        }),
      );

      expect(result.exitCode).toBe(1);
      expect(JSON.parse(result.stdout).reason).toMatch(/merkle_path/);
      await rm(dir, { recursive: true });
    });

    it('unknown field_path → verdict error, exit 1', async () => {
      vi.mocked(verifyBundle).mockResolvedValue(PASS_BUNDLE_RESULT);
      const { bundle, disclosure, candidate } = makePassFixtures();
      (disclosure as Record<string, unknown>).field_path = 'deal.amount';
      const { bundlePath, disclosurePath, dir } = await writeFixtures(bundle, disclosure);

      const result = await captureRun(() =>
        runVerifyFieldCommand({
          bundlePath,
          disclosurePath,
          candidate,
          candidateFile: null,
          json: true,
          verbose: false,
        }),
      );

      expect(result.exitCode).toBe(1);
      expect(JSON.parse(result.stdout).reason).toMatch(/field_path/);
      await rm(dir, { recursive: true });
    });
  });

  describe('Binding check', () => {
    it('event_hash mismatch → verdict error with both hashes in reason', async () => {
      vi.mocked(verifyBundle).mockResolvedValue(PASS_BUNDLE_RESULT);
      const bundleHash = 'a'.repeat(64);
      const disclosureHash = 'b'.repeat(64);
      const { bundle, disclosure, candidate } = makePassFixtures({
        bundleEventHash: bundleHash,
        disclosureEventHash: disclosureHash,
      });
      const { bundlePath, disclosurePath, dir } = await writeFixtures(bundle, disclosure);

      const result = await captureRun(() =>
        runVerifyFieldCommand({
          bundlePath,
          disclosurePath,
          candidate,
          candidateFile: null,
          json: true,
          verbose: false,
        }),
      );

      expect(result.exitCode).toBe(1);
      const report = JSON.parse(result.stdout);
      expect(report.verdict).toBe('error');
      expect(report.reason).toContain('event_hash mismatch');
      expect(report.reason).toContain(bundleHash);
      expect(report.reason).toContain(disclosureHash);
      await rm(dir, { recursive: true });
    });

    it('bundle.event_hash missing → verdict error', async () => {
      vi.mocked(verifyBundle).mockResolvedValue(PASS_BUNDLE_RESULT);
      const { bundle, disclosure, candidate } = makePassFixtures();
      delete (bundle as Record<string, unknown>).event_hash;
      const { bundlePath, disclosurePath, dir } = await writeFixtures(bundle, disclosure);

      const result = await captureRun(() =>
        runVerifyFieldCommand({
          bundlePath,
          disclosurePath,
          candidate,
          candidateFile: null,
          json: true,
          verbose: false,
        }),
      );

      expect(result.exitCode).toBe(1);
      expect(JSON.parse(result.stdout).reason).toMatch(/bundle\.event_hash/);
      await rm(dir, { recursive: true });
    });

    it('disclosure.event_hash in uppercase hex → verdict error (non-conforming encoding)', async () => {
      vi.mocked(verifyBundle).mockResolvedValue(PASS_BUNDLE_RESULT);
      const { bundle, disclosure, candidate } = makePassFixtures();
      (disclosure as Record<string, unknown>).event_hash = 'A'.repeat(64);
      const { bundlePath, disclosurePath, dir } = await writeFixtures(bundle, disclosure);

      const result = await captureRun(() =>
        runVerifyFieldCommand({
          bundlePath,
          disclosurePath,
          candidate,
          candidateFile: null,
          json: true,
          verbose: false,
        }),
      );

      expect(result.exitCode).toBe(1);
      expect(JSON.parse(result.stdout).reason).toMatch(/event_hash/);
      await rm(dir, { recursive: true });
    });
  });

  describe('File I/O errors', () => {
    it('missing bundle file → exit 2 (usage error)', async () => {
      const result = await captureRun(() =>
        runVerifyFieldCommand({
          bundlePath: '/nonexistent/path/bundle.json',
          disclosurePath: '/nonexistent/path/disclosure.json',
          candidate: 'alice@example.com',
          candidateFile: null,
          json: false,
          verbose: false,
        }),
      );
      expect(result.exitCode).toBe(2);
      expect(result.stderr).toContain('could not stat');
    });

    it('malformed JSON in disclosure → exit 2', async () => {
      vi.mocked(verifyBundle).mockResolvedValue(PASS_BUNDLE_RESULT);
      const dir = await mkdtemp(join(tmpdir(), 'verify-aul-vf-'));
      const bundlePath = join(dir, 'bundle.json');
      const disclosurePath = join(dir, 'disclosure.json');
      await writeFile(bundlePath, '{}', 'utf-8');
      await writeFile(disclosurePath, '{ this is not json }', 'utf-8');

      const result = await captureRun(() =>
        runVerifyFieldCommand({
          bundlePath,
          disclosurePath,
          candidate: 'alice@example.com',
          candidateFile: null,
          json: false,
          verbose: false,
        }),
      );
      expect(result.exitCode).toBe(2);
      expect(result.stderr).toContain('not valid JSON');
      await rm(dir, { recursive: true });
    });

    it('oversized disclosure (>10 MB) → exit 2', async () => {
      const dir = await mkdtemp(join(tmpdir(), 'verify-aul-vf-'));
      const bundlePath = join(dir, 'bundle.json');
      const disclosurePath = join(dir, 'disclosure.json');
      await writeFile(bundlePath, '{}', 'utf-8');
      // 10 MB + 1 byte of JSON-ish padding
      const bigBuf = Buffer.alloc(10 * 1024 * 1024 + 1, 0x20);
      bigBuf[0] = 0x7b; // '{'
      bigBuf[bigBuf.length - 1] = 0x7d; // '}'
      await writeFile(disclosurePath, bigBuf);

      const result = await captureRun(() =>
        runVerifyFieldCommand({
          bundlePath,
          disclosurePath,
          candidate: 'alice@example.com',
          candidateFile: null,
          json: false,
          verbose: false,
        }),
      );
      expect(result.exitCode).toBe(2);
      expect(result.stderr).toMatch(/10 MB cap/);
      await rm(dir, { recursive: true });
    });
  });
});
