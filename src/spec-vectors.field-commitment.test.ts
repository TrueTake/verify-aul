/**
 * End-to-end CLI test for the `field-commitment-binding` spec vector.
 *
 * Lives in its own file because `vi.mock('./core.js')` is module-hoisted
 * and would silently stub the real `verifyBundle` used by the bundle
 * vectors in `spec-vectors.test.ts`. Keep this file focused on the single
 * binding vector — add more fixture cases to the CLI handler test in
 * `cli/verify-field.test.ts`, not here.
 */

import { describe, expect, it, vi } from 'vitest';
import { readFile, writeFile, mkdtemp, rm } from 'node:fs/promises';
import { dirname, resolve, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { tmpdir } from 'node:os';

vi.mock('./core.js', () => ({
  verifyBundle: vi.fn(),
}));

import { verifyBundle } from './core.js';
import type { VerificationBundle, VerificationResult } from './types.js';
import { runVerifyFieldCommand } from './cli/verify-field.js';

const __dirname = dirname(fileURLToPath(import.meta.url));
const VECTORS_DIR = resolve(__dirname, '..', 'spec', 'test-vectors');

const PASS_BUNDLE_RESULT: VerificationResult = {
  verdict: 'pass',
  rpc_endpoint_used: 'https://api.mainnet-beta.solana.com',
  checks: [{ check: 'bundle_schema_version', status: 'pass' }],
};

interface CaptureResult {
  stdout: string;
  stderr: string;
  exitCode: number;
}

async function captureRun(fn: () => Promise<void>): Promise<CaptureResult> {
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

describe('field-commitment-binding spec vector — end-to-end CLI', () => {
  it('disclosure + bundle bind on event_hash, candidate verifies → verdict pass', async () => {
    vi.mocked(verifyBundle).mockResolvedValue(PASS_BUNDLE_RESULT);

    // Load the binding disclosure vector.
    const disclosurePath = resolve(VECTORS_DIR, 'field-commitment-binding.json');
    const disclosure = JSON.parse(await readFile(disclosurePath, 'utf-8')) as {
      event_hash: string;
    };

    // Load the tier2-pass bundle (its event_hash matches the binding vector).
    const bundlePath = resolve(VECTORS_DIR, 'tier2-pass.json');
    const bundle = JSON.parse(await readFile(bundlePath, 'utf-8')) as VerificationBundle;
    expect(bundle.event_hash).toBe(disclosure.event_hash);

    const result = await captureRun(() =>
      runVerifyFieldCommand({
        disclosurePath,
        bundlePath,
        candidate: 'alice@example.com',
        candidateFile: null,
        json: true,
        verbose: false,
      }),
    );

    expect(result.exitCode).toBe(0);
    const report = JSON.parse(result.stdout);
    expect(report.verdict).toBe('pass');
    expect(report.bundle_verdict).toBe('pass');
    expect(vi.mocked(verifyBundle)).toHaveBeenCalled();
  });

  it('candidate that does not canonicalize to field_value → verdict fail', async () => {
    vi.mocked(verifyBundle).mockResolvedValue(PASS_BUNDLE_RESULT);

    const disclosurePath = resolve(VECTORS_DIR, 'field-commitment-binding.json');
    const bundlePath = resolve(VECTORS_DIR, 'tier2-pass.json');

    const result = await captureRun(() =>
      runVerifyFieldCommand({
        disclosurePath,
        bundlePath,
        candidate: 'wrong@example.com',
        candidateFile: null,
        json: true,
        verbose: false,
      }),
    );

    expect(result.exitCode).toBe(1);
    expect(JSON.parse(result.stdout).verdict).toBe('fail');
  });

  it('bundle whose event_hash differs from disclosure → verdict error', async () => {
    vi.mocked(verifyBundle).mockResolvedValue(PASS_BUNDLE_RESULT);

    const disclosurePath = resolve(VECTORS_DIR, 'field-commitment-binding.json');

    // Craft a bundle that passes shape checks but has a different event_hash.
    const tier2Raw = await readFile(resolve(VECTORS_DIR, 'tier2-pass.json'), 'utf-8');
    const tier2 = JSON.parse(tier2Raw) as VerificationBundle;
    tier2.event_hash = 'f'.repeat(64);

    const dir = await mkdtemp(join(tmpdir(), 'verify-aul-fc-binding-'));
    const bundlePath = join(dir, 'bundle.json');
    await writeFile(bundlePath, JSON.stringify(tier2), 'utf-8');

    try {
      const result = await captureRun(() =>
        runVerifyFieldCommand({
          disclosurePath,
          bundlePath,
          candidate: 'alice@example.com',
          candidateFile: null,
          json: true,
          verbose: false,
        }),
      );

      expect(result.exitCode).toBe(1);
      const report = JSON.parse(result.stdout);
      expect(report.verdict).toBe('error');
      expect(report.reason).toContain('event_hash mismatch');
    } finally {
      await rm(dir, { recursive: true });
    }
  });
});
