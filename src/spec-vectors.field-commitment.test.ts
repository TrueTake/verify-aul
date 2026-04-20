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

/** Build a synthetic Tier 2 bundle bound to the binding vector. The real
 *  `tier2-pass.json` has no `event.metadata.event_root`, so Binding B (§10.7)
 *  rejects it outright; we construct a Tier 2 bundle with matching
 *  `event_hash` and `event.metadata.event_root` for these end-to-end tests. */
function buildBindingBundle(disclosure: {
  event_hash: string;
  root: string;
}): VerificationBundle {
  return {
    bundle_schema_version: 1,
    status: 'confirmed',
    event_hash: disclosure.event_hash,
    event: {
      deal_id: 'binding-vector-deal',
      event_type: 'APPROVE_DELIVERABLE',
      metadata: { event_root: disclosure.root, encoding_version: 'v1' },
    },
    server_signature: 'a'.repeat(128),
    signing_key_id: 'AAAAAAAAAAAAAAAA',
    signing_keys: [
      { fingerprint: 'AAAAAAAAAAAAAAAA', public_key_base64url: 'A'.repeat(43), status: 'active' },
    ],
    merkle_proof: { leaf_index: 0, siblings: [], root: '0'.repeat(64) },
    anchors: [],
    partial_anchors_reason: [],
  };
}

describe('field-commitment-binding spec vector — end-to-end CLI', () => {
  it('disclosure + bundle bind on event_hash AND event_root, candidate verifies → verdict pass', async () => {
    vi.mocked(verifyBundle).mockResolvedValue(PASS_BUNDLE_RESULT);

    const disclosurePath = resolve(VECTORS_DIR, 'field-commitment-binding.json');
    const disclosure = JSON.parse(await readFile(disclosurePath, 'utf-8')) as {
      event_hash: string;
      root: string;
    };

    // tier2-pass.json pins the binding vector's event_hash (generator
    // hashes TIER2_PASS_EVENT). Confirm the tie so the fixture stays aligned.
    const tier2 = JSON.parse(
      await readFile(resolve(VECTORS_DIR, 'tier2-pass.json'), 'utf-8'),
    ) as VerificationBundle;
    expect(tier2.event_hash).toBe(disclosure.event_hash);

    // Construct a Tier 2 bundle bound to the disclosure on both bindings.
    const bundle = buildBindingBundle(disclosure);
    const dir = await mkdtemp(join(tmpdir(), 'verify-aul-fc-binding-'));
    const bundlePath = join(dir, 'bundle.json');
    await writeFile(bundlePath, JSON.stringify(bundle), 'utf-8');

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

      expect(result.exitCode).toBe(0);
      const report = JSON.parse(result.stdout);
      expect(report.verdict).toBe('pass');
      expect(report.bundle_verdict).toBe('pass');
      expect(vi.mocked(verifyBundle)).toHaveBeenCalled();
    } finally {
      await rm(dir, { recursive: true });
    }
  });

  it('candidate that does not canonicalize to field_value → verdict fail', async () => {
    vi.mocked(verifyBundle).mockResolvedValue(PASS_BUNDLE_RESULT);

    const disclosurePath = resolve(VECTORS_DIR, 'field-commitment-binding.json');
    const disclosure = JSON.parse(await readFile(disclosurePath, 'utf-8')) as {
      event_hash: string;
      root: string;
    };
    const bundle = buildBindingBundle(disclosure);
    const dir = await mkdtemp(join(tmpdir(), 'verify-aul-fc-binding-'));
    const bundlePath = join(dir, 'bundle.json');
    await writeFile(bundlePath, JSON.stringify(bundle), 'utf-8');

    try {
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
    } finally {
      await rm(dir, { recursive: true });
    }
  });

  it('bundle whose event_hash differs from disclosure → verdict error', async () => {
    vi.mocked(verifyBundle).mockResolvedValue(PASS_BUNDLE_RESULT);

    const disclosurePath = resolve(VECTORS_DIR, 'field-commitment-binding.json');
    const disclosure = JSON.parse(await readFile(disclosurePath, 'utf-8')) as {
      event_hash: string;
      root: string;
    };
    // Bundle event_root matches but event_hash is wrong — Binding A fires first.
    const bundle = buildBindingBundle(disclosure);
    bundle.event_hash = 'f'.repeat(64);

    const dir = await mkdtemp(join(tmpdir(), 'verify-aul-fc-binding-'));
    const bundlePath = join(dir, 'bundle.json');
    await writeFile(bundlePath, JSON.stringify(bundle), 'utf-8');

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
