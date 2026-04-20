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
import { buildReport, runVerifyFieldCommand } from './verify-field.js';

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
  /** Override bundle.event.metadata.event_root (for Binding B tests). */
  bundleEventRoot?: string | null;
  /** Drop bundle.event entirely to simulate a Tier 1 proof. */
  omitBundleEvent?: boolean;
  /** Drop bundle.event.metadata to simulate a malformed Tier 2 bundle. */
  omitBundleMetadata?: boolean;
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

  // Single-leaf tree: event_root === leaf_hash === disclosure.root.
  const eventRoot = overrides.bundleEventRoot === undefined ? root : overrides.bundleEventRoot;

  let bundleEvent: Record<string, unknown> | undefined = undefined;
  if (!overrides.omitBundleEvent) {
    if (overrides.omitBundleMetadata) {
      bundleEvent = { placeholder: true };
    } else {
      bundleEvent = {
        deal_id: 'deal-test',
        event_type: 'APPROVE_DELIVERABLE',
        metadata: eventRoot === null ? {} : { event_root: eventRoot, encoding_version: 'v1' },
      };
    }
  }

  const bundle: Record<string, unknown> = {
    bundle_schema_version: 1,
    status: 'confirmed',
    event_hash: overrides.bundleEventHash ?? eventHash,
    merkle_proof: { leaf_index: 0, siblings: [], root: '0'.repeat(64) },
    anchors: [],
    partial_anchors_reason: [],
  };
  if (bundleEvent !== undefined) {
    bundle.event = bundleEvent;
  }
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

describe('buildReport pass invariant (spec §10.8 step 7 — direct unit test)', () => {
  // These tests exercise the invariant guard inside buildReport directly,
  // independently of the handler's earlier short-circuit. The guard is the
  // load-bearing defence against a hypothetical future regression that
  // loosens the earlier check (e.g., a --skip-bundle-check flag).
  const BASE = {
    disclosure: '/tmp/d.json',
    bundle: '/tmp/b.json',
    reason: null,
    rpcEndpoint: null,
  } as const;

  it('verdict=pass with bundleVerdict=pass → passes through', () => {
    const r = buildReport({ ...BASE, verdict: 'pass', bundleVerdict: 'pass' });
    expect(r.verdict).toBe('pass');
  });

  it('verdict=pass with bundleVerdict=partial → coerced to error', () => {
    const r = buildReport({ ...BASE, verdict: 'pass', bundleVerdict: 'partial' });
    expect(r.verdict).toBe('error');
    expect(r.bundle_verdict).toBe('partial');
  });

  it('verdict=pass with bundleVerdict=fail → coerced to error', () => {
    const r = buildReport({ ...BASE, verdict: 'pass', bundleVerdict: 'fail' });
    expect(r.verdict).toBe('error');
  });

  it('verdict=pass with bundleVerdict=null → coerced to error', () => {
    const r = buildReport({ ...BASE, verdict: 'pass', bundleVerdict: null });
    expect(r.verdict).toBe('error');
  });

  it('verdict=fail with bundleVerdict=pass → stays fail (walk failure path)', () => {
    const r = buildReport({ ...BASE, verdict: 'fail', bundleVerdict: 'pass' });
    expect(r.verdict).toBe('fail');
  });

  it('verdict=error always stays error', () => {
    const passBundle = buildReport({ ...BASE, verdict: 'error', bundleVerdict: 'pass' });
    const failBundle = buildReport({ ...BASE, verdict: 'error', bundleVerdict: 'fail' });
    expect(passBundle.verdict).toBe('error');
    expect(failBundle.verdict).toBe('error');
  });
});

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

  describe('Binding check — event_root (spec §10.7 Binding B / adv-01 regression)', () => {
    it('ATTACK: forged disclosure with attacker-chosen field_value + matching leaf+root is REJECTED', async () => {
      // Adversarial scenario: attacker has a legitimate bundle (i.e. a bundle
      // whose event_hash matches a real anchored event). Attacker fabricates
      // a disclosure with fresh salt + their chosen field_value + merkle_path=[]
      // + root=computeLeafHash(attackerValue, freshSalt). Without a Binding B
      // check, verdict would be `pass` with the attacker's chosen value.
      //
      // The bundle's real event.metadata.event_root is the committed tree's
      // root (from the real data). The attacker's fabricated root does NOT
      // equal it. Binding B catches the attack.
      vi.mocked(verifyBundle).mockResolvedValue(PASS_BUNDLE_RESULT);

      const attackerSalt = new Uint8Array(16).fill(0xde);
      const attackerSaltB64 = Buffer.from(attackerSalt).toString('base64url');
      const attackerValue = 'attacker@evil.com';
      const attackerLeaf = computeLeafHash('approver.email', attackerValue, attackerSalt);
      // The real committed tree's root — what the legitimate bundle embeds.
      const realEventRoot = '1'.repeat(64);

      const bundle = {
        bundle_schema_version: 1,
        status: 'confirmed',
        event_hash: 'a'.repeat(64),
        event: {
          deal_id: 'real-deal',
          event_type: 'APPROVE_DELIVERABLE',
          metadata: { event_root: realEventRoot, encoding_version: 'v1' },
        },
        merkle_proof: { leaf_index: 0, siblings: [], root: '0'.repeat(64) },
        anchors: [],
        partial_anchors_reason: [],
      };
      const forgedDisclosure = {
        field_path: 'approver.email',
        field_value: attackerValue,
        salt: attackerSaltB64,
        merkle_path: [],
        root: attackerLeaf, // attacker-chosen; does NOT equal realEventRoot
        event_hash: 'a'.repeat(64), // stolen from the real bundle
      };
      const { bundlePath, disclosurePath, dir } = await writeFixtures(bundle, forgedDisclosure);

      const result = await captureRun(() =>
        runVerifyFieldCommand({
          bundlePath,
          disclosurePath,
          candidate: attackerValue,
          candidateFile: null,
          json: true,
          verbose: false,
        }),
      );

      // MUST be error, NOT pass. Verdict `fail` or `pass` here = critical regression.
      expect(result.exitCode).toBe(1);
      const report = JSON.parse(result.stdout);
      expect(report.verdict).toBe('error');
      expect(report.verdict).not.toBe('pass');
      expect(report.reason).toContain('event_root mismatch');
      await rm(dir, { recursive: true });
    });

    it('Tier 1 bundle (no event field) → verdict error', async () => {
      vi.mocked(verifyBundle).mockResolvedValue(PASS_BUNDLE_RESULT);
      const { bundle, disclosure, candidate } = makePassFixtures({ omitBundleEvent: true });
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
      expect(report.reason).toMatch(/bundle\.event missing/);
      await rm(dir, { recursive: true });
    });

    it('bundle.event.metadata missing → verdict error', async () => {
      vi.mocked(verifyBundle).mockResolvedValue(PASS_BUNDLE_RESULT);
      const { bundle, disclosure, candidate } = makePassFixtures({ omitBundleMetadata: true });
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
      expect(report.reason).toMatch(/metadata/);
      await rm(dir, { recursive: true });
    });

    it('bundle.event.metadata.event_root missing → verdict error', async () => {
      vi.mocked(verifyBundle).mockResolvedValue(PASS_BUNDLE_RESULT);
      const { bundle, disclosure, candidate } = makePassFixtures({ bundleEventRoot: null });
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
      expect(report.reason).toMatch(/event_root/);
      await rm(dir, { recursive: true });
    });

    it('bundle.event.metadata.event_root is uppercase hex → verdict error (non-conforming)', async () => {
      vi.mocked(verifyBundle).mockResolvedValue(PASS_BUNDLE_RESULT);
      const { bundle, disclosure, candidate } = makePassFixtures({
        bundleEventRoot: 'A'.repeat(64),
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
      expect(JSON.parse(result.stdout).reason).toMatch(/event_root/);
      await rm(dir, { recursive: true });
    });

    it('event_root present but differs from disclosure.root → verdict error', async () => {
      vi.mocked(verifyBundle).mockResolvedValue(PASS_BUNDLE_RESULT);
      const { bundle, disclosure, candidate } = makePassFixtures({
        bundleEventRoot: 'f'.repeat(64), // different from disclosure.root
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
      expect(report.reason).toContain('event_root mismatch');
      await rm(dir, { recursive: true });
    });
  });

  describe('Binding check — event_hash', () => {
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
