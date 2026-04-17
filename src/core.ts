/**
 * AUL Verification Bundle — top-level entry point.
 *
 * Isomorphic — runs identically in Node 18+, browser (WebCrypto), and
 * Next.js client components. No `server-only` guard, no node:crypto.
 *
 * Usage:
 *   import { verifyBundle } from '@truetake/verify-aul';
 *   const result = await verifyBundle(bundle, { solanaRpcUrl: '...' });
 *
 * Tier 1 bundles (no `event` field) passively skip the canonical-recompute
 * and Ed25519-signature checks — the verifier iterates only the checks
 * applicable to the bundle shape. There are no explicit skip toggles.
 *
 * Trust anchor pinning:
 *   At first call, each bundled PEM cert is parsed, its SubjectKeyIdentifier
 *   extracted, and its SHA-256 compared to TRUST_ANCHOR_FINGERPRINTS. A
 *   mismatch throws immediately — defense against supply-chain substitution.
 */

import { sha256 } from '@noble/hashes/sha2.js';
import { bytesToHex, hexToBytes } from '@noble/hashes/utils.js';

import { canonicalize } from './canonicalize.js';
import { verifyEd25519Signature } from './ed25519.js';
import { verifyMerkleInclusion } from './merkle.js';
import { resolveSolanaRpcUrl, verifySolanaMemo } from './solana.js';
import { extractSkiBytes, parsePemCert, verifyTsaToken } from './tsa.js';
import { TRUST_ANCHOR_FINGERPRINTS } from './trust-anchors/fingerprints.js';

import type {
  Anchor,
  Check,
  TsaAnchor,
  VerificationBundle,
  VerificationResult,
  VerifyOptions,
} from './types.js';

// ---------------------------------------------------------------------------
// Bundled PEM constants (see trust-anchors/*.pem for provenance)
// ---------------------------------------------------------------------------

// FreeTSA Root CA — fetched from https://freetsa.org/tsa.crt on 2026-04-15
const FREETSA_PEM = `-----BEGIN CERTIFICATE-----
MIIH/zCCBeegAwIBAgIJAMHphhYNqOmAMA0GCSqGSIb3DQEBDQUAMIGVMREwDwYD
VQQKEwhGcmVlIFRTQTEQMA4GA1UECxMHUm9vdCBDQTEYMBYGA1UEAxMPd3d3LmZy
ZWV0c2Eub3JnMSIwIAYJKoZIhvcNAQkBFhNidXNpbGV6YXNAZ21haWwuY29tMRIw
EAYDVQQHEwlXdWVyemJ1cmcxDzANBgNVBAgTBkJheWVybjELMAkGA1UEBhMCREUw
HhcNMTYwMzEzMDE1MjEzWhcNNDEwMzA3MDE1MjEzWjCBlTERMA8GA1UEChMIRnJl
ZSBUU0ExEDAOBgNVBAsTB1Jvb3QgQ0ExGDAWBgNVBAMTD3d3dy5mcmVldHNhLm9y
ZzEiMCAGCSqGSIb3DQEJARYTYnVzaWxlemFzQGdtYWlsLmNvbTESMBAGA1UEBxMJ
V3VlcnpidXJnMQ8wDQYDVQQIEwZCYXllcm4xCzAJBgNVBAYTAkRFMIICIjANBgkq
hkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAtgKODjAy8REQ2WTNqUudAnjhlCrpE6ql
mQfNppeTmVvZrH4zutn+NwTaHAGpjSGv4/WRpZ1wZ3BRZ5mPUBZyLgq0YrIfQ5Fx
0s/MRZPzc1r3lKWrMR9sAQx4mN4z11xFEO529L0dFJjPF9MD8Gpd2feWzGyptlel
b+PqT+++fOa2oY0+NaMM7l/xcNHPOaMz0/2olk0i22hbKeVhvokPCqhFhzsuhKsm
q4Of/o+t6dI7sx5h0nPMm4gGSRhfq+z6BTRgCrqQG2FOLoVFgt6iIm/BnNffUr7V
DYd3zZmIwFOj/H3DKHoGik/xK3E82YA2ZulVOFRW/zj4ApjPa5OFbpIkd0pmzxzd
EcL479hSA9dFiyVmSxPtY5ze1P+BE9bMU1PScpRzw8MHFXxyKqW13Qv7LWw4sbk3
SciB7GACbQiVGzgkvXG6y85HOuvWNvC5GLSiyP9GlPB0V68tbxz4JVTRdw/Xn/XT
FNzRBM3cq8lBOAVt/PAX5+uFcv1S9wFE8YjaBfWCP1jdBil+c4e+0tdywT2oJmYB
BF/kEt1wmGwMmHunNEuQNzh1FtJY54hbUfiWi38mASE7xMtMhfj/C4SvapiDN837
gYaPfs8x3KZxbX7C3YAsFnJinlwAUss1fdKar8Q/YVs7H/nU4c4Ixxxz4f67fcVq
M2ITKentbCMCAwEAAaOCAk4wggJKMAwGA1UdEwQFMAMBAf8wDgYDVR0PAQH/BAQD
AgHGMB0GA1UdDgQWBBT6VQ2MNGZRQ0z357OnbJWveuaklzCBygYDVR0jBIHCMIG/
gBT6VQ2MNGZRQ0z357OnbJWveuakl6GBm6SBmDCBlTERMA8GA1UEChMIRnJlZSBU
U0ExEDAOBgNVBAsTB1Jvb3QgQ0ExGDAWBgNVBAMTD3d3dy5mcmVldHNhLm9yZzEi
MCAGCSqGSIb3DQEJARYTYnVzaWxlemFzQGdtYWlsLmNvbTESMBAGA1UEBxMJV3Vl
cnpidXJnMQ8wDQYDVQQIEwZCYXllcm4xCzAJBgNVBAYTAkRFggkAwemGFg2o6YAw
MwYDVR0fBCwwKjAooCagJIYiaHR0cDovL3d3dy5mcmVldHNhLm9yZy9yb290X2Nh
LmNybDCBzwYDVR0gBIHHMIHEMIHBBgorBgEEAYHyJAEBMIGyMDMGCCsGAQUFBwIB
FidodHRwOi8vd3d3LmZyZWV0c2Eub3JnL2ZyZWV0c2FfY3BzLmh0bWwwMgYIKwYB
BQUHAgEWJmh0dHA6Ly93d3cuZnJlZXRzYS5vcmcvZnJlZXRzYV9jcHMucGRmMEcG
CCsGAQUFBwICMDsaOUZyZWVUU0EgdHJ1c3RlZCB0aW1lc3RhbXBpbmcgU29mdHdh
cmUgYXMgYSBTZXJ2aWNlIChTYWFTKTA3BggrBgEFBQcBAQQrMCkwJwYIKwYBBQUH
MAGGG2h0dHA6Ly93d3cuZnJlZXRzYS5vcmc6MjU2MDANBgkqhkiG9w0BAQ0FAAOC
AgEAaK9+v5OFYu9M6ztYC+L69sw1omdyli89lZAfpWMMh9CRmJhM6KBqM/ipwoLt
nxyxGsbCPhcQjuTvzm+ylN6VwTMmIlVyVSLKYZcdSjt/eCUN+41K7sD7GVmxZBAF
ILnBDmTGJmLkrU0KuuIpj8lI/E6Z6NnmuP2+RAQSHsfBQi6sssnXMo4HOW5gtPO7
gDrUpVXID++1P4XndkoKn7Svw5n0zS9fv1hxBcYIHPPQUze2u30bAQt0n0iIyRLz
aWuhtpAtd7ffwEbASgzB7E+NGF4tpV37e8KiA2xiGSRqT5ndu28fgpOY87gD3ArZ
DctZvvTCfHdAS5kEO3gnGGeZEVLDmfEsv8TGJa3AljVa5E40IQDsUXpQLi8G+UC4
1DWZu8EVT4rnYaCw1VX7ShOR1PNCCvjb8S8tfdudd9zhU3gEB0rxdeTy1tVbNLXW
99y90xcwr1ZIDUwM/xQ/noO8FRhm0LoPC73Ef+J4ZBdrvWwauF3zJe33d4ibxEcb
8/pz5WzFkeixYM2nsHhqHsBKw7JPouKNXRnl5IAE1eFmqDyC7G/VT7OF669xM6hb
Ut5G21JE4cNK6NNucS+fzg1JPX0+3VhsYZjj7D5uljRvQXrJ8iHgr/M6j2oLHvTA
I2MLdq2qjZFDOCXsxBxJpbmLGBx9ow6ZerlUxzws2AWv2pk=
-----END CERTIFICATE-----`;

// DigiCert SHA2 Assured ID Timestamping CA — fetched 2026-04-15
const DIGICERT_PEM = `-----BEGIN CERTIFICATE-----
MIIFMTCCBBmgAwIBAgIQCqEl1tYyG35B5AXaNpfCFTANBgkqhkiG9w0BAQsFADBl
MQswCQYDVQQGEwJVUzEVMBMGA1UEChMMRGlnaUNlcnQgSW5jMRkwFwYDVQQLExB3
d3cuZGlnaWNlcnQuY29tMSQwIgYDVQQDExtEaWdpQ2VydCBBc3N1cmVkIElEIFJv
b3QgQ0EwHhcNMTYwMTA3MTIwMDAwWhcNMzEwMTA3MTIwMDAwWjByMQswCQYDVQQG
EwJVUzEVMBMGA1UEChMMRGlnaUNlcnQgSW5jMRkwFwYDVQQLExB3d3cuZGlnaWNl
cnQuY29tMTEwLwYDVQQDEyhEaWdpQ2VydCBTSEEyIEFzc3VyZWQgSUQgVGltZXN0
YW1waW5nIENBMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAvdAy7kvN
j3/dqbqCmcU5VChXtiNKxA4HRTNREH3Q+X1NaH7ntqD0jbOI5Je/YyGQmL8TvFfT
w+F+CNZqFAA49y4eO+7MpvYyWf5fZT/gm+vjRkcGGlV+Cyd+wKL1oODeIj8O/36V
+/OjuiI+GKwR5PCZA207hXwJ0+5dyJoLVOOoCXFr4M8iEA91z3FyTgqt30A6XLdR
4aF5FMZNJCMwXbzsPGBqrC8HzP3w6kfZiFBe/WZuVmEnKYmEUeaC50ZQ/ZQqLKfk
dT66mA+Ef58xFNat1fJky3seBdCEGXIX8RcG7z3N1k3vBkL9olMqT4UdxB08r8/a
rBD13ays6Vb/kwIDAQABo4IBzjCCAcowHQYDVR0OBBYEFPS24SAd/imu0uRhpbKi
JbLIFzVuMB8GA1UdIwQYMBaAFEXroq/0ksuCMS1Ri6enIZ3zbcgPMBIGA1UdEwEB
/wQIMAYBAf8CAQAwDgYDVR0PAQH/BAQDAgGGMBMGA1UdJQQMMAoGCCsGAQUFBwMI
MHkGCCsGAQUFBwEBBG0wazAkBggrBgEFBQcwAYYYaHR0cDovL29jc3AuZGlnaWNl
cnQuY29tMEMGCCsGAQUFBzAChjdodHRwOi8vY2FjZXJ0cy5kaWdpY2VydC5jb20v
RGlnaUNlcnRBc3N1cmVkSURSb290Q0EuY3J0MIGBBgNVHR8EejB4MDqgOKA2hjRo
dHRwOi8vY3JsNC5kaWdpY2VydC5jb20vRGlnaUNlcnRBc3N1cmVkSURSb290Q0Eu
Y3JsMDqgOKA2hjRodHRwOi8vY3JsMy5kaWdpY2VydC5jb20vRGlnaUNlcnRBc3N1
cmVkSURSb290Q0EuY3JsMFAGA1UdIARJMEcwOAYKYIZIAYb9bAACBDAqMCgGCCsG
AQUFBwIBFhxodHRwczovL3d3dy5kaWdpY2VydC5jb20vQ1BTMAsGCWCGSAGG/WwH
ATANBgkqhkiG9w0BAQsFAAOCAQEAcZUS6VGHVmnN793afKpjerN4zwY3QITvS4S/
ys8DAv3Fp8MOIEIsr3fzKx8MIVoqtwU0HWqumfgnoma/Capg33akOpMP+LLR2HwZ
YuhegiUexLoceywh4tZbLBQ1QwRostt1AuByx5jWPGTlH0gQGF+JOGFNYkYkh2OM
kVIsrymJ5Xgf1gsUpYDXEkdws3XVk4WTfraSZ/tTYYmo9WuWwPRYaQ18yAGxuSh1
t5ljhSKMYcp5lH5Z/IwP42+1ASa2bKXuh1Eh5Fhgm7oMLSttosR+u8QlK0cCCHxJ
rhO24XxCQijGGFbPQTS2Zl22dHv1VjMiLyI2skuiSpXY9aaOUg==
-----END CERTIFICATE-----`;

// ---------------------------------------------------------------------------
// Bundled PEM content (inline strings — avoids static file-import in vitest/Node)
// ---------------------------------------------------------------------------

/**
 * Load the bundled PEM content for each trust anchor.
 * Returns an array of { filename, pem } entries in the same order as
 * TRUST_ANCHOR_FINGERPRINTS.
 *
 * We use a lazy dynamic import so this works in all contexts:
 *   - Next.js (webpack handles .pem as asset)
 *   - vitest (raw string import via ?raw or inline)
 *   - Node CLI (reads via fs)
 *
 * In practice, the PEM content is small enough to inline here.
 * This avoids bundler-specific .pem handling entirely.
 */
function getBundledPems(): Array<{ filename: string; pem: string }> {
  // Inline the PEM content to avoid any bundler/test-runner complexity.
  // These are updated manually when certs rotate (see trust-anchors/freetsa.pem
  // and trust-anchors/digicert.pem for provenance).
  return [
    {
      filename: 'freetsa.pem',
      pem: FREETSA_PEM,
    },
    {
      filename: 'digicert.pem',
      pem: DIGICERT_PEM,
    },
  ];
}

// ---------------------------------------------------------------------------
// Supported bundle versions
// ---------------------------------------------------------------------------

const SUPPORTED_BUNDLE_VERSIONS = [1];

// ---------------------------------------------------------------------------
// Trust anchor loading and pin check (one-time, lazy)
// ---------------------------------------------------------------------------

interface TrustAnchorEntry {
  filename: string;
  pem: string;
  der: Uint8Array;
}

/** Bundled PEM entries keyed by filename (matches fingerprints.ts keys). */
const BUNDLED_ANCHORS: TrustAnchorEntry[] = getBundledPems().map((e) => ({
  ...e,
  der: null as unknown as Uint8Array,
}));

let _anchorsInitialized = false;
let _anchorDers: Uint8Array[] = [];

/**
 * One-time initialization: parse bundled PEMs, extract SKIs, verify pins.
 * Throws if any cert's SKI doesn't match the pinned fingerprint.
 */
function initTrustAnchors(): Uint8Array[] {
  if (_anchorsInitialized) return _anchorDers;

  const ders: Uint8Array[] = [];

  for (const entry of BUNDLED_ANCHORS) {
    const der = parsePemCert(entry.pem);

    // Extract SKI and verify pin
    const skiBytes = extractSkiBytes(der);
    if (!skiBytes) {
      throw new Error(
        `[verify-aul] Trust anchor ${entry.filename} has no SubjectKeyIdentifier extension — ` +
          'cannot verify pin. Bundled certs must include this extension.',
      );
    }

    const skiFingerprint = bytesToHex(sha256(skiBytes));
    const expectedFingerprint = TRUST_ANCHOR_FINGERPRINTS[entry.filename];

    if (!expectedFingerprint) {
      throw new Error(
        `[verify-aul] No pinned fingerprint for trust anchor ${entry.filename}. ` +
          'Update src/trust-anchors/fingerprints.ts when adding new anchors.',
      );
    }

    if (skiFingerprint !== expectedFingerprint) {
      throw new Error(
        `[verify-aul] TRUST ANCHOR PIN MISMATCH for ${entry.filename}!\n` +
          `  Expected SKI SHA-256: ${expectedFingerprint}\n` +
          `  Actual   SKI SHA-256: ${skiFingerprint}\n` +
          'The bundled certificate has been replaced. Verification aborted.',
      );
    }

    entry.der = der;
    ders.push(der);
  }

  _anchorsInitialized = true;
  _anchorDers = ders;
  return ders;
}

// ---------------------------------------------------------------------------
// Main entry point
// ---------------------------------------------------------------------------

/**
 * Verify an AUL verification bundle.
 *
 * Iterates through all checks applicable to the bundle shape and returns a
 * structured result with per-check status and an overall verdict.
 *
 * @param bundle - The bundle to verify (Tier 1 or Tier 2)
 * @param options - Optional overrides for Solana RPC and additional trust anchors
 */
export async function verifyBundle(
  bundle: VerificationBundle,
  options?: VerifyOptions,
): Promise<VerificationResult> {
  const checks: Check[] = [];
  // When the caller doesn't override, pass through undefined so per-anchor
  // verify picks a cluster-appropriate default (mainnet-beta / devnet /
  // testnet). The URL actually used is reported back from verifyAnchor for
  // Solana anchors and surfaced via rpc_endpoint_used.
  const solanaRpcOverride = options?.solanaRpcUrl;
  let rpcUrlUsed = solanaRpcOverride ?? '';

  // Initialize trust anchors (throws on pin mismatch)
  const bundledAnchorDers = initTrustAnchors();
  const allTrustAnchors: Uint8Array[] = [...bundledAnchorDers, ...(options?.trustAnchors ?? [])];

  // Helper to record a check result
  function pass(check: string, details?: string): void {
    checks.push({ check, status: 'pass', details });
  }
  function fail(check: string, details: string): void {
    checks.push({ check, status: 'fail', details });
  }

  // -------------------------------------------------------------------------
  // Check 1: Bundle schema version
  // -------------------------------------------------------------------------
  if (!SUPPORTED_BUNDLE_VERSIONS.includes(bundle.bundle_schema_version)) {
    fail('bundle_schema_version', `unsupported bundle version: ${bundle.bundle_schema_version}`);
    return buildResult('fail', checks, rpcUrlUsed);
  }
  pass('bundle_schema_version');

  // -------------------------------------------------------------------------
  // Check 2 (Tier 2 only): Canonical recompute
  // event_hash must equal SHA-256(RFC8785-canonicalize(event))
  // -------------------------------------------------------------------------
  if (bundle.event !== undefined) {
    try {
      const canonical = canonicalize(bundle.event);
      if (canonical === undefined) {
        fail('canonical_recompute', 'canonicalization returned undefined');
      } else {
        const recomputedBytes = sha256(new TextEncoder().encode(canonical));
        const recomputed = bytesToHex(recomputedBytes);
        if (recomputed === bundle.event_hash) {
          pass('canonical_recompute');
        } else {
          fail(
            'canonical_recompute',
            `hash mismatch: recomputed ${recomputed}, bundle has ${bundle.event_hash}`,
          );
        }
      }
    } catch (err) {
      fail('canonical_recompute', `error: ${err instanceof Error ? err.message : String(err)}`);
    }
  }

  // -------------------------------------------------------------------------
  // Check 3 (Tier 2 only): Ed25519 server signature
  // Present when bundle has server_signature + signing_keys
  // -------------------------------------------------------------------------
  if (bundle.server_signature !== undefined && bundle.signing_keys !== undefined) {
    const keyEntry = bundle.signing_keys.find((k) => k.fingerprint === bundle.signing_key_id);
    if (!keyEntry) {
      fail(
        'server_signature',
        `signing key ${bundle.signing_key_id ?? '(none)'} not found in bundle.signing_keys`,
      );
    } else {
      // The server signs raw event hash bytes:
      //   kmsSigner.sign(Buffer.from(eventHash, 'hex'))
      const messageBytes = hexToBytes(bundle.event_hash);
      try {
        const valid = await verifyEd25519Signature(
          bundle.server_signature,
          messageBytes,
          keyEntry.public_key_base64url,
        );
        if (valid) {
          pass('server_signature');
        } else {
          fail('server_signature', 'Ed25519 signature verification failed');
        }
      } catch (err) {
        fail('server_signature', `error: ${err instanceof Error ? err.message : String(err)}`);
      }
    }
  }

  // -------------------------------------------------------------------------
  // Checks 4+: Merkle + anchor verification
  // Skipped on pending bundles (no merkle_proof / no anchors)
  // -------------------------------------------------------------------------
  if (!bundle.merkle_proof || !bundle.anchors) {
    // Pending bundle — anchoring hasn't completed yet. If earlier checks
    // (canonical recompute, signature) failed, the bundle is tampered and
    // verdict must be 'fail'. Otherwise report 'partial' so the UI shows
    // "not fully verified" rather than "checks failed".
    if (bundle.status === 'pending') {
      checks.push({
        check: 'anchoring',
        status: 'skip',
        details: 'anchoring pending — merkle proof and anchors not yet available',
      });
      return buildResult(
        checks.some((c) => c.status === 'fail') ? 'fail' : 'partial',
        checks,
        rpcUrlUsed,
      );
    }
    // Confirmed/partial bundle must have merkle proof and anchors
    fail('merkle_inclusion', 'confirmed bundle is missing merkle_proof or anchors');
    return buildResult('fail', checks, rpcUrlUsed);
  }

  // -------------------------------------------------------------------------
  // Check 4: Merkle inclusion
  // -------------------------------------------------------------------------
  try {
    const included = verifyMerkleInclusion(bundle.event_hash, {
      siblings: bundle.merkle_proof.siblings,
      root: bundle.merkle_proof.root,
    });
    if (included) {
      pass('merkle_inclusion');
    } else {
      fail(
        'merkle_inclusion',
        `event hash ${bundle.event_hash.slice(0, 16)}... not included in Merkle root ${bundle.merkle_proof.root.slice(0, 16)}...`,
      );
    }
  } catch (err) {
    fail('merkle_inclusion', `error: ${err instanceof Error ? err.message : String(err)}`);
  }

  // -------------------------------------------------------------------------
  // Check 5+: Per-anchor verification
  // -------------------------------------------------------------------------
  if (bundle.anchors.length === 0) {
    fail('anchors', 'no anchors present in confirmed bundle');
  } else {
    const merkleRoot = bundle.merkle_proof.root;
    const results = await Promise.all(
      bundle.anchors.map((anchor) =>
        verifyAnchor(anchor, merkleRoot, allTrustAnchors, solanaRpcOverride),
      ),
    );
    for (const { check, rpcUrlUsed: url } of results) {
      checks.push(check);
      if (url !== undefined) rpcUrlUsed = url;
    }
  }

  // -------------------------------------------------------------------------
  // Compute final verdict
  // -------------------------------------------------------------------------
  const hasFailure = checks.some((c) => c.status === 'fail');
  if (hasFailure) {
    return buildResult('fail', checks, rpcUrlUsed);
  }

  // partial = all checks passed, but bundle reported some providers terminal-failed
  if (Array.isArray(bundle.partial_anchors_reason) && bundle.partial_anchors_reason.length > 0) {
    return buildResult('partial', checks, rpcUrlUsed);
  }

  return buildResult('pass', checks, rpcUrlUsed);
}

// ---------------------------------------------------------------------------
// Per-anchor verification dispatcher
// ---------------------------------------------------------------------------

async function verifyAnchor(
  anchor: Anchor,
  merkleRoot: string,
  trustAnchors: Uint8Array[],
  solanaRpcOverride: string | undefined,
): Promise<{ check: Check; rpcUrlUsed?: string }> {
  const checkName = `anchor:${anchor.type}`;

  if (anchor.type === 'solana') {
    const plannedRpcUrl = resolveSolanaRpcUrl(anchor.cluster, solanaRpcOverride);
    try {
      const result = await verifySolanaMemo(
        anchor.signature,
        anchor.cluster,
        merkleRoot,
        solanaRpcOverride,
      );
      return {
        check: result.verified
          ? {
              check: checkName,
              status: 'pass',
              details: result.slot !== undefined ? `slot=${result.slot}` : undefined,
            }
          : {
              check: checkName,
              status: 'fail',
              details: 'solana anchor not found or memo content mismatch',
            },
        rpcUrlUsed: result.rpcUrlUsed,
      };
    } catch (err) {
      return {
        check: {
          check: checkName,
          status: 'fail',
          details: `error: ${err instanceof Error ? err.message : String(err)}`,
        },
        rpcUrlUsed: plannedRpcUrl,
      };
    }
  }

  if (anchor.type === 'tsa_freetsa' || anchor.type === 'tsa_digicert') {
    const tsaAnchor = anchor as TsaAnchor;
    try {
      const result = await verifyTsaToken(tsaAnchor.token, merkleRoot, trustAnchors);
      return {
        check: result.verified
          ? {
              check: checkName,
              status: 'pass',
              details: result.genTime ? `genTime=${result.genTime.toISOString()}` : undefined,
            }
          : {
              check: checkName,
              status: 'fail',
              details: result.error ?? 'TSA token verification failed',
            },
      };
    } catch (err) {
      return {
        check: {
          check: checkName,
          status: 'fail',
          details: `error: ${err instanceof Error ? err.message : String(err)}`,
        },
      };
    }
  }

  return {
    check: {
      check: checkName,
      status: 'fail',
      details: `unknown anchor type: ${(anchor as Anchor).type}`,
    },
  };
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function buildResult(
  verdict: VerificationResult['verdict'],
  checks: Check[],
  rpcUrl: string,
): VerificationResult {
  return { verdict, checks, rpc_endpoint_used: rpcUrl };
}
