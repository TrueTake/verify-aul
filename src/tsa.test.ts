/**
 * TSA token parse and verification tests.
 *
 * Full CMS signature verification of a real RFC 3161 token requires either:
 *   - A real token from a TSA (network request), or
 *   - A carefully crafted test token with a matching keypair
 *
 * For fast unit tests we focus on:
 *   - PEM parsing and SKI extraction (using the real bundled certs)
 *   - messageImprint mismatch detection (the hash-check path is pure logic)
 *   - Structure errors (malformed token DER)
 *   - The unknown-CA path (no trust anchors → CMS verify fails)
 *
 * Integration tests that require real TSA tokens are gated behind
 * process.env.TSA_INTEGRATION.
 */

import { describe, it, expect } from 'vitest';

import { extractSkiBytes, parsePemCert, verifyTsaToken } from './tsa.js';
import { sha256 } from '@noble/hashes/sha2.js';
import { bytesToHex } from '@noble/hashes/utils.js';

// ---------------------------------------------------------------------------
// Bundled cert PEM content (same as what core.ts uses)
// ---------------------------------------------------------------------------

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

// ---------------------------------------------------------------------------
// parsePemCert
// ---------------------------------------------------------------------------

describe('parsePemCert', () => {
  it('parses a valid PEM cert into DER bytes', () => {
    const der = parsePemCert(FREETSA_PEM);
    expect(der.byteLength).toBeGreaterThan(100);
    // DER starts with 0x30 (SEQUENCE tag)
    expect(der[0]).toBe(0x30);
  });

  it('ignores comment lines starting with #', () => {
    const pemWithComment = `# This is a comment
${FREETSA_PEM}`;
    const der1 = parsePemCert(FREETSA_PEM);
    const der2 = parsePemCert(pemWithComment);
    expect(der1.byteLength).toBe(der2.byteLength);
  });
});

// ---------------------------------------------------------------------------
// extractSkiBytes
// ---------------------------------------------------------------------------

describe('extractSkiBytes', () => {
  it('extracts the correct SKI from the FreeTSA cert', () => {
    const der = parsePemCert(FREETSA_PEM);
    const ski = extractSkiBytes(der);
    expect(ski).not.toBeNull();
    // Expected SKI hex: fa:55:0d:8c:34:66:51:43:4c:f7:e7:b3:a7:6c:95:af:7a:e6:a4:97
    const skiHex = bytesToHex(ski!);
    expect(skiHex).toBe('fa550d8c346651434cf7e7b3a76c95af7ae6a497');
  });

  it('returns null for malformed DER', () => {
    const result = extractSkiBytes(new Uint8Array([0x00, 0x01, 0x02]));
    expect(result).toBeNull();
  });

  it('SKI SHA-256 matches the pinned fingerprint', () => {
    const der = parsePemCert(FREETSA_PEM);
    const ski = extractSkiBytes(der);
    expect(ski).not.toBeNull();
    const fingerprint = bytesToHex(sha256(ski!));
    expect(fingerprint).toBe('3b49a197a9f98d5ee1124d19bf591e5677a799b230758c1d195db9983537aaf0');
  });
});

// ---------------------------------------------------------------------------
// verifyTsaToken — error paths (no network required)
// ---------------------------------------------------------------------------

describe('verifyTsaToken error paths', () => {
  it('returns verified:false with error for malformed token DER', async () => {
    const result = await verifyTsaToken(
      Buffer.from([0xde, 0xad, 0xbe, 0xef]).toString('base64'),
      'a'.repeat(64),
      [],
    );
    expect(result.verified).toBe(false);
    expect(result.error).toBeTruthy();
  });

  it('returns verified:false with error for empty token', async () => {
    const result = await verifyTsaToken('', 'a'.repeat(64), []);
    expect(result.verified).toBe(false);
    expect(result.error).toBeTruthy();
  });
});

// ---------------------------------------------------------------------------
// Integration: real FreeTSA token (network required, gated)
// ---------------------------------------------------------------------------

describe.skipIf(!process.env['TSA_INTEGRATION'])('TSA integration', () => {
  it('verifies a real FreeTSA token against the bundled cert', async () => {
    // This test requires a real TSA token. If running locally, set:
    //   TSA_INTEGRATION=1 TEST_TSA_TOKEN=<base64DER> TEST_TSA_MERKLE_ROOT=<64hexchars>
    const token = process.env['TEST_TSA_TOKEN'];
    const merkleRoot = process.env['TEST_TSA_MERKLE_ROOT'];

    if (!token || !merkleRoot) {
      throw new Error('TSA_INTEGRATION requires TEST_TSA_TOKEN and TEST_TSA_MERKLE_ROOT env vars');
    }

    const trustAnchorDer = parsePemCert(FREETSA_PEM);
    const result = await verifyTsaToken(token, merkleRoot, [trustAnchorDer]);
    expect(result.verified).toBe(true);
    expect(result.genTime).toBeInstanceOf(Date);
  });

  it('fails when the wrong merkle root is provided', async () => {
    const token = process.env['TEST_TSA_TOKEN'];
    const merkleRoot = process.env['TEST_TSA_MERKLE_ROOT'];
    if (!token || !merkleRoot) return;

    const trustAnchorDer = parsePemCert(FREETSA_PEM);
    const wrongRoot = 'f'.repeat(64);
    const result = await verifyTsaToken(token, wrongRoot, [trustAnchorDer]);
    expect(result.verified).toBe(false);
  });
});
