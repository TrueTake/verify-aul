/**
 * RFC 3161 TimeStampToken parse and CMS signature verification.
 *
 * Isomorphic — uses pkijs + asn1js which rely on WebCrypto (available in Node
 * 18+ as globalThis.crypto, and in all modern browsers). No node:crypto.
 *
 * The TSA token in a verification bundle is stored as a base64-encoded DER
 * TimeStampToken (the CMS ContentInfo wrapping the SignedData). This is the
 * same format stored by server/services/ledger/anchor/tsa-provider.ts.
 *
 * Verification steps:
 * 1. DER-decode the token
 * 2. Parse as TimeStampResp (pkijs reconstructs TimeStampToken from ContentInfo)
 * 3. Extract TSTInfo → messageImprint.hashedMessage
 * 4. Check that hashedMessage matches SHA-256(hex_decode(expectedHashHex))
 * 5. Verify the CMS signature using the provided trust anchors
 *
 * Important: the messageImprint in the TSA token is a hash of the data that
 * was submitted to the TSA. Per tsa-provider.ts:
 *   const merkleRootBuffer = Buffer.from(merkleRoot, 'hex');
 *   const digest = createHash('sha256').update(merkleRootBuffer).digest();
 * So expectedHashHex is the Merkle root hex, and we verify:
 *   SHA-256(hex_decode(merkleRoot)) === messageImprint.hashedMessage
 */

import * as asn1js from 'asn1js';
import { BufferSourceConverter } from 'pvtsutils';
import * as pkijs from 'pkijs';

import { sha256 } from '@noble/hashes/sha2.js';
import { hexToBytes } from '@noble/hashes/utils.js';

const SHA256_OID = '2.16.840.1.101.3.4.2.1';

// ---------------------------------------------------------------------------
// SKI extraction (used by core.ts for trust anchor pinning)
// ---------------------------------------------------------------------------

/**
 * Extract the SubjectKeyIdentifier bytes from a DER-encoded X.509 certificate.
 * Returns null if the SKI extension is absent.
 */
export function extractSkiBytes(certDer: Uint8Array): Uint8Array | null {
  const asn1 = asn1js.fromBER(toCleanArrayBuffer(certDer));
  if (asn1.offset === -1) return null;

  let cert: pkijs.Certificate;
  try {
    cert = new pkijs.Certificate({ schema: asn1.result });
  } catch {
    return null;
  }
  const skiExt = cert.extensions?.find((e) => e.extnID === '2.5.29.14');
  if (!skiExt) return null;

  const extnValView = skiExt.extnValue.valueBlock.valueHexView;
  const extnValAb = toCleanArrayBuffer(extnValView);
  const inner = asn1js.fromBER(extnValAb);
  if (inner.offset === -1) return null;

  // valueHexView is available on primitive value blocks; cast to access it
  const block = inner.result.valueBlock as { valueHexView?: ArrayBufferView };
  if (!block.valueHexView) return null;
  return new Uint8Array(
    block.valueHexView.buffer,
    block.valueHexView.byteOffset,
    block.valueHexView.byteLength,
  );
}

/**
 * Parse a PEM-encoded certificate (with or without comment lines) into DER bytes.
 */
export function parsePemCert(pem: string): Uint8Array {
  const lines = pem.split(/\r?\n/);
  const b64 = lines
    .filter((l) => l.length > 0 && !l.startsWith('#') && !l.startsWith('-----'))
    .join('');
  return base64ToBytes(b64);
}

// ---------------------------------------------------------------------------
// TSA token verification
// ---------------------------------------------------------------------------

export interface TsaVerifyResult {
  verified: boolean;
  genTime?: Date;
  error?: string;
}

/**
 * Parse and verify an RFC 3161 TimeStampToken.
 *
 * @param tokenBase64Der - Base64-encoded DER TimeStampToken (ContentInfo wrapping SignedData)
 * @param expectedMerkleRootHex - 64-char hex Merkle root that was submitted to the TSA.
 *   The TSA hashed SHA-256(hex_decode(merkleRoot)) before timestamping; we verify that match.
 * @param trustAnchors - DER-encoded X.509 certificates to use as trust anchors.
 *   Should include the TSA's signing cert or its issuer.
 */
export async function verifyTsaToken(
  tokenBase64Der: string,
  expectedMerkleRootHex: string,
  trustAnchors: Uint8Array[],
): Promise<TsaVerifyResult> {
  // 1. Decode the token
  const tokenDer = base64ToBytes(tokenBase64Der);

  // 2. Parse as TimeStampResp
  // The token stored in the bundle is the raw TimeStampToken (ContentInfo),
  // not a full TimeStampResp. We need to reconstruct a minimal TimeStampResp
  // by wrapping the token in a PKIStatusInfo(granted) shell.
  //
  // pkijs.TimeStampResp.fromBER expects the full response DER. Instead, we
  // parse the ContentInfo directly as a SignedData and then verify.
  const contentInfoAsn1 = asn1js.fromBER(toCleanArrayBuffer(tokenDer));
  if (contentInfoAsn1.offset === -1) {
    return { verified: false, error: 'Failed to parse TimeStampToken DER' };
  }

  const contentInfo = new pkijs.ContentInfo({ schema: contentInfoAsn1.result });
  const signedData = new pkijs.SignedData({ schema: contentInfo.content });

  // 3. Extract TSTInfo from encapsulated content
  const eContent = signedData.encapContentInfo.eContent;
  if (!eContent) {
    return { verified: false, error: 'No encapsulated content in TimeStampToken' };
  }

  const tstInfoBytes = toCleanArrayBuffer(eContent.valueBlock.valueHexView);
  const tstInfo = pkijs.TSTInfo.fromBER(tstInfoBytes);

  // 4. Verify messageImprint matches expected Merkle root
  // The server hashed: SHA-256(Buffer.from(merkleRoot, 'hex'))
  const merkleRootBytes = hexToBytes(expectedMerkleRootHex);
  const expectedDigest = sha256(merkleRootBytes);
  const actualDigest = new Uint8Array(
    BufferSourceConverter.toArrayBuffer(
      tstInfo.messageImprint.hashedMessage.valueBlock.valueHexView,
    ),
  );

  if (!bytesEqual(actualDigest, expectedDigest)) {
    return {
      verified: false,
      error: `TSA token messageImprint mismatch: token was timestamped with a different hash`,
    };
  }

  // Verify hash algorithm is SHA-256
  const hashAlgOid = tstInfo.messageImprint.hashAlgorithm.algorithmId;
  if (hashAlgOid !== SHA256_OID) {
    return {
      verified: false,
      error: `Unsupported hash algorithm in TSA token: ${hashAlgOid}`,
    };
  }

  // 5. Verify CMS signature using trust anchors
  // pkijs.SignedData.verify() requires the original pre-hash data as `data`
  // and trust certs. The `data` param is the bytes that were originally hashed:
  // the Merkle root raw bytes (hex-decoded).
  const trustedCerts = buildTrustedCerts(signedData, trustAnchors);

  const merkleRootAb = toCleanArrayBuffer(merkleRootBytes);

  let sigVerified = false;
  try {
    sigVerified = await signedData.verify({
      signer: 0,
      trustedCerts,
      data: merkleRootAb,
    });
  } catch (err) {
    return {
      verified: false,
      error: `CMS signature verification failed: ${err instanceof Error ? err.message : String(err)}`,
    };
  }

  if (!sigVerified) {
    return { verified: false, error: 'CMS signature verification failed' };
  }

  return { verified: true, genTime: tstInfo.genTime };
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/**
 * Build a list of trusted certificates for CMS verification.
 * Includes certs embedded in the SignedData (certReq=true) plus user-supplied anchors.
 */
function buildTrustedCerts(
  signedData: pkijs.SignedData,
  trustAnchors: Uint8Array[],
): pkijs.Certificate[] {
  const certs: pkijs.Certificate[] = [];

  // Certs embedded in the token (added by TSA when certReq=true)
  if (signedData.certificates) {
    for (const c of signedData.certificates) {
      if (c instanceof pkijs.Certificate) {
        certs.push(c);
      }
    }
  }

  // User-supplied trust anchors
  for (const anchorDer of trustAnchors) {
    try {
      const asn1 = asn1js.fromBER(toCleanArrayBuffer(anchorDer));
      if (asn1.offset !== -1) {
        certs.push(new pkijs.Certificate({ schema: asn1.result }));
      }
    } catch {
      // Skip malformed anchors
    }
  }

  return certs;
}

/** Ensure an ArrayBuffer is not a slice of a larger buffer (pkijs requires this). */
function toCleanArrayBuffer(view: ArrayBufferLike | Uint8Array): ArrayBuffer {
  if (view instanceof Uint8Array) {
    const ab = new ArrayBuffer(view.byteLength);
    new Uint8Array(ab).set(view);
    return ab;
  }
  // Copy to a fresh ArrayBuffer to avoid slice-aliasing issues
  const ab = new ArrayBuffer(view.byteLength);
  new Uint8Array(ab).set(new Uint8Array(view));
  return ab;
}

function base64ToBytes(b64: string): Uint8Array {
  // Handle base64 with/without padding and any whitespace
  const clean = b64.replace(/\s/g, '');
  const padded = clean.padEnd(clean.length + ((4 - (clean.length % 4)) % 4), '=');

  if (typeof atob !== 'undefined') {
    const binary = atob(padded);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) {
      bytes[i] = binary.charCodeAt(i);
    }
    return bytes;
  } else {
    return new Uint8Array(Buffer.from(padded, 'base64'));
  }
}

function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) {
    if (a[i] !== b[i]) return false;
  }
  return true;
}
