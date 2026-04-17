/**
 * Build a local fixtures CA + TSA signing cert, then sign an RFC 3161
 * TimeStampToken under that CA. Used by `spec/generate-fixtures.ts` only
 * for the `fail-trust-anchor-mismatch` vector: its token is signed by a
 * cert whose issuer chain does NOT terminate at any PEM the verifier has
 * pinned, so CMS signature verification fails and the verdict is `fail`.
 *
 * Not part of the published tarball. Never ship these anchors to end users.
 */

import * as asn1js from 'asn1js';
import * as pkijs from 'pkijs';
import { webcrypto } from 'node:crypto';
import { sha256 } from '@noble/hashes/sha2.js';
import { hexToBytes } from '@noble/hashes/utils.js';

// pkijs needs a crypto engine set once per process. Setting here at module
// load is fine — the tools/ directory is never imported by runtime code,
// only by generate-fixtures.ts.
pkijs.setEngine('node-webcrypto', new pkijs.CryptoEngine({ crypto: webcrypto as unknown as Crypto }));

const SHA256_OID = '2.16.840.1.101.3.4.2.1';
const ID_SIGNED_DATA = '1.2.840.113549.1.7.2';
const ID_CT_TSTINFO = '1.2.840.113549.1.9.16.1.4';
const ID_EXT_KEY_USAGE = '2.5.29.37';
const ID_KP_TIMESTAMPING = '1.3.6.1.5.5.7.3.8';
const ID_SKI = '2.5.29.14';
const ID_AKI = '2.5.29.35';
const ID_BASIC_CONSTRAINTS = '2.5.29.19';
const ID_KEY_USAGE = '2.5.29.15';

// Deterministic SKIs so the committed fingerprints file doesn't churn on
// regeneration. The CA's SKI below is pinned in
// `spec/fixtures-trust-anchors/fingerprints.ts`.
const FIXTURES_CA_SKI = Uint8Array.from([
  0x66, 0x69, 0x78, 0x74, 0x75, 0x72, 0x65, 0x73, 0x2d, 0x63, 0x61, 0x2d, 0x73, 0x6b, 0x69, 0x01,
  0x02, 0x03, 0x04, 0x05,
]);
const FIXTURES_TSA_SKI = Uint8Array.from([
  0x66, 0x69, 0x78, 0x74, 0x75, 0x72, 0x65, 0x73, 0x2d, 0x74, 0x73, 0x61, 0x2d, 0x73, 0x6b, 0x69,
  0x01, 0x02, 0x03, 0x04,
]);

export interface FixturesCa {
  caCert: pkijs.Certificate;
  caCertPem: string;
  caSkiSha256Hex: string;
  tsaCert: pkijs.Certificate;
  tsaPrivateKey: CryptoKey;
}

/** Generate a self-signed fixtures root CA + a TSA signing cert issued by it. */
export async function buildFixturesCa(): Promise<FixturesCa> {
  const caKeys = await webcrypto.subtle.generateKey(
    {
      name: 'RSASSA-PKCS1-v1_5',
      modulusLength: 2048,
      publicExponent: new Uint8Array([1, 0, 1]),
      hash: 'SHA-256',
    },
    true,
    ['sign', 'verify'],
  );

  const caCert = await buildCert({
    subject: 'TrueTake Verify-AUL FIXTURES Root CA (NOT FOR PRODUCTION)',
    issuer: 'TrueTake Verify-AUL FIXTURES Root CA (NOT FOR PRODUCTION)',
    ski: FIXTURES_CA_SKI,
    issuerSki: FIXTURES_CA_SKI,
    serial: 1,
    isCa: true,
    keyUsageBits: [true, false, false, false, false, true, true, false, false], // digitalSignature + keyCertSign + cRLSign
    extKeyUsage: null,
    publicKey: caKeys.publicKey,
    signingPrivateKey: caKeys.privateKey,
  });

  const tsaKeys = await webcrypto.subtle.generateKey(
    {
      name: 'RSASSA-PKCS1-v1_5',
      modulusLength: 2048,
      publicExponent: new Uint8Array([1, 0, 1]),
      hash: 'SHA-256',
    },
    true,
    ['sign', 'verify'],
  );

  const tsaCert = await buildCert({
    subject: 'TrueTake Verify-AUL FIXTURES TSA (NOT FOR PRODUCTION)',
    issuer: 'TrueTake Verify-AUL FIXTURES Root CA (NOT FOR PRODUCTION)',
    ski: FIXTURES_TSA_SKI,
    issuerSki: FIXTURES_CA_SKI,
    serial: 2,
    isCa: false,
    keyUsageBits: [true, false, false, false, false, false, false, false, false], // digitalSignature
    extKeyUsage: [ID_KP_TIMESTAMPING],
    publicKey: tsaKeys.publicKey,
    signingPrivateKey: caKeys.privateKey,
  });

  const caDer = new Uint8Array(caCert.toSchema(true).toBER(false));
  const caSkiSha256Hex = Buffer.from(sha256(FIXTURES_CA_SKI)).toString('hex');

  return {
    caCert,
    caCertPem: derToPem(caDer, 'CERTIFICATE'),
    caSkiSha256Hex,
    tsaCert,
    tsaPrivateKey: tsaKeys.privateKey,
  };
}

/**
 * Sign an RFC 3161 `TimeStampToken` over a Merkle root using the fixtures
 * TSA cert + key. Returns base64-encoded DER suitable for dropping into
 * a bundle's `anchors[].token` field.
 */
export async function signFixturesTimeStampToken(
  fixtures: FixturesCa,
  merkleRootHex: string,
): Promise<{ tokenBase64Der: string; genTime: Date }> {
  if (!/^[0-9a-f]{64}$/.test(merkleRootHex)) {
    throw new Error(`invalid merkleRootHex: ${merkleRootHex}`);
  }

  const merkleRootBytes = hexToBytes(merkleRootHex);
  const hashedMessage = sha256(merkleRootBytes);
  const genTime = new Date('2026-04-17T00:00:00.000Z'); // deterministic across runs

  // Build the TSTInfo.
  const tstInfo = new pkijs.TSTInfo({
    version: 1,
    policy: '1.3.6.1.4.1.99999.1', // private enterprise OID arc, clearly synthetic
    messageImprint: new pkijs.MessageImprint({
      hashAlgorithm: new pkijs.AlgorithmIdentifier({ algorithmId: SHA256_OID }),
      hashedMessage: new asn1js.OctetString({ valueHex: hashedMessage }),
    }),
    serialNumber: new asn1js.Integer({ value: 1 }),
    genTime,
    ordering: false,
  });
  const tstInfoDer = new Uint8Array(tstInfo.toSchema().toBER(false));

  // Wrap as CMS SignedData.
  const signedData = new pkijs.SignedData({
    version: 3,
    encapContentInfo: new pkijs.EncapsulatedContentInfo({
      eContentType: ID_CT_TSTINFO,
      eContent: new asn1js.OctetString({ valueHex: tstInfoDer }),
    }),
    signerInfos: [
      new pkijs.SignerInfo({
        version: 1,
        sid: new pkijs.IssuerAndSerialNumber({
          issuer: fixtures.tsaCert.issuer,
          serialNumber: fixtures.tsaCert.serialNumber,
        }),
      }),
    ],
    certificates: [fixtures.tsaCert, fixtures.caCert],
  });

  await signedData.sign(fixtures.tsaPrivateKey, 0, 'SHA-256', tstInfoDer);

  const contentInfo = new pkijs.ContentInfo({
    contentType: ID_SIGNED_DATA,
    content: signedData.toSchema(true),
  });
  const tokenDer = new Uint8Array(contentInfo.toSchema().toBER(false));

  return {
    tokenBase64Der: Buffer.from(tokenDer).toString('base64'),
    genTime,
  };
}

// ---------------------------------------------------------------------------
// Internal cert-building helper
// ---------------------------------------------------------------------------

interface BuildCertOptions {
  subject: string;
  issuer: string;
  ski: Uint8Array;
  issuerSki: Uint8Array;
  serial: number;
  isCa: boolean;
  keyUsageBits: boolean[];
  extKeyUsage: string[] | null;
  publicKey: CryptoKey;
  signingPrivateKey: CryptoKey;
}

async function buildCert(opts: BuildCertOptions): Promise<pkijs.Certificate> {
  const cert = new pkijs.Certificate();
  cert.version = 2; // v3
  cert.serialNumber = new asn1js.Integer({ value: opts.serial });
  cert.issuer.typesAndValues.push(
    new pkijs.AttributeTypeAndValue({
      type: '2.5.4.3',
      value: new asn1js.Utf8String({ value: opts.issuer }),
    }),
  );
  cert.subject.typesAndValues.push(
    new pkijs.AttributeTypeAndValue({
      type: '2.5.4.3',
      value: new asn1js.Utf8String({ value: opts.subject }),
    }),
  );
  cert.notBefore.value = new Date('2026-01-01T00:00:00.000Z');
  cert.notAfter.value = new Date('2036-01-01T00:00:00.000Z');

  await cert.subjectPublicKeyInfo.importKey(opts.publicKey);

  cert.extensions = [];

  // SubjectKeyIdentifier — extnValue wraps the DER of `SubjectKeyIdentifier ::= OCTET STRING`.
  cert.extensions.push(
    new pkijs.Extension({
      extnID: ID_SKI,
      critical: false,
      extnValue: new asn1js.OctetString({ valueHex: opts.ski }).toBER(false),
    }),
  );

  // AuthorityKeyIdentifier — extnValue wraps the DER of `AuthorityKeyIdentifier ::= SEQUENCE`
  // with a single `[0] IMPLICIT OCTET STRING` keyIdentifier.
  cert.extensions.push(
    new pkijs.Extension({
      extnID: ID_AKI,
      critical: false,
      extnValue: new asn1js.Sequence({
        value: [
          new asn1js.Primitive({
            idBlock: { tagClass: 3, tagNumber: 0 },
            valueHex: opts.issuerSki,
          }),
        ],
      }).toBER(false),
    }),
  );

  // BasicConstraints (cA if root/intermediate)
  cert.extensions.push(
    new pkijs.Extension({
      extnID: ID_BASIC_CONSTRAINTS,
      critical: true,
      extnValue: new pkijs.BasicConstraints({ cA: opts.isCa }).toSchema().toBER(false),
    }),
  );

  // KeyUsage
  cert.extensions.push(
    new pkijs.Extension({
      extnID: ID_KEY_USAGE,
      critical: true,
      extnValue: new asn1js.BitString({
        valueHex: boolsToByte(opts.keyUsageBits),
        unusedBits: 8 - opts.keyUsageBits.length,
      }).toBER(false),
    }),
  );

  // ExtendedKeyUsage (only on TSA signing cert)
  if (opts.extKeyUsage) {
    cert.extensions.push(
      new pkijs.Extension({
        extnID: ID_EXT_KEY_USAGE,
        critical: true,
        extnValue: new pkijs.ExtKeyUsage({
          keyPurposes: opts.extKeyUsage,
        })
          .toSchema()
          .toBER(false),
      }),
    );
  }

  await cert.sign(opts.signingPrivateKey, 'SHA-256');
  return cert;
}

function boolsToByte(bits: boolean[]): Uint8Array {
  let byte = 0;
  for (let i = 0; i < bits.length; i++) {
    if (bits[i]) {
      byte |= 1 << (7 - i);
    }
  }
  return Uint8Array.from([byte]);
}

function derToPem(der: Uint8Array, label: string): string {
  const b64 = Buffer.from(der).toString('base64');
  const lines: string[] = [];
  for (let i = 0; i < b64.length; i += 64) {
    lines.push(b64.slice(i, i + 64));
  }
  return `-----BEGIN ${label}-----\n${lines.join('\n')}\n-----END ${label}-----\n`;
}
