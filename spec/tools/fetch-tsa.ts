/**
 * Fetch a real RFC 3161 TimeStampToken from a public TSA for a given merkle root.
 *
 * Used by `spec/generate-fixtures.ts` to build pass / partial test vectors
 * whose TSA anchors are real — signed by the production CAs already pinned
 * in `src/trust-anchors/`. That means the same verifier code path end users
 * run will validate these vectors without any fixtures CA or override.
 *
 * Network is required. Regenerate the vectors when token content needs to
 * change; otherwise they stay stable.
 */

import * as asn1js from 'asn1js';
import * as pkijs from 'pkijs';
import { sha256 } from '@noble/hashes/sha2.js';
import { hexToBytes } from '@noble/hashes/utils.js';

const SHA256_OID = '2.16.840.1.101.3.4.2.1';

export interface TsaFetchTarget {
  /** Label that becomes the anchor `type` (`tsa_freetsa` or `tsa_digicert`). */
  name: 'freetsa' | 'digicert';
  /** HTTP endpoint that accepts `application/timestamp-query`. */
  url: string;
}

export const FREETSA: TsaFetchTarget = { name: 'freetsa', url: 'https://freetsa.org/tsr' };
export const DIGICERT: TsaFetchTarget = { name: 'digicert', url: 'http://timestamp.digicert.com' };

export interface FetchedTsaToken {
  /** Base64-encoded DER of the RFC 3161 `TimeStampToken` (a `ContentInfo` wrapping `SignedData`). */
  tokenBase64Der: string;
  /** `genTime` from the parsed `TSTInfo`, ISO-8601. */
  externalTimestamp: string;
}

/**
 * Build an RFC 3161 `TimeStampReq`, POST it to the TSA, parse the
 * `TimeStampResp`, and extract the embedded `TimeStampToken` as
 * base64-encoded DER.
 */
export async function fetchTsaToken(
  target: TsaFetchTarget,
  merkleRootHex: string,
): Promise<FetchedTsaToken> {
  if (!/^[0-9a-f]{64}$/.test(merkleRootHex)) {
    throw new Error(`invalid merkleRootHex: ${merkleRootHex}`);
  }

  // The TSA will hash our pre-hashed imprint again and sign the resulting
  // digest; the verifier expects `messageImprint.hashedMessage` to equal
  // SHA-256(hex_decode(merkleRoot)). See `src/tsa.ts` for the check.
  const merkleRootBytes = hexToBytes(merkleRootHex);
  const hashedMessage = sha256(merkleRootBytes);

  const tsReq = new pkijs.TimeStampReq({
    version: 1,
    messageImprint: new pkijs.MessageImprint({
      hashAlgorithm: new pkijs.AlgorithmIdentifier({ algorithmId: SHA256_OID }),
      hashedMessage: new asn1js.OctetString({ valueHex: hashedMessage }),
    }),
    certReq: true,
  });
  const reqDer = new Uint8Array(tsReq.toSchema().toBER(false));

  const resp = await fetch(target.url, {
    method: 'POST',
    headers: { 'Content-Type': 'application/timestamp-query' },
    body: reqDer,
  });
  if (!resp.ok) {
    throw new Error(`[${target.name}] HTTP ${resp.status} ${resp.statusText}`);
  }
  const respBytes = new Uint8Array(await resp.arrayBuffer());

  const asn1 = asn1js.fromBER(respBytes.buffer.slice(0, respBytes.byteLength));
  if (asn1.offset === -1) {
    throw new Error(`[${target.name}] could not parse TimeStampResp ASN.1`);
  }
  const tsResp = new pkijs.TimeStampResp({ schema: asn1.result });
  const status = tsResp.status.status;
  if (status !== 0 && status !== 1) {
    // 0 = granted, 1 = grantedWithMods, anything else is a rejection
    const info =
      tsResp.status.statusStrings?.map((s: asn1js.Utf8String) => s.valueBlock.value).join('; ') ??
      '';
    throw new Error(`[${target.name}] TSA rejected request: status=${status} ${info}`);
  }
  if (!tsResp.timeStampToken) {
    throw new Error(`[${target.name}] TimeStampResp has no TimeStampToken`);
  }

  const tokenDer = new Uint8Array(tsResp.timeStampToken.toSchema().toBER(false));

  // Extract genTime from TSTInfo so the vector's `external_timestamp` is real.
  const signedData = new pkijs.SignedData({ schema: tsResp.timeStampToken.content });
  const eContent = signedData.encapContentInfo.eContent;
  if (!eContent) {
    throw new Error(`[${target.name}] TimeStampToken has no encapsulated content`);
  }
  const tstInfoBytes = eContent.valueBlock.valueHexView;
  const ab = new ArrayBuffer(tstInfoBytes.byteLength);
  new Uint8Array(ab).set(tstInfoBytes);
  const tstInfo = pkijs.TSTInfo.fromBER(ab);
  const externalTimestamp = tstInfo.genTime.toISOString();

  return {
    tokenBase64Der: Buffer.from(tokenDer).toString('base64'),
    externalTimestamp,
  };
}
