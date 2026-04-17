/**
 * Fixture generator — regenerates the fixtures CA, signs TimeStampTokens
 * under it, and writes `spec/test-vectors/{tier1-pass,tier2-pass, ...}.json`
 * so the crypto-bearing vectors stay in sync with the verifier.
 *
 * **Status (v1.0-rc.1):** stub. This file exists to establish the location
 * and responsibility contract; real generation is Unit 4b.
 *
 * Planned behavior (see TRU-625 plan Unit 4):
 *   1. Generate a self-signed test root CA (P-256 or RSA-2048) using pkijs.
 *   2. Generate a TSA signing cert signed by the test root.
 *   3. For each crypto-bearing vector (tier1-pass, tier2-pass, partial-missing-anchor, fail-bad-anchor):
 *      a. Build a TSTInfo ASN.1 structure with messageImprint = SHA-256(merkle_root_bytes).
 *      b. Wrap in CMS SignedData signed by the TSA cert.
 *      c. Base64-encode DER and assemble into a bundle JSON.
 *   4. Write out `spec/fixtures-trust-anchors/root.pem` and update
 *      `spec/fixtures-trust-anchors/fingerprints.ts` with SHA-256(SKI).
 *   5. Run `verifyBundleForTesting` over each generated vector with the
 *      fixtures fingerprint map; fail if any verdict diverges from the
 *      documented expected verdict in the sibling `.md`.
 *
 * Solana anchors in crypto-bearing vectors use real or crafted transaction
 * signatures; the RPC response is mocked by the test harness, not the generator.
 */

export async function main(): Promise<void> {
  // eslint-disable-next-line no-console
  console.error(
    '[generate-fixtures] Unit 4b not yet implemented. ' +
      'Tracking blocker for v1.0 stable; see spec/README.md for status.',
  );
  process.exit(1);
}

// Run when invoked directly.
// eslint-disable-next-line @typescript-eslint/no-floating-promises
main();
