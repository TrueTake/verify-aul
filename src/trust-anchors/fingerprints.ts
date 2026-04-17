/**
 * Pinned SubjectKeyIdentifier (SKI) fingerprints for bundled trust anchor PEM files.
 *
 * At module load time, `core.ts` parses each bundled PEM, extracts its SKI,
 * computes SHA-256(SKI bytes), and compares against this map. A mismatch aborts
 * verification with a loud error — defense against silent supply-chain substitution.
 *
 * To update: fetch the new cert, run:
 *   openssl x509 -in cert.pem -text -noout | grep -A1 "Subject Key Identifier"
 * then compute SHA-256 of the raw SKI bytes (colon-separated hex → binary → SHA-256).
 *
 * Keys match the filename under src/trust-anchors/ (without path).
 */
export const TRUST_ANCHOR_FINGERPRINTS: Record<string, string> = {
  // FreeTSA Root CA — SKI: FA:55:0D:8C:34:66:51:43:4C:F7:E7:B3:A7:6C:95:AF:7A:E6:A4:97
  'freetsa.pem': '3b49a197a9f98d5ee1124d19bf591e5677a799b230758c1d195db9983537aaf0',

  // DigiCert SHA2 Assured ID Timestamping CA — SKI: F4:B6:E1:20:1D:FE:29:AE:D2:E4:61:A5:B2:A2:25:B2:C8:17:35:6E
  'digicert.pem': '39c96b1c3a8859f48176ece42139d97fc4eaf731c29214c24994f92167ad06e0',
};
