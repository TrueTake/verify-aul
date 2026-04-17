# `partial-missing-anchor.json`

**Expected verdict:** `partial`

**Exercises:** the §5 row "All checks pass AND non-empty `partial_anchors_reason`". The bundle carries a valid DigiCert TimeStampToken; FreeTSA is declared in `partial_anchors_reason` (terminal-failed at issuance, not present in the bundle). The verifier passes all present checks and downgrades the verdict from `pass` to `partial`.

**Generation:** `npm run fixtures:generate` contacts DigiCert once. FreeTSA is intentionally not contacted.
