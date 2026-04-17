# `partial-missing-anchor.json`

**Status:** **PLACEHOLDER** — shape-only. Unit 4b supplies real crypto.

**Expected verdict (once generated):** `partial`

**Exercises:** the §5 row "All checks pass AND non-empty `partial_anchors_reason`". Both DigiCert (present + verifying) and FreeTSA (terminal-failed at issuance, captured in `partial_anchors_reason`) are represented; the verifier passes all present checks and downgrades the verdict from `pass` to `partial` because the bundle declares incomplete anchoring.

**Blocker:** the single DigiCert TSA token must actually verify. Tracked in Unit 4b.
