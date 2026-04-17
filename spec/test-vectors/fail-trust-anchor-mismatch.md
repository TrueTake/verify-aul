# `fail-trust-anchor-mismatch.json`

**Status:** **PLACEHOLDER** — Unit 4b supplies the real alternate-CA-signed token.

**Expected verdict (once generated):** `fail`

**Exercises:** the trust-anchor-pinning defense. This vector's TSA token is signed by a fixtures CA whose SKI SHA-256 is **not** in `TRUST_ANCHOR_FINGERPRINTS_FIXTURES` when the verifier is invoked via `verifyBundleForTesting({ trustAnchorFingerprints: FIXTURES_FINGERPRINTS })`. The pin check fires at trust-anchor load time, verification short-circuits, and the verdict is `fail`.

**Blocker:** requires two distinct fixtures CAs (one in the pin set, one used to sign this vector). Tracked in Unit 4b.
