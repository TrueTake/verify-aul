# `field-commitment-nfc` — NFC normalizer invariant

**Expected verdict (primitives):** `pass`.

**Scope:** Pins the Unicode Normalization Form C (NFC) invariant
declared in spec §10.4. The committed `field_value` is in NFC form; a
candidate in NFD form that composes to the same codepoints under NFC
MUST verify against this disclosure.

## Candidates that should verify against this disclosure

| Form | Bytes (UTF-8, hex)                                       | Notes                    |
|------|----------------------------------------------------------|--------------------------|
| NFC  | `63 61 66 c3 a9 40 65 78 61 6d 70 6c 65 2e 63 6f 6d`     | Precomposed `é` (U+00E9) |
| NFD  | `63 61 66 65 cc 81 40 65 78 61 6d 70 6c 65 2e 63 6f 6d`  | Decomposed `e` + U+0301 `◌́` |

Both strings, when canonicalized under the §10.4 rule (NFC → trim →
lowercase), produce identical bytes and therefore identical leaf hashes.

The NFC form is the committed `field_value`. The NFD form (`caf` + `e` +
combining acute `U+0301` + `@example.com`) is the candidate
documentation in this `.md`; a verifier handed the NFD candidate MUST
produce verdict `pass`.

## Tree shape

Single-leaf tree. `merkle_path: []`, `root === leaf_hash`.

## Regeneration

Run `npm run fixtures:generate:offline`. CI gates byte-equality via
`git diff --exit-code`.
