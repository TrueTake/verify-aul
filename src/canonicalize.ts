/**
 * Re-export of the `canonicalize` package (RFC 8785 JCS).
 *
 * Previously this module used a lazy dynamic import because the platform ran
 * a mix of ESM + CJS transpilation contexts. In the OSS package, which is
 * ESM-only (Node >=20, "type": "module"), a static ESM import is correct and
 * avoids top-level-await (which would break require(esm) interop).
 */

export { default as canonicalize } from 'canonicalize';
