/**
 * Ed25519 signature verification.
 *
 * Uses @noble/ed25519 — pure JS, isomorphic, works in Node and all evergreen
 * browsers. Consumes raw 32-byte public keys (base64url encoded), matching the
 * format published by /.well-known/ledger-public-key.json and embedded in
 * Tier 2 verification bundles.
 *
 * Why not SubtleCrypto?  WebCrypto Ed25519 is not baseline available
 * (Chrome unflagged 2024, Firefox ESR behind flag, Safari partial), and SPKI
 * vs. raw key import semantics differ from Node's crypto, creating
 * silent-divergence risk. @noble/ed25519 avoids all of that.
 *
 * The async API (`verifyAsync`) is used because it delegates to WebCrypto
 * (globalThis.crypto.subtle) in both Node 18+ and browsers, which avoids the
 * need to manually set the sha512Sync shim required by the sync API.
 */

import { verifyAsync } from '@noble/ed25519';
import { hexToBytes } from '@noble/hashes/utils.js';

/**
 * Verify an Ed25519 signature.
 *
 * @param signatureHex - 128-char hex string (64-byte raw signature)
 * @param messageBytes - The bytes that were signed (typically event hash bytes)
 * @param publicKeyBase64Url - Raw 32-byte Ed25519 public key, base64url encoded
 * @returns Promise<true> if valid; throws or returns false on any failure
 */
export async function verifyEd25519Signature(
  signatureHex: string,
  messageBytes: Uint8Array,
  publicKeyBase64Url: string,
): Promise<boolean> {
  // Decode public key from base64url (standard base64url without padding)
  const publicKeyBytes = base64urlToBytes(publicKeyBase64Url);

  // Decode signature from hex
  const signatureBytes = hexToBytes(signatureHex);

  return verifyAsync(signatureBytes, messageBytes, publicKeyBytes);
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function base64urlToBytes(b64url: string): Uint8Array {
  // base64url → base64 (add padding, replace - and _)
  const base64 = b64url.replace(/-/g, '+').replace(/_/g, '/');
  const padded = base64.padEnd(base64.length + ((4 - (base64.length % 4)) % 4), '=');

  if (typeof atob !== 'undefined') {
    // Browser
    const binary = atob(padded);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) {
      bytes[i] = binary.charCodeAt(i);
    }
    return bytes;
  } else {
    // Node.js
    return new Uint8Array(Buffer.from(padded, 'base64'));
  }
}
