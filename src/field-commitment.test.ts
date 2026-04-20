/**
 * Unit tests for field-commitment primitives.
 *
 * Byte-level parity against the platform implementation is enforced in
 * `src/platform-parity.test.ts`. These tests cover the canonicalizer,
 * leaf-hash shape, and proof-walk mechanics in isolation.
 */

import { describe, expect, it } from 'vitest';
import { sha256 } from '@noble/hashes/sha2.js';
import { bytesToHex } from '@noble/hashes/utils.js';
import canonicalize from 'canonicalize';

import {
  DISCLOSABLE_FIELDS,
  ENCODING_VERSION,
  canonicalizeFieldValue,
  computeLeafHash,
  verifyFieldProof,
} from './field-commitment.js';

describe('DISCLOSABLE_FIELDS', () => {
  it('contains exactly approver.email in v1', () => {
    expect(DISCLOSABLE_FIELDS).toEqual(['approver.email']);
  });

  it('encoding version is v1', () => {
    expect(ENCODING_VERSION).toBe('v1');
  });
});

describe('canonicalizeFieldValue', () => {
  it('normalizes approver.email: NFC + trim + lowercase', () => {
    expect(canonicalizeFieldValue('approver.email', '  Maya@Example.COM  ')).toBe(
      'maya@example.com',
    );
  });

  it('NFC-composes decomposed Unicode (café NFD → NFC)', () => {
    const decomposed = 'cafe\u0301@example.com';
    const precomposed = 'caf\u00e9@example.com';
    expect(canonicalizeFieldValue('approver.email', decomposed)).toBe(
      canonicalizeFieldValue('approver.email', precomposed),
    );
  });

  it('throws with E_UNKNOWN_FIELD_PATH on unknown field name, no value leakage', () => {
    const SECRET = 'SECRET_CANDIDATE_VALUE';
    try {
      canonicalizeFieldValue('deal.amount', SECRET);
      expect.unreachable('expected throw');
    } catch (err) {
      expect((err as Error).message).toMatch(/unknown field_name for encoding v1: deal\.amount/);
      expect((err as Error).message).not.toContain(SECRET);
      expect((err as Error & { code?: string }).code).toBe('E_UNKNOWN_FIELD_PATH');
    }
  });

  it('throws with E_UNKNOWN_ENCODING_VERSION on unknown version, no value leakage', () => {
    const SECRET = 'SECRET_CANDIDATE_VALUE';
    try {
      canonicalizeFieldValue('approver.email', SECRET, 'v99');
      expect.unreachable('expected throw');
    } catch (err) {
      expect((err as Error).message).toMatch(/unknown encoding_version: v99/);
      expect((err as Error).message).not.toContain(SECRET);
      expect((err as Error & { code?: string }).code).toBe('E_UNKNOWN_ENCODING_VERSION');
    }
  });
});

describe('computeLeafHash', () => {
  it('matches the JCS-wrapped recipe for a known input', () => {
    // Recompute expected hash by hand to prove the module's recipe matches
    // spec §10.5: SHA-256(0x00 || salt || utf8(jcs({encoding_version, field_name, value}))).
    const salt = new Uint8Array(16).fill(0x2a);
    const canonical = 'alice@example.com';
    const leafInput = canonicalize({
      encoding_version: 'v1',
      field_name: 'approver.email',
      value: canonical,
    });
    if (leafInput === undefined) throw new Error('unreachable');
    const h = sha256.create();
    h.update(new Uint8Array([0x00]));
    h.update(salt);
    h.update(new TextEncoder().encode(leafInput));
    const expected = bytesToHex(h.digest());

    expect(computeLeafHash('approver.email', 'alice@example.com', salt)).toBe(expected);
  });

  it('canonicalizes candidate before hashing (mixed case + whitespace input)', () => {
    const salt = new Uint8Array(16).fill(0x11);
    const canonicalForm = computeLeafHash('approver.email', 'alice@example.com', salt);
    const messyForm = computeLeafHash('approver.email', '  Alice@Example.COM  ', salt);
    expect(canonicalForm).toBe(messyForm);
  });

  it('rejects non-16-byte salt', () => {
    expect(() =>
      computeLeafHash('approver.email', 'alice@example.com', new Uint8Array(15)),
    ).toThrow(/salt must be 16 bytes/);
    expect(() =>
      computeLeafHash('approver.email', 'alice@example.com', new Uint8Array(17)),
    ).toThrow(/salt must be 16 bytes/);
  });

  it('propagates E_UNKNOWN_FIELD_PATH from canonicalizer', () => {
    expect(() =>
      computeLeafHash('deal.amount', 'value', new Uint8Array(16)),
    ).toThrow(/unknown field_name for encoding v1: deal\.amount/);
  });
});

describe('verifyFieldProof', () => {
  it('verifies single-leaf tree (empty siblings, root === leaf)', () => {
    const leaf = 'a'.repeat(64);
    expect(verifyFieldProof(leaf, [], leaf)).toBe(true);
  });

  it('returns false on single-leaf tree when root does not match leaf', () => {
    expect(verifyFieldProof('a'.repeat(64), [], 'b'.repeat(64))).toBe(false);
  });

  it('verifies two-leaf tree — walk right sibling', () => {
    // Build a two-leaf tree by hand:
    //  L0 L1 → root = SHA256(0x01 || L0 || L1)
    // Proof for leaf index 0: sibling {hash: L1, direction: 'right'}
    const L0 = 'a'.repeat(64);
    const L1 = 'b'.repeat(64);
    const hexToBytes = (hex: string): Uint8Array =>
      new Uint8Array(hex.match(/.{2}/g)!.map((b) => parseInt(b, 16)));
    const h = sha256.create();
    h.update(new Uint8Array([0x01]));
    h.update(hexToBytes(L0));
    h.update(hexToBytes(L1));
    const root = bytesToHex(h.digest());

    expect(verifyFieldProof(L0, [{ hash: L1, direction: 'right' }], root)).toBe(true);
  });

  it('verifies two-leaf tree — walk left sibling', () => {
    const L0 = 'a'.repeat(64);
    const L1 = 'b'.repeat(64);
    const hexToBytes = (hex: string): Uint8Array =>
      new Uint8Array(hex.match(/.{2}/g)!.map((b) => parseInt(b, 16)));
    const h = sha256.create();
    h.update(new Uint8Array([0x01]));
    h.update(hexToBytes(L0));
    h.update(hexToBytes(L1));
    const root = bytesToHex(h.digest());

    // Proof for leaf index 1: sibling {hash: L0, direction: 'left'}
    expect(verifyFieldProof(L1, [{ hash: L0, direction: 'left' }], root)).toBe(true);
  });

  it('returns false on tampered sibling hash', () => {
    const L0 = 'a'.repeat(64);
    const L1 = 'b'.repeat(64);
    const tampered = 'c'.repeat(64);
    const hexToBytes = (hex: string): Uint8Array =>
      new Uint8Array(hex.match(/.{2}/g)!.map((b) => parseInt(b, 16)));
    const h = sha256.create();
    h.update(new Uint8Array([0x01]));
    h.update(hexToBytes(L0));
    h.update(hexToBytes(L1));
    const root = bytesToHex(h.digest());

    expect(verifyFieldProof(L0, [{ hash: tampered, direction: 'right' }], root)).toBe(false);
  });

  it('returns false on tampered root', () => {
    const L0 = 'a'.repeat(64);
    const L1 = 'b'.repeat(64);
    const tamperedRoot = 'f'.repeat(64);

    expect(verifyFieldProof(L0, [{ hash: L1, direction: 'right' }], tamperedRoot)).toBe(false);
  });

  it('returns false when direction is wrong', () => {
    const L0 = 'a'.repeat(64);
    const L1 = 'b'.repeat(64);
    const hexToBytes = (hex: string): Uint8Array =>
      new Uint8Array(hex.match(/.{2}/g)!.map((b) => parseInt(b, 16)));
    const h = sha256.create();
    h.update(new Uint8Array([0x01]));
    h.update(hexToBytes(L0));
    h.update(hexToBytes(L1));
    const root = bytesToHex(h.digest());

    // L0 is left child in the real tree; flipping the direction breaks the walk.
    expect(verifyFieldProof(L0, [{ hash: L1, direction: 'left' }], root)).toBe(false);
  });
});
