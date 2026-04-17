import { describe, expect, it } from 'vitest';
import { extractInlineConstant, normalizePem } from './check-trust-anchor-fingerprints.js';

describe('normalizePem', () => {
  it('extracts the PEM block and strips surrounding whitespace', () => {
    const pem = `
      Some header

      -----BEGIN CERTIFICATE-----
      MIIBxTCCASygAwI
      -----END CERTIFICATE-----

      Some footer
    `;
    expect(normalizePem(pem)).toContain('-----BEGIN CERTIFICATE-----');
    expect(normalizePem(pem)).toContain('-----END CERTIFICATE-----');
    expect(normalizePem(pem).startsWith('-----BEGIN')).toBe(true);
    expect(normalizePem(pem).endsWith('-----END CERTIFICATE-----')).toBe(true);
  });

  it('converts CRLF to LF so byte-exact compare catches line-ending drift', () => {
    const crlf = '-----BEGIN CERTIFICATE-----\r\nABC\r\n-----END CERTIFICATE-----';
    const lf = normalizePem(crlf);
    expect(lf.includes('\r')).toBe(false);
    expect(lf.split('\n').length).toBe(3);
  });

  it('throws when no PEM block is present', () => {
    expect(() => normalizePem('no pem here')).toThrow(/No PEM block/);
  });
});

describe('extractInlineConstant', () => {
  it('returns the template literal body for a single-line constant', () => {
    const source = "const FOO = `hello`;";
    expect(extractInlineConstant(source, 'FOO')).toBe('hello');
  });

  it('returns the template literal body across multiple lines', () => {
    const source = "const PEM = `-----BEGIN CERT-----\nAAA\nBBB\n-----END CERT-----`;";
    expect(extractInlineConstant(source, 'PEM')).toContain('\nAAA\nBBB\n');
  });

  it('throws if the constant is not found', () => {
    expect(() => extractInlineConstant('const OTHER = "x";', 'MISSING')).toThrow(/MISSING/);
  });
});
