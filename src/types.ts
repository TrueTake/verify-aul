/**
 * Types for the AUL verification bundle and result.
 *
 * These types are the contract between the server (which emits bundles) and
 * the verifier (which consumes them). They are isomorphic — safe to import
 * in Node scripts, server code, and browser client components.
 */

// ---------------------------------------------------------------------------
// Bundle input types
// ---------------------------------------------------------------------------

/** Sibling node in a Merkle inclusion proof. */
export interface MerkleSibling {
  hash: string; // 64-char lowercase hex
  direction: 'left' | 'right';
}

/**
 * Field-disclosure payload shape (spec §10.2).
 *
 * The normative shape is defined in `spec/schema/disclosure.v1.json` and §10.2
 * of `spec/v1.md`. This TypeScript interface is illustrative — it matches the
 * schema's required fields but does not substitute for schema validation at
 * I/O boundaries.
 */
export interface Disclosure {
  field_path: string;
  field_value: string;
  /** 16-byte salt, unpadded base64url (22 chars). */
  salt: string;
  merkle_path: MerkleSibling[];
  /** 64-char lowercase hex. MUST equal `bundle.event.metadata.event_root` (§10.7). */
  root: string;
  /** 64-char lowercase hex. MUST equal `bundle.event_hash` (§10.7). */
  event_hash: string;
}

/** RFC 6962 Merkle inclusion proof. */
export interface MerkleProof {
  leaf_index: number;
  siblings: MerkleSibling[];
  root: string; // 64-char lowercase hex
}

/** Signing key embedded in a Tier 2 bundle. */
export interface BundleSigningKey {
  fingerprint: string; // 16-char base64url fingerprint
  public_key_base64url: string; // raw 32-byte Ed25519 public key, base64url encoded
  status: 'active' | 'retired';
}

/** Solana anchor record. */
export interface SolanaAnchor {
  type: 'solana';
  signature: string; // base58-encoded transaction signature
  cluster: string; // e.g. 'mainnet-beta'
}

/** TSA anchor record (FreeTSA or DigiCert). */
export interface TsaAnchor {
  type: 'tsa_freetsa' | 'tsa_digicert';
  token: string; // base64-encoded DER TimeStampToken
  external_timestamp: string; // ISO 8601
}

export type Anchor = SolanaAnchor | TsaAnchor;

/**
 * Verification bundle shape.
 *
 * Tier 1 (no auth): omits `event`, `server_signature`, `signing_key_id`,
 * `signing_keys`. These fields are present only in Tier 2 bundles.
 *
 * Pending bundles (status === 'pending') omit `merkle_proof` and `anchors`.
 */
export interface VerificationBundle {
  bundle_schema_version: number;
  status: 'confirmed' | 'pending' | 'partial';

  event_hash: string; // 64-char lowercase hex

  // Tier 2 only (present when authorized deal-party or admin fetches):
  event?: Record<string, unknown>; // HashInputV2 JSON object
  server_signature?: string; // 128-char hex Ed25519 signature
  signing_key_id?: string; // 16-char base64url fingerprint
  signing_keys?: BundleSigningKey[];

  // Present on confirmed/partial bundles:
  merkle_proof?: MerkleProof;
  anchors?: Anchor[];

  /**
   * Lists anchor provider names that terminal-failed after retries.
   * Present (possibly empty []) on confirmed/partial bundles.
   * Empty → fully confirmed. Non-empty → partial.
   */
  partial_anchors_reason?: string[];
}

// ---------------------------------------------------------------------------
// Verification result types
// ---------------------------------------------------------------------------

export type CheckStatus = 'pass' | 'fail' | 'skip';

export interface Check {
  check: string;
  status: CheckStatus;
  details?: string;
}

export type Verdict = 'pass' | 'fail' | 'partial';

export interface VerificationResult {
  verdict: Verdict;
  checks: Check[];
  /** Solana RPC URL actually used during verification (always set, even if Solana not in bundle). */
  rpc_endpoint_used: string;
}

// ---------------------------------------------------------------------------
// Verifier options
// ---------------------------------------------------------------------------

export interface VerifyOptions {
  /**
   * Additional trust anchors (DER-encoded X.509 certificates as Uint8Arrays).
   * These are additive — they extend the bundled anchors, and they skip the
   * SubjectKeyIdentifier pin check (user supplies them explicitly).
   */
  trustAnchors?: Uint8Array[];

  /**
   * Override the Solana RPC endpoint.
   * Defaults to https://api.mainnet-beta.solana.com
   */
  solanaRpcUrl?: string;
}
