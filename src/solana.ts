/**
 * Solana memo verification via raw JSON-RPC fetch.
 *
 * Does NOT import @solana/web3.js — that package pulls large node-only
 * paths which bloat the browser bundle and break tree-shaking.
 *
 * Mirrors the memo-content check from:
 *   server/services/ledger/anchor/solana-provider.ts#verifyFinality
 *
 * The memo program logs: "Program log: Memo (len N): "<root>""
 * We scan logMessages for any entry that includes the expected merkle root.
 */

const DEFAULT_MAINNET_RPC = 'https://api.mainnet-beta.solana.com';

const DEFAULT_RPC_BY_CLUSTER: Record<string, string> = {
  'mainnet-beta': DEFAULT_MAINNET_RPC,
  devnet: 'https://api.devnet.solana.com',
  testnet: 'https://api.testnet.solana.com',
};

/** Resolve the RPC URL for a given cluster, honoring explicit overrides. */
export function resolveSolanaRpcUrl(cluster: string, override?: string): string {
  return override ?? DEFAULT_RPC_BY_CLUSTER[cluster] ?? DEFAULT_MAINNET_RPC;
}

export interface SolanaVerifyResult {
  verified: boolean;
  slot?: number;
  blockTime?: number;
  rpcUrlUsed: string;
}

/**
 * Verify that a Solana transaction's memo log contains the expected Merkle root.
 *
 * @param signature - Base58-encoded transaction signature
 * @param cluster - Cluster identifier from the bundle's anchor entry; determines the
 *   default RPC URL (`mainnet-beta`, `devnet`, or `testnet`). Explicit overrides via
 *   `rpcUrlOverride` always win.
 * @param expectedMerkleRoot - 64-char hex Merkle root to find in memo logs
 * @param rpcUrlOverride - Optional RPC URL override
 */
export async function verifySolanaMemo(
  signature: string,
  cluster: string,
  expectedMerkleRoot: string,
  rpcUrlOverride?: string,
): Promise<SolanaVerifyResult> {
  const rpcUrl = resolveSolanaRpcUrl(cluster, rpcUrlOverride);

  const body = {
    jsonrpc: '2.0',
    id: 1,
    method: 'getTransaction',
    params: [
      signature,
      {
        encoding: 'json',
        maxSupportedTransactionVersion: 0,
        commitment: 'finalized',
      },
    ],
  };

  const response = await fetch(rpcUrl, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  });

  if (!response.ok) {
    throw new Error(
      `[Solana verify] HTTP ${response.status} from RPC ${rpcUrl}: ${response.statusText}`,
    );
  }

  const json = (await response.json()) as SolanaRpcResponse;

  if (json.error) {
    throw new Error(`[Solana verify] RPC error ${json.error.code}: ${json.error.message}`);
  }

  const tx = json.result;

  if (!tx) {
    return { verified: false, rpcUrlUsed: rpcUrl };
  }

  const logMessages: string[] = tx.meta?.logMessages ?? [];
  const memoFound = logMessages.some((log) => log.includes(expectedMerkleRoot));

  if (!memoFound) {
    return { verified: false, rpcUrlUsed: rpcUrl };
  }

  return {
    verified: true,
    slot: tx.slot,
    blockTime: tx.blockTime ?? undefined,
    rpcUrlUsed: rpcUrl,
  };
}

// ---------------------------------------------------------------------------
// JSON-RPC response types (minimal — only what we need)
// ---------------------------------------------------------------------------

interface SolanaRpcResponse {
  jsonrpc: '2.0';
  id: number;
  result: SolanaTransaction | null;
  error?: { code: number; message: string };
}

interface SolanaTransaction {
  slot: number;
  blockTime: number | null;
  meta?: {
    logMessages?: string[];
  };
}
