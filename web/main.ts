/**
 * Entry point for the static verifier UI.
 *
 * During development this imports from `../src` (relative source) so the
 * browser gets a direct view of the verifier. At build time (esbuild), it's
 * still bundled into a single `main.js`. When running via `npm install
 * @truetake/verify-aul`, consumers can swap this import to the npm specifier;
 * the hosted page in this repo always builds against `../src`.
 */

import { verifyBundle, type VerificationBundle } from '../src/index.js';

import { wireBundleInput } from './bundle-input.js';
import { renderError, renderReport } from './verification-report.js';

function getOverrideRpcUrl(): string | undefined {
  const input = document.getElementById('solana-rpc') as HTMLInputElement | null;
  const value = input?.value.trim();
  if (!value) return undefined;
  // Reject non-https URLs — the static CSP's connect-src tolerates https:,
  // but we don't want http: / javascript: / data: slipping through to
  // the verifier where they'd trigger network errors or worse.
  try {
    const url = new URL(value);
    if (url.protocol !== 'https:') {
      throw new Error('URL must use https://');
    }
    return url.toString();
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    renderError(`Invalid Solana RPC URL: ${msg}`);
    return undefined;
  }
}

async function onBundle(bundle: VerificationBundle): Promise<void> {
  try {
    const solanaRpcUrl = getOverrideRpcUrl();
    const result = await verifyBundle(bundle, solanaRpcUrl ? { solanaRpcUrl } : undefined);
    renderReport(result);
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    // Errors here are typically thrown by initTrustAnchors() on pin mismatch,
    // or by malformed crypto blobs. Surface to the user in the report pane;
    // no remote telemetry.
    // eslint-disable-next-line no-console
    console.error('[verify-aul] verification threw:', err);
    renderError(msg);
  }
}

function init(): void {
  wireBundleInput({
    onBundle: (bundle) => {
      void onBundle(bundle);
    },
    onError: (message) => {
      renderError(message);
    },
  });
}

if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', init);
} else {
  init();
}
