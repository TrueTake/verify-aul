/**
 * Verdict + per-check report rendering.
 *
 * Mirrors the result shape returned by `verifyBundle`. aria-live on the
 * verdict means screen readers announce the outcome on status change.
 */

import type { VerificationResult } from '../src/index.js';

const VERDICT_LABEL: Record<VerificationResult['verdict'], string> = {
  pass: 'PASS — bundle fully verified',
  partial: 'PARTIAL — not fully verified',
  fail: 'FAIL — verification error',
};

export function renderReport(result: VerificationResult): void {
  const section = document.getElementById('report-section');
  const verdictEl = document.getElementById('verdict');
  const checksEl = document.getElementById('checks');
  const rpcEl = document.getElementById('rpc-used');

  if (!section || !verdictEl || !checksEl || !rpcEl) return;

  section.hidden = false;

  verdictEl.dataset['verdict'] = result.verdict;
  verdictEl.textContent = VERDICT_LABEL[result.verdict] ?? result.verdict;

  checksEl.innerHTML = '';
  for (const check of result.checks) {
    const li = document.createElement('li');

    const status = document.createElement('span');
    status.className = 'status';
    status.dataset['status'] = check.status;
    status.textContent = check.status;
    li.appendChild(status);

    const wrap = document.createElement('div');

    const name = document.createElement('span');
    name.className = 'check-name';
    name.textContent = check.check;
    wrap.appendChild(name);

    if (check.details) {
      const details = document.createElement('span');
      details.className = 'check-details';
      details.textContent = check.details;
      wrap.appendChild(details);
    }

    li.appendChild(wrap);
    checksEl.appendChild(li);
  }

  rpcEl.textContent = result.rpc_endpoint_used
    ? `Solana RPC: ${result.rpc_endpoint_used}`
    : '';
}

export function renderError(message: string): void {
  const section = document.getElementById('report-section');
  const verdictEl = document.getElementById('verdict');
  const checksEl = document.getElementById('checks');
  const rpcEl = document.getElementById('rpc-used');

  if (!section || !verdictEl || !checksEl || !rpcEl) return;

  section.hidden = false;
  verdictEl.dataset['verdict'] = 'fail';
  verdictEl.textContent = `ERROR — ${message}`;
  checksEl.innerHTML = '';
  rpcEl.textContent = '';
}
