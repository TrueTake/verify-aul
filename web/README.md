# `web/` — static verifier UI

The page hosted at [truetake.github.io/verify-aul/](https://truetake.github.io/verify-aul/). Vanilla HTML + TypeScript + esbuild. No framework, no runtime dependencies beyond `@truetake/verify-aul` (which is built from `../src/` at deploy time).

## Files

| File | Purpose |
|---|---|
| `index.html` | Single-page shell with drop zone, advanced panel, report region. |
| `style.css` | Minimal CSS with light / dark via `prefers-color-scheme`. |
| `main.ts` | Entry. Wires the drop zone, calls `verifyBundle`, renders the report. |
| `bundle-input.ts` | Drop-zone file-handling (drag, click, keyboard). Size + JSON guards. |
| `verification-report.ts` | DOM rendering of verdict + per-check breakdown. |
| `build.mjs` | esbuild invocation. Writes `web/dist/`. |

## Building

```bash
node web/build.mjs
```

Output lands in `web/dist/`. Open directly in a browser (`open web/dist/index.html`) or serve:

```bash
npx serve web/dist
```

## Reproducible build

Every deploy publishes a `MANIFEST.sha256` next to `main.js`. A third party can rebuild from the tagged commit and compare:

```bash
git checkout v0.1.0-alpha.0
npm ci
node web/build.mjs
diff <(cat web/dist/MANIFEST.sha256) <(curl -s https://truetake.github.io/verify-aul/MANIFEST.sha256)
```

The hashing script strips `sourceMappingURL=` comments and normalizes line endings to LF before hashing, so cosmetic build-environment differences don't produce mismatches. Byte-identical `diff -r` is **not** the reproducibility claim; normalized-hash equality is.

## CSP tradeoffs

The static CSP meta tag in `index.html` is:

```
default-src 'self'; script-src 'self'; style-src 'self';
connect-src 'self' https:; img-src 'self' data:;
base-uri 'none'; form-action 'none';
```

**`connect-src` is deliberately broadened to `https:`** so the advanced panel can aim the verifier at any user-chosen Solana RPC or TSA host without runtime CSP gymnastics. The trust story does **not** rest on `connect-src` tightness — it rests on:

- `script-src 'self'` — no off-origin script can load. This is the invariant an auditor actually checks in DevTools → Network.
- `style-src 'self'` — no off-origin CSS can load.
- No `'unsafe-inline'`, no `'unsafe-eval'`.
- The user's chosen RPC/TSA URL is visible in the advanced panel and in DevTools → Network; whatever gets called is observable.

**`frame-ancestors` is omitted** because CSP spec requires it to be delivered via HTTP response header, and GitHub Pages doesn't let us set response headers. Clickjacking risk (an attacker iframing this page inside a spoofed UI) is a residual the user mitigates by checking the URL bar. We do not attempt to defeat attackers who control the user's DNS.

**No dynamic `<meta>` CSP rewrites.** Post-parse mutation of CSP meta tags is not enforced by any major browser. Whatever CSP the parser sees on first render is the active policy.

## Telemetry

**None.** Errors log to `console.error` only. No Sentry, no analytics, no beacon. If a bundle fails to verify, the user sees the failure in the report region and in DevTools. Nothing leaves the browser.

## Accessibility

- Drop zone is keyboard-accessible (`role="button"`, `tabindex="0"`, space/enter opens picker).
- Verdict pane has `role="status"` + `aria-live="polite"` so screen readers announce verdict changes.
- Error state sets `aria-invalid="true"` on the drop zone.
- Color-coded verdict states also carry text labels (`PASS`, `FAIL`, `PARTIAL`) — not color-only.
