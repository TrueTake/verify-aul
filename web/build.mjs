#!/usr/bin/env node
/**
 * esbuild invocation for the static verifier UI.
 *
 * Produces `web/dist/` from `web/*.ts` + `web/index.html` + `web/style.css`
 * + a `MANIFEST.sha256` integrity file so a third party can rebuild from a
 * tag and diff against the deployed bytes.
 *
 * Reproducibility invariants (see `scripts/verify-reproducible-build.sh`):
 *   - strip `//# sourceMappingURL=...` comments from main.js before hashing
 *   - LF line endings
 *   - no timestamps in output
 *
 * No HMR, no dev server — use `npx serve web/dist` for local preview.
 */

import { mkdir, copyFile, readFile, writeFile } from 'node:fs/promises';
import { createHash } from 'node:crypto';
import { dirname, join, relative, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import * as esbuild from 'esbuild';

const __dirname = dirname(fileURLToPath(import.meta.url));
const webDir = __dirname;
const outDir = resolve(webDir, 'dist');

async function main() {
  await mkdir(outDir, { recursive: true });

  const result = await esbuild.build({
    entryPoints: [resolve(webDir, 'main.ts')],
    bundle: true,
    format: 'esm',
    target: 'es2022',
    outfile: resolve(outDir, 'main.js'),
    sourcemap: true,
    minify: false,
    define: {
      'process.env.NODE_ENV': '"production"',
    },
    metafile: true,
    logLevel: 'info',
  });

  // Copy static assets
  await copyFile(resolve(webDir, 'index.html'), resolve(outDir, 'index.html'));
  await copyFile(resolve(webDir, 'style.css'), resolve(outDir, 'style.css'));

  // Build MANIFEST.sha256 for reproducibility: normalized hash of each shipped
  // file (index.html, style.css, main.js without sourceMappingURL trailer).
  const files = ['index.html', 'style.css', 'main.js'];
  const lines = [];
  for (const name of files) {
    const raw = await readFile(resolve(outDir, name));
    const normalized = normalize(name, raw);
    const hash = createHash('sha256').update(normalized).digest('hex');
    lines.push(`${hash}  ${name}`);
  }
  await writeFile(resolve(outDir, 'MANIFEST.sha256'), lines.join('\n') + '\n');

  const bytes = Object.values(result.metafile.outputs).reduce((n, out) => n + out.bytes, 0);
  console.log(`\n✓ built ${files.length} files to ${relative(process.cwd(), outDir)} (${bytes} bytes of JS)`);
}

function normalize(name, raw) {
  let text = raw.toString('utf8');
  // Strip sourceMappingURL comments so they can change across builds without
  // affecting the hash.
  if (name.endsWith('.js')) {
    text = text.replace(/\r?\n\/\/[#@] sourceMappingURL=.*$/m, '');
  }
  // Normalize line endings to LF.
  text = text.replace(/\r\n/g, '\n');
  return Buffer.from(text, 'utf8');
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
