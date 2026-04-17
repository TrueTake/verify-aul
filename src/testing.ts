/**
 * Test-only surface — reached via `import { ... } from '@truetake/verify-aul/testing'`.
 *
 * The production API (`verifyBundle`) enforces the pinned production trust
 * anchors at module-load time. That means tests cannot exercise the
 * trust-anchor mismatch error path (or pass vectors signed under a fixtures
 * CA) without an alternative entry point.
 *
 * This module provides `verifyBundleForTesting`, which accepts a trust-anchor
 * fingerprint override. Third-party implementers reading the spec never see
 * this on the main API surface; it's reached only through the `./testing`
 * subpath export in `package.json.exports`.
 *
 * Populated in Unit 4 alongside the spec and fixtures.
 */

export { verifyBundle as verifyBundleForTesting } from './core.js';
