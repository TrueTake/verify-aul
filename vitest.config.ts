import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    include: ['src/**/*.test.ts'],
    environment: 'node',
    globals: false,
    // Tests rely on WebCrypto (globalThis.crypto.subtle), available in Node 20+
    // via the built-in crypto.webcrypto binding. No polyfill needed.
  },
});
