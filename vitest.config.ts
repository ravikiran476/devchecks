import { fileURLToPath } from 'node:url';
import { defineConfig } from 'vitest/config';

const core = (file: string) => fileURLToPath(new URL(`./packages/core/src/${file}`, import.meta.url));

export default defineConfig({
  define: { __VERSION__: JSON.stringify('0.0.0-test') },
  resolve: {
    alias: [
      { find: /^@devchecks\/core\/node$/, replacement: core('node.ts') },
      { find: /^@devchecks\/core$/, replacement: core('index.ts') },
    ],
  },
  test: {
    include: ['packages/*/test/**/*.test.ts'],
    testTimeout: 30000,
  },
});
