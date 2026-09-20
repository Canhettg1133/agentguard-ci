import { defineConfig } from 'tsup';

export default defineConfig([
  // Library bundle
  {
    entry: ['src/index.ts'],
    format: ['cjs', 'esm'],
    dts: true,
    clean: true,
    sourcemap: true,
  },
  // CLI executable bundle
  {
    entry: {
      cli: 'src/cli/index.ts',
    },
    format: ['cjs'],
    banner: {
      js: '#!/usr/bin/env node',
    },
    sourcemap: false,
  },
  // GitHub Action bundle (bundled with all dependencies)
  {
    entry: {
      action: 'src/action/index.ts',
    },
    format: ['cjs'],
    noExternal: [/.*/], // bundle everything into a single file for GitHub Actions
    sourcemap: false,
  },
]);
