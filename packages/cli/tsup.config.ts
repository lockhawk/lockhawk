import { defineConfig } from 'tsup';

export default defineConfig({
  entry: ['src/index.ts'],
  format: ['esm'],
  target: 'node18',
  dts: false,
  clean: true,
  minify: true,
  sourcemap: true,
  // Make the published file directly executable as a CLI.
  banner: { js: '#!/usr/bin/env node' },
});
