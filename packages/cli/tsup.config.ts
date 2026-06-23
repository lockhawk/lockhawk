import { readFileSync } from 'node:fs';
import { defineConfig } from 'tsup';

// Inject the real package version at build time so `--version` never drifts
// from package.json (and stays correct after every release bump).
const { version } = JSON.parse(
  readFileSync(new URL('./package.json', import.meta.url), 'utf8'),
) as { version: string };

export default defineConfig({
  entry: ['src/index.ts'],
  format: ['esm'],
  target: 'node18',
  dts: false,
  clean: true,
  minify: true,
  sourcemap: true,
  define: { __LOCKHAWK_VERSION__: JSON.stringify(version) },
  // Make the published file directly executable as a CLI.
  banner: { js: '#!/usr/bin/env node' },
});
