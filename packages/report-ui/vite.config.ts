import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';
import { viteSingleFile } from 'vite-plugin-singlefile';

// Build a single self-contained HTML file: all JS/CSS inlined so the report
// works offline / from file:// / as a CI artifact, with no external requests.
// The CLI injects the scan data into this shell at the DATA_MARKER (or via
// window.__SCAN_RESULT__) and also serves it for `lockhawk serve`.
export default defineConfig({
  plugins: [react(), viteSingleFile()],
  build: {
    target: 'es2020',
    cssCodeSplit: false,
    assetsInlineLimit: 100_000_000,
    chunkSizeWarningLimit: 100_000_000,
    reportCompressedSize: false,
  },
});
