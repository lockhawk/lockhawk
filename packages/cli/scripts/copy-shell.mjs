// Copy the prebuilt single-file report UI into the CLI's dist as report-shell.html
// so the HTML reporter can inject scan data into it. If the UI hasn't been built,
// the core HTML reporter falls back to its built-in template.
import { copyFileSync, existsSync, mkdirSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const here = dirname(fileURLToPath(import.meta.url));
const src = join(here, '..', '..', 'report-ui', 'dist', 'index.html');
const destDir = join(here, '..', 'dist');
const dest = join(destDir, 'report-shell.html');

if (existsSync(src)) {
  mkdirSync(destDir, { recursive: true });
  copyFileSync(src, dest);
  console.error('[copy-shell] report UI shell copied to dist/report-shell.html');
} else {
  console.error('[copy-shell] report UI not built; HTML reporter will use the fallback template');
}
