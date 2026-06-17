import { readFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

/**
 * Load the prebuilt report-UI shell (the single-file React app) that the HTML
 * reporter injects scan data into. The shell is copied next to the CLI bundle
 * at build time (M6). If it is absent, `undefined` is returned and the core
 * HTML reporter falls back to its built-in template — so `--format html` always
 * works, even before the UI is built.
 */
let cached: string | null | undefined;

export async function loadReportShell(): Promise<string | undefined> {
  if (cached !== undefined) return cached ?? undefined;
  try {
    const here = dirname(fileURLToPath(import.meta.url));
    cached = await readFile(join(here, 'report-shell.html'), 'utf8');
  } catch {
    cached = null;
  }
  return cached ?? undefined;
}
