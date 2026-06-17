import ora from 'ora';
import {
  offlineDbDir,
  readOfflineMeta,
  resolveCacheDir,
  updateOfflineDatabase,
} from '@npm-scanner/core';

interface DbOptions {
  cacheDir?: string;
  force?: boolean;
}

/** `db update` — download/refresh the offline OSV database. */
export async function runDbUpdate(opts: DbOptions): Promise<void> {
  const cacheDir = resolveCacheDir(opts.cacheDir);
  const useSpinner = Boolean(process.stderr.isTTY) && !process.env.CI;
  const spinner = useSpinner
    ? ora({ stream: process.stderr, text: 'Updating database…' }).start()
    : undefined;
  try {
    const { status, meta } = await updateOfflineDatabase({
      cacheDir,
      nowIso: new Date().toISOString(),
      force: opts.force,
      onProgress: (message) => {
        if (spinner) spinner.text = message;
        else process.stderr.write(`${message}\n`);
      },
    });
    const summary = `${status === 'updated' ? 'Updated' : 'Already up to date'} — ${meta.recordCount} advisories across ${meta.packageCount} packages.`;
    if (spinner) spinner.succeed(summary);
    else process.stderr.write(`${summary}\n`);
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    if (spinner) spinner.fail(`Database update failed: ${message}`);
    else process.stderr.write(`Database update failed: ${message}\n`);
    process.exitCode = 3;
  }
}

/** `db status` — report freshness of the offline database. */
export async function runDbStatus(opts: DbOptions): Promise<void> {
  const cacheDir = resolveCacheDir(opts.cacheDir);
  const meta = await readOfflineMeta(cacheDir);
  if (!meta) {
    process.stdout.write('No offline database found. Run `npm-scanner db update` to create one.\n');
    return;
  }
  const ageHours = Math.round((Date.now() - Date.parse(meta.lastUpdated)) / 3_600_000);
  process.stdout.write(
    [
      `Ecosystem:    ${meta.ecosystem}`,
      `Source:       ${meta.source}`,
      `Advisories:   ${meta.recordCount}`,
      `Packages:     ${meta.packageCount}`,
      `Last updated: ${meta.lastUpdated} (${ageHours}h ago)`,
      `Location:     ${offlineDbDir(cacheDir)}`,
    ].join('\n') + '\n',
  );
}

/** `db path` — print the offline database directory. */
export function runDbPath(opts: DbOptions): void {
  process.stdout.write(`${offlineDbDir(resolveCacheDir(opts.cacheDir))}\n`);
}
