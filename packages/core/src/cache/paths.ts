import { join } from 'node:path';
import envPaths from 'env-paths';

/**
 * Resolve the on-disk cache directory, honoring (in priority order):
 *   1. an explicit override (the `--cache-dir` flag)
 *   2. the `NPM_SCANNER_CACHE` environment variable
 *   3. the OS-conventional cache location (via env-paths)
 */
export function resolveCacheDir(override?: string): string {
  if (override) return override;
  if (process.env.NPM_SCANNER_CACHE) return process.env.NPM_SCANNER_CACHE;
  return envPaths('npm-scanner', { suffix: '' }).cache;
}

/** Directory holding the offline OSV database for the npm ecosystem. */
export function offlineDbDir(cacheDir: string): string {
  return join(cacheDir, 'osv-db', 'npm');
}

/** Per-package advisory shard path (filename-safe encoding of the package name). */
export function shardPath(cacheDir: string, packageName: string): string {
  return join(offlineDbDir(cacheDir), 'by-name', `${encodeURIComponent(packageName)}.json`);
}

/** Metadata file describing offline-DB freshness. */
export function offlineMetaPath(cacheDir: string): string {
  return join(offlineDbDir(cacheDir), 'meta.json');
}

/** Per-id online query cache file. */
export function queryCachePath(cacheDir: string, id: string): string {
  return join(cacheDir, 'query-cache', `${encodeURIComponent(id)}.json`);
}
