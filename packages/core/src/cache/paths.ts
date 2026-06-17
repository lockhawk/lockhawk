import { join } from 'node:path';
import envPaths from 'env-paths';

/**
 * Resolve the on-disk cache directory, honoring (in priority order):
 *   1. an explicit override (the `--cache-dir` flag)
 *   2. the `LOCKHAWK_CACHE` environment variable
 *   3. the OS-conventional cache location (via env-paths)
 */
export function resolveCacheDir(override?: string): string {
  if (override) return override;
  if (process.env.LOCKHAWK_CACHE) return process.env.LOCKHAWK_CACHE;
  return envPaths('lockhawk', { suffix: '' }).cache;
}

/** Directory holding the offline OSV database for the npm ecosystem. */
export function offlineDbDir(cacheDir: string): string {
  return join(cacheDir, 'osv-db', 'npm');
}

/** Number of advisory shard buckets — bounds the on-disk file count for CI caching. */
export const SHARD_BUCKETS = 4096;

/** FNV-1a hash → stable shard bucket for a package name. */
export function shardBucket(packageName: string): number {
  let hash = 0x811c9dc5;
  for (let i = 0; i < packageName.length; i++) {
    hash ^= packageName.charCodeAt(i);
    hash = Math.imul(hash, 0x01000193);
  }
  return (hash >>> 0) % SHARD_BUCKETS;
}

/** Path to the advisory shard file that holds a given package's advisories. */
export function shardPath(cacheDir: string, packageName: string): string {
  return join(offlineDbDir(cacheDir), 'by-name', `${shardBucket(packageName)}.json`);
}

/** Metadata file describing offline-DB freshness. */
export function offlineMetaPath(cacheDir: string): string {
  return join(offlineDbDir(cacheDir), 'meta.json');
}

/** Per-id online query cache file. */
export function queryCachePath(cacheDir: string, id: string): string {
  return join(cacheDir, 'query-cache', `${encodeURIComponent(id)}.json`);
}
