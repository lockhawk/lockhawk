import { mkdirSync, mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { gzipSync } from 'node:zlib';
import { describe, expect, it } from 'vitest';
import { offlineDbDir, offlineMetaPath, shardBucket } from '../src/cache/paths.js';
import {
  OfflineDbMissingError,
  loadAdvisoriesForPackages,
  sanitizeETag,
  sanitizeHttpDate,
} from '../src/osv/offline-db.js';
import type { OsvVulnerability } from '../src/types.js';

/** Seed gzipped per-bucket shards + meta, exactly as `db update` would. */
function seed(cacheDir: string, advisories: Record<string, OsvVulnerability[]>): void {
  const dir = join(offlineDbDir(cacheDir), 'by-name');
  mkdirSync(dir, { recursive: true });
  const buckets = new Map<number, Record<string, OsvVulnerability[]>>();
  for (const [name, list] of Object.entries(advisories)) {
    const bucket = shardBucket(name);
    const map = buckets.get(bucket) ?? {};
    map[name] = list;
    buckets.set(bucket, map);
  }
  for (const [bucket, map] of buckets) {
    writeFileSync(join(dir, `${bucket}.json.gz`), gzipSync(Buffer.from(JSON.stringify(map))));
  }
  writeFileSync(
    offlineMetaPath(cacheDir),
    JSON.stringify({
      ecosystem: 'npm',
      source: 'osv.dev',
      lastUpdated: new Date().toISOString(),
      recordCount: 2,
      packageCount: Object.keys(advisories).length,
    }),
  );
}

const adv = (id: string, name: string): OsvVulnerability => ({
  id,
  affected: [
    {
      package: { ecosystem: 'npm', name },
      ranges: [{ type: 'SEMVER', events: [{ introduced: '0' }] }],
    },
  ],
});

describe('offline DB shards (gzip round-trip)', () => {
  it('loads advisories for requested packages from gzipped buckets', async () => {
    const cacheDir = mkdtempSync(join(tmpdir(), 'lockhawk-offdb-'));
    seed(cacheDir, { lodash: [adv('GHSA-l', 'lodash')], minimist: [adv('GHSA-m', 'minimist')] });

    const map = await loadAdvisoriesForPackages(cacheDir, ['lodash', 'minimist', 'safe-pkg']);
    expect(map.get('lodash')?.[0]?.id).toBe('GHSA-l');
    expect(map.get('minimist')?.[0]?.id).toBe('GHSA-m');
    expect(map.has('safe-pkg')).toBe(false);
  });

  it('throws OfflineDbMissingError when the DB has not been built', async () => {
    const empty = mkdtempSync(join(tmpdir(), 'lockhawk-offdb-empty-'));
    await expect(loadAdvisoriesForPackages(empty, ['lodash'])).rejects.toBeInstanceOf(
      OfflineDbMissingError,
    );
  });
});

describe('cache-validator sanitizers (file-derived header values)', () => {
  describe('sanitizeHttpDate', () => {
    it('accepts a well-formed IMF-fixdate', () => {
      expect(sanitizeHttpDate('Sun, 06 Nov 1994 08:49:37 GMT')).toBe(
        'Sun, 06 Nov 1994 08:49:37 GMT',
      );
    });

    it('rejects undefined and empty values', () => {
      expect(sanitizeHttpDate(undefined)).toBeUndefined();
      expect(sanitizeHttpDate('')).toBeUndefined();
    });

    it('rejects malformed dates', () => {
      expect(sanitizeHttpDate('not a date')).toBeUndefined();
      expect(sanitizeHttpDate('2026-06-18T00:00:00Z')).toBeUndefined();
    });

    it('rejects a value carrying an injected header (CRLF)', () => {
      expect(sanitizeHttpDate('Sun, 06 Nov 1994 08:49:37 GMT\r\nX-Evil: 1')).toBeUndefined();
    });
  });

  describe('sanitizeETag', () => {
    it('accepts a strong entity-tag', () => {
      expect(sanitizeETag('"abc123"')).toBe('"abc123"');
    });

    it('accepts a weak entity-tag', () => {
      expect(sanitizeETag('W/"abc123"')).toBe('W/"abc123"');
    });

    it('rejects undefined and unquoted values', () => {
      expect(sanitizeETag(undefined)).toBeUndefined();
      expect(sanitizeETag('abc123')).toBeUndefined();
    });

    it('rejects a value carrying an injected header (CRLF)', () => {
      expect(sanitizeETag('"abc"\r\nX-Evil: 1')).toBeUndefined();
    });
  });
});
