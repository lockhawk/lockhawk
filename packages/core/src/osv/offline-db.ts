import { createWriteStream } from 'node:fs';
import { mkdir, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { Readable } from 'node:stream';
import { pipeline } from 'node:stream/promises';
import yauzl from 'yauzl';
import type { OsvVulnerability } from '../types.js';
import { offlineDbDir, offlineMetaPath, shardPath } from '../cache/paths.js';

const OSV_NPM_ZIP_URL = 'https://storage.googleapis.com/osv-vulnerabilities/npm/all.zip';

export interface OfflineMeta {
  ecosystem: 'npm';
  source: string;
  /** ISO timestamp of the last successful refresh/check. */
  lastUpdated: string;
  recordCount: number;
  packageCount: number;
  etag?: string;
  lastModified?: string;
}

export interface UpdateResult {
  status: 'updated' | 'unchanged';
  meta: OfflineMeta;
}

export class OfflineDbMissingError extends Error {
  constructor() {
    super('No offline OSV database found. Run `npm-scanner db update` first.');
    this.name = 'OfflineDbMissingError';
  }
}

/** Read the offline DB metadata, or `undefined` if it has never been built. */
export async function readOfflineMeta(cacheDir: string): Promise<OfflineMeta | undefined> {
  try {
    return JSON.parse(await readFile(offlineMetaPath(cacheDir), 'utf8')) as OfflineMeta;
  } catch {
    return undefined;
  }
}

/**
 * Download (or conditionally refresh) the npm OSV database and rebuild the
 * per-package shards. Uses ETag / Last-Modified so an unchanged DB costs a
 * single 304 and no rewrite. `nowIso` is injected so callers stamp the time
 * (the engine never calls Date.now itself in pure paths).
 */
export async function updateOfflineDatabase(opts: {
  cacheDir: string;
  nowIso: string;
  force?: boolean;
  onProgress?: (message: string) => void;
}): Promise<UpdateResult> {
  const { cacheDir, nowIso, force, onProgress } = opts;
  const dir = offlineDbDir(cacheDir);
  await mkdir(dir, { recursive: true });

  const previous = force ? undefined : await readOfflineMeta(cacheDir);
  const headers: Record<string, string> = {};
  if (previous?.etag) headers['If-None-Match'] = previous.etag;
  if (previous?.lastModified) headers['If-Modified-Since'] = previous.lastModified;

  onProgress?.('Fetching npm advisory database from OSV.dev…');
  const res = await fetch(OSV_NPM_ZIP_URL, { headers });

  if (res.status === 304 && previous) {
    const meta: OfflineMeta = { ...previous, lastUpdated: nowIso };
    await writeFile(offlineMetaPath(cacheDir), JSON.stringify(meta, null, 2));
    return { status: 'unchanged', meta };
  }
  if (!res.ok || !res.body) {
    throw new Error(`OSV database download failed: HTTP ${res.status}`);
  }

  const zipPath = join(tmpdir(), `npm-scanner-osv-${process.pid}.zip`);
  await pipeline(Readable.fromWeb(res.body as Parameters<typeof Readable.fromWeb>[0]), createWriteStream(zipPath));

  onProgress?.('Extracting advisories…');
  const records = await readZipRecords(zipPath);
  await rm(zipPath, { force: true });

  onProgress?.('Building package index…');
  const byName = groupByPackage(records);
  await writeShards(cacheDir, byName);

  const meta: OfflineMeta = {
    ecosystem: 'npm',
    source: 'osv.dev',
    lastUpdated: nowIso,
    recordCount: records.length,
    packageCount: byName.size,
    etag: res.headers.get('etag') ?? undefined,
    lastModified: res.headers.get('last-modified') ?? undefined,
  };
  await writeFile(offlineMetaPath(cacheDir), JSON.stringify(meta, null, 2));
  return { status: 'updated', meta };
}

/** Load advisories for the given package names from the per-package shards. */
export async function loadAdvisoriesForPackages(
  cacheDir: string,
  names: Iterable<string>,
): Promise<Map<string, OsvVulnerability[]>> {
  if (!(await readOfflineMeta(cacheDir))) throw new OfflineDbMissingError();
  const result = new Map<string, OsvVulnerability[]>();
  const unique = new Set(names);
  await Promise.all(
    [...unique].map(async (name) => {
      try {
        const records = JSON.parse(await readFile(shardPath(cacheDir, name), 'utf8')) as OsvVulnerability[];
        if (records.length) result.set(name, records);
      } catch {
        // No shard for this package → no known advisories.
      }
    }),
  );
  return result;
}

function groupByPackage(records: OsvVulnerability[]): Map<string, OsvVulnerability[]> {
  const byName = new Map<string, OsvVulnerability[]>();
  for (const record of records) {
    if (record.withdrawn) continue;
    const names = new Set<string>();
    for (const affected of record.affected ?? []) {
      const ecosystem = affected.package?.ecosystem;
      if (ecosystem && ecosystem !== 'npm') continue;
      if (affected.package?.name) names.add(affected.package.name);
    }
    for (const name of names) {
      const list = byName.get(name);
      if (list) list.push(record);
      else byName.set(name, [record]);
    }
  }
  return byName;
}

async function writeShards(cacheDir: string, byName: Map<string, OsvVulnerability[]>): Promise<void> {
  const byNameDir = join(offlineDbDir(cacheDir), 'by-name');
  await rm(byNameDir, { recursive: true, force: true });
  await mkdir(byNameDir, { recursive: true });
  const entries = [...byName.entries()];
  // Write in batches to bound open file handles.
  const BATCH = 200;
  for (let i = 0; i < entries.length; i += BATCH) {
    await Promise.all(
      entries.slice(i, i + BATCH).map(([name, records]) =>
        writeFile(shardPath(cacheDir, name), JSON.stringify(records)),
      ),
    );
  }
}

function readZipRecords(zipPath: string): Promise<OsvVulnerability[]> {
  return new Promise((resolve, reject) => {
    const out: OsvVulnerability[] = [];
    yauzl.open(zipPath, { lazyEntries: true }, (err, zip) => {
      if (err || !zip) return reject(err ?? new Error('Failed to open OSV zip'));
      zip.on('entry', (entry) => {
        if (!entry.fileName.endsWith('.json')) return zip.readEntry();
        zip.openReadStream(entry, (streamErr, stream) => {
          if (streamErr || !stream) return zip.readEntry();
          const chunks: Buffer[] = [];
          stream.on('data', (chunk: Buffer) => chunks.push(chunk));
          stream.on('error', () => zip.readEntry());
          stream.on('end', () => {
            try {
              out.push(JSON.parse(Buffer.concat(chunks).toString('utf8')) as OsvVulnerability);
            } catch {
              // Skip malformed entries rather than failing the whole import.
            }
            zip.readEntry();
          });
        });
      });
      zip.on('end', () => resolve(out));
      zip.on('error', reject);
      zip.readEntry();
    });
  });
}
