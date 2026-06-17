import { mkdir, readFile, writeFile } from 'node:fs/promises';
import { dirname } from 'node:path';
import pLimit from 'p-limit';
import pRetry, { AbortError } from 'p-retry';
import type { OsvVulnerability } from '../types.js';
import { queryCachePath } from '../cache/paths.js';

const OSV_API = 'https://api.osv.dev/v1';
const BATCH_SIZE = 1000;

export interface PackageRef {
  name: string;
  version: string;
}

export interface OnlineClientOptions {
  cacheDir: string;
  concurrency?: number;
  noCache?: boolean;
  cacheTtlHours?: number;
  retries?: number;
}

interface BatchResult {
  vulns?: { id: string; modified?: string }[];
  next_page_token?: string;
}

/**
 * Online OSV source. Uses the batch endpoint (which returns only matched ids)
 * then hydrates each unique id to a full record — caching records by id so
 * repeat scans do no network work. All matching is re-validated downstream by
 * `buildFindings`, so this client only has to gather candidate records.
 */
export class OsvClient {
  private readonly limit;

  constructor(private readonly opts: OnlineClientOptions) {
    this.limit = pLimit(opts.concurrency ?? 5);
  }

  /** Fetch advisories affecting the given packages, keyed by package name. */
  async fetchAdvisories(packages: PackageRef[]): Promise<Map<string, OsvVulnerability[]>> {
    const unique = dedupePackages(packages);
    const idsByName = await this.queryBatch(unique);

    const allIds = new Set<string>();
    for (const ids of idsByName.values()) for (const id of ids) allIds.add(id);

    const records = await this.hydrate([...allIds]);

    const byName = new Map<string, OsvVulnerability[]>();
    for (const [name, ids] of idsByName) {
      const list: OsvVulnerability[] = [];
      for (const id of ids) {
        const record = records.get(id);
        if (record) list.push(record);
      }
      if (list.length) byName.set(name, list);
    }
    return byName;
  }

  private async queryBatch(packages: PackageRef[]): Promise<Map<string, Set<string>>> {
    const idsByName = new Map<string, Set<string>>();

    for (let i = 0; i < packages.length; i += BATCH_SIZE) {
      const chunk = packages.slice(i, i + BATCH_SIZE);
      const body = { queries: chunk.map((p) => ({ package: { name: p.name, ecosystem: 'npm' }, version: p.version })) };
      const data = await this.request<{ results: BatchResult[] }>(`${OSV_API}/querybatch`, body);

      for (let j = 0; j < chunk.length; j++) {
        const pkg = chunk[j]!;
        const result = data.results[j];
        if (!result) continue;
        const set = idsByName.get(pkg.name) ?? new Set<string>();
        for (const vuln of result.vulns ?? []) set.add(vuln.id);
        // Pagination is rare for a single npm package; pull remaining pages if present.
        let pageToken = result.next_page_token;
        while (pageToken) {
          const page = await this.request<BatchResult>(`${OSV_API}/query`, {
            package: { name: pkg.name, ecosystem: 'npm' },
            version: pkg.version,
            page_token: pageToken,
          });
          for (const vuln of page.vulns ?? []) set.add(vuln.id);
          pageToken = page.next_page_token;
        }
        if (set.size) idsByName.set(pkg.name, set);
      }
    }
    return idsByName;
  }

  private async hydrate(ids: string[]): Promise<Map<string, OsvVulnerability>> {
    const records = new Map<string, OsvVulnerability>();
    await Promise.all(
      ids.map((id) =>
        this.limit(async () => {
          const record = await this.getVulnerability(id);
          if (record) records.set(id, record);
        }),
      ),
    );
    return records;
  }

  private async getVulnerability(id: string): Promise<OsvVulnerability | undefined> {
    const cached = await this.readCache(id);
    if (cached) return cached;
    const record = await this.request<OsvVulnerability>(`${OSV_API}/vulns/${encodeURIComponent(id)}`);
    await this.writeCache(id, record);
    return record;
  }

  private async request<T>(url: string, body?: unknown): Promise<T> {
    const retries = this.opts.retries ?? 3;
    return pRetry(
      async () => {
        const res = await fetch(url, {
          method: body ? 'POST' : 'GET',
          headers: body ? { 'content-type': 'application/json' } : undefined,
          body: body ? JSON.stringify(body) : undefined,
        });
        if (res.ok) return (await res.json()) as T;
        if (res.status === 429 || res.status >= 500) {
          throw new Error(`OSV ${res.status} for ${url}`); // retryable
        }
        throw new AbortError(`OSV ${res.status} for ${url}`); // client error: do not retry
      },
      { retries },
    );
  }

  private async readCache(id: string): Promise<OsvVulnerability | undefined> {
    if (this.opts.noCache) return undefined;
    try {
      const parsed = JSON.parse(await readFile(queryCachePath(this.opts.cacheDir, id), 'utf8')) as {
        fetchedAt: number;
        vuln: OsvVulnerability;
      };
      const ttlMs = (this.opts.cacheTtlHours ?? 24) * 3_600_000;
      if (Date.now() - parsed.fetchedAt > ttlMs) return undefined;
      return parsed.vuln;
    } catch {
      return undefined;
    }
  }

  private async writeCache(id: string, vuln: OsvVulnerability): Promise<void> {
    if (this.opts.noCache) return;
    try {
      const path = queryCachePath(this.opts.cacheDir, id);
      await mkdir(dirname(path), { recursive: true });
      await writeFile(path, JSON.stringify({ fetchedAt: Date.now(), vuln }));
    } catch {
      // Cache write failures are non-fatal.
    }
  }
}

function dedupePackages(packages: PackageRef[]): PackageRef[] {
  const seen = new Set<string>();
  const out: PackageRef[] = [];
  for (const p of packages) {
    const key = `${p.name}@${p.version}`;
    if (!seen.has(key)) {
      seen.add(key);
      out.push(p);
    }
  }
  return out;
}
