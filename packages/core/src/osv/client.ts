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
 * Online OSV source. Queries the batch endpoint by package *name only* — never
 * pinning an installed version — so OSV returns every advisory naming each
 * package; lockhawk's own range matcher (`buildFindings` → `vulnerabilityAffects`)
 * then decides what actually affects the installed version. Delegating the
 * version match to OSV's server would cap coverage at OSV's matcher; doing it
 * locally makes coverage depend only on lockhawk (and mirrors the offline path).
 * Hydrated records are cached by id so repeat scans do no network work.
 */
export class OsvClient {
  private readonly limit;

  constructor(private readonly opts: OnlineClientOptions) {
    this.limit = pLimit(opts.concurrency ?? 5);
  }

  /** Fetch advisories naming the given packages, keyed by package name. */
  async fetchAdvisories(packages: PackageRef[]): Promise<Map<string, OsvVulnerability[]>> {
    const names = [...new Set(packages.map((p) => p.name))];
    const idsByName = await this.queryBatch(names);

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

  private async queryBatch(names: string[]): Promise<Map<string, Set<string>>> {
    const idsByName = new Map<string, Set<string>>();

    for (let i = 0; i < names.length; i += BATCH_SIZE) {
      const chunk = names.slice(i, i + BATCH_SIZE);
      const body = {
        queries: chunk.map((name) => ({ package: { name, ecosystem: 'npm' } })),
      };
      const data = await this.request<{ results: BatchResult[] }>(`${OSV_API}/querybatch`, body);

      for (let j = 0; j < chunk.length; j++) {
        const name = chunk[j]!;
        const result = data.results[j];
        if (!result) continue;
        const set = idsByName.get(name) ?? new Set<string>();
        for (const vuln of result.vulns ?? []) set.add(vuln.id);
        // Querying by name (all versions) makes pagination more likely; pull every page.
        let pageToken = result.next_page_token;
        while (pageToken) {
          const page = await this.request<BatchResult>(`${OSV_API}/query`, {
            package: { name, ecosystem: 'npm' },
            page_token: pageToken,
          });
          for (const vuln of page.vulns ?? []) set.add(vuln.id);
          pageToken = page.next_page_token;
        }
        if (set.size) idsByName.set(name, set);
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
    const record = await this.request<OsvVulnerability>(
      `${OSV_API}/vulns/${encodeURIComponent(id)}`,
    );
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
