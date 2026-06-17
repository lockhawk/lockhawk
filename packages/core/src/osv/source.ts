import type { DatabaseInfo, OsvVulnerability, SourceMode } from '../types.js';
import { OsvClient } from './client.js';
import type { PackageRef } from './client.js';
import { OfflineDbMissingError, loadAdvisoriesForPackages, readOfflineMeta } from './offline-db.js';

/** A source prepared for a specific package set: synchronous lookup + provenance. */
export interface ResolvedSource {
  candidatesFor(name: string): OsvVulnerability[];
  database: DatabaseInfo;
}

/** Strategy for obtaining advisories (offline DB, online API, or auto). */
export interface VulnSource {
  prepare(packages: PackageRef[]): Promise<ResolvedSource>;
}

export interface SourceOptions {
  cacheDir: string;
  concurrency?: number;
  noCache?: boolean;
  cacheTtlHours?: number;
  /** Fail hard on network errors instead of degrading to cache. */
  strictNetwork?: boolean;
  /** Offline DB older than this many hours is flagged stale (default 24). */
  staleAfterHours?: number;
}

const HOUR_MS = 3_600_000;

/** Reads advisories from the on-disk offline database. */
export class OfflineSource implements VulnSource {
  constructor(private readonly opts: SourceOptions) {}

  async prepare(packages: PackageRef[]): Promise<ResolvedSource> {
    const meta = await readOfflineMeta(this.opts.cacheDir);
    if (!meta) throw new OfflineDbMissingError();
    const map = await loadAdvisoriesForPackages(this.opts.cacheDir, packages.map((p) => p.name));

    const ageHours = (Date.now() - Date.parse(meta.lastUpdated)) / HOUR_MS;
    const stale = ageHours > (this.opts.staleAfterHours ?? 24);
    const warnings = stale
      ? [`Offline database is ${Math.round(ageHours)}h old. Run \`npm-scanner db update\` for current results.`]
      : [];

    return {
      candidatesFor: (name) => map.get(name) ?? [],
      database: {
        source: 'offline',
        recordCount: meta.recordCount,
        lastUpdated: meta.lastUpdated,
        ageHours: Math.round(ageHours * 10) / 10,
        stale,
        warnings,
      },
    };
  }
}

/** Queries the live OSV.dev API. Fail-open unless `strictNetwork` is set. */
export class OnlineSource implements VulnSource {
  constructor(private readonly opts: SourceOptions) {}

  async prepare(packages: PackageRef[]): Promise<ResolvedSource> {
    const client = new OsvClient({
      cacheDir: this.opts.cacheDir,
      concurrency: this.opts.concurrency,
      noCache: this.opts.noCache,
      cacheTtlHours: this.opts.cacheTtlHours,
    });
    try {
      const map = await client.fetchAdvisories(packages);
      return {
        candidatesFor: (name) => map.get(name) ?? [],
        database: { source: 'online', stale: false, warnings: [] },
      };
    } catch (err) {
      if (this.opts.strictNetwork) throw err;
      const reason = err instanceof Error ? err.message : String(err);
      return {
        candidatesFor: () => [],
        database: {
          source: 'online',
          stale: true,
          warnings: [`OSV.dev was unreachable (${reason}). Scan completed without online data — results may be incomplete.`],
        },
      };
    }
  }
}

/**
 * Prefers a fresh offline DB (fast, zero network), falls back to the online API,
 * and finally to a stale offline DB if the network is down — always degrading
 * gracefully so a scan never hard-fails on a transient outage.
 */
export class AutoSource implements VulnSource {
  constructor(private readonly opts: SourceOptions) {}

  async prepare(packages: PackageRef[]): Promise<ResolvedSource> {
    const meta = await readOfflineMeta(this.opts.cacheDir);
    const ttl = this.opts.staleAfterHours ?? 24;

    if (meta) {
      const ageHours = (Date.now() - Date.parse(meta.lastUpdated)) / HOUR_MS;
      if (ageHours <= ttl) {
        return new OfflineSource(this.opts).prepare(packages); // fresh offline → fast path
      }
    }

    try {
      return await new OnlineSource({ ...this.opts, strictNetwork: true }).prepare(packages);
    } catch (err) {
      if (meta) {
        const resolved = await new OfflineSource(this.opts).prepare(packages);
        resolved.database.warnings.push('Used the stale offline database because OSV.dev was unreachable.');
        return resolved;
      }
      if (this.opts.strictNetwork) throw err;
      const reason = err instanceof Error ? err.message : String(err);
      return {
        candidatesFor: () => [],
        database: {
          source: 'online',
          stale: true,
          warnings: [`No offline database and OSV.dev was unreachable (${reason}). Run \`npm-scanner db update\`.`],
        },
      };
    }
  }
}

/** Build the right source for the requested mode. */
export function createSource(mode: SourceMode, opts: SourceOptions): VulnSource {
  switch (mode) {
    case 'offline':
      return new OfflineSource(opts);
    case 'online':
      return new OnlineSource(opts);
    default:
      return new AutoSource(opts);
  }
}
