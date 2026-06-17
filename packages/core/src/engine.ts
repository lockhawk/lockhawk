import { resolve } from 'node:path';
import type {
  DependencyGraph,
  Finding,
  ScanOptions,
  ScanResult,
  ScanSummary,
  Severity,
  UnscannablePackage,
} from './types.js';
import { SEVERITY_RANK, severityAtLeast } from './types.js';
import { loadDependencyGraph } from './lockfiles/normalize.js';
import { detectLockfile } from './lockfiles/detect.js';
import { buildFindings } from './match/findings.js';
import { resolveCacheDir } from './cache/paths.js';
import { createSource } from './osv/source.js';
import type { VulnSource } from './osv/source.js';
import type { PackageRef } from './osv/client.js';

export const TOOL = { name: 'lockhawk', version: '0.1.0' } as const;

/**
 * Run a full scan: load and normalize the lockfile, query OSV for the unique
 * scannable packages, build findings, and assemble a {@link ScanResult}.
 *
 * A `source` can be injected (used by tests and by the CLI once it has resolved
 * options); otherwise one is created from `options.mode`.
 */
export async function scan(options: ScanOptions = {}, source?: VulnSource): Promise<ScanResult> {
  const start = Date.now();
  const dir = resolve(options.path ?? '.');
  const graph = loadDependencyGraph(dir);
  const detected = detectLockfile(dir);

  const scannable = uniqueScannablePackages(graph, options.prodOnly);
  const cacheDir = resolveCacheDir(options.cacheDir);
  const src =
    source ??
    createSource(options.mode ?? 'auto', {
      cacheDir,
      concurrency: options.concurrency,
      noCache: options.noCache,
      cacheTtlHours: options.cacheTtlHours,
      strictNetwork: options.strictNetwork,
    });

  options.onProgress?.('Checking dependencies against OSV.dev…');
  const resolved = await src.prepare(scannable);

  let findings = buildFindings(graph, resolved.candidatesFor, {
    prodOnly: options.prodOnly,
    ignore: options.ignore && options.ignore.length ? new Set(options.ignore) : undefined,
  });
  if (options.severityThreshold && options.severityThreshold !== 'none') {
    findings = findings.filter((f) =>
      severityAtLeast(f.severity.level, options.severityThreshold!),
    );
  }
  findings.sort(bySeverityThenName);

  const unscannable = unscannablePackages(graph);

  return {
    schemaVersion: 1,
    tool: { ...TOOL },
    scannedAt: new Date(start).toISOString(),
    target: {
      path: dir,
      manager: graph.manager,
      lockfile: detected?.filename ?? '',
      root: graph.root,
    },
    database: resolved.database,
    summary: summarize(findings),
    stats: {
      totalPackages: Object.keys(graph.nodes).length,
      uniquePackages: scannable.length,
      directDependencies: graph.directKeys.length,
      unscannable: unscannable.length,
      durationMs: Date.now() - start,
    },
    findings,
    unscannable,
  };
}

/** Unique `name@version` packages worth querying (skips local/unscannable, optionally dev). */
export function uniqueScannablePackages(graph: DependencyGraph, prodOnly?: boolean): PackageRef[] {
  const seen = new Set<string>();
  const out: PackageRef[] = [];
  for (const node of Object.values(graph.nodes)) {
    if (node.unscannable) continue;
    if (prodOnly && node.scope === 'dev') continue;
    if (seen.has(node.key)) continue;
    seen.add(node.key);
    out.push({ name: node.name, version: node.version });
  }
  return out;
}

function unscannablePackages(graph: DependencyGraph): UnscannablePackage[] {
  const out: UnscannablePackage[] = [];
  for (const node of Object.values(graph.nodes)) {
    if (node.unscannable)
      out.push({ name: node.name, version: node.version, reason: node.unscannable.reason });
  }
  return out;
}

function summarize(findings: Finding[]): ScanSummary {
  const summary: ScanSummary = {
    total: findings.length,
    critical: 0,
    high: 0,
    medium: 0,
    low: 0,
    unknown: 0,
    none: 0,
    vulnerablePackages: 0,
    fixable: 0,
  };
  const vulnerable = new Set<string>();
  for (const f of findings) {
    summary[f.severity.level] += 1;
    vulnerable.add(`${f.packageName}@${f.version}`);
    if (f.fixedVersions.length > 0) summary.fixable += 1;
  }
  summary.vulnerablePackages = vulnerable.size;
  return summary;
}

function bySeverityThenName(a: Finding, b: Finding): number {
  const rank = SEVERITY_RANK[b.severity.level] - SEVERITY_RANK[a.severity.level];
  if (rank !== 0) return rank;
  return a.packageName.localeCompare(b.packageName);
}

/** Lowest severity that should trigger a non-zero exit given a `--fail-on` threshold. */
export function shouldFail(summary: ScanSummary, failOn: Severity): boolean {
  const levels: Severity[] = ['critical', 'high', 'medium', 'low', 'unknown'];
  return levels.some(
    (level) => SEVERITY_RANK[level] >= SEVERITY_RANK[failOn] && summary[level] > 0,
  );
}
