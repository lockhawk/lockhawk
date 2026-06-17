import semver from 'semver';
import type { DependencyGraph, Finding, OsvVulnerability, PackageManager } from '../types.js';
import { shortestPath } from '../graph/paths.js';
import { dedupeVulnerabilities } from './dedupe.js';
import { nearestFix, vulnerabilityAffects } from './ranges.js';
import { resolveSeverity } from '../score/cvss.js';

export interface FindingsOptions {
  /** Skip dev-only dependencies. */
  prodOnly?: boolean;
  /** Advisory ids/aliases to suppress. */
  ignore?: Set<string>;
}

/**
 * Turn a dependency graph plus a per-package advisory lookup into findings.
 *
 * `candidatesFor(name)` returns advisories that *name* the package; this
 * function performs the authoritative version match, de-duplicates aliased
 * advisories, scores severity and traces the dependency path. Keeping the
 * version match here (rather than trusting the source) means offline and online
 * sources share one accuracy-critical code path.
 */
export function buildFindings(
  graph: DependencyGraph,
  candidatesFor: (name: string) => OsvVulnerability[],
  options: FindingsOptions = {},
): Finding[] {
  const findings: Finding[] = [];

  for (const node of Object.values(graph.nodes)) {
    if (node.unscannable) continue;
    if (options.prodOnly && node.scope === 'dev') continue;

    const candidates = candidatesFor(node.name);
    if (candidates.length === 0) continue;

    const matched = candidates.filter(
      (vuln) => vulnerabilityAffects(node.name, node.version, vuln).affected,
    );
    if (matched.length === 0) continue;

    const path = shortestPath(graph, node.key);
    for (const vuln of dedupeVulnerabilities(matched)) {
      if (isIgnored(vuln, options.ignore)) continue;

      const { fixedVersions } = vulnerabilityAffects(node.name, node.version, vuln);
      const sortedFixes = sortVersions(fixedVersions);
      const nearest = nearestFix(node.version, fixedVersions);

      findings.push({
        id: vuln.id,
        aliases: vuln.aliases ?? [],
        packageName: node.name,
        version: node.version,
        scope: node.scope,
        direct: node.direct,
        severity: resolveSeverity(vuln),
        summary: vuln.summary ?? vuln.id,
        details: vuln.details,
        references: (vuln.references ?? []).map((ref) => ref.url),
        fixedVersions: sortedFixes,
        recommendation: buildRecommendation(node.name, node.direct, nearest, graph.manager),
        dependencyPaths: path ? [path] : [],
        source: 'osv',
      });
    }
  }

  return findings;
}

function isIgnored(vuln: OsvVulnerability, ignore?: Set<string>): boolean {
  if (!ignore || ignore.size === 0) return false;
  if (ignore.has(vuln.id)) return true;
  return (vuln.aliases ?? []).some((alias) => ignore.has(alias));
}

function sortVersions(versions: string[]): string[] {
  return [...new Set(versions)].sort((a, b) => {
    const pa = semver.parse(a, { loose: true });
    const pb = semver.parse(b, { loose: true });
    if (pa && pb) return pa.compare(pb);
    return a.localeCompare(b);
  });
}

const INSTALL_COMMAND: Record<PackageManager, string> = {
  npm: 'npm install',
  yarn: 'yarn add',
  pnpm: 'pnpm add',
};

function buildRecommendation(
  name: string,
  direct: boolean,
  nearest: string | undefined,
  manager: PackageManager,
): string {
  if (!nearest) {
    return direct
      ? 'No fixed version is available yet. Watch the advisory, or evaluate an alternative package.'
      : 'No fixed version is available yet. Pressure the parent dependency to update, or override the version.';
  }
  if (direct) {
    return `Upgrade to ${name}@${nearest} or later (e.g. \`${INSTALL_COMMAND[manager]} ${name}@${nearest}\`).`;
  }
  return `Update the dependency that pulls in ${name} so it resolves to ${name}@${nearest} or later. If it cannot, force the resolution via an override.`;
}
