import semver from 'semver';
import type { OsvAffected, OsvEvent, OsvVulnerability } from '../types.js';

/**
 * Whether `version` is affected by a single OSV `affected` entry — the heart of
 * accuracy. We honor enumerated `versions[]` exactly and walk `ranges[].events`
 * with the canonical OSV sweep. We never coerce a non-semver installed version
 * into a range match (that would manufacture false positives); such versions
 * only match via the explicit `versions[]` list.
 */
export function isVersionAffected(version: string, affected: OsvAffected): boolean {
  if (affected.versions?.includes(version)) return true;

  const installed = semver.parse(version, { loose: true });
  if (!installed) return false; // non-semver: only the enumerated list (checked above) can match

  for (const range of affected.ranges ?? []) {
    if (range.type === 'GIT') continue; // not applicable to npm
    if (rangeAffects(installed, range.events)) return true;
  }
  return false;
}

type Boundary = { kind: 'introduced' | 'fixed' | 'last_affected'; version: semver.SemVer | null };

/**
 * OSV event sweep: sort the introduced/fixed/last_affected boundaries ascending
 * and replay them. `introduced` opens the affected interval (`"0"` = from the
 * beginning), `fixed` closes it exclusively, `last_affected` closes it inclusively.
 */
function rangeAffects(installed: semver.SemVer, events: OsvEvent[]): boolean {
  const boundaries: Boundary[] = [];
  for (const event of events) {
    if (event.introduced !== undefined) {
      boundaries.push({
        kind: 'introduced',
        version: event.introduced === '0' ? null : parse(event.introduced),
      });
    } else if (event.fixed !== undefined) {
      boundaries.push({ kind: 'fixed', version: parse(event.fixed) });
    } else if (event.last_affected !== undefined) {
      boundaries.push({ kind: 'last_affected', version: parse(event.last_affected) });
    }
    // `limit` events are not affected-state boundaries; ignore.
  }

  boundaries.sort((a, b) => {
    if (a.version === null) return b.version === null ? 0 : -1; // introduced:0 sorts first (-inf)
    if (b.version === null) return 1;
    return a.version.compare(b.version);
  });

  let affected = false;
  for (const boundary of boundaries) {
    if (boundary.version === null) {
      affected = true; // introduced from the beginning
      continue;
    }
    const cmp = installed.compare(boundary.version);
    switch (boundary.kind) {
      case 'introduced':
        if (cmp >= 0) affected = true;
        break;
      case 'fixed':
        if (cmp >= 0) affected = false; // fixed is exclusive
        break;
      case 'last_affected':
        if (cmp > 0) affected = false; // last_affected is inclusive
        break;
    }
  }
  return affected;
}

function parse(version: string): semver.SemVer | null {
  return semver.parse(version, { loose: true }) ?? semver.coerce(version);
}

export interface VulnMatch {
  affected: boolean;
  /** Distinct `fixed` versions across the matching affected entries. */
  fixedVersions: string[];
}

/**
 * Whether a whole OSV record affects `name@version` for the npm ecosystem, and
 * which fixed versions it advertises. Withdrawn advisories never match.
 */
export function vulnerabilityAffects(
  name: string,
  version: string,
  vuln: OsvVulnerability,
): VulnMatch {
  if (vuln.withdrawn) return { affected: false, fixedVersions: [] };

  let affected = false;
  const fixed = new Set<string>();
  for (const entry of vuln.affected ?? []) {
    const ecosystem = entry.package?.ecosystem;
    if (ecosystem && ecosystem !== 'npm') continue;
    if (entry.package?.name && entry.package.name !== name) continue;
    if (!isVersionAffected(version, entry)) continue;
    affected = true;
    for (const range of entry.ranges ?? []) {
      for (const event of range.events) {
        if (event.fixed) fixed.add(event.fixed);
      }
    }
  }
  return { affected, fixedVersions: [...fixed] };
}

/**
 * The lowest advertised fixed version strictly greater than `installed`
 * (the nearest safe upgrade), or `undefined` if none is known.
 */
export function nearestFix(installed: string, fixedVersions: string[]): string | undefined {
  const current = semver.parse(installed, { loose: true });
  const candidates = fixedVersions
    .map((v) => semver.parse(v, { loose: true }) ?? semver.coerce(v))
    .filter((v): v is semver.SemVer => v !== null)
    .filter((v) => (current ? v.compare(current) > 0 : true))
    .sort((a, b) => a.compare(b));
  return candidates[0]?.version;
}
