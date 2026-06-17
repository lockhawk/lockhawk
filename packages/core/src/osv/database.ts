import type { OsvVulnerability } from '../types.js';

/**
 * In-memory index of OSV advisories for the npm ecosystem, keyed by package
 * name. Populated either from the downloaded offline DB zip (M3) or from online
 * API responses, then queried per installed package during a scan.
 *
 * Withdrawn advisories are dropped on insert so they can never produce a finding.
 */
export class OsvDatabase {
  private readonly byName = new Map<string, OsvVulnerability[]>();
  private readonly ids = new Set<string>();

  add(vuln: OsvVulnerability): void {
    if (vuln.withdrawn) return;
    if (this.ids.has(vuln.id)) return;
    this.ids.add(vuln.id);

    const names = new Set<string>();
    for (const affected of vuln.affected ?? []) {
      const ecosystem = affected.package?.ecosystem;
      if (ecosystem && ecosystem !== 'npm') continue;
      if (affected.package?.name) names.add(affected.package.name);
    }
    for (const name of names) {
      const list = this.byName.get(name);
      if (list) list.push(vuln);
      else this.byName.set(name, [vuln]);
    }
  }

  addAll(vulns: Iterable<OsvVulnerability>): void {
    for (const vuln of vulns) this.add(vuln);
  }

  /** Candidate advisories that name `packageName` (still need a version check). */
  vulnerabilitiesFor(packageName: string): OsvVulnerability[] {
    return this.byName.get(packageName) ?? [];
  }

  /** Number of distinct advisories indexed. */
  get size(): number {
    return this.ids.size;
  }
}
