import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';
import { loadDependencyGraph } from '../src/lockfiles/normalize.js';
import { buildFindings } from '../src/match/findings.js';
import { dedupeVulnerabilities } from '../src/match/dedupe.js';
import { OsvDatabase } from '../src/osv/database.js';
import type { OsvVulnerability } from '../src/types.js';

const graph = loadDependencyGraph(fileURLToPath(new URL('./fixtures/npm-v3', import.meta.url)));

const advisory = (
  overrides: Partial<OsvVulnerability> & { id: string; name: string; fixed?: string },
): OsvVulnerability => ({
  id: overrides.id,
  aliases: overrides.aliases,
  summary: overrides.summary ?? `${overrides.name} is vulnerable`,
  severity: overrides.severity ?? [
    { type: 'CVSS_V3', score: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H' },
  ],
  references: overrides.references,
  database_specific: overrides.database_specific,
  affected: [
    {
      package: { ecosystem: 'npm', name: overrides.name },
      // Default: affects every version (no fix yet). Pass `fixed` to bound it.
      ranges: [
        {
          type: 'SEMVER',
          events: overrides.fixed
            ? [{ introduced: '0' }, { fixed: overrides.fixed }]
            : [{ introduced: '0' }],
        },
      ],
    },
  ],
});

function db(...vulns: OsvVulnerability[]): (name: string) => OsvVulnerability[] {
  const database = new OsvDatabase();
  database.addAll(vulns);
  return (name) => database.vulnerabilitiesFor(name);
}

describe('buildFindings', () => {
  it('reports vulnerable packages with the dependency path and a fix recommendation', () => {
    const findings = buildFindings(
      graph,
      db(advisory({ id: 'GHSA-b', name: 'pkg-b', fixed: '2.0.1' })),
    );
    expect(findings).toHaveLength(1);
    const f = findings[0]!;
    expect(f.packageName).toBe('pkg-b');
    expect(f.severity.level).toBe('critical');
    expect(f.fixedVersions).toContain('2.0.1');
    expect(f.dependencyPaths[0]).toEqual(['demo@1.0.0', 'pkg-a@1.0.0', 'pkg-b@2.0.0']);
    expect(f.recommendation).toMatch(/2\.0\.1/);
    expect(f.direct).toBe(false);
  });

  it('does not report packages whose installed version is already fixed', () => {
    // pkg-a@1.0.0 with an advisory fixed in 1.0.0 → not affected.
    const notAffecting = advisory({ id: 'GHSA-a', name: 'pkg-a' });
    notAffecting.affected![0]!.ranges![0]!.events = [{ introduced: '0' }, { fixed: '1.0.0' }];
    expect(buildFindings(graph, db(notAffecting))).toHaveLength(0);
  });

  it('drops dev dependencies when prodOnly is set', () => {
    const all = db(
      advisory({ id: 'GHSA-d', name: 'pkg-d' }),
      advisory({ id: 'GHSA-b', name: 'pkg-b' }),
    );
    expect(buildFindings(graph, all)).toHaveLength(2);
    expect(buildFindings(graph, all, { prodOnly: true })).toHaveLength(1);
  });

  it('suppresses ignored advisory ids (and aliases)', () => {
    const lookup = db(advisory({ id: 'GHSA-b', name: 'pkg-b', aliases: ['CVE-2024-0001'] }));
    expect(buildFindings(graph, lookup, { ignore: new Set(['CVE-2024-0001']) })).toHaveLength(0);
  });

  it('collapses aliased advisories into a single finding', () => {
    const lookup = db(
      advisory({ id: 'GHSA-b', name: 'pkg-b', aliases: ['CVE-2024-0002'] }),
      advisory({ id: 'CVE-2024-0002', name: 'pkg-b' }),
    );
    const findings = buildFindings(graph, lookup);
    expect(findings).toHaveLength(1);
    expect(findings[0]!.id).toBe('CVE-2024-0002'); // canonical id prefers CVE
  });
});

describe('dedupeVulnerabilities', () => {
  it('unions ids, aliases and references across a group', () => {
    const merged = dedupeVulnerabilities([
      { id: 'GHSA-x', aliases: ['CVE-1'], references: [{ url: 'https://a' }] },
      { id: 'CVE-1', references: [{ url: 'https://b' }] },
    ]);
    expect(merged).toHaveLength(1);
    expect(merged[0]!.id).toBe('CVE-1');
    expect(merged[0]!.references?.map((r) => r.url).sort()).toEqual(['https://a', 'https://b']);
  });
});
