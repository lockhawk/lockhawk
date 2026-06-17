import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';
import { scan, shouldFail } from '../src/engine.js';
import { OsvDatabase } from '../src/osv/database.js';
import type { ResolvedSource, VulnSource } from '../src/osv/source.js';
import type { OsvVulnerability } from '../src/types.js';

const projectDir = fileURLToPath(new URL('./fixtures/npm-v3', import.meta.url));

/** A source backed by an in-memory DB — no network, fully deterministic. */
function stubSource(vulns: OsvVulnerability[], database?: Partial<ResolvedSource['database']>): VulnSource {
  const db = new OsvDatabase();
  db.addAll(vulns);
  return {
    prepare: async () => ({
      candidatesFor: (name) => db.vulnerabilitiesFor(name),
      database: { source: 'offline', stale: false, warnings: [], ...database },
    }),
  };
}

const critical = (name: string, fixed?: string): OsvVulnerability => ({
  id: `GHSA-${name}`,
  summary: `${name} flaw`,
  severity: [{ type: 'CVSS_V3', score: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H' }],
  affected: [
    {
      package: { ecosystem: 'npm', name },
      ranges: [{ type: 'SEMVER', events: fixed ? [{ introduced: '0' }, { fixed }] : [{ introduced: '0' }] }],
    },
  ],
});

describe('scan engine', () => {
  it('assembles a complete ScanResult', async () => {
    const result = await scan({ path: projectDir }, stubSource([critical('pkg-b', '2.0.1')]));

    expect(result.tool.name).toBe('npm-scanner');
    expect(result.target.manager).toBe('npm');
    expect(result.target.root.name).toBe('demo');
    expect(result.findings).toHaveLength(1);
    expect(result.summary.critical).toBe(1);
    expect(result.summary.vulnerablePackages).toBe(1);
    expect(result.summary.fixable).toBe(1);
    expect(result.stats.totalPackages).toBe(3);
    expect(result.database.source).toBe('offline');
    expect(typeof result.scannedAt).toBe('string');
  });

  it('returns no findings for a clean project', async () => {
    const result = await scan({ path: projectDir }, stubSource([]));
    expect(result.findings).toHaveLength(0);
    expect(result.summary.total).toBe(0);
  });

  it('respects prodOnly (drops dev dependency findings)', async () => {
    const result = await scan({ path: projectDir, prodOnly: true }, stubSource([critical('pkg-d')]));
    expect(result.findings).toHaveLength(0);
  });

  it('applies the severity threshold filter', async () => {
    const low: OsvVulnerability = {
      id: 'GHSA-low',
      database_specific: { severity: 'LOW' },
      affected: [{ package: { ecosystem: 'npm', name: 'pkg-b' }, ranges: [{ type: 'SEMVER', events: [{ introduced: '0' }] }] }],
    };
    const result = await scan({ path: projectDir, severityThreshold: 'high' }, stubSource([low]));
    expect(result.findings).toHaveLength(0);
  });

  it('sorts findings by severity (critical first)', async () => {
    const low: OsvVulnerability = {
      id: 'GHSA-low',
      database_specific: { severity: 'LOW' },
      affected: [{ package: { ecosystem: 'npm', name: 'pkg-d' }, ranges: [{ type: 'SEMVER', events: [{ introduced: '0' }] }] }],
    };
    const result = await scan({ path: projectDir }, stubSource([critical('pkg-b'), low]));
    expect(result.findings[0]!.severity.level).toBe('critical');
  });
});

describe('shouldFail (exit-code gating)', () => {
  const summary = { total: 0, critical: 0, high: 0, medium: 0, low: 0, unknown: 0, none: 0, vulnerablePackages: 0, fixable: 0 };

  it('fails when a finding meets the threshold', () => {
    expect(shouldFail({ ...summary, high: 1 }, 'high')).toBe(true);
    expect(shouldFail({ ...summary, critical: 1 }, 'high')).toBe(true);
  });

  it('passes when findings are below the threshold', () => {
    expect(shouldFail({ ...summary, medium: 3 }, 'high')).toBe(false);
    expect(shouldFail({ ...summary, low: 5, medium: 2 }, 'high')).toBe(false);
  });
});
