import { fileURLToPath } from 'node:url';
import { beforeAll, describe, expect, it } from 'vitest';
import { scan } from '../src/engine.js';
import { OsvDatabase } from '../src/osv/database.js';
import { toJunit } from '../src/report/junit.js';
import type { ResolvedSource, VulnSource } from '../src/osv/source.js';
import type { OsvVulnerability, ScanResult } from '../src/types.js';

const projectDir = fileURLToPath(new URL('./fixtures/npm-v3', import.meta.url));

function stub(vulns: OsvVulnerability[]): VulnSource {
  const db = new OsvDatabase();
  db.addAll(vulns);
  const database: ResolvedSource['database'] = { source: 'offline', stale: false, warnings: [] };
  return { prepare: async () => ({ candidatesFor: (n) => db.vulnerabilitiesFor(n), database }) };
}

const advisory: OsvVulnerability = {
  id: 'GHSA-b',
  summary: 'pkg-b <script> & "danger"', // exercises XML escaping
  severity: [{ type: 'CVSS_V3', score: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H' }],
  affected: [
    {
      package: { ecosystem: 'npm', name: 'pkg-b' },
      ranges: [{ type: 'SEMVER', events: [{ introduced: '0' }, { fixed: '2.0.1' }] }],
    },
  ],
};

describe('JUnit reporter', () => {
  let result: ScanResult;
  beforeAll(async () => {
    result = await scan({ path: projectDir }, stub([advisory]));
  });

  it('emits one failed testcase per finding with detail', () => {
    const xml = toJunit(result);
    expect(xml).toContain('<?xml version="1.0" encoding="UTF-8"?>');
    expect(xml).toContain('failures="1"');
    expect(xml).toContain('tests="1"');
    expect(xml).toContain('classname="lockhawk.critical"');
    expect(xml).toContain('<failure');
    expect(xml).toContain('Fixed in: 2.0.1');
    // `>` in the path is XML-escaped within the failure body.
    expect(xml).toContain('Dependency path: demo@1.0.0 &gt; pkg-a@1.0.0 &gt; pkg-b@2.0.0');
  });

  it('escapes XML special characters from advisory text', () => {
    const xml = toJunit(result);
    expect(xml).toContain('&lt;script&gt;');
    expect(xml).not.toContain('<script>');
  });

  it('emits a single passing test for a clean scan', async () => {
    const clean = await scan({ path: projectDir }, stub([]));
    const xml = toJunit(clean);
    expect(xml).toContain('failures="0"');
    expect(xml).toContain('tests="1"');
    expect(xml).toContain('No known vulnerabilities');
    expect(xml).not.toContain('<failure');
  });
});
