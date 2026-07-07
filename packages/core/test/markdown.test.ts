import { fileURLToPath } from 'node:url';
import { beforeAll, describe, expect, it } from 'vitest';
import { scan } from '../src/engine.js';
import { OsvDatabase } from '../src/osv/database.js';
import { toMarkdown } from '../src/report/markdown.js';
import type { ResolvedSource, VulnSource } from '../src/osv/source.js';
import type { Finding, OsvVulnerability, ScanResult } from '../src/types.js';

const projectDir = fileURLToPath(new URL('./fixtures/npm-v3', import.meta.url));

function stub(vulns: OsvVulnerability[]): VulnSource {
  const db = new OsvDatabase();
  db.addAll(vulns);
  const database: ResolvedSource['database'] = { source: 'offline', stale: false, warnings: [] };
  return { prepare: async () => ({ candidatesFor: (n) => db.vulnerabilitiesFor(n), database }) };
}

const advisory: OsvVulnerability = {
  id: 'GHSA-b',
  summary: 'RCE | pipe & <script>', // exercises GFM cell escaping (pipe + HTML)
  severity: [{ type: 'CVSS_V3', score: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H' }],
  affected: [
    {
      package: { ecosystem: 'npm', name: 'pkg-b' },
      ranges: [{ type: 'SEMVER', events: [{ introduced: '0' }, { fixed: '2.0.1' }] }],
    },
  ],
};

function cloneFinding(f: Finding, i: number): Finding {
  return { ...f, packageName: `pkg-${i}`, id: `GHSA-${i}` };
}

describe('Markdown reporter', () => {
  let result: ScanResult;
  beforeAll(async () => {
    result = await scan({ path: projectDir }, stub([advisory]));
  });

  it('renders a heading and severity counts from the summary', () => {
    const md = toMarkdown(result);
    expect(md).toContain('## 🛡️ lockhawk');
    expect(md).toContain('1 vulnerability'); // singular for a single finding
    expect(md).toContain('1 critical');
  });

  it('renders a findings row with package, linked advisory, and fix', () => {
    const md = toMarkdown(result);
    expect(md).toContain('pkg-b@2.0.0');
    expect(md).toContain('GHSA-b');
    expect(md).toContain('https://osv.dev/GHSA-b');
    expect(md).toContain('2.0.1'); // fixed version
  });

  it('escapes GFM table-breaking and HTML characters in cell text', () => {
    const md = toMarkdown(result);
    expect(md).toContain('RCE \\| pipe'); // pipe escaped so the row keeps its columns
    expect(md).not.toContain('<script>'); // raw HTML neutralized
    expect(md).toContain('&lt;script');
  });

  it('shows a clean-scan message and no table when there are no findings', async () => {
    const clean = await scan({ path: projectDir }, stub([]));
    const md = toMarkdown(clean);
    expect(md).toContain('No known vulnerabilities');
    expect(md).not.toContain('| Severity |');
  });

  it('caps the table and notes the remainder for large result sets', () => {
    const findings = Array.from({ length: 130 }, (_, i) => cloneFinding(result.findings[0]!, i));
    const many: ScanResult = {
      ...result,
      findings,
      summary: {
        ...result.summary,
        total: 130,
        critical: 130,
        vulnerablePackages: 130,
        fixable: 130,
      },
    };
    const md = toMarkdown(many);
    expect(md).toContain('30 more'); // 130 - MAX_ROWS(100)
    expect(md).not.toContain('pkg-129'); // beyond the cap, not rendered
  });
});
