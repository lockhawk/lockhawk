import { fileURLToPath } from 'node:url';
import { beforeAll, describe, expect, it } from 'vitest';
import { scan } from '../src/engine.js';
import { OsvDatabase } from '../src/osv/database.js';
import { toJson } from '../src/report/json.js';
import { toSarif } from '../src/report/sarif.js';
import { toHtml } from '../src/report/html.js';
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
  summary: 'pkg-b is vulnerable',
  severity: [{ type: 'CVSS_V3', score: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H' }],
  references: [{ url: 'https://example.com/advisory' }, { url: 'javascript:alert(1)' }],
  affected: [
    {
      package: { ecosystem: 'npm', name: 'pkg-b' },
      ranges: [{ type: 'SEMVER', events: [{ introduced: '0' }, { fixed: '2.0.1' }] }],
    },
  ],
};

let result: ScanResult;
beforeAll(async () => {
  result = await scan({ path: projectDir }, stub([advisory]));
});

describe('JSON reporter', () => {
  it('round-trips', () => {
    const parsed = JSON.parse(toJson(result)) as ScanResult;
    expect(parsed.findings).toHaveLength(1);
    expect(parsed.summary.critical).toBe(1);
  });
});

describe('SARIF reporter', () => {
  it('produces a valid 2.1.0 log with rules, results and fingerprints', () => {
    const sarif = toSarif(result);
    expect(sarif.version).toBe('2.1.0');
    const run = sarif.runs[0] as {
      tool: { driver: { rules: { id: string; properties?: Record<string, unknown> }[] } };
      results: { level: string; partialFingerprints: Record<string, string> }[];
    };
    expect(run.tool.driver.rules[0]?.id).toBe('GHSA-b');
    expect(run.tool.driver.rules[0]?.properties?.['security-severity']).toBe('9.8');
    expect(run.results[0]?.level).toBe('error'); // critical → error
    expect(run.results[0]?.partialFingerprints.lockhawkFinding).toBe('pkg-b@2.0.0@GHSA-b');
  });

  it('never emits a non-http(s) reference as a rule helpUri', async () => {
    const evil: OsvVulnerability = {
      ...advisory,
      id: 'GHSA-evil',
      references: [{ url: 'javascript:alert(1)' }, { url: 'https://example.com/ok' }],
    };
    const r = await scan({ path: projectDir }, stub([evil]));
    const run = toSarif(r).runs[0] as {
      tool: { driver: { rules: { id: string; helpUri?: string }[] } };
    };
    const rule = run.tool.driver.rules.find((x) => x.id === 'GHSA-evil');
    expect(rule?.helpUri).not.toContain('javascript:');
    expect(rule?.helpUri).toBe('https://example.com/ok');
  });
});

describe('HTML reporter', () => {
  let html: string;
  beforeAll(() => {
    html = toHtml(result);
  });

  it('renders the finding in a self-contained page', () => {
    expect(html).toContain('pkg-b');
    expect(html).toContain('GHSA-b');
  });

  it('renders http(s) references but never a javascript: href', () => {
    expect(html).toContain('href="https://example.com/advisory"');
    expect(html).not.toContain('href="javascript:');
  });

  it('loads no external resources and ships no client-side script', () => {
    // The dashboard is fully server-rendered: no <script> at all (no embedded
    // JSON blob, no React bundle), no remote <link>, and styles are inlined.
    expect(html).not.toContain('<script');
    expect(html).not.toMatch(/<link\b/);
    expect(html).toContain('<style>');
  });

  it('renders advisory details HTML-escaped, never as live markup', async () => {
    // Real OSV advisories embed HTML, <script> tags and regex/ReDoS payloads in
    // their details. None of it may become live markup in the rendered page.
    const payload =
      '<script>alert(1)</script> <img src=x onerror="alert(1)"> regex \'\\$&\' (.+)+$';
    const evil: OsvVulnerability = { ...advisory, id: 'GHSA-nasty', details: payload };
    const r = await scan({ path: projectDir }, stub([evil]));
    const out = toHtml(r);
    expect(out).not.toContain('<script>alert(1)</script>');
    expect(out).not.toContain('onerror="alert(1)"');
    expect(out).toContain('&lt;script&gt;alert(1)&lt;/script&gt;');
  });

  it('shows the advisory details in a collapsible block', async () => {
    const withDetails: OsvVulnerability = {
      ...advisory,
      id: 'GHSA-det',
      summary: 'short summary',
      details: 'First detail line.\nSecond detail line.',
    };
    const r = await scan({ path: projectDir }, stub([withDetails]));
    const out = toHtml(r);
    expect(out).toContain('<details');
    expect(out).toContain('First detail line.');
    expect(out).toContain('Second detail line.');
  });
});
