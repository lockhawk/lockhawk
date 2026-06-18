import { fileURLToPath } from 'node:url';
import { beforeAll, describe, expect, it } from 'vitest';
import { scan } from '../src/engine.js';
import { OsvDatabase } from '../src/osv/database.js';
import { toJson } from '../src/report/json.js';
import { toSarif } from '../src/report/sarif.js';
import { toHtml, DATA_MARKER } from '../src/report/html.js';
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

describe('HTML reporter (fallback template)', () => {
  let html: string;
  beforeAll(() => {
    html = toHtml(result);
  });

  it('embeds the scan data and renders the finding', () => {
    expect(html).toContain('__SCAN_RESULT__');
    expect(html).toContain('pkg-b');
    expect(html).toContain('GHSA-b');
  });

  it('renders http(s) references but never a javascript: href', () => {
    expect(html).toContain('href="https://example.com/advisory"');
    // The URL may appear as inert JSON data, but never as a live link.
    expect(html).not.toContain('href="javascript:');
  });

  it('loads no external resources (inline styles, no remote scripts/links)', () => {
    expect(html).not.toMatch(/<script[^>]+src=/);
    expect(html).not.toMatch(/<link\b/);
    expect(html).toContain('<style>');
  });
});

describe('HTML reporter (shell injection)', () => {
  // A shell mimicking the built report-UI: a marker in <head> and the inlined
  // app bundle + closing </script> after it.
  const shell = `<!doctype html>\n<html lang="en"><head>\n${DATA_MARKER}\n<script>boot();</script></head><body></body></html>`;

  // Advisory text that exercises every special String.replace replacement
  // pattern: $$, $&, $\` (prefix), $' (suffix) and $1 (capture group). Real OSV
  // advisories embed exactly these — e.g. regex-escape code (`'\\$&'`) and
  // ReDoS payloads written inline as `(.+)+$`.
  const nasty = "regex escape uses '\\$&'; ReDoS payload `(.+)+$`; literal $$ and $' and $1 too";

  async function renderWithDetails(details: string): Promise<{ html: string; data: ScanResult }> {
    const evil: OsvVulnerability = { ...advisory, id: 'GHSA-nasty', details };
    const r = await scan({ path: projectDir }, stub([evil]));
    const out = toHtml(r, shell);
    const m = out.match(/window\.__SCAN_RESULT__ = ([\s\S]*?);<\/script>/);
    if (!m) throw new Error('embedded data script not found');
    return { html: out, data: JSON.parse(m[1]!) as ScanResult };
  }

  it('injects the data without interpreting $ replacement patterns', async () => {
    const { data } = await renderWithDetails(nasty);
    const finding = data.findings.find((f) => f.id === 'GHSA-nasty');
    // The advisory text must survive verbatim — no $-pattern expansion.
    expect(finding?.details).toBe(nasty);
  });

  it('does not leak the data marker or close the script tag early', async () => {
    const { html: out } = await renderWithDetails(nasty);
    // The marker must be fully consumed, not re-emitted by a `$&` expansion.
    expect(out).not.toContain(DATA_MARKER);
    // Exactly two scripts survive: the injected data script and the app's.
    expect((out.match(/<\/script>/g) ?? []).length).toBe(2);
    // The doctype/head must appear exactly once (a `$\`` expansion duplicates it).
    expect((out.match(/<!doctype html>/g) ?? []).length).toBe(1);
  });
});
