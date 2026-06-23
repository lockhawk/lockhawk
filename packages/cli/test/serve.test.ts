import { describe, expect, it } from 'vitest';
import type { IncomingMessage, ServerResponse } from 'node:http';
import type { ScanResult } from '@lockhawk/core';
import { createDashboardHandler, summaryLine } from '../src/commands/serve.js';

/** Minimal ServerResponse stand-in that records headers and the written body. */
function fakeRes(): ServerResponse & { headers: Record<string, string>; body: string } {
  const res = {
    headers: {} as Record<string, string>,
    body: '',
    setHeader(key: string, value: string) {
      this.headers[key.toLowerCase()] = value;
    },
    end(chunk?: string) {
      if (chunk) this.body = chunk;
    },
  };
  return res as unknown as ServerResponse & { headers: Record<string, string>; body: string };
}

const req = (url: string, host = 'localhost:7777') =>
  ({ url, headers: { host } }) as unknown as IncomingMessage;

describe('dashboard request handler', () => {
  const handler = createDashboardHandler('<html>DASHBOARD</html>', '{"findings":[]}');

  it('serves the dashboard with no-store so a re-run never shows a cached page', () => {
    const res = fakeRes();
    handler(req('/'), res);
    // The bug: without this, a browser keeps serving the previously-rendered
    // dashboard from cache when `serve` is re-run at the same localhost URL.
    expect(res.headers['cache-control']).toMatch(/no-store/);
    expect(res.headers['content-type']).toContain('text/html');
    expect(res.headers['x-content-type-options']).toBe('nosniff');
    expect(res.body).toContain('DASHBOARD');
  });

  it('serves the JSON result no-store as well', () => {
    const res = fakeRes();
    handler(req('/api/result'), res);
    expect(res.headers['cache-control']).toMatch(/no-store/);
    expect(res.headers['content-type']).toContain('application/json');
    expect(res.body).toContain('findings');
  });

  it('rejects non-loopback Host headers (DNS-rebinding defense)', () => {
    const res = fakeRes();
    handler(req('/api/result', 'evil.example.com'), res);
    expect(res.statusCode).toBe(403);
    expect(res.body).not.toContain('findings');
  });

  it('does not serve the result on a near-miss path (exact match only)', () => {
    const res = fakeRes();
    handler(req('/api/results-leak'), res);
    // Falls through to the HTML dashboard rather than leaking JSON.
    expect(res.headers['content-type']).toContain('text/html');
    expect(res.body).toContain('DASHBOARD');
  });
});

describe('summaryLine', () => {
  const make = (summary: Partial<ScanResult['summary']>, uniquePackages: number): ScanResult =>
    ({
      summary: {
        total: 0,
        critical: 0,
        high: 0,
        medium: 0,
        low: 0,
        unknown: 0,
        none: 0,
        vulnerablePackages: 0,
        fixable: 0,
        ...summary,
      },
      stats: {
        totalPackages: uniquePackages,
        uniquePackages,
        directDependencies: 0,
        unscannable: 0,
      },
    }) as ScanResult;

  it('reports the scanned package count alongside findings (comparable to npm audit)', () => {
    const line = summaryLine(make({ total: 126, critical: 1, high: 53, medium: 63, low: 9 }, 1036));
    expect(line).toBe('126 findings across 1036 packages — 1 critical, 53 high, 63 medium, 9 low.');
  });

  it('reports the package count even when there are no vulnerabilities', () => {
    expect(summaryLine(make({ total: 0 }, 42))).toBe(
      '✓ No known vulnerabilities found across 42 packages.',
    );
  });

  it('singularizes a one-package scan', () => {
    expect(summaryLine(make({ total: 0 }, 1))).toBe(
      '✓ No known vulnerabilities found across 1 package.',
    );
  });
});
