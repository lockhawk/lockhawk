import { describe, expect, it } from 'vitest';
import type { IncomingMessage, ServerResponse } from 'node:http';
import { createDashboardHandler } from '../src/commands/serve.js';

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

const req = (url: string) => ({ url }) as IncomingMessage;

describe('dashboard request handler', () => {
  const handler = createDashboardHandler('<html>DASHBOARD</html>', '{"findings":[]}');

  it('serves the dashboard with no-store so a re-run never shows a cached page', () => {
    const res = fakeRes();
    handler(req('/'), res);
    // The bug: without this, a browser keeps serving the previously-rendered
    // dashboard from cache when `serve` is re-run at the same localhost URL.
    expect(res.headers['cache-control']).toMatch(/no-store/);
    expect(res.headers['content-type']).toContain('text/html');
    expect(res.body).toContain('DASHBOARD');
  });

  it('serves the JSON result no-store as well', () => {
    const res = fakeRes();
    handler(req('/api/result'), res);
    expect(res.headers['cache-control']).toMatch(/no-store/);
    expect(res.headers['content-type']).toContain('application/json');
    expect(res.body).toContain('findings');
  });
});
