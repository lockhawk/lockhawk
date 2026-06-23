import { createServer } from 'node:http';
import type { IncomingMessage, ServerResponse } from 'node:http';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import open from 'open';
import { scan, toHtml, toJson } from '@lockhawk/core';
import type { ScanResult, SourceMode } from '@lockhawk/core';
import { loadReportShell } from '../report/shell.js';

interface ServeOptions {
  input?: string;
  port?: number;
  open?: boolean; // commander sets false for --no-open
  offline?: boolean;
  online?: boolean;
}

/** `serve` — run a scan (or load a saved result) and serve the dashboard locally. */
export async function runServe(pathArg: string, opts: ServeOptions): Promise<void> {
  let result: ScanResult;
  if (opts.input) {
    result = JSON.parse(readFileSync(opts.input, 'utf8')) as ScanResult;
  } else {
    const mode: SourceMode = opts.offline ? 'offline' : opts.online ? 'online' : 'auto';
    process.stderr.write('Scanning…\n');
    result = await scan({ path: resolve(pathArg || '.'), mode });
  }

  const html = toHtml(result, await loadReportShell());
  const json = toJson(result);

  const server = createServer(createDashboardHandler(html, json));

  const port = opts.port ?? 7777;
  // Bind to loopback only — the dashboard embeds the full dependency tree and
  // scan result, which should not be exposed to the local network.
  server.listen(port, '127.0.0.1', () => {
    const url = `http://localhost:${port}`;
    process.stderr.write(
      `\nlockhawk dashboard running at ${url}\n${summaryLine(result)}\nPress Ctrl+C to stop.\n`,
    );
    if (opts.open !== false) void open(url).catch(() => undefined);
  });
}

/**
 * Build the request handler for the dashboard server.
 *
 * Every `serve` run rescans and re-renders the dashboard from scratch, but it is
 * always served from the same `http://localhost:<port>/` URL. Without an explicit
 * caching policy a browser treats the response as cacheable and, on a re-run,
 * shows the *previously* rendered dashboard instead of fetching the new one. We
 * send `Cache-Control: no-store` so the browser always pulls the current report.
 */
export function createDashboardHandler(
  html: string,
  json: string,
): (req: IncomingMessage, res: ServerResponse) => void {
  return (req, res) => {
    res.setHeader('cache-control', 'no-store, max-age=0');
    res.setHeader('x-content-type-options', 'nosniff');

    // The dashboard embeds the full dependency tree and scan result. The server
    // is bound to loopback, but a DNS-rebinding attack can still point a hostile
    // domain at 127.0.0.1 and have a victim's browser reach it. Only honour
    // requests actually addressed to localhost so such cross-origin reads fail.
    if (!isLoopbackHost(req.headers?.host)) {
      res.statusCode = 403;
      res.end('Forbidden');
      return;
    }

    // Exact path match (not `startsWith`) so only the intended endpoint serves
    // the result payload.
    const pathname = (req.url ?? '').split('?')[0] ?? '';
    if (pathname === '/api/result') {
      res.setHeader('content-type', 'application/json');
      res.end(json);
      return;
    }
    res.setHeader('content-type', 'text/html; charset=utf-8');
    res.end(html);
  };
}

/** True only for loopback `Host` headers (`localhost`/`127.0.0.1`/`[::1]`, any port). */
export function isLoopbackHost(host: string | undefined): boolean {
  if (!host) return false;
  const name = host.replace(/:\d+$/, '').toLowerCase();
  return name === 'localhost' || name === '127.0.0.1' || name === '[::1]' || name === '::1';
}

/**
 * One-line summary printed under the dashboard URL. Includes the count of unique
 * packages checked so the output is directly comparable to `npm audit`'s
 * "audited N packages" — querying OSV per unique `name@version`, this is the
 * coverage figure (deduped install instances, local workspace packages excluded).
 */
export function summaryLine(result: ScanResult): string {
  const n = result.stats.uniquePackages;
  const across = `across ${n} ${n === 1 ? 'package' : 'packages'}`;
  const s = result.summary;
  return s.total === 0
    ? `✓ No known vulnerabilities found ${across}.`
    : `${s.total} findings ${across} — ${s.critical} critical, ${s.high} high, ${s.medium} medium, ${s.low} low.`;
}
