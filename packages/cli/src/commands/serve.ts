import { createServer } from 'node:http';
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

  const server = createServer((req, res) => {
    if (req.url && req.url.startsWith('/api/result')) {
      res.setHeader('content-type', 'application/json');
      res.end(json);
      return;
    }
    res.setHeader('content-type', 'text/html; charset=utf-8');
    res.end(html);
  });

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

function summaryLine(result: ScanResult): string {
  const s = result.summary;
  return s.total === 0
    ? '✓ No known vulnerabilities found.'
    : `${s.total} findings — ${s.critical} critical, ${s.high} high, ${s.medium} medium, ${s.low} low.`;
}
