import { writeFileSync } from 'node:fs';
import { join, resolve } from 'node:path';
import ora from 'ora';
import { LockfileError, scan, shouldFail } from '@lockhawk/core';
import type { ScanOptions, ScanResult, Severity, SourceMode } from '@lockhawk/core';
import { renderResult } from '../report/render.js';
import type { Format } from '../report/render.js';
import { loadFileConfig, readIgnoreFile } from '../config.js';

export interface ScanCliOptions {
  format?: Format;
  output?: string;
  severityThreshold?: Severity;
  failOn?: Severity;
  offline?: boolean;
  online?: boolean;
  strictNetwork?: boolean;
  prodOnly?: boolean;
  ignore?: string[];
  ignoreFile?: string;
  cacheDir?: string;
  cacheTtl?: number;
  cache?: boolean; // commander sets false for --no-cache
  concurrency?: number;
}

/** Stable exit-code contract (documented for CI). */
export const EXIT = { OK: 0, FINDINGS: 1, USAGE: 2, INTERNAL: 3, NETWORK: 4 } as const;

export async function runScan(pathArg: string, cli: ScanCliOptions): Promise<void> {
  const dir = resolve(pathArg || '.');
  const fileConfig = loadFileConfig(dir);

  const mode: SourceMode = cli.offline
    ? 'offline'
    : cli.online
      ? 'online'
      : (fileConfig.mode ?? 'auto');
  const format: Format = cli.format ?? 'table';
  const failOn: Severity = cli.failOn ?? fileConfig.failOn ?? 'high';

  const ignore = [
    ...(cli.ignore ?? []),
    ...(fileConfig.ignore ?? []),
    ...readIgnoreFile(cli.ignoreFile ?? join(dir, '.lockhawkignore')),
  ];

  const useSpinner = format === 'table' && Boolean(process.stderr.isTTY) && !process.env.CI;
  const spinner = useSpinner
    ? ora({ stream: process.stderr, text: 'Scanning…' }).start()
    : undefined;

  const options: ScanOptions = {
    path: dir,
    mode,
    cacheDir: cli.cacheDir,
    cacheTtlHours: cli.cacheTtl,
    noCache: cli.cache === false,
    concurrency: cli.concurrency,
    prodOnly: cli.prodOnly ?? fileConfig.prodOnly,
    ignore,
    strictNetwork: cli.strictNetwork,
    severityThreshold: cli.severityThreshold ?? fileConfig.severityThreshold,
    onProgress: (message) => {
      if (spinner) spinner.text = message;
    },
  };

  let result: ScanResult;
  try {
    result = await scan(options);
  } catch (err) {
    spinner?.stop();
    const message = err instanceof Error ? err.message : String(err);
    process.stderr.write(`lockhawk: ${message}\n`);
    if (err instanceof LockfileError) process.exitCode = EXIT.USAGE;
    else process.exitCode = cli.strictNetwork ? EXIT.NETWORK : EXIT.INTERNAL;
    return;
  }
  spinner?.stop();

  const rendered = await renderResult(result, format);
  if (cli.output) {
    writeFileSync(cli.output, rendered.endsWith('\n') ? rendered : `${rendered}\n`);
    process.stderr.write(`Report written to ${cli.output}\n${briefSummary(result)}\n`);
  } else {
    process.stdout.write(`${rendered}\n`);
  }

  process.exitCode = shouldFail(result.summary, failOn) ? EXIT.FINDINGS : EXIT.OK;
}

function briefSummary(result: ScanResult): string {
  const s = result.summary;
  if (s.total === 0) return '✓ No known vulnerabilities found.';
  const parts = (['critical', 'high', 'medium', 'low', 'unknown'] as const)
    .filter((level) => s[level] > 0)
    .map((level) => `${s[level]} ${level}`);
  return `Found ${s.total} ${s.total === 1 ? 'vulnerability' : 'vulnerabilities'} (${parts.join(', ')}).`;
}
