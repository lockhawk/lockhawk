import { readFileSync, writeFileSync } from 'node:fs';
import type { ScanResult } from '@npm-scanner/core';
import { renderResult } from '../report/render.js';
import type { Format } from '../report/render.js';

interface ReportOptions {
  input: string;
  format?: Format;
  output?: string;
}

/** `report` — re-render a previously saved JSON result into another format. */
export async function runReport(opts: ReportOptions): Promise<void> {
  let result: ScanResult;
  try {
    result = JSON.parse(readFileSync(opts.input, 'utf8')) as ScanResult;
  } catch (err) {
    process.stderr.write(
      `npm-scanner: could not read ${opts.input}: ${err instanceof Error ? err.message : err}\n`,
    );
    process.exitCode = 2;
    return;
  }

  const rendered = await renderResult(result, opts.format ?? 'html');
  if (opts.output) {
    writeFileSync(opts.output, rendered.endsWith('\n') ? rendered : `${rendered}\n`);
    process.stderr.write(`Report written to ${opts.output}\n`);
  } else {
    process.stdout.write(`${rendered}\n`);
  }
}
