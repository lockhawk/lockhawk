import { toHtml, toJson, toJunit, toSarifString } from '@lockhawk/core';
import type { ScanResult } from '@lockhawk/core';
import { renderTable } from './table.js';
import { loadReportShell } from './shell.js';

export type Format = 'table' | 'json' | 'sarif' | 'html' | 'junit';

/** Render a scan result into the requested output format. */
export async function renderResult(result: ScanResult, format: Format): Promise<string> {
  switch (format) {
    case 'json':
      return toJson(result);
    case 'sarif':
      return toSarifString(result);
    case 'junit':
      return toJunit(result);
    case 'html':
      return toHtml(result, await loadReportShell());
    default:
      return renderTable(result);
  }
}
