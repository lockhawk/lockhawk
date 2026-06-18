import type { ScanResult, Severity } from '../types.js';

/** Placeholder the report UI shell embeds so we can inject scan data at scan time. */
export const DATA_MARKER = '<!--LOCKHAWK_DATA-->';

/** Escape a JSON string for safe embedding inside a <script> tag. */
function embed(result: ScanResult): string {
  // U+2028/U+2029 are legal in JSON but terminate lines inside inline <script>.
  const json = JSON.stringify(result)
    .replace(/</g, '\\u003c')
    .replace(/\u2028/g, '\\u2028')
    .replace(/\u2029/g, '\\u2029');
  return `<script>window.__SCAN_RESULT__ = ${json};</script>`;
}

/**
 * Produce a self-contained HTML report. When given the built report-UI `shell`
 * (M6), the scan data is injected into it; otherwise a dependency-free fallback
 * template is rendered so `--format html` always works.
 */
export function toHtml(result: ScanResult, shell?: string): string {
  const dataScript = embed(result);
  // A function replacer is required: a string replacement would interpret `$&`,
  // `$\``, `$'`, `$1` and `$$` inside the embedded JSON as special patterns,
  // corrupting (and breaking out of) the data script. Advisory text routinely
  // contains these (regex-escape idioms, ReDoS payloads), so escape them away.
  if (shell) {
    if (shell.includes(DATA_MARKER)) return shell.replace(DATA_MARKER, () => dataScript);
    return shell.replace('</head>', () => `${dataScript}</head>`);
  }
  return fallbackTemplate(result, dataScript);
}

const SEVERITY_COLORS: Record<Severity, string> = {
  critical: '#b4232c',
  high: '#d9822b',
  medium: '#c9a227',
  low: '#3a7bd5',
  unknown: '#7a7a7a',
  none: '#3a9e54',
};

function esc(text: string): string {
  return text.replace(
    /[&<>"]/g,
    (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' })[c]!,
  );
}

/** Only http(s) URLs are safe to render as links (blocks javascript:/data: hrefs). */
function httpHref(url: string): string | undefined {
  try {
    const u = new URL(url);
    return u.protocol === 'http:' || u.protocol === 'https:' ? url : undefined;
  } catch {
    return undefined;
  }
}

function fallbackTemplate(result: ScanResult, dataScript: string): string {
  const { summary } = result;
  const cards = (['critical', 'high', 'medium', 'low', 'unknown'] as Severity[])
    .map(
      (sev) => `
      <div class="card" style="border-top:4px solid ${SEVERITY_COLORS[sev]}">
        <div class="count">${summary[sev]}</div><div class="label">${sev}</div>
      </div>`,
    )
    .join('');

  const rows = result.findings
    .map((f) => {
      const path = f.dependencyPaths[0]?.join(' › ') ?? f.packageName;
      const refs = f.references
        .slice(0, 3)
        .map((u) => httpHref(u))
        .filter((u): u is string => u !== undefined)
        .map((u) => `<a href="${esc(u)}" target="_blank" rel="noopener">link</a>`)
        .join(' ');
      return `
      <tr>
        <td><span class="pill" style="background:${SEVERITY_COLORS[f.severity.level]}">${f.severity.level}${
          f.severity.score ? ` ${f.severity.score}` : ''
        }</span></td>
        <td><code>${esc(f.packageName)}@${esc(f.version)}</code><div class="scope">${f.scope}${
          f.direct ? ' · direct' : ''
        }</div></td>
        <td><a href="https://osv.dev/${esc(f.id)}" target="_blank" rel="noopener">${esc(f.id)}</a></td>
        <td>${esc(f.summary)}<div class="path">${esc(path)}</div></td>
        <td>${f.fixedVersions[0] ? esc(f.fixedVersions[0]) : '—'}</td>
        <td>${refs}</td>
      </tr>`;
    })
    .join('');

  const dbWarnings = result.database.warnings
    .map((w) => `<div class="warn">⚠ ${esc(w)}</div>`)
    .join('');

  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>lockhawk report — ${esc(result.target.root.name)}</title>
${dataScript}
<style>
  :root { color-scheme: light dark; }
  * { box-sizing: border-box; }
  body { font: 15px/1.5 -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; margin: 0; background: #f6f7f9; color: #1c1e21; }
  header { background: #11161d; color: #fff; padding: 24px 32px; }
  header h1 { margin: 0 0 4px; font-size: 20px; }
  header .meta { color: #9aa4b2; font-size: 13px; }
  main { max-width: 1100px; margin: 0 auto; padding: 24px 32px; }
  .cards { display: grid; grid-template-columns: repeat(5, 1fr); gap: 12px; margin-bottom: 8px; }
  .card { background: #fff; border-radius: 8px; padding: 14px 16px; box-shadow: 0 1px 3px rgba(0,0,0,.08); }
  .card .count { font-size: 28px; font-weight: 700; }
  .card .label { text-transform: capitalize; color: #6b7280; font-size: 13px; }
  .warn { background: #fff7e6; border: 1px solid #ffd591; color: #874d00; padding: 8px 12px; border-radius: 6px; margin: 12px 0; font-size: 13px; }
  table { width: 100%; border-collapse: collapse; background: #fff; border-radius: 8px; overflow: hidden; box-shadow: 0 1px 3px rgba(0,0,0,.08); margin-top: 16px; }
  th, td { text-align: left; padding: 10px 12px; border-bottom: 1px solid #eef0f3; vertical-align: top; font-size: 13px; }
  th { background: #f0f2f5; font-size: 12px; text-transform: uppercase; letter-spacing: .03em; color: #6b7280; }
  .pill { color: #fff; padding: 2px 8px; border-radius: 999px; font-size: 12px; text-transform: capitalize; white-space: nowrap; }
  .scope, .path { color: #6b7280; font-size: 12px; }
  .path { margin-top: 4px; }
  code { background: #eef0f3; padding: 1px 5px; border-radius: 4px; }
  .empty { background: #fff; border-radius: 8px; padding: 40px; text-align: center; color: #3a9e54; font-size: 18px; box-shadow: 0 1px 3px rgba(0,0,0,.08); }
  footer { max-width: 1100px; margin: 0 auto; padding: 16px 32px 40px; color: #9aa4b2; font-size: 12px; }
</style>
</head>
<body>
<header>
  <h1>lockhawk report</h1>
  <div class="meta">${esc(result.target.root.name)}${
    result.target.root.version ? `@${esc(result.target.root.version)}` : ''
  } · ${esc(result.target.manager)} · ${result.stats.totalPackages} packages · scanned ${esc(result.scannedAt)}</div>
</header>
<main>
  <div class="cards">${cards}</div>
  ${dbWarnings}
  ${
    result.findings.length === 0
      ? '<div class="empty">✓ No known vulnerabilities found.</div>'
      : `<table>
    <thead><tr><th>Severity</th><th>Package</th><th>Advisory</th><th>Summary &amp; path</th><th>Fixed in</th><th>Refs</th></tr></thead>
    <tbody>${rows}</tbody>
  </table>`
  }
</main>
<footer>Generated by lockhawk v${esc(result.tool.version)} · data from OSV.dev · database: ${esc(
    result.database.source,
  )}</footer>
</body>
</html>`;
}
