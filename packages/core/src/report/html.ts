import type { ScanResult, Severity } from '../types.js';

/**
 * Produce a self-contained HTML report for a scan result.
 *
 * The page is fully server-rendered: no client-side JavaScript, no embedded
 * data blob, no external resources. Every dynamic value is HTML-escaped, the
 * layout flows normally within a width-constrained container, and long advisory
 * text lives in a collapsed, contained block — so the report cannot overflow the
 * viewport or render attacker-controlled advisory text as live markup.
 */
export function toHtml(result: ScanResult): string {
  return renderHtml(result);
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

function renderHtml(result: ScanResult): string {
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
      const rec = f.recommendation
        ? `<p class="rec"><strong>Recommendation:</strong> ${esc(f.recommendation)}</p>`
        : '';
      return `
      <tr>
        <td><span class="pill" style="background:${SEVERITY_COLORS[f.severity.level]}">${esc(
          f.severity.level,
        )}${f.severity.score ? ` ${f.severity.score}` : ''}</span></td>
        <td><code>${esc(f.packageName)}@${esc(f.version)}</code><div class="scope">${esc(f.scope)}${
          f.direct ? ' · direct' : ''
        }</div></td>
        <td><a href="https://osv.dev/${encodeURIComponent(f.id)}" target="_blank" rel="noopener">${esc(
          f.id,
        )}</a></td>
        <td>${esc(f.summary)}<div class="path">${esc(path)}</div></td>
        <td>${f.fixedVersions[0] ? esc(f.fixedVersions[0]) : '—'}</td>
        <td class="refs">${refs}</td>
      </tr>
      <tr class="detail-row">
        <td colspan="6">
          <details>
            <summary>Advisory details</summary>
            ${rec}<pre class="advisory">${esc(f.details ?? f.summary)}</pre>
          </details>
        </td>
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
<style>
  :root { color-scheme: light dark; }
  * { box-sizing: border-box; }
  html, body { max-width: 100%; overflow-x: hidden; }
  body { font: 15px/1.5 -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; margin: 0; background: #f6f7f9; color: #1c1e21; }
  header { background: #11161d; color: #fff; padding: 24px 32px; }
  header h1 { margin: 0 0 4px; font-size: 20px; }
  header .meta { color: #9aa4b2; font-size: 13px; overflow-wrap: anywhere; }
  main { max-width: 1100px; margin: 0 auto; padding: 24px clamp(16px, 4vw, 32px) 40px; }
  .cards { display: grid; grid-template-columns: repeat(auto-fit, minmax(110px, 1fr)); gap: 12px; margin-bottom: 8px; }
  .card { background: #fff; border-radius: 8px; padding: 14px 16px; box-shadow: 0 1px 3px rgba(0,0,0,.08); }
  .card .count { font-size: 28px; font-weight: 700; }
  .card .label { text-transform: capitalize; color: #6b7280; font-size: 13px; }
  .warn { background: #fff7e6; border: 1px solid #ffd591; color: #874d00; padding: 8px 12px; border-radius: 6px; margin: 12px 0; font-size: 13px; overflow-wrap: anywhere; }
  .table-wrap { margin-top: 16px; overflow-x: auto; -webkit-overflow-scrolling: touch; border-radius: 8px; box-shadow: 0 1px 3px rgba(0,0,0,.08); }
  table { width: 100%; border-collapse: collapse; background: #fff; }
  th, td { text-align: left; padding: 10px 12px; border-bottom: 1px solid #eef0f3; vertical-align: top; font-size: 13px; overflow-wrap: anywhere; word-break: break-word; }
  th { background: #f0f2f5; font-size: 12px; text-transform: uppercase; letter-spacing: .03em; color: #6b7280; white-space: nowrap; }
  .pill { color: #fff; padding: 2px 8px; border-radius: 999px; font-size: 12px; text-transform: capitalize; white-space: nowrap; }
  .scope, .path { color: #6b7280; font-size: 12px; }
  .path { margin-top: 4px; }
  .refs { white-space: nowrap; }
  code { background: #eef0f3; padding: 1px 5px; border-radius: 4px; max-width: 100%; }
  .detail-row td { border-bottom: 2px solid #eef0f3; padding-top: 0; }
  details { font-size: 13px; }
  summary { cursor: pointer; color: #3a7bd5; font-size: 12px; padding: 4px 0; width: max-content; }
  .rec { margin: 8px 0; font-size: 13px; }
  pre.advisory { white-space: pre-wrap; word-break: break-word; overflow-x: auto; max-width: 100%; background: #f6f7f9; border: 1px solid #eef0f3; border-radius: 6px; padding: 10px 12px; margin: 6px 0 4px; font-size: 12.5px; }
  .empty { background: #fff; border-radius: 8px; padding: 40px; text-align: center; color: #3a9e54; font-size: 18px; box-shadow: 0 1px 3px rgba(0,0,0,.08); margin-top: 16px; }
  footer { max-width: 1100px; margin: 0 auto; padding: 16px clamp(16px, 4vw, 32px) 40px; color: #9aa4b2; font-size: 12px; }
</style>
</head>
<body>
<header>
  <h1>lockhawk report</h1>
  <div class="meta">${esc(result.target.root.name)}${
    result.target.root.version ? `@${esc(result.target.root.version)}` : ''
  } · ${esc(result.target.manager)} · ${result.stats.totalPackages} packages · scanned ${esc(
    result.scannedAt,
  )}</div>
</header>
<main>
  <div class="cards">${cards}</div>
  ${dbWarnings}
  ${
    result.findings.length === 0
      ? '<div class="empty">✓ No known vulnerabilities found.</div>'
      : `<div class="table-wrap"><table>
    <thead><tr><th>Severity</th><th>Package</th><th>Advisory</th><th>Summary &amp; path</th><th>Fixed in</th><th>Refs</th></tr></thead>
    <tbody>${rows}</tbody>
  </table></div>`
  }
</main>
<footer>Generated by lockhawk v${esc(result.tool.version)} · data from OSV.dev · database: ${esc(
    result.database.source,
  )}</footer>
</body>
</html>`;
}
