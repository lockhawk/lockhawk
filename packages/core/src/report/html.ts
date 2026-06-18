import type { ScanResult, Severity } from '../types.js';

/**
 * Produce a self-contained HTML report for a scan result.
 *
 * The page is fully server-rendered: no client-side JavaScript, no embedded
 * data blob, no external resources (fonts included). Every dynamic value is
 * HTML-escaped, the layout flows within a width-constrained container, and long
 * advisory text lives in a collapsed, contained block — so the report cannot
 * overflow the viewport or render attacker-controlled advisory text as live
 * markup. Copy affordances use CSS `user-select: all` (one click selects a whole
 * command/version) rather than a clipboard script, preserving the no-JS model.
 */
export function toHtml(result: ScanResult): string {
  return renderHtml(result);
}

const SEVERITY_COLORS: Record<Severity, string> = {
  critical: '#ff5d67',
  high: '#ff9f43',
  medium: '#ffd23f',
  low: '#5b9dff',
  unknown: '#8b95a5',
  none: '#34d399',
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

/** Inline SVG identity mark: a watchful hawk eye set in a keyhole shield. */
const MARK = `<svg class="mark" viewBox="0 0 48 48" fill="none" aria-hidden="true">
  <defs>
    <linearGradient id="lh-g" x1="6" y1="4" x2="40" y2="44" gradientUnits="userSpaceOnUse">
      <stop stop-color="#ffc266"/><stop offset="1" stop-color="#ff5d67"/>
    </linearGradient>
  </defs>
  <path d="M24 4 40 11v13c0 9-7 15.2-16 20-9-4.8-16-11-16-20V11Z" stroke="url(#lh-g)" stroke-width="2.2" stroke-linejoin="round"/>
  <path d="M14 18.5 24 15l10 3.5" stroke="url(#lh-g)" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"/>
  <circle cx="24" cy="23" r="3.2" fill="url(#lh-g)"/>
  <path d="M24 26.2V32" stroke="url(#lh-g)" stroke-width="2.2" stroke-linecap="round"/>
</svg>`;

const CHEVRON = `<svg class="chev" width="11" height="11" viewBox="0 0 16 16" fill="none" aria-hidden="true"><path d="M6 4l4 4-4 4" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/></svg>`;

/**
 * Render the recommendation as a "fix" callout. When the recommendation carries
 * an install command (direct-dependency fixes wrap it in backticks), the command
 * is lifted into a copyable terminal bar and the redundant "(e.g. …)" parenthetical
 * is trimmed from the prose. esc() runs first, so the backtick scan and the chip
 * contents are already neutralized markup.
 */
function renderFix(rec: string): string {
  const match = rec.match(/`([^`]+)`/);
  const command = match?.[1];
  const pending = /^No fixed version/i.test(rec);
  const prose = command ? rec.replace(/\s*\(e\.g\.[^)]*\)/, '') : rec;
  const bar = command
    ? `<div class="cmdbar"><code class="cmd" title="Click to select, then ⌘/Ctrl+C to copy">${esc(
        command,
      )}</code><span class="hint">click to select</span></div>`
    : '';
  return `<div class="fix${pending ? ' fix-pending' : ''}">
        <div class="fix-label">${CHEVRON.replace('chev', 'spark')}${
          pending ? 'No fix available yet' : 'Recommended fix'
        }</div>
        <p class="fix-text">${esc(prose)}</p>${bar}
      </div>`;
}

function renderHtml(result: ScanResult): string {
  const { summary } = result;
  const cards = (['critical', 'high', 'medium', 'low', 'unknown'] as Severity[])
    .map(
      (sev, i) => `
      <div class="card${summary[sev] === 0 ? ' zero' : ''}" style="--c:${SEVERITY_COLORS[sev]};--i:${i}">
        <div class="count">${summary[sev]}</div><div class="label">${sev}</div>
      </div>`,
    )
    .join('');

  const rows = result.findings
    .map((f, i) => {
      const path = f.dependencyPaths[0]?.join(' › ') ?? f.packageName;
      const refs = f.references
        .slice(0, 3)
        .map((u) => httpHref(u))
        .filter((u): u is string => u !== undefined)
        .map((u) => `<a class="ref" href="${esc(u)}" target="_blank" rel="noopener">link</a>`)
        .join('');
      const fixed = f.fixedVersions[0]
        ? `<span class="fixchip" title="Click to select, then ⌘/Ctrl+C to copy">${esc(
            f.fixedVersions[0],
          )}</span>`
        : '<span class="nofix">—</span>';
      return `
      <tr class="main" style="--i:${i}">
        <td><span class="pill" style="--c:${SEVERITY_COLORS[f.severity.level]}">${esc(
          f.severity.level,
        )}${f.severity.score ? ` ${f.severity.score}` : ''}</span></td>
        <td><span class="pkg">${esc(f.packageName)}@${esc(f.version)}</span><div class="scope">${esc(
          f.scope,
        )}${f.direct ? ' · direct' : ''}</div></td>
        <td><a class="advid" href="https://osv.dev/${encodeURIComponent(
          f.id,
        )}" target="_blank" rel="noopener">${esc(f.id)}</a></td>
        <td><div class="summary">${esc(f.summary)}</div><div class="path">${esc(path)}</div></td>
        <td>${fixed}</td>
        <td class="refs">${refs}</td>
      </tr>
      <tr class="detail-row">
        <td colspan="6">
          ${f.recommendation ? renderFix(f.recommendation) : ''}
          <details>
            <summary>${CHEVRON}<span>Advisory details</span></summary>
            <div class="detail-body">
              <div class="advisory-wrap">
                <div class="advisory-head"><span class="dots"><i></i><i></i><i></i></span><span class="advisory-title">advisory · ${esc(
                  f.id,
                )}</span></div>
                <pre class="advisory">${esc(f.details ?? f.summary)}</pre>
              </div>
            </div>
          </details>
        </td>
      </tr>`;
    })
    .join('');

  const dbWarnings = result.database.warnings
    .map((w) => `<div class="warn"><span class="warn-i">⚠</span>${esc(w)}</div>`)
    .join('');

  const resultsMeta =
    result.findings.length === 0
      ? ''
      : `<div class="results-meta">
      <span><b>${summary.total}</b> findings</span><span class="sep">·</span>
      <span><b>${summary.vulnerablePackages}</b> packages</span><span class="sep">·</span>
      <span><b>${summary.fixable}</b> fixable</span>
    </div>`;

  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>lockhawk report — ${esc(result.target.root.name)}</title>
<style>
  :root {
    --bg:#070a12; --panel:#11151e; --panel-2:#141926; --elev:#171d2b;
    --border:#222a3a; --border-soft:#1b2230;
    --text:#f1f4fa; --muted:#aeb8cc; --faint:#808b9f;
    --accent:#ffc266; --fix:#48e0a6;
    --glass: rgba(255,255,255,.055); --glass-2: rgba(255,255,255,.09);
    --glass-line: rgba(255,255,255,.14); --glass-hi: inset 0 1px 0 rgba(255,255,255,.10);
    --glass-dark: rgba(8,11,18,.42);
    --blur: blur(18px) saturate(160%);
    --mono: ui-monospace,'SF Mono','JetBrains Mono','Cascadia Code','Fira Code',Menlo,Consolas,monospace;
    --sans: -apple-system,BlinkMacSystemFont,'SF Pro Text','Segoe UI',system-ui,Roboto,sans-serif;
    color-scheme: dark;
  }
  * { box-sizing: border-box; }
  html, body { max-width: 100%; overflow-x: hidden; }
  body {
    margin: 0; min-height: 100vh; font: 15px/1.6 var(--sans); color: var(--text);
    background:
      radial-gradient(820px 620px at 8% -8%, rgba(91,157,255,.22), transparent 58%),
      radial-gradient(760px 600px at 94% -4%, rgba(255,93,103,.16), transparent 56%),
      radial-gradient(900px 760px at 80% 108%, rgba(72,224,166,.16), transparent 58%),
      radial-gradient(720px 640px at 16% 98%, rgba(255,179,71,.13), transparent 58%),
      linear-gradient(180deg, #0a1020, #070a12 60%);
    background-attachment: fixed;
    -webkit-font-smoothing: antialiased;
  }

  /* ---- Header / wordmark ------------------------------------------------ */
  header { position: relative; overflow: hidden; padding: 30px clamp(18px,5vw,40px) 28px; background: linear-gradient(180deg, rgba(255,255,255,.08), rgba(255,255,255,.03)); -webkit-backdrop-filter: var(--blur); backdrop-filter: var(--blur); border-bottom: 1px solid var(--glass-line); box-shadow: var(--glass-hi); }
  header::before { content:''; position:absolute; inset:0; pointer-events:none;
    background: radial-gradient(620px 220px at 10% 0%, rgba(255,194,102,.12), transparent 70%),
                radial-gradient(520px 240px at 58% -25%, rgba(255,93,103,.10), transparent 70%); }
  header::after { content:''; position:absolute; inset:0; opacity:.35; pointer-events:none;
    background-image: linear-gradient(rgba(255,255,255,.025) 1px,transparent 1px), linear-gradient(90deg,rgba(255,255,255,.025) 1px,transparent 1px);
    background-size: 34px 34px; -webkit-mask: linear-gradient(180deg,#000,transparent); mask: linear-gradient(180deg,#000,transparent); }
  header > * { position: relative; }
  .brand { display:flex; align-items:center; gap:14px; }
  .mark { width:38px; height:38px; flex:none; filter: drop-shadow(0 3px 12px rgba(255,93,103,.3)); }
  .wordmark { font-family: var(--mono); font-size: clamp(22px,4vw,27px); letter-spacing:-.02em; display:flex; align-items:center; }
  .wordmark .lock { color: var(--muted); font-weight:500; }
  .wordmark .hawk { color: var(--text); font-weight:700; }
  .caret { display:inline-block; width:9px; height:1em; margin-left:5px; background: var(--accent); border-radius:1px; box-shadow:0 0 12px var(--accent); animation: blink 1.2s steps(1) infinite; }
  .meta { margin-top:12px; color: var(--muted); font:12.5px/1.7 var(--mono); letter-spacing:.01em; overflow-wrap:anywhere; }
  .meta b { color: var(--text); font-weight:600; }

  /* ---- Layout ----------------------------------------------------------- */
  main { max-width: 1120px; margin: 0 auto; padding: 26px clamp(16px,4vw,32px) 48px; }
  .cards { display:grid; grid-template-columns: repeat(auto-fit, minmax(116px,1fr)); gap:14px; }
  .card { position:relative; overflow:hidden; background: linear-gradient(180deg, var(--glass-2), var(--glass)); -webkit-backdrop-filter: var(--blur); backdrop-filter: var(--blur); border:1px solid var(--glass-line); border-radius:16px; padding:16px 18px; box-shadow: 0 12px 36px -18px rgba(0,0,0,.75), var(--glass-hi); animation: rise .55s both cubic-bezier(.2,.7,.2,1); animation-delay: calc(var(--i)*55ms); }
  .card::before { content:''; position:absolute; top:0; left:0; right:0; height:3px; background:var(--c); box-shadow:0 0 16px var(--c); }
  .card .count { font:700 32px/1 var(--mono); font-variant-numeric: tabular-nums; letter-spacing:-.03em; color:var(--c); text-shadow: 0 0 24px color-mix(in srgb, var(--c) 45%, transparent); }
  .card .label { margin-top:7px; color:var(--muted); font-size:11.5px; text-transform:uppercase; letter-spacing:.09em; }
  .card.zero .count { color: var(--faint); text-shadow:none; }
  .card.zero::before { box-shadow:none; opacity:.45; }

  .warn { display:flex; gap:9px; align-items:flex-start; background: rgba(255,210,63,.1); -webkit-backdrop-filter: blur(10px); backdrop-filter: blur(10px); border:1px solid rgba(255,210,63,.32); color:#ffe6a6; padding:10px 14px; border-radius:12px; margin-top:14px; font-size:13px; overflow-wrap:anywhere; }
  .warn-i { color: var(--accent); }

  .results-meta { display:flex; gap:14px; flex-wrap:wrap; align-items:center; margin:26px 2px 0; color:var(--muted); font:12px/1 var(--mono); letter-spacing:.04em; }
  .results-meta b { color:var(--text); font-weight:600; }
  .results-meta .sep { color:var(--faint); }

  /* ---- Table ------------------------------------------------------------ */
  .table-wrap { margin-top:14px; border:1px solid var(--glass-line); border-radius:18px; overflow:hidden; background: linear-gradient(180deg, rgba(255,255,255,.06), rgba(255,255,255,.025)); -webkit-backdrop-filter: var(--blur); backdrop-filter: var(--blur); box-shadow: 0 22px 60px -32px rgba(0,0,0,.85), var(--glass-hi); }
  .scroll { overflow-x:auto; -webkit-overflow-scrolling:touch; }
  table { width:100%; border-collapse:collapse; }
  thead th { text-align:left; background: rgba(255,255,255,.05); color:var(--muted); font:600 11px/1 var(--mono); text-transform:uppercase; letter-spacing:.08em; padding:14px 16px; border-bottom:1px solid var(--glass-line); white-space:nowrap; }
  tbody td { padding:15px 16px; border-bottom:1px solid rgba(255,255,255,.07); vertical-align:top; font-size:13.5px; overflow-wrap:anywhere; word-break:break-word; }
  tbody tr.main { animation: rise .5s both ease; animation-delay: calc(var(--i)*30ms + 120ms); }
  tbody tr.main:hover { background: rgba(255,255,255,.05); }

  .pill { display:inline-flex; align-items:center; gap:7px; font:600 11.5px/1 var(--mono); padding:6px 10px; border-radius:8px; white-space:nowrap; text-transform:capitalize; color:var(--c); background: color-mix(in srgb, var(--c) 15%, transparent); border:1px solid color-mix(in srgb, var(--c) 34%, transparent); }
  .pill::before { content:''; width:7px; height:7px; border-radius:50%; background:var(--c); box-shadow:0 0 9px var(--c); flex:none; }

  .pkg { display:inline-block; font-family:var(--mono); font-size:12.5px; color:var(--text); background: rgba(255,255,255,.07); border:1px solid var(--glass-line); padding:4px 9px; border-radius:8px; }
  .scope { margin-top:7px; color:var(--faint); font:11px/1 var(--mono); text-transform:uppercase; letter-spacing:.06em; }
  .advid { font-family:var(--mono); font-size:12.5px; color:var(--accent); text-decoration:none; border-bottom:1px solid transparent; }
  .advid:hover { border-bottom-color: color-mix(in srgb, var(--accent) 60%, transparent); }
  .summary { color:var(--text); }
  .path { margin-top:7px; color:var(--faint); font:11.5px/1.5 var(--mono); }

  .fixchip { display:inline-block; font-family:var(--mono); font-size:12.5px; color:var(--fix); background: color-mix(in srgb, var(--fix) 13%, transparent); border:1px solid color-mix(in srgb, var(--fix) 30%, transparent); padding:4px 10px; border-radius:8px; cursor:copy; white-space:nowrap; user-select:all; -webkit-user-select:all; transition: background .15s ease; }
  .fixchip:hover { background: color-mix(in srgb, var(--fix) 22%, transparent); }
  .nofix { color:var(--faint); }
  .refs { white-space:nowrap; }
  .ref { display:inline-block; font:11.5px/1 var(--mono); color:var(--muted); text-decoration:none; padding:4px 8px; border:1px solid var(--glass-line); border-radius:7px; margin:0 4px 4px 0; background: rgba(255,255,255,.04); transition: color .15s, border-color .15s, background .15s; }
  .ref:hover { color:var(--text); border-color: rgba(255,255,255,.28); background: rgba(255,255,255,.08); }

  /* ---- Disclosure / advisory ------------------------------------------- */
  .detail-row td { padding:0 16px 4px; background: rgba(0,0,0,.16); border-bottom:1px solid rgba(255,255,255,.07); }
  details { margin:0; }
  summary { list-style:none; cursor:pointer; display:inline-flex; align-items:center; gap:9px; color:var(--muted); font:600 11px/1 var(--mono); letter-spacing:.08em; text-transform:uppercase; padding:13px 0; user-select:none; transition: color .15s ease; }
  summary::-webkit-details-marker { display:none; }
  summary:hover { color:var(--text); }
  summary .chev { color:var(--accent); transition: transform .25s cubic-bezier(.2,.7,.2,1); flex:none; }
  details[open] summary .chev { transform: rotate(90deg); }
  .detail-body { padding-bottom:18px; animation: fade .3s both ease; }

  .fix { border:1px solid color-mix(in srgb, var(--fix) 28%, transparent); background: linear-gradient(180deg, color-mix(in srgb, var(--fix) 12%, transparent), rgba(255,255,255,.02)); -webkit-backdrop-filter: blur(8px); backdrop-filter: blur(8px); border-radius:13px; padding:13px 15px; margin:12px 0; box-shadow: var(--glass-hi); }
  .fix-label { display:flex; align-items:center; gap:7px; font:700 10px/1 var(--mono); letter-spacing:.12em; text-transform:uppercase; color:var(--fix); margin-bottom:9px; }
  .fix-label .spark { color:var(--fix); }
  .fix-pending { border-color: color-mix(in srgb, var(--accent) 32%, transparent); background: linear-gradient(180deg, color-mix(in srgb, var(--accent) 11%, transparent), rgba(255,255,255,.02)); }
  .fix-pending .fix-label, .fix-pending .spark { color: var(--accent); }
  .fix-text { margin:0; color:var(--text); font-size:13px; }
  .fix-text + .cmdbar { margin-top:11px; }
  .cmdbar { display:flex; align-items:center; gap:14px; flex-wrap:wrap; background: rgba(4,7,12,.55); -webkit-backdrop-filter: blur(6px); backdrop-filter: blur(6px); border:1px solid var(--glass-line); border-radius:11px; padding:11px 14px; transition: border-color .18s ease, background .18s ease; }
  .cmdbar:hover { border-color: color-mix(in srgb, var(--fix) 55%, transparent); background: rgba(4,7,12,.68); }
  .cmdbar .cmd { font-family:var(--mono); font-size:13px; color:#d7f7e8; cursor:copy; white-space:pre-wrap; word-break:break-all; user-select:all; -webkit-user-select:all; }
  .cmdbar .cmd::before { content:'$\\00a0\\00a0'; color:var(--fix); user-select:none; -webkit-user-select:none; }
  .cmdbar .hint { margin-left:auto; font:11px/1 var(--sans); color:var(--muted); white-space:nowrap; }

  .advisory-wrap { border:1px solid var(--glass-line); border-radius:13px; overflow:hidden; background: var(--glass-dark); -webkit-backdrop-filter: blur(10px); backdrop-filter: blur(10px); box-shadow: var(--glass-hi); }
  .advisory-head { display:flex; align-items:center; gap:11px; padding:10px 15px; background: rgba(255,255,255,.05); border-bottom:1px solid var(--glass-line); font:600 10.5px/1 var(--mono); letter-spacing:.07em; text-transform:uppercase; color:var(--muted); }
  .dots { display:flex; gap:6px; }
  .dots i { width:9px; height:9px; border-radius:50%; background: rgba(255,255,255,.18); }
  pre.advisory { margin:0; padding:15px 16px; white-space:pre-wrap; word-break:break-word; overflow-x:auto; max-width:100%; font-family:var(--mono); font-size:12.5px; line-height:1.65; color:#d2dae8; }

  .empty { background: linear-gradient(180deg, var(--glass-2), var(--glass)); -webkit-backdrop-filter: var(--blur); backdrop-filter: var(--blur); border:1px solid var(--glass-line); border-radius:18px; padding:48px; text-align:center; color:var(--fix); font:600 19px/1.4 var(--sans); margin-top:16px; box-shadow: var(--glass-hi); }
  footer { max-width:1120px; margin:0 auto; padding:18px clamp(16px,4vw,32px) 44px; color:var(--faint); font:12px/1.6 var(--mono); letter-spacing:.02em; }

  /* Entrance animates position only — content stays fully opaque/visible throughout. */
  @keyframes rise { from { transform: translateY(12px); } to { transform: none; } }
  @keyframes fade { from { opacity:0; } to { opacity:1; } }
  @keyframes blink { 50% { opacity:0; } }
  @media (prefers-reduced-motion: reduce) { *, *::before, *::after { animation:none !important; transition:none !important; } }

  @media print {
    body { background:#fff; color:#111; }
    header, .card, .table-wrap, .advisory-wrap, .cmdbar, .fix, thead th, .warn, .empty {
      background:#fff !important; -webkit-backdrop-filter:none !important; backdrop-filter:none !important;
      box-shadow:none !important; border-color:#ddd !important; color:#111;
    }
    .caret { display:none; }
    pre.advisory, .fix-text, .summary, .pkg { color:#111 !important; }
  }
</style>
</head>
<body>
<header>
  <div class="brand">${MARK}<div class="wordmark"><span class="lock">lock</span><span class="hawk">hawk</span><span class="caret"></span></div></div>
  <div class="meta"><b>${esc(result.target.root.name)}${
    result.target.root.version ? `@${esc(result.target.root.version)}` : ''
  }</b> · ${esc(result.target.manager)} · ${result.stats.totalPackages} packages · scanned ${esc(
    result.scannedAt,
  )}</div>
</header>
<main>
  <div class="cards">${cards}</div>
  ${dbWarnings}
  ${
    result.findings.length === 0
      ? '<div class="empty">✓ No known vulnerabilities found.</div>'
      : `${resultsMeta}
  <div class="table-wrap"><div class="scroll"><table>
    <thead><tr><th>Severity</th><th>Package</th><th>Advisory</th><th>Summary &amp; path</th><th>Fixed in</th><th>Refs</th></tr></thead>
    <tbody>${rows}</tbody>
  </table></div></div>`
  }
</main>
<footer>Generated by lockhawk v${esc(result.tool.version)} · data from OSV.dev · database: ${esc(
    result.database.source,
  )}</footer>
</body>
</html>`;
}
