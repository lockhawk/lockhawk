import type { ScanResult, Severity } from '../types.js';

// Markdown reporter. Produces GitHub-Flavored Markdown for inline CI summaries —
// GitHub Actions renders it in the run's Job Summary ($GITHUB_STEP_SUMMARY) and
// Azure DevOps as a native build-summary tab (##vso[task.uploadsummary]). Both
// render plain GFM, so this avoids raw HTML (e.g. <details>) for portability.

// Emoji per severity — mirrors SEVERITY_COLORS in html.ts.
const SEVERITY_EMOJI: Record<Severity, string> = {
  critical: '🔴',
  high: '🟠',
  medium: '🟡',
  low: '⚪',
  unknown: '⚫',
  none: '🟢',
};

// GitHub caps a single job summary at ~1 MiB; keep the inline table readable and
// well under that. Findings arrive sorted most-severe-first, so the cap keeps
// what matters and the remainder is noted rather than dropped silently.
const MAX_ROWS = 100;
const SUMMARY_MAX = 100;

/** Escape text for one GFM table cell: pipes/newlines break the table; neutralize HTML tags. */
function mdCell(text: string): string {
  return text
    .replace(/\r?\n/g, ' ')
    .replace(/\\/g, '\\\\')
    .replace(/\|/g, '\\|')
    .replace(/`/g, '\\`')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;');
}

function truncate(text: string, max: number): string {
  return text.length > max ? `${text.slice(0, max - 1)}…` : text;
}

function footer(result: ScanResult): string {
  return `_lockhawk ${result.tool.version} · data: OSV.dev (${result.database.source}) · scanned ${result.scannedAt}_`;
}

/** Render a scan result as GitHub-Flavored Markdown for inline CI summaries. */
export function toMarkdown(result: ScanResult): string {
  const { summary, findings } = result;
  const out: string[] = [];

  const noun = summary.total === 1 ? 'vulnerability' : 'vulnerabilities';
  out.push(`## 🛡️ lockhawk — ${summary.total} ${noun}`, '');

  if (findings.length === 0) {
    out.push('✓ No known vulnerabilities found.', '', footer(result));
    return `${out.join('\n')}\n`;
  }

  out.push(
    `${SEVERITY_EMOJI.critical} ${summary.critical} critical · ` +
      `${SEVERITY_EMOJI.high} ${summary.high} high · ` +
      `${SEVERITY_EMOJI.medium} ${summary.medium} medium · ` +
      `${SEVERITY_EMOJI.low} ${summary.low} low · ` +
      `${summary.vulnerablePackages} packages · ${summary.fixable} fixable`,
    '',
  );

  const warnings = result.database.warnings;
  if (result.database.stale || warnings.length) {
    for (const w of warnings) out.push(`> ⚠️ ${mdCell(w)}`);
    if (result.database.stale && warnings.length === 0) {
      out.push('> ⚠️ The offline advisory database is stale.');
    }
    out.push('');
  }

  out.push('| Severity | Package | Advisory | Fixed in | Summary |', '|---|---|---|---|---|');
  for (const f of findings.slice(0, MAX_ROWS)) {
    const score = f.severity.score !== undefined ? ` ${f.severity.score}` : '';
    const sev = `${SEVERITY_EMOJI[f.severity.level]} ${f.severity.level}${score}`;
    const pkg = `\`${mdCell(`${f.packageName}@${f.version}`)}\`${f.direct ? ' (direct)' : ''}`;
    const adv = `[${mdCell(f.id)}](https://osv.dev/${encodeURIComponent(f.id)})`;
    const fixed = f.fixedVersions[0] ? mdCell(f.fixedVersions[0]) : 'none';
    const sum = mdCell(truncate(f.summary, SUMMARY_MAX));
    out.push(`| ${sev} | ${pkg} | ${adv} | ${fixed} | ${sum} |`);
  }

  if (findings.length > MAX_ROWS) {
    out.push('', `_…and ${findings.length - MAX_ROWS} more — see the downloadable report._`);
  }

  out.push('', footer(result));
  return `${out.join('\n')}\n`;
}
