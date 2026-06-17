import chalk from 'chalk';
import Table from 'cli-table3';
import type { ScanResult, Severity } from '@npm-scanner/core';

const paint: Record<Severity, (s: string) => string> = {
  critical: (s) => chalk.bgRed.white.bold(` ${s} `),
  high: (s) => chalk.hex('#d9822b').bold(s),
  medium: (s) => chalk.yellow(s),
  low: (s) => chalk.blue(s),
  unknown: (s) => chalk.gray(s),
  none: (s) => chalk.green(s),
};

/** Render a scan result as a colorized terminal report. */
export function renderTable(result: ScanResult): string {
  const lines: string[] = [];
  const { summary, target, stats, database } = result;

  lines.push(
    chalk.bold(`\nnpm-scanner`) +
      chalk.dim(
        ` · ${target.root.name}${target.root.version ? `@${target.root.version}` : ''} · ${target.manager} · ${stats.totalPackages} packages`,
      ),
  );

  for (const warning of database.warnings) lines.push(chalk.yellow(`⚠ ${warning}`));

  if (result.findings.length === 0) {
    lines.push(chalk.green.bold('\n✓ No known vulnerabilities found.\n'));
    lines.push(chalk.dim(footer(result)));
    return lines.join('\n');
  }

  const table = new Table({
    head: ['Severity', 'Package', 'Advisory', 'Fixed in', 'Path'].map((h) => chalk.dim(h)),
    style: { head: [], border: [] },
    colWidths: [12, 26, 22, 12, 40],
    wordWrap: true,
  });

  for (const f of result.findings) {
    const sev = f.severity;
    const sevText = `${sev.level}${sev.score ? ` ${sev.score}` : ''}`;
    const path = f.dependencyPaths[0]?.join(' › ') ?? f.packageName;
    table.push([
      paint[sev.level](sevText),
      `${f.packageName}\n${chalk.dim(f.version)}${f.direct ? chalk.dim(' (direct)') : ''}`,
      f.id,
      f.fixedVersions[0] ?? chalk.dim('none'),
      chalk.dim(path),
    ]);
  }

  lines.push('');
  lines.push(table.toString());
  lines.push('');
  lines.push(summaryLine(summary));
  lines.push(chalk.dim(footer(result)));
  return lines.join('\n');
}

function summaryLine(summary: ScanResult['summary']): string {
  const parts: string[] = [];
  if (summary.critical) parts.push(paint.critical(`${summary.critical} critical`));
  if (summary.high) parts.push(paint.high(`${summary.high} high`));
  if (summary.medium) parts.push(paint.medium(`${summary.medium} medium`));
  if (summary.low) parts.push(paint.low(`${summary.low} low`));
  if (summary.unknown) parts.push(paint.unknown(`${summary.unknown} unknown`));
  return (
    chalk.bold(
      `Found ${summary.total} ${summary.total === 1 ? 'vulnerability' : 'vulnerabilities'}`,
    ) +
    (parts.length ? ` (${parts.join(', ')})` : '') +
    chalk.dim(` · ${summary.fixable} fixable`)
  );
}

function footer(result: ScanResult): string {
  const age = result.database.ageHours !== undefined ? `, ${result.database.ageHours}h old` : '';
  return `\nData from OSV.dev · database: ${result.database.source}${age} · scanned in ${result.stats.durationMs ?? 0}ms`;
}
