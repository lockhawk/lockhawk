import type { Finding, ScanResult } from '../types.js';

// JUnit XML reporter. Each vulnerability is emitted as a failed <testcase> so
// CI systems that render JUnit results natively — Azure DevOps "Tests" tab,
// GitHub test reporters, GitLab's test report / MR widget — show the findings
// as a pass/fail dashboard with full detail, no custom UI required. A clean
// scan emits a single passing test.

function xml(text: string): string {
  return text.replace(
    /[&<>"']/g,
    (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&apos;' })[c]!,
  );
}

function failureBody(f: Finding): string {
  const lines = [
    `Package: ${f.packageName}@${f.version} (${f.scope}${f.direct ? ', direct' : ', transitive'})`,
    `Severity: ${f.severity.level}${f.severity.score !== undefined ? `, CVSS ${f.severity.score}` : ''}${
      f.severity.vector ? ` (${f.severity.vector})` : ''
    }`,
    f.fixedVersions.length ? `Fixed in: ${f.fixedVersions.join(', ')}` : 'Fix: none available yet',
    f.dependencyPaths[0] ? `Dependency path: ${f.dependencyPaths[0].join(' > ')}` : '',
    f.recommendation ? `Recommendation: ${f.recommendation}` : '',
    f.references.length ? `References:\n${f.references.join('\n')}` : '',
  ];
  return lines.filter(Boolean).join('\n');
}

/** Render a scan result as JUnit XML (one failed test per finding). */
export function toJunit(result: ScanResult): string {
  const { findings } = result;
  const failures = findings.length;
  const tests = findings.length === 0 ? 1 : findings.length;
  const time = ((result.stats.durationMs ?? 0) / 1000).toFixed(3);
  const suiteName = `${result.target.root.name} npm dependency vulnerabilities`;

  const cases =
    findings.length === 0
      ? ['    <testcase name="No known vulnerabilities" classname="lockhawk" time="0" />']
      : findings.map((f) => {
          const name = `${f.packageName}@${f.version}: ${f.id} (${f.severity.level})`;
          const message = `${f.severity.level.toUpperCase()}${
            f.severity.score !== undefined ? ` ${f.severity.score}` : ''
          } ${f.id}: ${f.summary}`;
          return [
            `    <testcase name="${xml(name)}" classname="lockhawk.${xml(f.severity.level)}" time="0">`,
            `      <failure message="${xml(message)}" type="${xml(f.severity.level)}">${xml(failureBody(f))}</failure>`,
            `    </testcase>`,
          ].join('\n');
        });

  return [
    '<?xml version="1.0" encoding="UTF-8"?>',
    `<testsuites name="lockhawk" tests="${tests}" failures="${failures}" errors="0" time="${time}">`,
    `  <testsuite name="${xml(suiteName)}" tests="${tests}" failures="${failures}" errors="0" time="${time}">`,
    ...cases,
    '  </testsuite>',
    '</testsuites>',
    '',
  ].join('\n');
}
