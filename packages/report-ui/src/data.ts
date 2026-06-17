import type { ScanResult } from '@npm-scanner/core';

declare global {
  interface Window {
    __SCAN_RESULT__?: ScanResult;
  }
}

/**
 * Resolve the scan result. The static report has it injected on
 * `window.__SCAN_RESULT__`; `serve` exposes it at `/api/result`; the dev server
 * falls back to a small sample so the UI renders during development.
 */
export async function loadScanResult(): Promise<ScanResult> {
  if (typeof window !== 'undefined' && window.__SCAN_RESULT__) return window.__SCAN_RESULT__;
  try {
    const res = await fetch('/api/result');
    if (res.ok) return (await res.json()) as ScanResult;
  } catch {
    /* fall through */
  }
  if (import.meta.env.DEV) return SAMPLE;
  throw new Error('No scan data');
}

const SAMPLE: ScanResult = {
  schemaVersion: 1,
  tool: { name: 'npm-scanner', version: '0.1.0' },
  scannedAt: '2026-06-17T18:54:13.551Z',
  target: {
    path: '/demo',
    manager: 'npm',
    lockfile: 'package-lock.json',
    root: { name: 'acme-web', version: '2.4.1' },
  },
  database: {
    source: 'offline',
    recordCount: 221009,
    lastUpdated: '2026-06-17T06:00:00.000Z',
    ageHours: 12.9,
    stale: false,
    warnings: [],
  },
  summary: {
    total: 4,
    critical: 1,
    high: 1,
    medium: 1,
    low: 1,
    unknown: 0,
    none: 0,
    vulnerablePackages: 3,
    fixable: 4,
  },
  stats: {
    totalPackages: 842,
    uniquePackages: 842,
    directDependencies: 31,
    unscannable: 1,
    durationMs: 184,
  },
  unscannable: [{ name: 'internal-ui', version: '0.0.0', reason: 'local workspace package' }],
  findings: [
    {
      id: 'CVE-2021-23337',
      aliases: ['GHSA-35jh-r3h4-6jhm'],
      packageName: 'lodash',
      version: '4.17.11',
      scope: 'prod',
      direct: true,
      severity: {
        level: 'critical',
        score: 9.1,
        vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
        cvssVersion: 'CVSS:3.1',
        source: 'cvss',
      },
      summary: 'Command injection in lodash',
      details:
        'lodash versions prior to 4.17.21 are vulnerable to command injection via the template function.',
      references: [
        'https://github.com/advisories/GHSA-35jh-r3h4-6jhm',
        'https://nvd.nist.gov/vuln/detail/CVE-2021-23337',
      ],
      fixedVersions: ['4.17.21'],
      recommendation: 'Upgrade to lodash@4.17.21 or later (e.g. `npm install lodash@4.17.21`).',
      dependencyPaths: [['acme-web@2.4.1', 'lodash@4.17.11']],
      source: 'osv',
    },
    {
      id: 'CVE-2020-7598',
      aliases: ['GHSA-vh95-rmgr-6w4m'],
      packageName: 'minimist',
      version: '1.2.0',
      scope: 'dev',
      direct: false,
      severity: {
        level: 'high',
        score: 7.3,
        vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L',
        cvssVersion: 'CVSS:3.1',
        source: 'cvss',
      },
      summary: 'Prototype pollution in minimist',
      references: ['https://github.com/advisories/GHSA-vh95-rmgr-6w4m'],
      fixedVersions: ['1.2.3'],
      recommendation:
        'Update the dependency that pulls in minimist so it resolves to minimist@1.2.3 or later.',
      dependencyPaths: [['acme-web@2.4.1', 'mkdirp@0.5.1', 'minimist@1.2.0']],
      source: 'osv',
    },
    {
      id: 'GHSA-93q8-gq69-wqmw',
      aliases: [],
      packageName: 'ansi-regex',
      version: '3.0.0',
      scope: 'prod',
      direct: false,
      severity: {
        level: 'medium',
        score: 5.3,
        source: 'cvss',
        cvssVersion: 'CVSS:3.1',
        vector: 'CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:H',
      },
      summary: 'Inefficient regular expression complexity in ansi-regex',
      references: ['https://github.com/advisories/GHSA-93q8-gq69-wqmw'],
      fixedVersions: ['3.0.1', '4.1.1', '5.0.1'],
      recommendation:
        'Update the dependency that pulls in ansi-regex so it resolves to ansi-regex@3.0.1 or later.',
      dependencyPaths: [['acme-web@2.4.1', 'chalk@2.4.2', 'ansi-styles@3.2.1', 'ansi-regex@3.0.0']],
      source: 'osv',
    },
    {
      id: 'GHSA-hrpp-h998-j3pp',
      aliases: [],
      packageName: 'qs',
      version: '6.2.0',
      scope: 'prod',
      direct: false,
      severity: {
        level: 'low',
        score: 3.7,
        source: 'cvss',
        cvssVersion: 'CVSS:3.1',
        vector: 'CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:L',
      },
      summary: 'qs prototype poisoning',
      references: ['https://github.com/advisories/GHSA-hrpp-h998-j3pp'],
      fixedVersions: ['6.2.4'],
      recommendation: 'Update the dependency that pulls in qs so it resolves to qs@6.2.4 or later.',
      dependencyPaths: [['acme-web@2.4.1', 'body-parser@1.18.0', 'qs@6.2.0']],
      source: 'osv',
    },
  ],
};
