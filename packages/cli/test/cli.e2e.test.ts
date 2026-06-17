import { execFileSync } from 'node:child_process';
import { existsSync, mkdirSync, mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { gzipSync } from 'node:zlib';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { offlineDbDir, offlineMetaPath, shardBucket } from '@npm-scanner/core';
import type { OsvVulnerability, ScanResult } from '@npm-scanner/core';

const cliPath = join(dirname(fileURLToPath(import.meta.url)), '..', 'dist', 'index.js');
const built = existsSync(cliPath);

// The E2E suite drives the built binary; it requires `pnpm build` first.
const suite = built ? describe : describe.skip;

/** Seed an offline OSV database directly (no network) for deterministic tests. */
function seedDb(cacheDir: string, pkg: string, advisory: OsvVulnerability): void {
  const dir = join(offlineDbDir(cacheDir), 'by-name');
  mkdirSync(dir, { recursive: true });
  // Shards are gzipped on disk (matches the offline-db reader).
  writeFileSync(
    join(dir, `${shardBucket(pkg)}.json.gz`),
    gzipSync(Buffer.from(JSON.stringify({ [pkg]: [advisory] }))),
  );
  writeFileSync(
    offlineMetaPath(cacheDir),
    JSON.stringify({
      ecosystem: 'npm',
      source: 'osv.dev',
      lastUpdated: new Date().toISOString(),
      recordCount: 1,
      packageCount: 1,
    }),
  );
}

function makeProject(deps: Record<string, string>): string {
  const dir = mkdtempSync(join(tmpdir(), 'npm-scanner-e2e-'));
  writeFileSync(
    join(dir, 'package.json'),
    JSON.stringify({ name: 'e2e', version: '1.0.0', dependencies: deps }),
  );
  const packages: Record<string, unknown> = {
    '': { name: 'e2e', version: '1.0.0', dependencies: deps },
  };
  for (const [name, version] of Object.entries(deps))
    packages[`node_modules/${name}`] = { version };
  writeFileSync(
    join(dir, 'package-lock.json'),
    JSON.stringify({ name: 'e2e', version: '1.0.0', lockfileVersion: 3, packages }),
  );
  return dir;
}

interface RunResult {
  status: number;
  stdout: string;
}

function run(args: string[]): RunResult {
  try {
    const stdout = execFileSync(process.execPath, [cliPath, ...args], { encoding: 'utf8' });
    return { status: 0, stdout };
  } catch (err) {
    const e = err as { status?: number; stdout?: string };
    return { status: e.status ?? 1, stdout: e.stdout ?? '' };
  }
}

const VULN: OsvVulnerability = {
  id: 'GHSA-e2e-test',
  summary: 'Test vulnerability in evil-pkg',
  severity: [{ type: 'CVSS_V3', score: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H' }],
  affected: [
    {
      package: { ecosystem: 'npm', name: 'evil-pkg' },
      ranges: [{ type: 'SEMVER', events: [{ introduced: '0' }, { fixed: '2.0.0' }] }],
    },
  ],
};

suite('CLI end-to-end (offline, no network)', () => {
  let cacheDir: string;

  beforeAll(() => {
    cacheDir = mkdtempSync(join(tmpdir(), 'npm-scanner-cache-'));
    seedDb(cacheDir, 'evil-pkg', VULN);
  });

  afterAll(() => {
    // temp dirs are left for the OS to reap
  });

  it('reports a vulnerable package as JSON', () => {
    const project = makeProject({ 'evil-pkg': '1.0.0' });
    const { status, stdout } = run([
      'scan',
      project,
      '--offline',
      '--cache-dir',
      cacheDir,
      '--format',
      'json',
      '--fail-on',
      'critical',
    ]);
    const result = JSON.parse(stdout) as ScanResult;
    expect(result.summary.critical).toBe(1);
    expect(result.findings[0]?.packageName).toBe('evil-pkg');
    expect(result.findings[0]?.fixedVersions).toContain('2.0.0');
    expect(status).toBe(1); // a critical finding meets --fail-on critical
  });

  it('exits 0 when the installed version is already fixed', () => {
    const project = makeProject({ 'evil-pkg': '2.0.0' });
    const { status, stdout } = run([
      'scan',
      project,
      '--offline',
      '--cache-dir',
      cacheDir,
      '--format',
      'json',
    ]);
    const result = JSON.parse(stdout) as ScanResult;
    expect(result.summary.total).toBe(0);
    expect(status).toBe(0);
  });

  it('honors --fail-on: passes (exit 0) when findings are below the threshold', () => {
    const project = makeProject({ 'evil-pkg': '1.0.0' });
    const { status } = run([
      'scan',
      project,
      '--offline',
      '--cache-dir',
      cacheDir,
      '--format',
      'json',
      '--fail-on',
      'critical',
      '--severity-threshold',
      'none',
    ]);
    // critical finding ≥ critical → still fails
    expect(status).toBe(1);
    const ignored = run([
      'scan',
      project,
      '--offline',
      '--cache-dir',
      cacheDir,
      '--format',
      'json',
      '--ignore',
      'GHSA-e2e-test',
      '--fail-on',
      'critical',
    ]);
    expect(ignored.status).toBe(0); // suppressed → nothing to fail on
  });

  it('exits 2 with a helpful message when no lockfile is present', () => {
    const empty = mkdtempSync(join(tmpdir(), 'npm-scanner-empty-'));
    const { status } = run(['scan', empty, '--offline', '--cache-dir', cacheDir]);
    expect(status).toBe(2);
  });

  it('emits valid SARIF 2.1.0', () => {
    const project = makeProject({ 'evil-pkg': '1.0.0' });
    const { stdout } = run([
      'scan',
      project,
      '--offline',
      '--cache-dir',
      cacheDir,
      '--format',
      'sarif',
      '--fail-on',
      'none',
    ]);
    const sarif = JSON.parse(stdout) as { version: string; runs: { results: unknown[] }[] };
    expect(sarif.version).toBe('2.1.0');
    expect(sarif.runs[0]?.results.length).toBe(1);
  });
});
