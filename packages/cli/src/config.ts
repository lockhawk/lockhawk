import { existsSync, readFileSync } from 'node:fs';
import { cosmiconfigSync } from 'cosmiconfig';
import type { Severity, SourceMode } from '@npm-scanner/core';

/** Configuration resolvable from a config file (`.npmscannerrc`, `package.json#npm-scanner`, …). */
export interface FileConfig {
  mode?: SourceMode;
  failOn?: Severity;
  severityThreshold?: Severity;
  prodOnly?: boolean;
  ignore?: string[];
  concurrency?: number;
  cacheTtlHours?: number;
}

/** Load a config file by searching upward from `cwd`. Returns `{}` if none found. */
export function loadFileConfig(cwd: string): FileConfig {
  try {
    const result = cosmiconfigSync('npm-scanner').search(cwd);
    return (result?.config as FileConfig) ?? {};
  } catch {
    return {};
  }
}

/**
 * Parse a `.npmscanignore` file. Each non-comment line is an advisory id with an
 * optional expiry date (`GHSA-xxxx 2026-12-31`); expired entries are dropped so
 * suppressions don't silently outlive their review.
 */
export function readIgnoreFile(path: string, now: Date = new Date()): string[] {
  if (!existsSync(path)) return [];
  const ids: string[] = [];
  for (const raw of readFileSync(path, 'utf8').split(/\r?\n/)) {
    const line = raw.replace(/#.*$/, '').trim();
    if (!line) continue;
    const [id, expiry] = line.split(/\s+/);
    if (!id) continue;
    if (expiry) {
      const when = Date.parse(expiry);
      if (!Number.isNaN(when) && when < now.getTime()) continue; // expired → no longer ignored
    }
    ids.push(id);
  }
  return ids;
}
