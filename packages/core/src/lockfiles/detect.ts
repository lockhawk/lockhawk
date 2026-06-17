import { existsSync, readFileSync, statSync } from 'node:fs';
import { join } from 'node:path';
import type { PackageManager } from '../types.js';

export interface DetectedLockfile {
  manager: PackageManager;
  /** Absolute or relative path to the lockfile. */
  path: string;
  filename: string;
}

const LOCKFILES: { filename: string; manager: PackageManager }[] = [
  { filename: 'pnpm-lock.yaml', manager: 'pnpm' },
  { filename: 'yarn.lock', manager: 'yarn' },
  { filename: 'package-lock.json', manager: 'npm' },
  { filename: 'npm-shrinkwrap.json', manager: 'npm' },
];

/**
 * Find the lockfile to scan in `dir`. If several are present we prefer pnpm,
 * then yarn, then npm — mirroring how a project that committed multiple
 * lockfiles is most likely actually installed.
 */
export function detectLockfile(dir: string): DetectedLockfile | undefined {
  for (const { filename, manager } of LOCKFILES) {
    const path = join(dir, filename);
    if (existsSync(path) && statSync(path).isFile()) {
      return { manager, path, filename };
    }
  }
  return undefined;
}

export interface RootManifest {
  name: string;
  version?: string;
  dependencies: Record<string, string>;
  devDependencies: Record<string, string>;
  optionalDependencies: Record<string, string>;
  peerDependencies: Record<string, string>;
}

/** Read and normalize the project's `package.json` (used to determine direct deps). */
export function readRootManifest(dir: string): RootManifest {
  const path = join(dir, 'package.json');
  let raw: Record<string, unknown> = {};
  if (existsSync(path)) {
    try {
      raw = JSON.parse(readFileSync(path, 'utf8')) as Record<string, unknown>;
    } catch {
      raw = {};
    }
  }
  const asMap = (v: unknown): Record<string, string> =>
    v && typeof v === 'object' ? (v as Record<string, string>) : {};
  return {
    name: typeof raw.name === 'string' ? raw.name : 'project',
    version: typeof raw.version === 'string' ? raw.version : undefined,
    dependencies: asMap(raw.dependencies),
    devDependencies: asMap(raw.devDependencies),
    optionalDependencies: asMap(raw.optionalDependencies),
    peerDependencies: asMap(raw.peerDependencies),
  };
}
