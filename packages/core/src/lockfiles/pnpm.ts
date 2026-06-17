import { readFileSync } from 'node:fs';
import { dirname } from 'node:path';
import yaml from 'js-yaml';
import { pkgKey } from '../types.js';
import type { RawGraph, RawNode } from './raw.js';
import { readRootManifest } from './detect.js';

interface PnpmEntry {
  dependencies?: Record<string, string>;
  optionalDependencies?: Record<string, string>;
}

interface ImporterDeps {
  dependencies?: Record<string, unknown>;
  devDependencies?: Record<string, unknown>;
  optionalDependencies?: Record<string, unknown>;
}

interface PnpmLock {
  lockfileVersion?: string | number;
  importers?: Record<string, ImporterDeps>;
  packages?: Record<string, PnpmEntry>;
  snapshots?: Record<string, PnpmEntry>;
  dependencies?: Record<string, unknown>;
  devDependencies?: Record<string, unknown>;
  optionalDependencies?: Record<string, unknown>;
}

/** Parse a `pnpm-lock.yaml` (lockfile v5, v6 or v9). */
export function parsePnpm(lockfilePath: string): RawGraph {
  const doc = (yaml.load(readFileSync(lockfilePath, 'utf8')) as PnpmLock) ?? {};
  const manifest = readRootManifest(dirname(lockfilePath));
  const major = majorVersion(doc.lockfileVersion);

  const nodes: Record<string, RawNode> = {};

  // Nodes come from the `packages` map (one entry per installed package).
  for (const key of Object.keys(doc.packages ?? {})) {
    const parsed = parseKey(key, major);
    if (!parsed) continue;
    const nodeKey = pkgKey(parsed.name, parsed.version);
    if (!nodes[nodeKey]) {
      nodes[nodeKey] = {
        key: nodeKey,
        name: parsed.name,
        version: parsed.version,
        dependencies: [],
      };
    }
  }

  // Edges: from `snapshots` in v9, else from `packages` directly.
  const edgeSource = major >= 9 ? (doc.snapshots ?? {}) : (doc.packages ?? {});
  for (const [key, entry] of Object.entries(edgeSource)) {
    const parsed = parseKey(key, major);
    if (!parsed) continue;
    const fromKey = pkgKey(parsed.name, parsed.version);
    if (!nodes[fromKey]) {
      nodes[fromKey] = {
        key: fromKey,
        name: parsed.name,
        version: parsed.version,
        dependencies: [],
      };
    }
    const addEdges = (deps?: Record<string, string>): void => {
      for (const [depName, depValue] of Object.entries(deps ?? {})) {
        const targetKey = pkgKey(depName, stripVersion(depValue, major));
        if (targetKey !== fromKey && nodes[targetKey]) nodes[fromKey]!.dependencies.push(targetKey);
      }
    };
    addEdges(entry.dependencies);
    addEdges(entry.optionalDependencies);
  }

  // Roots: from `importers` (workspaces + modern single project) or the
  // top-level dependency maps (older single-project lockfiles).
  const importers: Record<string, ImporterDeps> = doc.importers ?? {
    '.': {
      dependencies: doc.dependencies,
      devDependencies: doc.devDependencies,
      optionalDependencies: doc.optionalDependencies,
    },
  };

  const directProd = new Set<string>();
  const directDev = new Set<string>();
  const directOptional = new Set<string>();
  const collect = (deps: Record<string, unknown> | undefined, into: Set<string>): void => {
    for (const [name, val] of Object.entries(deps ?? {})) {
      const version = importerVersion(val, major);
      if (!version) continue;
      const key = pkgKey(name, version);
      if (nodes[key]) into.add(key);
    }
  };
  for (const imp of Object.values(importers)) {
    collect(imp.dependencies, directProd);
    collect(imp.optionalDependencies, directOptional);
    collect(imp.devDependencies, directDev);
  }

  return {
    manager: 'pnpm',
    lockfilePath,
    lockfileVersion: doc.lockfileVersion,
    root: { name: manifest.name, version: manifest.version },
    nodes,
    directProd: [...directProd],
    directDev: [...directDev],
    directOptional: [...directOptional],
    unscannable: [],
  };
}

function majorVersion(v: string | number | undefined): number {
  const n = parseFloat(String(v ?? '9'));
  return Number.isNaN(n) ? 9 : Math.floor(n);
}

/** Parse a pnpm package key into `{ name, version }`, format-aware. */
function parseKey(key: string, major: number): { name: string; version: string } | undefined {
  const k = key.startsWith('/') ? key.slice(1) : key;
  if (major < 6) {
    // `name/version[_peers]`
    const lastSlash = k.lastIndexOf('/');
    if (lastSlash <= 0) return undefined;
    const name = k.slice(0, lastSlash);
    const version = stripVersion(k.slice(lastSlash + 1), major);
    return version ? { name, version } : undefined;
  }
  // `name@version[(peers)]`
  const at = k.lastIndexOf('@');
  if (at <= 0) return undefined;
  const name = k.slice(0, at);
  const version = stripVersion(k.slice(at + 1), major);
  return version ? { name, version } : undefined;
}

/** Strip pnpm's peer-dependency suffix from a version ref. */
function stripVersion(value: string, major: number): string {
  let v = value;
  if (major < 6) {
    const us = v.indexOf('_');
    if (us !== -1) v = v.slice(0, us);
  }
  const paren = v.indexOf('(');
  if (paren !== -1) v = v.slice(0, paren);
  return v;
}

/** Extract the installed version from an importer dependency entry. */
function importerVersion(val: unknown, major: number): string | undefined {
  let ref: string | undefined;
  if (typeof val === 'string') ref = val;
  else if (
    val &&
    typeof val === 'object' &&
    typeof (val as { version?: unknown }).version === 'string'
  ) {
    ref = (val as { version: string }).version;
  }
  if (!ref) return undefined;
  if (ref.startsWith('link:') || ref.startsWith('file:') || ref.startsWith('workspace:'))
    return undefined;
  return stripVersion(ref, major);
}
