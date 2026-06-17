import { readFileSync } from 'node:fs';
import { dirname } from 'node:path';
import { pkgKey } from '../types.js';
import type { UnscannablePackage } from '../types.js';
import type { RawGraph, RawNode } from './raw.js';
import { readRootManifest } from './detect.js';

interface PkgEntry {
  name?: string;
  version?: string;
  resolved?: string;
  link?: boolean;
  dependencies?: Record<string, string>;
  devDependencies?: Record<string, string>;
  optionalDependencies?: Record<string, string>;
  peerDependencies?: Record<string, string>;
}

interface V1Entry {
  version?: string;
  dev?: boolean;
  optional?: boolean;
  requires?: Record<string, string>;
  dependencies?: Record<string, V1Entry>;
}

/** Parse a `package-lock.json` / `npm-shrinkwrap.json` (lockfile v1, v2 or v3). */
export function parseNpm(lockfilePath: string): RawGraph {
  const data = JSON.parse(readFileSync(lockfilePath, 'utf8')) as {
    name?: string;
    version?: string;
    lockfileVersion?: number;
    packages?: Record<string, PkgEntry>;
    dependencies?: Record<string, V1Entry>;
  };

  if (data.packages) {
    return parsePackages(data, lockfilePath);
  }
  return parseLegacy(data, lockfilePath);
}

/** Last `node_modules/<name>` segment of an install path, scope-aware. */
function nameFromPath(p: string): string {
  const marker = 'node_modules/';
  const idx = p.lastIndexOf(marker);
  return idx === -1 ? p : p.slice(idx + marker.length);
}

/** Lockfile v2/v3: a flat `packages` map keyed by install path. */
function parsePackages(
  data: { name?: string; version?: string; lockfileVersion?: number; packages?: Record<string, PkgEntry> },
  lockfilePath: string,
): RawGraph {
  const packages = data.packages ?? {};
  const rootEntry = packages[''] ?? {};
  const root = {
    name: rootEntry.name ?? data.name ?? 'project',
    version: rootEntry.version ?? data.version,
  };

  const nodes: Record<string, RawNode> = {};
  const unscannable: UnscannablePackage[] = [];
  const pathToKey: Record<string, string> = {};

  // First pass: create a node per installed package and map its path → key.
  for (const [p, entry] of Object.entries(packages)) {
    if (p === '' || entry.link) continue;
    const name = entry.name ?? nameFromPath(p);
    const version = entry.version;
    if (!version) continue;
    const key = pkgKey(name, version);
    pathToKey[p] = key;
    if (!nodes[key]) {
      const node: RawNode = { key, name, version, dependencies: [] };
      // A package living outside node_modules is a local workspace package —
      // it is your own code, not something to look up in OSV.
      if (!p.includes('node_modules')) {
        node.unscannable = { reason: 'local workspace package' };
        unscannable.push({ name, version, reason: 'local workspace package' });
      }
      nodes[key] = node;
    }
  }

  // Resolve a dependency name from a package path using node_modules hoisting:
  // check the nearest node_modules first, then walk up toward the root.
  const resolveDep = (fromPath: string, depName: string): string | undefined => {
    let prefix = fromPath;
    for (;;) {
      const candidate = `${prefix ? `${prefix}/` : ''}node_modules/${depName}`;
      const entry = packages[candidate];
      if (entry) {
        if (entry.link && typeof entry.resolved === 'string') return entry.resolved;
        return candidate;
      }
      if (!prefix) return undefined;
      const i = prefix.lastIndexOf('/node_modules/');
      prefix = i === -1 ? '' : prefix.slice(0, i);
    }
  };

  const directProd = new Set<string>();
  const directDev = new Set<string>();
  const directOptional = new Set<string>();

  // Second pass: build edges. Only the root/workspace packages contribute
  // direct deps and dev edges; transitive packages contribute prod/optional only.
  for (const [p, entry] of Object.entries(packages)) {
    if (entry.link) continue;
    const fromKey = p === '' ? undefined : pathToKey[p];
    const isLocalRoot = p === '' || !p.includes('node_modules');

    const addEdges = (names: string[], bucket?: Set<string>): void => {
      for (const depName of names) {
        const targetPath = resolveDep(p, depName);
        if (!targetPath) continue; // unmet optional / not installed on this platform
        const targetKey = pathToKey[targetPath];
        if (!targetKey) continue;
        if (fromKey && fromKey !== targetKey) nodes[fromKey]!.dependencies.push(targetKey);
        if (bucket) bucket.add(targetKey);
      }
    };

    addEdges(Object.keys(entry.dependencies ?? {}), isLocalRoot ? directProd : undefined);
    addEdges(Object.keys(entry.optionalDependencies ?? {}), isLocalRoot ? directOptional : undefined);
    if (isLocalRoot) {
      addEdges(Object.keys(entry.devDependencies ?? {}), directDev);
    }
  }

  return {
    manager: 'npm',
    lockfilePath,
    lockfileVersion: data.lockfileVersion,
    root,
    nodes,
    directProd: [...directProd],
    directDev: [...directDev],
    directOptional: [...directOptional],
    unscannable,
  };
}

/** Lockfile v1: a nested `dependencies` tree. Direct deps come from package.json. */
function parseLegacy(
  data: { name?: string; version?: string; lockfileVersion?: number; dependencies?: Record<string, V1Entry> },
  lockfilePath: string,
): RawGraph {
  const manifest = readRootManifest(dirname(lockfilePath));
  const root = { name: data.name ?? manifest.name, version: data.version ?? manifest.version };

  const nodes: Record<string, RawNode> = {};

  const buildLevel = (deps?: Record<string, V1Entry>): Map<string, string> => {
    const m = new Map<string, string>();
    for (const [name, info] of Object.entries(deps ?? {})) {
      if (info?.version) m.set(name, info.version);
    }
    return m;
  };

  // Resolve a required name against the visibility chain, nearest level first.
  const resolveFromChain = (name: string, chain: Map<string, string>[]): string | undefined => {
    for (let i = chain.length - 1; i >= 0; i--) {
      const v = chain[i]!.get(name);
      if (v) return v;
    }
    return undefined;
  };

  const visit = (deps: Record<string, V1Entry> | undefined, ancestors: Map<string, string>[]): void => {
    const level = buildLevel(deps);
    const chain = [...ancestors, level];
    for (const [name, info] of Object.entries(deps ?? {})) {
      const version = info?.version;
      if (!version) continue;
      const key = pkgKey(name, version);
      if (!nodes[key]) nodes[key] = { key, name, version, dependencies: [] };

      const ownChain = [...chain, buildLevel(info.dependencies)];
      for (const reqName of Object.keys(info.requires ?? {})) {
        const v = resolveFromChain(reqName, ownChain);
        if (v) {
          const targetKey = pkgKey(reqName, v);
          if (targetKey !== key) nodes[key]!.dependencies.push(targetKey);
        }
      }
      if (info.dependencies) visit(info.dependencies, chain);
    }
  };
  visit(data.dependencies, []);

  // Direct deps: declared in package.json, resolved to top-level installed versions.
  const topLevel = buildLevel(data.dependencies);
  const directProd: string[] = [];
  const directDev: string[] = [];
  const directOptional: string[] = [];
  const classify = (names: string[], out: string[]): void => {
    for (const name of names) {
      const v = topLevel.get(name);
      if (v) out.push(pkgKey(name, v));
    }
  };
  classify(Object.keys(manifest.dependencies), directProd);
  classify(Object.keys(manifest.optionalDependencies), directOptional);
  classify(Object.keys(manifest.devDependencies), directDev);

  return {
    manager: 'npm',
    lockfilePath,
    lockfileVersion: data.lockfileVersion,
    root,
    nodes,
    directProd,
    directDev,
    directOptional,
    unscannable: [],
  };
}
