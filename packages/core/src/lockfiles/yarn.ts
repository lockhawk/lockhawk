import { readFileSync } from 'node:fs';
import { dirname } from 'node:path';
import { createRequire } from 'node:module';
import yaml from 'js-yaml';
import { pkgKey } from '../types.js';
import type { RawGraph, RawNode } from './raw.js';
import { readRootManifest } from './detect.js';
import type { RootManifest } from './detect.js';

// @yarnpkg/lockfile is CommonJS with no ESM default; load it via require so the
// interop is identical under vitest (vite) and the built Node ESM bundle.
const require = createRequire(import.meta.url);
const yarnLockfile = require('@yarnpkg/lockfile') as {
  parse(content: string): { type: string; object: Record<string, YarnEntry> };
};

interface YarnEntry {
  version?: string;
  resolution?: string;
  dependencies?: Record<string, string>;
  optionalDependencies?: Record<string, string>;
}

/** Parse a `yarn.lock` (classic v1 or berry v2+). */
export function parseYarn(lockfilePath: string): RawGraph {
  const content = readFileSync(lockfilePath, 'utf8');
  const manifest = readRootManifest(dirname(lockfilePath));
  const isBerry = content.includes('__metadata');
  const { descriptorToVersion, entryByVersion, lockfileVersion } = isBerry
    ? parseBerry(content)
    : parseClassic(content);
  return assemble(
    lockfilePath,
    manifest,
    descriptorToVersion,
    entryByVersion,
    lockfileVersion,
    isBerry,
  );
}

/** Split a "name@range" descriptor, scope-aware. */
function splitDescriptor(descriptor: string): { name: string; range: string } | undefined {
  const at = descriptor.lastIndexOf('@');
  if (at <= 0) return undefined;
  return { name: descriptor.slice(0, at), range: descriptor.slice(at + 1) };
}

interface ParsedLock {
  /** "name@range" → resolved version. */
  descriptorToVersion: Map<string, string>;
  /** "name@version" → its dependency ranges. */
  entryByVersion: Map<string, YarnEntry>;
  lockfileVersion: string | number;
}

function parseClassic(content: string): ParsedLock {
  const parsed = yarnLockfile.parse(content) as { object: Record<string, YarnEntry> };
  const descriptorToVersion = new Map<string, string>();
  const entryByVersion = new Map<string, YarnEntry>();
  for (const [rawKey, entry] of Object.entries(parsed.object)) {
    if (!entry.version) continue;
    // A key may list several descriptors joined by ", ".
    for (const descriptor of rawKey.split(/,\s*/)) {
      const split = splitDescriptor(descriptor);
      if (split) descriptorToVersion.set(`${split.name}@${split.range}`, entry.version);
      if (split) entryByVersion.set(pkgKey(split.name, entry.version), entry);
    }
  }
  return { descriptorToVersion, entryByVersion, lockfileVersion: 1 };
}

function parseBerry(content: string): ParsedLock {
  const doc = (yaml.load(content) as Record<string, YarnEntry & { version?: string }>) ?? {};
  const descriptorToVersion = new Map<string, string>();
  const entryByVersion = new Map<string, YarnEntry>();
  let lockfileVersion: string | number = 'berry';
  for (const [rawKey, entry] of Object.entries(doc)) {
    if (rawKey === '__metadata') {
      const v = (entry as { version?: string | number }).version;
      if (v !== undefined) lockfileVersion = v;
      continue;
    }
    if (!entry.version) continue;
    for (const descriptor of rawKey.split(/,\s*/)) {
      const split = splitDescriptor(descriptor);
      if (!split) continue;
      descriptorToVersion.set(`${split.name}@${split.range}`, entry.version);
      entryByVersion.set(pkgKey(split.name, entry.version), entry);
    }
  }
  return { descriptorToVersion, entryByVersion, lockfileVersion };
}

function assemble(
  lockfilePath: string,
  manifest: RootManifest,
  descriptorToVersion: Map<string, string>,
  entryByVersion: Map<string, YarnEntry>,
  lockfileVersion: string | number,
  isBerry: boolean,
): RawGraph {
  // Resolve a (name, range) request to an installed version, tolerating berry's
  // protocol prefixes (e.g. "npm:^1.0.0") that the manifest omits.
  const resolve = (name: string, range: string): string | undefined => {
    const candidates = isBerry
      ? [`${name}@${range}`, `${name}@npm:${range}`]
      : [`${name}@${range}`];
    for (const c of candidates) {
      const v = descriptorToVersion.get(c);
      if (v) return v;
    }
    return undefined;
  };

  const nodes: Record<string, RawNode> = Object.create(null);
  for (const [key, entry] of entryByVersion) {
    // `key` is already a `name@version` PkgKey; recover both halves.
    const at = key.lastIndexOf('@');
    const name = key.slice(0, at);
    const version = key.slice(at + 1);
    if (!nodes[key]) nodes[key] = { key, name, version, dependencies: [] };
    const addEdges = (deps?: Record<string, string>): void => {
      for (const [depName, depRange] of Object.entries(deps ?? {})) {
        const v = resolve(depName, depRange);
        if (!v) continue;
        const targetKey = pkgKey(depName, v);
        if (targetKey !== key) nodes[key]!.dependencies.push(targetKey);
      }
    };
    addEdges(entry.dependencies);
    addEdges(entry.optionalDependencies);
  }

  const toDirect = (deps: Record<string, string>): string[] => {
    const out: string[] = [];
    for (const [name, range] of Object.entries(deps)) {
      const v = resolve(name, range);
      if (v) out.push(pkgKey(name, v));
    }
    return out;
  };

  return {
    manager: 'yarn',
    lockfilePath,
    lockfileVersion,
    root: { name: manifest.name, version: manifest.version },
    nodes,
    directProd: toDirect(manifest.dependencies),
    directDev: toDirect(manifest.devDependencies),
    directOptional: toDirect(manifest.optionalDependencies),
    unscannable: [],
  };
}
