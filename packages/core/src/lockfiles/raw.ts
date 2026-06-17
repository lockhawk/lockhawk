import type {
  DependencyGraph,
  DepNode,
  DepScope,
  PackageManager,
  PkgKey,
  UnscannablePackage,
} from '../types.js';

/**
 * Manager-agnostic parser output. Each lockfile parser produces one of these;
 * a single {@link buildDependencyGraph} step then classifies scopes by
 * reachability and assembles the final {@link DependencyGraph}.
 *
 * Computing scope from reachability (rather than per-package `dev` flags) is
 * what lets us treat npm, yarn and pnpm uniformly — pnpm v9 lockfiles, for
 * instance, no longer carry a per-package `dev` field.
 */
export interface RawNode {
  key: PkgKey;
  name: string;
  version: string;
  /** Keys of packages this node depends on (edges out). May contain duplicates. */
  dependencies: PkgKey[];
  /** Set when there is no queryable registry version (file:/link:/git:/workspace). */
  unscannable?: { reason: string };
}

export interface RawGraph {
  manager: PackageManager;
  lockfilePath: string;
  lockfileVersion?: string | number;
  root: { name: string; version?: string };
  nodes: Record<PkgKey, RawNode>;
  /** Direct production dependencies of the project root. */
  directProd: PkgKey[];
  /** Direct dev dependencies of the project root. */
  directDev: PkgKey[];
  /** Direct optional dependencies of the project root. */
  directOptional: PkgKey[];
  unscannable: UnscannablePackage[];
}

/** Breadth-first set of all keys reachable from the given starting keys. */
function reachable(start: Iterable<PkgKey>, nodes: Record<PkgKey, RawNode>): Set<PkgKey> {
  const seen = new Set<PkgKey>();
  const queue: PkgKey[] = [];
  for (const k of start) {
    if (!seen.has(k)) {
      seen.add(k);
      queue.push(k);
    }
  }
  for (let i = 0; i < queue.length; i++) {
    const node = nodes[queue[i]!];
    if (!node) continue;
    for (const dep of node.dependencies) {
      if (!seen.has(dep)) {
        seen.add(dep);
        queue.push(dep);
      }
    }
  }
  return seen;
}

/**
 * Classify every node's scope by reachability and assemble the normalized graph.
 * Priority when a node is reachable multiple ways: prod > optional > dev.
 */
export function buildDependencyGraph(raw: RawGraph): DependencyGraph {
  const prodReach = reachable(raw.directProd, raw.nodes);
  const optionalReach = reachable(raw.directOptional, raw.nodes);
  const devReach = reachable(raw.directDev, raw.nodes);
  const direct = new Set<PkgKey>([...raw.directProd, ...raw.directOptional, ...raw.directDev]);

  const nodes: Record<PkgKey, DepNode> = {};
  for (const [key, rn] of Object.entries(raw.nodes)) {
    let scope: DepScope;
    if (prodReach.has(key)) scope = 'prod';
    else if (optionalReach.has(key)) scope = 'optional';
    else if (devReach.has(key)) scope = 'dev';
    else scope = 'prod'; // explicitly-listed-but-unreferenced: treat as prod

    nodes[key] = {
      key,
      name: rn.name,
      version: rn.version,
      scope,
      direct: direct.has(key),
      dependencies: dedupe(rn.dependencies),
      ...(rn.unscannable ? { unscannable: rn.unscannable } : {}),
    };
  }

  return {
    manager: raw.manager,
    lockfilePath: raw.lockfilePath,
    lockfileVersion: raw.lockfileVersion,
    root: raw.root,
    nodes,
    directKeys: [...direct].filter((k) => nodes[k] !== undefined),
  };
}

function dedupe(keys: PkgKey[]): PkgKey[] {
  return keys.length > 1 ? [...new Set(keys)] : keys;
}
