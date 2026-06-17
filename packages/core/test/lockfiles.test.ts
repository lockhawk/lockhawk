import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';
import { loadDependencyGraph } from '../src/lockfiles/normalize.js';
import { shortestPath } from '../src/graph/paths.js';
import type { PackageManager } from '../src/types.js';

const fixture = (name: string): string =>
  fileURLToPath(new URL(`./fixtures/${name}`, import.meta.url));

// Every fixture encodes the same project so the normalized graph must match:
//   demo@1.0.0
//     ├─ pkg-a@1.0.0      (prod, direct)  ─► pkg-b@2.0.0 (prod, transitive)
//     └─ pkg-d@3.0.0      (dev,  direct)
const cases: { dir: string; manager: PackageManager }[] = [
  { dir: 'npm-v3', manager: 'npm' },
  { dir: 'npm-v1', manager: 'npm' },
  { dir: 'npm-shrinkwrap', manager: 'npm' },
  { dir: 'yarn-classic', manager: 'yarn' },
  { dir: 'yarn-berry', manager: 'yarn' },
  { dir: 'pnpm-v9', manager: 'pnpm' },
  { dir: 'pnpm-v6', manager: 'pnpm' },
];

describe.each(cases)('lockfile parsing: $dir', ({ dir, manager }) => {
  const graph = loadDependencyGraph(fixture(dir));

  it('detects the right package manager and root', () => {
    expect(graph.manager).toBe(manager);
    expect(graph.root.name).toBe('demo');
  });

  it('produces exactly the three installed packages', () => {
    expect(Object.keys(graph.nodes).sort()).toEqual(['pkg-a@1.0.0', 'pkg-b@2.0.0', 'pkg-d@3.0.0']);
  });

  it('identifies only pkg-a and pkg-d as direct dependencies', () => {
    expect([...graph.directKeys].sort()).toEqual(['pkg-a@1.0.0', 'pkg-d@3.0.0']);
  });

  it('classifies scopes by reachability', () => {
    expect(graph.nodes['pkg-a@1.0.0']!.scope).toBe('prod');
    expect(graph.nodes['pkg-b@2.0.0']!.scope).toBe('prod');
    expect(graph.nodes['pkg-d@3.0.0']!.scope).toBe('dev');
  });

  it('records the transitive edge pkg-a → pkg-b', () => {
    expect(graph.nodes['pkg-a@1.0.0']!.dependencies).toContain('pkg-b@2.0.0');
  });

  it('traces the dependency path to the transitive package', () => {
    expect(shortestPath(graph, 'pkg-b@2.0.0')).toEqual([
      'demo@1.0.0',
      'pkg-a@1.0.0',
      'pkg-b@2.0.0',
    ]);
  });
});

describe('lockfile detection', () => {
  it('throws a helpful error when no lockfile is present', () => {
    expect(() => loadDependencyGraph(fixture('.'))).toThrowError(/No lockfile found/);
  });
});
