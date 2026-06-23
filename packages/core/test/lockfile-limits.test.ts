import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, describe, expect, it } from 'vitest';
import { loadDependencyGraph, LockfileError } from '../src/lockfiles/normalize.js';

/** Create a throwaway project dir with a package.json and a package-lock.json. */
function makeProject(lock: unknown): string {
  const dir = mkdtempSync(join(tmpdir(), 'lockhawk-limits-'));
  writeFileSync(
    join(dir, 'package.json'),
    JSON.stringify({ name: 'demo', version: '1.0.0', dependencies: { a: '1.0.0' } }),
  );
  writeFileSync(join(dir, 'package-lock.json'), JSON.stringify(lock));
  return dir;
}

const dirs: string[] = [];
const track = (dir: string): string => (dirs.push(dir), dir);
afterEach(() => {
  delete process.env.LOCKHAWK_MAX_LOCKFILE_BYTES;
  while (dirs.length) rmSync(dirs.pop()!, { recursive: true, force: true });
});

describe('lockfile safety limits', () => {
  it('rejects a package-lock v1 nested far deeper than any real tree (DoS guard)', () => {
    // Build a v1 lockfile nested ~600 levels deep (cap is 500).
    let dep: Record<string, unknown> = { version: '1.0.0' };
    for (let i = 0; i < 600; i++) {
      dep = { version: '1.0.0', dependencies: { [`p${i}`]: dep } };
    }
    const lock = {
      name: 'demo',
      version: '1.0.0',
      lockfileVersion: 1,
      dependencies: { root: dep },
    };
    const dir = track(makeProject(lock));

    expect(() => loadDependencyGraph(dir)).toThrowError(LockfileError);
    expect(() => loadDependencyGraph(dir)).toThrowError(/nesting exceeds/i);
  });

  it('accepts a normally-nested v1 lockfile (guard does not false-positive)', () => {
    let dep: Record<string, unknown> = { version: '1.0.0' };
    for (let i = 0; i < 50; i++) {
      dep = { version: '1.0.0', dependencies: { [`p${i}`]: dep } };
    }
    const lock = {
      name: 'demo',
      version: '1.0.0',
      lockfileVersion: 1,
      dependencies: { root: dep },
    };
    const dir = track(makeProject(lock));

    expect(() => loadDependencyGraph(dir)).not.toThrow();
  });

  it('rejects a lockfile larger than the configured byte cap (memory-exhaustion guard)', () => {
    process.env.LOCKHAWK_MAX_LOCKFILE_BYTES = '50';
    const lock = {
      name: 'demo',
      version: '1.0.0',
      lockfileVersion: 1,
      dependencies: { root: { version: '1.0.0' } },
    };
    const dir = track(makeProject(lock)); // serialized JSON is well over 50 bytes

    expect(() => loadDependencyGraph(dir)).toThrowError(/safety limit/i);
  });

  it('honors a raised byte cap', () => {
    process.env.LOCKHAWK_MAX_LOCKFILE_BYTES = String(10 * 1024 * 1024);
    const lock = {
      name: 'demo',
      version: '1.0.0',
      lockfileVersion: 1,
      dependencies: { root: { version: '1.0.0' } },
    };
    const dir = track(makeProject(lock));

    expect(() => loadDependencyGraph(dir)).not.toThrow();
  });
});
