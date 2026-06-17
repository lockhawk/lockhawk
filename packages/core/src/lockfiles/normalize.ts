import { resolve } from 'node:path';
import type { DependencyGraph } from '../types.js';
import { detectLockfile } from './detect.js';
import type { DetectedLockfile } from './detect.js';
import { buildDependencyGraph } from './raw.js';
import type { RawGraph } from './raw.js';
import { parseNpm } from './npm.js';
import { parseYarn } from './yarn.js';
import { parsePnpm } from './pnpm.js';

export class LockfileError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'LockfileError';
  }
}

/** Parse a detected lockfile into the manager-agnostic {@link RawGraph}. */
export function parseLockfile(detected: DetectedLockfile): RawGraph {
  try {
    switch (detected.manager) {
      case 'npm':
        return parseNpm(detected.path);
      case 'yarn':
        return parseYarn(detected.path);
      case 'pnpm':
        return parsePnpm(detected.path);
    }
  } catch (err) {
    throw new LockfileError(
      `Failed to parse ${detected.filename}: ${err instanceof Error ? err.message : String(err)}`,
    );
  }
}

/**
 * Detect, parse and normalize the lockfile in `dir` into a {@link DependencyGraph}.
 * Throws {@link LockfileError} when no lockfile is present or parsing fails.
 */
export function loadDependencyGraph(dir: string): DependencyGraph {
  const detected = detectLockfile(resolve(dir));
  if (!detected) {
    throw new LockfileError(
      `No lockfile found in ${dir}. Expected one of: package-lock.json, yarn.lock, pnpm-lock.yaml.`,
    );
  }
  return buildDependencyGraph(parseLockfile(detected));
}
