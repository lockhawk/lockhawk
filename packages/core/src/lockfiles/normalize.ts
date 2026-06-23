import { statSync } from 'node:fs';
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

/**
 * Upper bound on lockfile size, read once per call so it can be overridden in
 * tests / by power users via `LOCKHAWK_MAX_LOCKFILE_BYTES`. Lockfiles are read
 * fully into memory before parsing, so an unbounded file is a memory-exhaustion
 * vector when scanning untrusted projects; 64 MB is far above any real lockfile.
 */
function maxLockfileBytes(): number {
  const override = Number(process.env.LOCKHAWK_MAX_LOCKFILE_BYTES);
  return Number.isFinite(override) && override > 0 ? override : 64 * 1024 * 1024;
}

/** Parse a detected lockfile into the manager-agnostic {@link RawGraph}. */
export function parseLockfile(detected: DetectedLockfile): RawGraph {
  let bytes = 0;
  try {
    bytes = statSync(detected.path).size;
  } catch {
    // If we can't stat it, let the parser surface a clear read error below.
  }
  const limit = maxLockfileBytes();
  if (bytes > limit) {
    throw new LockfileError(
      `${detected.filename} is ${bytes} bytes, exceeding the ${limit}-byte safety limit. ` +
        `Set LOCKHAWK_MAX_LOCKFILE_BYTES to raise it.`,
    );
  }
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
