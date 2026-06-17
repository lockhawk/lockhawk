// Public programmatic API for @npm-scanner/core.
// The full surface is wired up across the M1–M6 milestones; this file is the
// single entry point consumers (and the CLI) import from.

export * from './types.js';

// Lockfile parsing → normalized dependency graph (M1).
export { loadDependencyGraph, parseLockfile, LockfileError } from './lockfiles/normalize.js';
export { detectLockfile, readRootManifest } from './lockfiles/detect.js';
export type { DetectedLockfile, RootManifest } from './lockfiles/detect.js';
export { buildDependencyGraph } from './lockfiles/raw.js';
export type { RawGraph, RawNode } from './lockfiles/raw.js';
export { shortestPath, rootLabel } from './graph/paths.js';
