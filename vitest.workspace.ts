import { defineWorkspace } from 'vitest/config';

// Aggregates every package's vitest config so `vitest run` at the repo root
// executes the whole monorepo's test suite.
export default defineWorkspace(['packages/*']);
