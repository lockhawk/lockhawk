import { test } from 'node:test';
import assert from 'node:assert/strict';
import { planRelease } from './release-plan.mjs';

test('patch / minor / major bump and publish to latest', () => {
  assert.deepEqual(planRelease('0.1.0', 'patch'), { version: '0.1.1', npmTag: 'latest' });
  assert.deepEqual(planRelease('0.1.0', 'minor'), { version: '0.2.0', npmTag: 'latest' });
  assert.deepEqual(planRelease('0.1.0', 'major'), { version: '1.0.0', npmTag: 'latest' });
});

test('preminor with an identifier publishes under that tag', () => {
  assert.deepEqual(planRelease('0.1.0', 'preminor', { preid: 'beta' }), {
    version: '0.2.0-beta.0',
    npmTag: 'beta',
  });
});

test('prerelease increments an existing prerelease line', () => {
  assert.deepEqual(planRelease('0.2.0-beta.0', 'prerelease', { preid: 'beta' }), {
    version: '0.2.0-beta.1',
    npmTag: 'beta',
  });
});

test('custom version derives its own tag', () => {
  assert.deepEqual(planRelease('0.1.0', 'custom', { exact: '2.0.0-rc.3' }), {
    version: '2.0.0-rc.3',
    npmTag: 'rc',
  });
  assert.deepEqual(planRelease('0.1.0', 'custom', { exact: '1.2.3' }), {
    version: '1.2.3',
    npmTag: 'latest',
  });
});

test('rejects an invalid custom version', () => {
  assert.throws(() => planRelease('0.1.0', 'custom', { exact: 'nope' }));
});
