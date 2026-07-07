import { test } from 'node:test';
import assert from 'node:assert/strict';
import { setActionVersion } from './action-yaml.mjs';

// A faithful slice of action.yml: several inputs whose defaults are NOT
// semver-shaped, plus the single `version` input whose default is.
const SAMPLE = `inputs:
  path:
    description: 'Project directory to scan'
    default: '.'
  fail-on:
    description: 'Minimum severity that fails the build'
    default: 'high'
  offline:
    default: 'true'
  prod-only:
    default: 'false'
  version:
    description: 'lockhawk version to run via npx.'
    default: '0.2.5'
`;

test('rewrites the version input default', () => {
  const out = setActionVersion(SAMPLE, '0.2.11');
  assert.match(out, /default: '0\.2\.11'/);
  assert.doesNotMatch(out, /default: '0\.2\.5'/);
});

test('leaves every other default untouched', () => {
  const out = setActionVersion(SAMPLE, '0.2.11');
  assert.match(out, /default: '\.'/); // path
  assert.match(out, /default: 'high'/); // fail-on
  assert.match(out, /default: 'true'/); // offline
  assert.match(out, /default: 'false'/); // prod-only
});

test('supports prerelease versions', () => {
  const out = setActionVersion(SAMPLE, '1.0.0-rc.1');
  assert.match(out, /default: '1\.0\.0-rc\.1'/);
});

test('throws when no semver-shaped default is present', () => {
  const noSemver = `inputs:\n  fail-on:\n    default: 'high'\n`;
  assert.throws(() => setActionVersion(noSemver, '1.0.0'), /exactly one/i);
});

test('throws when more than one semver-shaped default is present', () => {
  const two = SAMPLE + `  extra:\n    default: '9.9.9'\n`;
  assert.throws(() => setActionVersion(two, '1.0.0'), /exactly one/i);
});
