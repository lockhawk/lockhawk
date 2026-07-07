// Rewrite the composite action's pinned CLI version so `lockhawk/lockhawk@v1`
// always runs the just-released CLI. Used by scripts/release.mjs.

// The `version` input's default is the only semver-shaped default in action.yml
// (every other default is `.`, `none`, `high`, `low`, `true`, or `false`), so a
// single semver match uniquely identifies it — no risk of touching `fail-on`,
// `path`, etc.
const SEMVER_DEFAULT = /default: '\d+\.\d+\.\d+[^']*'/g;

/**
 * Set the composite action's pinned lockhawk version.
 *
 * @param {string} yamlText  contents of the root action.yml
 * @param {string} version   semver to pin, e.g. "0.2.11"
 * @returns {string}         action.yml with the version default rewritten
 * @throws if there is not exactly one semver-shaped default (fail loud rather
 *         than silently mis-edit if action.yml changes shape).
 */
export function setActionVersion(yamlText, version) {
  const matches = yamlText.match(SEMVER_DEFAULT) ?? [];
  if (matches.length !== 1) {
    throw new Error(
      `action.yml: expected exactly one semver-shaped input default, found ${matches.length}. ` +
        'The version-input default may have moved — update scripts/action-yaml.mjs.',
    );
  }
  return yamlText.replace(SEMVER_DEFAULT, `default: '${version}'`);
}
