import semver from 'semver';

/**
 * Compute the next version and the npm dist-tag for a release choice.
 *
 * @param {string} current  current semver, e.g. "0.1.0"
 * @param {'patch'|'minor'|'major'|'prepatch'|'preminor'|'premajor'|'prerelease'|'custom'} type
 * @param {{ preid?: string, exact?: string }} [opts]  preid for prereleases, exact for custom
 * @returns {{ version: string, npmTag: string }}
 */
export function planRelease(current, type, opts = {}) {
  let version;
  if (type === 'custom') {
    version = semver.valid(opts.exact);
    if (!version) throw new Error(`Not a valid version: "${opts.exact}"`);
  } else {
    version = semver.inc(current, type, opts.preid);
    if (!version) throw new Error(`Cannot apply "${type}" to ${current}`);
  }

  // Prereleases publish under their identifier (alpha/beta/rc) so they never
  // displace the default `latest` install; stable releases go to `latest`.
  const pre = semver.prerelease(version);
  const npmTag = pre ? String(pre[0]) : 'latest';

  return { version, npmTag };
}
