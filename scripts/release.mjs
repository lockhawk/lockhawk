#!/usr/bin/env node
// Interactive release for lockhawk's published packages (@lockhawk/core + lockhawk).
//
// The two are version-locked: every release bumps both to the same version.
// Flow: pick a bump → confirm → test → build → write versions → publish
// (core first, since the CLI depends on it) → commit + tag → optionally push.
//
// Usage:
//   npm run pb                interactive release
//   npm run pb -- --dry-run   preview only (packs from current dist/, publishes nothing)
import { readFileSync, writeFileSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { execFileSync } from 'node:child_process';
import { createInterface } from 'node:readline/promises';
import { stdin as input, stdout as output } from 'node:process';
import semver from 'semver';
import { planRelease } from './release-plan.mjs';

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..');
const DRY_RUN = process.argv.includes('--dry-run');

// Published, version-locked packages, in publish order (core first; the CLI depends on it).
const PACKAGES = [
  { name: '@lockhawk/core', dir: 'packages/core' },
  { name: 'lockhawk', dir: 'packages/cli' },
];

const pkgFile = (dir) => join(ROOT, dir, 'package.json');
const readPkg = (dir) => JSON.parse(readFileSync(pkgFile(dir), 'utf8'));
const run = (cmd, args) => execFileSync(cmd, args, { cwd: ROOT, stdio: 'inherit' });
const capture = (cmd, args) => execFileSync(cmd, args, { cwd: ROOT, encoding: 'utf8' }).trim();

function fail(msg) {
  console.error(`\n✖ ${msg}\n`);
  process.exit(1);
}

function writeVersion(dir, version) {
  const json = readPkg(dir);
  json.version = version;
  writeFileSync(pkgFile(dir), `${JSON.stringify(json, null, 2)}\n`);
}

// Write the bumped version to every package and return a restore() that puts the
// files back byte-for-byte — lets --dry-run pack the real next version safely.
function applyVersion(version) {
  const saved = PACKAGES.map((p) => [pkgFile(p.dir), readFileSync(pkgFile(p.dir), 'utf8')]);
  for (const p of PACKAGES) writeVersion(p.dir, version);
  return () => {
    for (const [file, raw] of saved) writeFileSync(file, raw);
  };
}

async function chooseBump(rl, current) {
  console.log('Select a release type:');
  for (const [i, type] of ['patch', 'minor', 'major'].entries()) {
    console.log(`  ${i + 1}) ${type.padEnd(11)}${current} → ${planRelease(current, type).version}`);
  }
  console.log('  4) prerelease  alpha / beta / rc');
  console.log('  5) custom      type an exact version');
  const choice = (await rl.question('\n→ Choice [1-5]: ')).trim();

  if (choice === '1') return planRelease(current, 'patch');
  if (choice === '2') return planRelease(current, 'minor');
  if (choice === '3') return planRelease(current, 'major');
  if (choice === '4') {
    const preid = (await rl.question('  Identifier (alpha/beta/rc) [beta]: ')).trim() || 'beta';
    let base;
    if (semver.prerelease(current)) {
      const b =
        (
          await rl.question('  1) bump prerelease  2) preminor  3) premajor  4) prepatch [1]: ')
        ).trim() || '1';
      base = { 1: 'prerelease', 2: 'preminor', 3: 'premajor', 4: 'prepatch' }[b];
    } else {
      const b = (await rl.question('  1) preminor  2) prepatch  3) premajor [1]: ')).trim() || '1';
      base = { 1: 'preminor', 2: 'prepatch', 3: 'premajor' }[b];
    }
    if (!base) fail('Invalid prerelease base.');
    return planRelease(current, base, { preid });
  }
  if (choice === '5') {
    const exact = (await rl.question('  Exact version (e.g. 1.0.0-rc.1): ')).trim();
    return planRelease(current, 'custom', { exact });
  }
  fail(`Invalid choice: "${choice}".`);
}

const askYesNo = async (rl, q) => /^y(es)?$/i.test((await rl.question(`${q} (y/N): `)).trim());

async function main() {
  console.log('\n🦅 lockhawk release\n');

  let npmUser;
  try {
    npmUser = capture('npm', ['whoami']);
  } catch {
    fail('Not logged into npm — run `npm login` first.');
  }

  const versions = PACKAGES.map((p) => readPkg(p.dir).version);
  const current = versions[0];
  if (!versions.every((v) => v === current)) {
    fail(
      `Package versions are out of sync (${PACKAGES.map((p, i) => `${p.name}@${versions[i]}`).join(', ')}). ` +
        'Make them match before releasing.',
    );
  }

  console.log(`  Packages : ${PACKAGES.map((p) => p.name).join('  ')}`);
  console.log(`  Current  : v${current}`);
  console.log(`  npm user : ${npmUser}${DRY_RUN ? '\n  Mode     : DRY RUN' : ''}\n`);

  const rl = createInterface({ input, output });
  try {
    const { version, npmTag } = await chooseBump(rl, current);

    console.log('\n→ Will publish:');
    for (const p of PACKAGES) console.log(`    ${p.name}@${version}`);
    console.log(`  npm dist-tag : ${npmTag}`);
    console.log(`  git tag      : v${version}`);

    if (DRY_RUN) {
      console.log('\n▶ Dry-run publish (packs the next version, uploads nothing):\n');
      const restore = applyVersion(version);
      try {
        for (const p of PACKAGES) {
          run('pnpm', [
            '--filter',
            p.name,
            'publish',
            '--access',
            'public',
            '--tag',
            npmTag,
            '--no-git-checks',
            '--dry-run',
          ]);
        }
      } finally {
        restore();
      }
      console.log(`\n✓ Dry run OK — would publish v${version} (npm tag: ${npmTag}).`);
      return;
    }

    if (!(await askYesNo(rl, '\nProceed?'))) {
      console.log('Aborted.');
      return;
    }

    const branch = capture('git', ['rev-parse', '--abbrev-ref', 'HEAD']);
    if (branch !== 'main') console.warn(`\n! On branch "${branch}", not "main".`);
    if (capture('git', ['status', '--porcelain'])) {
      fail('Working tree is not clean — commit or stash your changes first.');
    }

    console.log('\n▶ Testing…');
    run('pnpm', ['test']);
    console.log('\n▶ Building…');
    run('pnpm', ['run', 'build']);

    console.log(`\n▶ Setting version → ${version}…`);
    applyVersion(version);

    for (const p of PACKAGES) {
      console.log(`\n▶ Publishing ${p.name}@${version}…`);
      run('pnpm', [
        '--filter',
        p.name,
        'publish',
        '--access',
        'public',
        '--tag',
        npmTag,
        '--no-git-checks',
      ]);
    }

    console.log('\n▶ Committing + tagging…');
    run('git', ['add', ...PACKAGES.map((p) => join(p.dir, 'package.json'))]);
    run('git', ['commit', '-m', `release: v${version}`]);
    run('git', ['tag', `v${version}`]);

    if (await askYesNo(rl, '\nPush commit + tag to origin?')) {
      try {
        run('git', ['push', '--follow-tags']);
      } catch {
        console.warn(
          '! Push failed (no remote yet?). Run `git push --follow-tags` once your remote is set.',
        );
      }
    } else {
      console.log('Skipped push — run `git push --follow-tags` when ready.');
    }

    console.log(`\n✓ Released v${version} (npm tag: ${npmTag}).`);
  } finally {
    rl.close();
  }
}

main().catch((err) => fail(err?.message ?? String(err)));
