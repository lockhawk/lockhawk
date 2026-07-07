# Design: make `lockhawk/lockhawk@v1` resolve as documented

> Reference: [npm — lockhawk](https://www.npmjs.com/package/lockhawk?activeTab=readme)

**Date:** 2026-07-07
**Status:** Approved (design)

## Problem

The docs and READMEs advertise the GitHub Action as:

```yaml
- uses: lockhawk/lockhawk@v1
  with:
    fail-on: high
```

But this reference does not resolve today:

- The action definition lives at `apps/action/action.yml`, not at the repo root.
  GitHub resolves `owner/repo@ref` by looking for `action.yml` / `action.yaml` /
  `Dockerfile` at the **repo root** at that ref — so it 404s
  (`Can't find 'action.yml' … in lockhawk/lockhawk/v1`).
- No `v1` tag exists (published tags stop at `v0.2.5`).
- Bonus defect: the action's `version` input defaults to a stale `0.2.5` (latest
  published CLI is `0.2.10`), so even if it resolved it would scan with an old CLI.

Verified against the live remote: `raw.githubusercontent.com/lockhawk/lockhawk/{v1,main}/action.yml`
both return 404, and `git ls-remote --tags origin` shows no `v1`.

## Goal

A user copying `uses: lockhawk/lockhawk@v1` from `docs/ci-cd.md` gets a working
scan, and it stays working across future releases with no manual upkeep.

## Non-goals

- GitHub Marketplace listing (searchable page / badge). The pieces here are a
  strict subset, so this can be added later without rework.
- An action `v2` / breaking the action interface.
- Any change to the CLI / npm release cadence or the `@lockhawk/core` + `lockhawk`
  version-locking.

## Key facts that make this safe

- The action is a **composite action** that only runs `npx -y lockhawk@<inputs.version>`,
  `actions/cache@v4`, and `github/codeql-action/upload-sarif@v3`. It has **no local
  file dependencies** (no `./` step references), so it can be relocated to the repo
  root unchanged.
- The action's `v1` is an **interface** version, independent of the CLI's `0.2.x`
  semver. It remains `v1` for as long as the action's inputs stay backward compatible.
- Releases are performed locally via `scripts/release.mjs` (`npm run pb`): it bumps
  `@lockhawk/core` + `lockhawk` in lockstep, publishes to npm, commits, creates a
  `vX.Y.Z` git tag, and optionally pushes. It does not currently touch the action or
  create a `v1` tag.

## Design

### 1. Relocate the action to the repo root (one-time)

- `git mv apps/action/action.yml action.yml` (repo root).
- Update the `version` input default from `0.2.5` to `0.2.10` (current latest CLI).
- Dispose of the now-vestigial `apps/action/`:
  - `git mv apps/action/README.md docs/github-action.md` (preserve the action's
    input docs).
  - Delete `apps/action/package.json` and the empty `apps/action/` directory (drops
    a dead private pnpm workspace member; `pnpm-workspace.yaml` keeps `apps/*` glob,
    which simply matches nothing there anymore).
- Confirm nothing references `apps/action/action.yml` at a fixed path (CI `dogfood`
  job runs the CLI directly; CodeQL analyzes JS — neither depends on the action).

### 2. Bootstrap the `v1` tag (one-time)

- Commit the moved root `action.yml` (this is a repo-infra change, **not** an npm
  release — the CLI stays at `0.2.10`).
- `git tag v1 && git push origin v1`.
- Side effect: because root `action.yml` now lives on `main` permanently, every
  future `vX.Y.Z` release tag also resolves as an action ref, so `@v0.2.11` etc.
  work too. `@v1` remains the documented, floating reference.

### 3. Automate upkeep in `scripts/release.mjs`

- Add a pure helper `setActionVersion(yamlText, version) -> yamlText` that rewrites
  the version default. It targets the **only semver-shaped default** via
  `/default: '\d+\.\d+\.\d+[^']*'/` — no other input default (`none`, `high`, `.`,
  `true`, `false`, `low`) looks like a dotted version, so it cannot accidentally hit
  `fail-on`, `path`, `offline`, etc. Throws if it finds zero or more than one match
  (fail loud rather than silently mis-edit).
- Fold `action.yml` into `applyVersion()`'s write+restore set so `--dry-run` restores
  it byte-for-byte and uploads/changes nothing.
- Add `action.yml` to the pre-commit `git add` list.
- After creating the `vX.Y.Z` tag: `git tag -f v1` (force-move the floating major).
- On push: keep `git push --follow-tags` for the immutable tag, and additionally
  `git push -f origin v1` (force-update the moved ref), reusing the existing
  "push failed → warn, run manually later" handling.

### 4. Docs

- Update the reference that says "the bundled action (see `apps/action`)"
  (`docs/ci-cd.md:10`) to point at the root `action.yml` / `docs/github-action.md`.
- Update any root-README pointer to `apps/action`.
- The `@v1` usage snippets themselves become correct as-is — no change to those.

## Error handling / edge cases

- `setActionVersion` must edit only the `version` input default. The single-semver
  match strategy guarantees this; a zero/multi-match throws so a future action.yml
  change can't cause a silent wrong edit.
- Force-moving `v1` is destructive to that ref by design (standard action-maintainer
  practice) and happens only on a real release, after a successful publish — never in
  `--dry-run`.
- Pre-1.0 CLI vs action `v1`: documented as intentional — the action interface is
  what's versioned, not the wrapped CLI.

## Testing

- Unit tests for `setActionVersion` (in `scripts/release-plan.test.mjs` or a sibling
  `scripts/*.test.mjs`, matching the existing `test:release` runner):
  - Rewrites `0.2.5` → a new version; round-trips.
  - Leaves every other `default:` line untouched.
  - Throws on zero matches and on multiple semver matches.
- `--dry-run` leaves `action.yml` byte-for-byte unchanged (restore path).
- Post-bootstrap manual checks: root `action.yml` parses as valid YAML;
  `git ls-remote --tags origin v1` shows the tag; a workflow referencing
  `lockhawk/lockhawk@v1` (e.g. truckhub's, once pushed) resolves and runs.

## Rollout

1. One-time: relocate action.yml + fix version default + tidy `apps/action/` + docs
   (one commit).
2. One-time: create + push `v1`.
3. Wire `scripts/release.mjs` + add tests (can be the same or a follow-up commit).

After this, `uses: lockhawk/lockhawk@v1` works immediately and each `npm run pb`
keeps it pointing at the just-released CLI.
