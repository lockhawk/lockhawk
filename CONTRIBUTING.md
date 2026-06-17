# Contributing to lockhawk

Thanks for your interest — contributions of all kinds are welcome: bug reports, fixes, new
features, docs, fixtures, and ideas. This guide gets you productive fast.

By participating you agree to abide by our [Code of Conduct](CODE_OF_CONDUCT.md).

## Project layout

This is a [pnpm](https://pnpm.io) monorepo:

| Path                 | What it is                                                                       |
| -------------------- | -------------------------------------------------------------------------------- |
| `packages/core`      | `@lockhawk/core` — the scanning engine (lockfiles → graph → OSV match → reports) |
| `packages/cli`       | `lockhawk` — the command-line interface                                          |
| `packages/report-ui` | `@lockhawk/report-ui` — the React dashboard (single-file build)                  |
| `apps/action`        | the GitHub Action (composite)                                                    |
| `docs/`              | CI/CD recipes and other docs                                                     |

## Getting set up

Requirements: **Node ≥ 18.18** and **pnpm 9** (`corepack enable pnpm`).

```bash
git clone https://github.com/lockhawk/lockhawk.git
cd lockhawk
pnpm install
pnpm build        # builds core → report-ui → cli (the CLI bundles the dashboard shell)
pnpm test         # runs the whole vitest suite
```

Useful scripts (run from the repo root):

```bash
pnpm test           # all tests
pnpm typecheck      # tsc --noEmit across packages
pnpm lint           # prettier --check + typecheck
pnpm format         # prettier --write
pnpm --filter @lockhawk/core test       # one package
node packages/cli/dist/index.js scan ./some/project --online   # run the built CLI
pnpm --filter @lockhawk/report-ui dev   # dashboard dev server (uses sample data)
```

## Development workflow

1. **Fork** and create a branch off `main` (`git switch -c fix/short-description`).
2. Make your change with a test. Tests live in each package's `test/` folder; lockfile and OSV
   fixtures go under `packages/core/test/fixtures/`.
3. Keep it green: `pnpm build && pnpm test && pnpm typecheck && pnpm lint`.
4. Open a PR. Fill in the template; link any related issue.

## Releasing (maintainers)

Releases are cut from a maintainer's machine with one command:

```bash
npm run pb              # interactive: pick patch / minor / major / prerelease
npm run pb -- --dry-run # preview what would be published, without publishing
```

`@lockhawk/core` and `lockhawk` are version-locked, so `pb` bumps both to the same version, runs
the tests and build, publishes them (core first), then commits and tags `vX.Y.Z`. Prereleases go
to their own npm dist-tag (`beta`/`alpha`/`rc`) and never become the default `latest` install.

## Conventions

- **TypeScript, strict.** No `any`; prefer precise types. Match the surrounding style.
- **Formatting** is Prettier — run `pnpm format` (CI checks it).
- **Commits**: clear, imperative messages; [Conventional Commits](https://www.conventionalcommits.org/)
  prefixes (`feat:`, `fix:`, `docs:`, `test:`, `chore:`) are appreciated but not required.
- **Accuracy is the bar.** The matcher and scorer are the heart of the tool — changes there must
  come with tests (ideally validated against an authoritative source, as the CVSS v4 port is).
- **Keep `core` lean** — no UI or CLI-only dependencies in `packages/core`.

## Where to start

- Issues labelled [`good first issue`](https://github.com/lockhawk/lockhawk/labels/good%20first%20issue)
  and [`help wanted`](https://github.com/lockhawk/lockhawk/labels/help%20wanted).
- Add lockfile fixtures for edge cases (monorepo workspaces, aliases, `git:`/`file:` deps).
- The [roadmap in the README](README.md#️-roadmap).

## Reporting bugs & requesting features

Use the issue templates. For **security** issues, do **not** open a public issue — see
[SECURITY.md](SECURITY.md).

## License

By contributing, you agree that your contributions are licensed under the [MIT License](LICENSE).
