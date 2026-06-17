# npm-scanner

> Fast, free, and accurate npm dependency vulnerability scanner — for your local machine **and** your CI/CD pipeline.

`npm-scanner` reads your lockfile (`package-lock.json`, `yarn.lock`, or `pnpm-lock.yaml`),
builds the full dependency tree (including transitive dependencies), and checks every package
against the free [OSV.dev](https://osv.dev) vulnerability database. It produces a beautiful,
self-contained HTML report and an interactive dashboard so you can understand and prioritise
fixes — no account, no API key, no usage limits.

## Why

- **Fast & non-intrusive.** A warm scan does zero network I/O. The vulnerability database is
  cached on disk (and downloadable for fully offline CI runs), lookups are batched, and the
  scanner is **fail-open** — a transient network blip never breaks your build.
- **Free forever.** Powered by Google's OSV.dev. No API key, no rate-limited account.
- **Accurate.** Canonical OSV range matching with `semver`, CVSS-based severity, and
  withdrawn-advisory / alias de-duplication.
- **Beautiful analysis.** A single-file HTML report you can open anywhere or attach as a CI
  artifact, plus `npm-scanner serve` for an interactive dashboard with dependency-path tracing
  and mitigation guidance.

## Quick start

```bash
# one-off, no install
npx npm-scanner scan

# fail the build only on high+ severity, emit SARIF for the GitHub Security tab
npx npm-scanner scan --format sarif --output scan.sarif --fail-on high

# generate the standalone HTML report
npx npm-scanner scan --format html --output report.html

# explore findings in an interactive dashboard
npx npm-scanner serve
```

## CLI

```
npm-scanner scan [path]            Scan a project (default command)
  -f, --format <fmt>               table | json | sarif | html        (default: table)
  -o, --output <file>              write the report to a file
  --severity-threshold <level>     minimum severity to report
  --fail-on <level>                minimum severity for a non-zero exit (default: high)
  --offline | --online             force the offline DB or live OSV.dev queries
  --strict-network                 fail on network errors instead of degrading
  --prod-only                      ignore dev dependencies
  --ignore <ids...>                suppress specific advisory ids
  --ignore-file <path>             a .npmscanignore file (ids, optional expiry date)
  --cache-dir <dir> | --cache-ttl <hours> | --no-cache | --concurrency <n>

npm-scanner report -i result.json -f html -o report.html   Re-render a saved result
npm-scanner serve [path]                                    Interactive local dashboard
npm-scanner db update | status | path                       Manage the offline OSV database
```

### Exit codes

`0` clean · `1` finding ≥ `--fail-on` · `2` usage error · `3` internal error ·
`4` network error under `--strict-network`. Plain network failures never fail the build.

## Configuration

Drop a `.npmscannerrc`, `npm-scanner.config.js`, or a `"npm-scanner"` key in `package.json`:

```json
{
  "mode": "auto",
  "failOn": "high",
  "prodOnly": false,
  "ignore": ["GHSA-xxxx-xxxx-xxxx"]
}
```

A `.npmscanignore` file suppresses advisories, with an optional expiry so suppressions
don't outlive their review:

```
# reviewed 2026-06-01, revisit by year end
GHSA-xxxx-xxxx-xxxx 2026-12-31
```

## CI/CD

Runs in any pipeline without slowing it down — warm the cached DB once, then scan offline
in well under a second. See **[docs/ci-cd.md](docs/ci-cd.md)** for GitHub Actions, Azure
DevOps, and GitLab recipes. The simplest GitHub setup:

```yaml
permissions: { contents: read, security-events: write }
steps:
  - uses: actions/checkout@v4
  - uses: npm-scanner/npm-scanner@v1
    with: { fail-on: high }
```

## Programmatic API

```ts
import { scan } from '@npm-scanner/core';

const result = await scan({ path: '.', mode: 'auto', failOn: 'high' });
console.log(result.summary, result.findings);
```

## Packages

| Package                                        | Description                             |
| ---------------------------------------------- | --------------------------------------- |
| [`npm-scanner`](packages/cli)                  | The CLI (the `npm-scanner` binary).     |
| [`@npm-scanner/core`](packages/core)           | The scanning engine (programmatic API). |
| [`@npm-scanner/report-ui`](packages/report-ui) | The React dashboard / report UI.        |
| [`apps/action`](apps/action)                   | The GitHub Action wrapper.              |

## Development

```bash
pnpm install
pnpm build        # build core → report-ui → cli (in order)
pnpm test         # vitest across the workspace
pnpm typecheck
node packages/cli/dist/index.js scan ./some/project --online
```

## How it works

1. **Parse** the lockfile (npm v1/v2/v3, yarn classic/berry, pnpm v5/v6/v9) into a normalized
   dependency graph; dependency scope is derived by reachability.
2. **Query** OSV.dev for the unique installed packages — offline from a cached, sharded copy of
   the database, or online via the batch API with a per-advisory cache.
3. **Match** each installed version against advisory ranges using the canonical OSV event sweep,
   score severity from CVSS vectors, and de-duplicate aliased advisories.
4. **Report** as a colorized table, JSON, SARIF 2.1.0, or a self-contained HTML dashboard.

## License

[MIT](LICENSE) — free to use, modify, and distribute.
