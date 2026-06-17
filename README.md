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

## Packages

| Package | Description |
| --- | --- |
| [`npm-scanner`](packages/cli) | The CLI (the `npm-scanner` binary). |
| [`@npm-scanner/core`](packages/core) | The scanning engine (programmatic API). |
| [`@npm-scanner/report-ui`](packages/report-ui) | The React dashboard / report UI. |
| [`apps/action`](apps/action) | The GitHub Action wrapper. |

## License

[MIT](LICENSE) — free to use, modify, and distribute.
