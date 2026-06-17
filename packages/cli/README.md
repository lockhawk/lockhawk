<div align="center">

# 🛡️ lockhawk

### Fast, free, and accurate npm dependency vulnerability scanning — for your machine **and** your pipeline.

[![npm](https://img.shields.io/npm/v/lockhawk.svg)](https://www.npmjs.com/package/lockhawk)
[![CI](https://github.com/lockhawk/lockhawk/actions/workflows/ci.yml/badge.svg)](https://github.com/lockhawk/lockhawk/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://github.com/lockhawk/lockhawk/blob/main/LICENSE)
[![Data: OSV.dev](https://img.shields.io/badge/data-OSV.dev-4285F4.svg)](https://osv.dev)

</div>

---

`lockhawk` reads your lockfile (`package-lock.json`, `yarn.lock`, or `pnpm-lock.yaml`), builds the
full dependency tree — including transitive dependencies — and checks every package against the
free [OSV.dev](https://osv.dev) vulnerability database. It produces a beautiful, self-contained
HTML dashboard and machine-readable reports so you can understand and prioritise fixes.
**No account, no API key, no usage limits.**

```console
$ npx lockhawk scan

lockhawk · acme-web@2.4.1 · npm · 842 packages

┌────────────┬──────────────────────────┬──────────────────────┬────────────┬──────────────────────────────────┐
│ Severity   │ Package                  │ Advisory             │ Fixed in   │ Path                             │
├────────────┼──────────────────────────┼──────────────────────┼────────────┼──────────────────────────────────┤
│  critical  │ lodash  4.17.11 (direct) │ GHSA-jf85-cpcp-j695  │ 4.17.12    │ acme-web › lodash                │
│ high 7.4   │ lodash  4.17.11 (direct) │ GHSA-p6mc-m468-83gw  │ 4.17.19    │ acme-web › lodash                │
│ medium 5.3 │ minimist 1.2.0           │ GHSA-vh95-rmgr-6w4m  │ 1.2.3      │ acme-web › mkdirp › minimist     │
└────────────┴──────────────────────────┴──────────────────────┴────────────┴──────────────────────────────────┘

Found 3 vulnerabilities (1 critical, 1 high, 1 medium) · 3 fixable
Data from OSV.dev · database: offline · scanned in 184ms
```

## 🚀 Quick start

```bash
# One-off, no install
npx lockhawk scan

# Fail the build on high+ severity and emit SARIF for the GitHub Security tab
npx lockhawk scan --format sarif --output scan.sarif --fail-on high

# Generate the standalone HTML dashboard
npx lockhawk scan --format html --output report.html

# Explore findings in an interactive local dashboard
npx lockhawk serve
```

Install it globally or as a dev dependency:

```bash
npm install -g lockhawk            # global `lockhawk` command
npm install --save-dev lockhawk    # for use in package scripts / CI
```

## ✨ Features

- **⚡ Fast & non-intrusive** — a warm scan does **zero network I/O** and finishes in well under a
  second. The vulnerability database is cached on disk (and downloadable for fully offline CI),
  lookups are batched, and the scanner is **fail-open**: a transient network blip never breaks
  your build.
- **🆓 Free forever** — powered by Google's [OSV.dev](https://osv.dev). No API key, no
  rate-limited account, no seat licensing.
- **🎯 Accurate** — canonical OSV range matching with `semver`, **CVSS v3 _and_ v4** scoring,
  withdrawn-advisory handling, and alias de-duplication.
- **📦 Every package manager** — npm (`package-lock` v1/v2/v3 + shrinkwrap), Yarn (classic &
  Berry), and pnpm (v5/v6/v9), including workspaces.
- **📊 Beautiful analysis** — a self-contained HTML dashboard you can open anywhere or attach as
  a CI artifact, plus `lockhawk serve` for interactive drill-down with dependency-path tracing.
- **🔌 Built for CI/CD** — first-class **SARIF** (GitHub Security tab), **JUnit** (Azure DevOps /
  GitLab test dashboards), JSON, and a stable exit-code contract for build gating.

## 🧭 CLI

```
lockhawk scan [path]            Scan a project (default command)
  -f, --format <fmt>               table | json | sarif | html | junit   (default: table)
  -o, --output <file>              write the report to a file
  --severity-threshold <level>     minimum severity to report
  --fail-on <level>                minimum severity for a non-zero exit (default: high)
  --offline | --online             force the offline DB or live OSV.dev queries
  --strict-network                 fail on network errors instead of degrading
  --prod-only                      ignore dev dependencies
  --ignore <ids...>                suppress specific advisory ids
  --ignore-file <path>             a .lockhawkignore file (ids, optional expiry date)
  --cache-dir <dir> | --cache-ttl <hours> | --no-cache | --concurrency <n>

lockhawk report -i result.json -f html -o report.html   Re-render a saved result
lockhawk serve [path]                                    Interactive local dashboard
lockhawk db update | status | path                       Manage the offline OSV database
```

### Exit codes

| Code | Meaning                                       |
| ---- | --------------------------------------------- |
| `0`  | Clean — no finding at or above `--fail-on`    |
| `1`  | At least one finding at or above `--fail-on`  |
| `2`  | Usage error (e.g. no lockfile found)          |
| `3`  | Internal error                                |
| `4`  | Network error while `--strict-network` is set |

Plain network failures never fail the build unless you opt in with `--strict-network`.

## 🔁 CI/CD

Runs in any pipeline without slowing it down — warm the cached DB once, then scan offline in well
under a second. Full recipes for **GitHub Actions**, **Azure DevOps**, and **GitLab CI** are in
[docs/ci-cd.md](https://github.com/lockhawk/lockhawk/blob/main/docs/ci-cd.md).

```yaml
permissions: { contents: read, security-events: write }
steps:
  - uses: actions/checkout@v4
  - uses: lockhawk/lockhawk@v1
    with: { fail-on: high }
```

## ⚙️ Configuration

Add a `.lockhawkrc`, `lockhawk.config.js`, or a `"lockhawk"` key in `package.json`:

```json
{
  "mode": "auto",
  "failOn": "high",
  "prodOnly": false,
  "ignore": ["GHSA-xxxx-xxxx-xxxx"]
}
```

## 🧩 Programmatic API

To embed the scanner in your own tooling, use the engine package
[`@lockhawk/core`](https://www.npmjs.com/package/@lockhawk/core):

```ts
import { scan } from '@lockhawk/core';

const result = await scan({ path: '.', mode: 'auto', failOn: 'high' });
console.log(result.summary, result.findings);
```

## 📚 Full documentation

Full docs, CI/CD recipes, configuration reference, and the contributing guide live in the main
repository: **https://github.com/lockhawk/lockhawk**

## 📄 License

[MIT](https://github.com/lockhawk/lockhawk/blob/main/LICENSE) — free to use, modify, and distribute.
