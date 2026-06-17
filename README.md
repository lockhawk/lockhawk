<div align="center">

# 🛡️ lockhawk

### Fast, free, and accurate npm dependency vulnerability scanning — for your machine **and** your pipeline.

[![CI](https://github.com/lockhawk/lockhawk/actions/workflows/ci.yml/badge.svg)](https://github.com/lockhawk/lockhawk/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen.svg)](CONTRIBUTING.md)
[![TypeScript](https://img.shields.io/badge/TypeScript-strict-3178c6.svg)](https://www.typescriptlang.org/)
[![Node](https://img.shields.io/badge/node-%E2%89%A518.18-339933.svg)](https://nodejs.org/)
[![Data: OSV.dev](https://img.shields.io/badge/data-OSV.dev-4285F4.svg)](https://osv.dev)

[Quick start](#-quick-start) · [Features](#-features) · [Dashboard](#-the-dashboard) · [CI/CD](docs/ci-cd.md) · [Contributing](CONTRIBUTING.md)

</div>

---

`lockhawk` reads your lockfile (`package-lock.json`, `yarn.lock`, or `pnpm-lock.yaml`),
builds the full dependency tree — including transitive dependencies — and checks every package
against the free [OSV.dev](https://osv.dev) vulnerability database. It produces a beautiful,
self-contained HTML dashboard and machine-readable reports so you can understand and prioritise
fixes. **No account, no API key, no usage limits.**

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

## ✨ Features

- **⚡ Fast & non-intrusive** — a warm scan does **zero network I/O** and finishes in well under a
  second. The vulnerability database is cached on disk (and downloadable for fully offline CI),
  lookups are batched, and the scanner is **fail-open**: a transient network blip never breaks
  your build.
- **🆓 Free forever** — powered by Google's [OSV.dev](https://osv.dev). No API key, no
  rate-limited account, no seat licensing.
- **🎯 Accurate** — canonical OSV range matching (the official event sweep) with `semver`,
  **CVSS v3 _and_ v4** scoring, withdrawn-advisory handling, and alias de-duplication.
- **📦 Every package manager** — npm (`package-lock` v1/v2/v3 + shrinkwrap), Yarn (classic &
  Berry), and pnpm (v5/v6/v9), including workspaces.
- **📊 Beautiful analysis** — a self-contained HTML dashboard you can open anywhere or attach as
  a CI artifact, plus `lockhawk serve` for interactive drill-down with dependency-path tracing
  and mitigation guidance.
- **🔌 Built for CI/CD** — first-class **SARIF** (GitHub Security tab), **JUnit** (Azure DevOps /
  GitLab test dashboards), JSON, and a stable exit-code contract for build gating.

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

Install it as a dev dependency to use in scripts:

```bash
npm install --save-dev lockhawk
```

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

## 📊 The dashboard

`--format html` produces a **single self-contained file** (all JS/CSS inlined, zero external
requests) that works offline, from `file://`, or as a CI artifact. `lockhawk serve` serves the
same app live for unlimited drill-down. Each finding shows a decoded CVSS breakdown, the dependency
path that pulls the package in (`root › … › vulnerable`), the nearest safe version, and a copy-ready
upgrade command.

> 💡 To showcase it, drop a screenshot at `docs/dashboard.png` and reference it here.

## 🔁 CI/CD

Runs in any pipeline without slowing it down — warm the cached DB once, then scan offline in well
under a second. Full recipes for **GitHub Actions**, **Azure DevOps**, and **GitLab CI** (including
rendering findings natively in the Azure **Tests** tab via JUnit) are in
**[docs/ci-cd.md](docs/ci-cd.md)**.

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

A `.lockhawkignore` file suppresses advisories, with an optional expiry so suppressions don't
silently outlive their review:

```
# reviewed 2026-06-01, revisit by year end
GHSA-xxxx-xxxx-xxxx 2026-12-31
```

## 🧩 Programmatic API

```ts
import { scan } from '@lockhawk/core';

const result = await scan({ path: '.', mode: 'auto', failOn: 'high' });
console.log(result.summary, result.findings);
```

## 🛠️ How it works

1. **Parse** the lockfile into a normalized dependency graph; dependency scope is derived by
   reachability (so pnpm v9, which drops per-package `dev` flags, is handled correctly).
2. **Query** OSV.dev for the unique installed packages — offline from a cached, gzipped, sharded
   copy of the database, or online via the batch API with a per-advisory cache.
3. **Match** each installed version against advisory ranges using the canonical OSV event sweep,
   score severity from CVSS v3/v4 vectors, and de-duplicate aliased advisories.
4. **Report** as a colorized table, JSON, SARIF 2.1.0, JUnit XML, or a self-contained HTML dashboard.

## 📦 Packages

| Package                                     | Description                             |
| ------------------------------------------- | --------------------------------------- |
| [`lockhawk`](packages/cli)                  | The CLI (the `lockhawk` binary).        |
| [`@lockhawk/core`](packages/core)           | The scanning engine (programmatic API). |
| [`@lockhawk/report-ui`](packages/report-ui) | The React dashboard / report UI.        |
| [`apps/action`](apps/action)                | The GitHub Action wrapper.              |

## 🤝 Contributing

Contributions are very welcome — this is a community project. See
**[CONTRIBUTING.md](CONTRIBUTING.md)** to get set up (it's a `pnpm` monorepo; `pnpm install &&
pnpm build && pnpm test`). Good places to start are labelled
[`good first issue`](https://github.com/lockhawk/lockhawk/labels/good%20first%20issue).

By participating you agree to our [Code of Conduct](CODE_OF_CONDUCT.md).

## 🗺️ Roadmap

- [ ] Per-package pass/fail mode for JUnit (`--junit-all-packages`)
- [ ] Markdown summary output for inline CI summaries
- [ ] Richer dependency-path view (multiple paths per finding)
- [ ] Optional reachability hints to cut dev-only / unreachable noise
- [ ] More ecosystems (the engine is npm-focused today)

## 🔐 Security

Found a vulnerability in lockhawk itself? Please report it privately — see
**[SECURITY.md](SECURITY.md)**. Don't open a public issue for security reports.

## 📄 License

[MIT](LICENSE) — free to use, modify, and distribute.

## 🙏 Acknowledgements

- [**OSV.dev**](https://osv.dev) — the open vulnerability database that powers every scan.
- [**FIRST.org**](https://www.first.org/cvss/) — the CVSS specification and reference calculator.

<div align="center">
<sub>Built with TypeScript. Free and open source.</sub>
</div>
