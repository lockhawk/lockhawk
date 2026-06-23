<div align="center">

# 🛡️ lockhawk

### Fast, free, and accurate vulnerability scanning for your npm dependencies — on your machine and in your pipeline.

[![CI](https://github.com/lockhawk/lockhawk/actions/workflows/ci.yml/badge.svg)](https://github.com/lockhawk/lockhawk/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen.svg)](CONTRIBUTING.md)
[![TypeScript](https://img.shields.io/badge/TypeScript-strict-3178c6.svg)](https://www.typescriptlang.org/)
[![Node](https://img.shields.io/badge/node-%E2%89%A518.18-339933.svg)](https://nodejs.org/)
[![Data: OSV.dev](https://img.shields.io/badge/data-OSV.dev-4285F4.svg)](https://osv.dev)

[Quick start](#-quick-start) · [Why lockhawk](#-why-lockhawk) · [Dashboard](#-the-dashboard) · [CI/CD](docs/ci-cd.md) · [Contributing](CONTRIBUTING.md)

</div>

---

`lockhawk` reads your lockfile (`package-lock.json`, `yarn.lock`, or `pnpm-lock.yaml`), builds the
full dependency tree including every transitive dependency, and checks each package against the free
[OSV.dev](https://osv.dev) vulnerability database. It produces a polished, standalone HTML dashboard
and structured reports so you can understand and prioritise fixes. **No account, no API key, no usage
limits.**

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

## ✨ Why lockhawk

- **⚡ Fast and quiet.** A warm scan does zero network requests and finishes in well under a second.
  The vulnerability database is cached on disk (and you can download it for fully offline CI), and
  lookups are batched. The scanner also fails open, so a temporary network problem never breaks your
  build.
- **🆓 Free forever.** Powered by Google's [OSV.dev](https://osv.dev). There is no API key, no
  rate-limited account, and no per-seat license.
- **🎯 Accurate.** Canonical OSV range matching (the official event sweep) with `semver`, CVSS v3
  _and_ v4 scoring, correct handling of withdrawn advisories, and de-duplication of aliased
  advisories.
- **📦 Every package manager.** npm (`package-lock` v1, v2, v3, and shrinkwrap), Yarn (classic and
  Berry), and pnpm (v5, v6, v9), including workspaces.
- **📊 Clear results.** A standalone HTML dashboard (one file, works offline) that you can open
  anywhere or attach as a CI artifact, plus `lockhawk serve` to drill into findings interactively,
  trace dependency paths, and read mitigation guidance.
- **🔌 Built for CI.** First-class SARIF (GitHub Security tab), JUnit (Azure DevOps and GitLab test
  dashboards), JSON, and a stable exit-code contract for gating builds.

## 🚀 Quick start

```bash
# Run once, no install needed
npx lockhawk scan

# Fail the build on high or critical findings and write SARIF for the GitHub Security tab
npx lockhawk scan --format sarif --output scan.sarif --fail-on high

# Generate a standalone HTML dashboard
npx lockhawk scan --format html --output report.html

# Explore findings in an interactive dashboard in your browser
npx lockhawk@latest serve
```

> **Tip:** pin `@latest` (e.g. `npx lockhawk@latest serve`) so npx fetches the newest
> release instead of silently reusing an older copy from its cache. Each `serve` always
> re-scans your current lockfile and re-renders the dashboard — just refresh the browser
> tab after re-running.

Install it as a dev dependency to use in scripts:

```bash
npm install --save-dev lockhawk
```

## 🧭 CLI

```
lockhawk scan [path]            Scan a project (this is the default command)
  -f, --format <fmt>               table | json | sarif | html | junit   (default: table)
  -o, --output <file>              write the report to a file
  --severity-threshold <level>     minimum severity to include in the report
  --fail-on <level>                minimum severity that causes a non-zero exit (default: high)
  --offline | --online             force the offline database or live OSV.dev queries
  --strict-network                 fail on network errors instead of degrading gracefully
  --prod-only                      ignore dev dependencies
  --ignore <ids...>                suppress specific advisory ids
  --ignore-file <path>             a .lockhawkignore file (ids, with an optional expiry date)
  --cache-dir <dir> | --cache-ttl <hours> | --no-cache | --concurrency <n>

lockhawk report -i result.json -f html -o report.html   Re-render a saved result
lockhawk serve [path]                                    Interactive local dashboard
lockhawk db update | status | path                       Manage the offline OSV database
```

### Exit codes

| Code | Meaning                                        |
| ---- | ---------------------------------------------- |
| `0`  | Clean. No finding at or above `--fail-on`.     |
| `1`  | At least one finding at or above `--fail-on`.  |
| `2`  | Usage error, for example no lockfile found.    |
| `3`  | Internal error.                                |
| `4`  | Network error while `--strict-network` is set. |

Network failures never fail the build unless you opt in with `--strict-network`.

## 📊 The dashboard

`--format html` produces a single standalone file (all JS and CSS inlined, zero external requests)
that works offline, from `file://`, or as a CI artifact. `lockhawk serve` serves the same app live
so you can keep exploring. Each finding shows a decoded CVSS breakdown, the dependency path that
pulls the package in (`root › … › vulnerable`), the nearest safe version, and a copy-ready upgrade
command.

## 🔁 CI/CD

lockhawk runs in any pipeline without slowing it down. Warm the cached database once, then scan
offline in well under a second. The snippets below are the short version; full recipes for all three
platforms (including rendering findings natively in the Azure **Tests** tab via JUnit) are in
**[docs/ci-cd.md](docs/ci-cd.md)**.

**GitHub Actions** (the bundled action):

```yaml
permissions: { contents: read, security-events: write }
steps:
  - uses: actions/checkout@v4
  - uses: lockhawk/lockhawk@v1
    with: { fail-on: high }
```

**Azure DevOps** (findings render natively in the Tests tab via JUnit):

```yaml
- script: npx lockhawk db update
  displayName: Warm OSV database
- script: npx lockhawk scan --offline --format junit --output lockhawk.junit.xml --fail-on none
  displayName: Scan dependencies
- task: PublishTestResults@2
  condition: always()
  inputs:
    testResultsFormat: JUnit
    testResultsFiles: lockhawk.junit.xml
    failTaskOnFailedTests: true # fail the pipeline when there are findings
```

**GitLab CI** (JUnit surfaces in the pipeline and merge-request test widgets):

```yaml
dependency_scan:
  image: node:22
  script:
    - npx lockhawk db update
    - npx lockhawk scan --offline --format junit --output scan.junit.xml --fail-on high
  artifacts:
    when: always
    reports:
      junit: scan.junit.xml
```

## ⚙️ Configuration

Add a `.lockhawkrc`, a `lockhawk.config.js`, or a `"lockhawk"` key in `package.json`:

```json
{
  "mode": "auto",
  "failOn": "high",
  "prodOnly": false,
  "ignore": ["GHSA-xxxx-xxxx-xxxx"]
}
```

`failOn` is a severity gate: the scan exits non-zero when any finding is at or above that level. With
`"failOn": "high"`, a single high or critical finding fails the build, while `"critical"` tolerates
highs and `"none"` never fails on findings (report-only). CLI flags always override config-file
values.

A `.lockhawkignore` file suppresses advisories, with an optional expiry so suppressions do not
silently outlive their review:

```
# reviewed 2026-06-01, revisit by year end
GHSA-xxxx-xxxx-xxxx 2026-12-31
```

## 🧊 Caching & freshness

lockhawk is fast because it caches aggressively — but a scan never reuses a stale _result_. Your
lockfile is re-parsed and re-matched on every run, so the dependency coverage is always current. Only
the vulnerability data is cached:

- **Advisory data is cached on disk for 24h.** In the default `auto` mode lockhawk uses a fresh
  offline database if one is present and under 24h old, otherwise it queries OSV.dev live and caches
  those responses for 24h. A re-run inside that window reuses the cached advisories — it still scans
  your full tree, so coverage is unchanged; only a brand-new advisory might not appear until the
  cache expires.
- **The `npx` package is cached by npx itself.** That is why the install prompt only appears once.
  Pin `npx lockhawk@latest` so you run the newest release instead of a cached older copy of the tool.
- **The `serve` dashboard is sent `no-store`,** so re-running `serve` always serves the current scan
  — just refresh the browser tab after a re-run.

To force completely fresh advisory data:

```bash
npx lockhawk scan --online --no-cache   # bypass the 24h cache and query OSV.dev live
npx lockhawk db update --force          # refresh the offline database
```

## 🧩 Programmatic API

```ts
import { scan } from '@lockhawk/core';

const result = await scan({ path: '.', mode: 'auto', failOn: 'high' });
console.log(result.summary, result.findings);
```

## 🛠️ How it works

1. **Parse** the lockfile into a normalized dependency graph. Dependency scope is derived by
   reachability, so pnpm v9 (which drops per-package `dev` flags) is handled correctly.
2. **Query** OSV.dev for the unique installed packages, either offline from a cached, gzipped,
   sharded copy of the database, or online via the batch API with a per-advisory cache.
3. **Match** each installed version against advisory ranges using the canonical OSV event sweep,
   score severity from CVSS v3 and v4 vectors, and de-duplicate aliased advisories.
4. **Report** as a colorized table, JSON, SARIF 2.1.0, JUnit XML, or a standalone HTML dashboard.

## 📦 Packages

| Package                           | Description                             |
| --------------------------------- | --------------------------------------- |
| [`lockhawk`](packages/cli)        | The CLI (the `lockhawk` binary).        |
| [`@lockhawk/core`](packages/core) | The scanning engine (programmatic API). |
| [`apps/action`](apps/action)      | The GitHub Action wrapper.              |

## 🤝 Contributing

Contributions are very welcome, this is a community project. See **[CONTRIBUTING.md](CONTRIBUTING.md)**
to get set up (it's a `pnpm` monorepo: `pnpm install && pnpm build && pnpm test`). Good places to
start are labelled [`good first issue`](https://github.com/lockhawk/lockhawk/labels/good%20first%20issue).

By participating you agree to our [Code of Conduct](CODE_OF_CONDUCT.md).

## 🗺️ Roadmap

- [ ] Per-package pass/fail mode for JUnit (`--junit-all-packages`)
- [ ] Markdown summary output for inline CI summaries
- [ ] Richer dependency-path view (multiple paths per finding)
- [ ] Optional reachability hints to cut dev-only and unreachable noise
- [ ] More ecosystems (the engine is npm-focused today)

## 🔐 Security

Found a vulnerability in lockhawk itself? Please report it privately, see **[SECURITY.md](SECURITY.md)**.
Please do not open a public issue for security reports.

## 📄 License

[MIT](LICENSE). Free to use, modify, and distribute.

<div align="center">
<sub>Built with TypeScript. Free and open source.</sub>
</div>
