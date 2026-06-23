# 🛡️ lockhawk

**Fast, free, and accurate vulnerability scanning for your npm dependencies — on your machine and in your pipeline.**

[![npm](https://img.shields.io/npm/v/lockhawk.svg)](https://www.npmjs.com/package/lockhawk)
[![CI](https://github.com/lockhawk/lockhawk/actions/workflows/ci.yml/badge.svg)](https://github.com/lockhawk/lockhawk/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://github.com/lockhawk/lockhawk/blob/main/LICENSE)
[![Data: OSV.dev](https://img.shields.io/badge/data-OSV.dev-4285F4.svg)](https://osv.dev)

`lockhawk` reads your lockfile (`package-lock.json`, `yarn.lock`, or `pnpm-lock.yaml`), builds the full dependency tree including every transitive dependency, and checks each package against the free [OSV.dev](https://osv.dev) vulnerability database. You get a clear terminal report, a polished HTML dashboard, and structured output (JSON, SARIF, JUnit) for CI.

**No account. No API key. No usage limits.**

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

## Quick start

```bash
# Run once, no install needed
npx lockhawk scan

# Fail the build on high or critical findings and write SARIF for the GitHub Security tab
npx lockhawk scan --format sarif --output scan.sarif --fail-on high

# Generate a standalone HTML dashboard
npx lockhawk scan --format html --output report.html

# Explore findings in an interactive dashboard in your browser
npx lockhawk serve
```

Prefer to install it?

```bash
npm install -g lockhawk            # global `lockhawk` command
npm install --save-dev lockhawk    # for use in package scripts and CI
```

## Why lockhawk

- **⚡ Fast and quiet.** A warm scan does zero network requests and finishes in well under a second. The vulnerability database is cached on disk (and you can download it for fully offline CI), and lookups are batched. The scanner also fails open: a temporary network problem never breaks your build.
- **🆓 Free forever.** Powered by Google's [OSV.dev](https://osv.dev). There is no API key, no rate-limited account, and no per-seat license.
- **🎯 Accurate.** Canonical OSV range matching with `semver`, CVSS v3 and v4 scoring, correct handling of withdrawn advisories, and de-duplication of aliased advisories.
- **📦 Every package manager.** npm (`package-lock` v1, v2, v3, and shrinkwrap), Yarn (classic and Berry), and pnpm (v5, v6, v9), including workspaces.
- **📊 Clear results.** A standalone HTML dashboard (one file, works offline) that you can open anywhere or attach as a CI artifact, plus `lockhawk serve` to drill into findings interactively.
- **🔌 Built for CI.** First-class SARIF (GitHub Security tab), JUnit (Azure DevOps and GitLab test dashboards), JSON, and a stable exit-code contract for gating builds.

## CLI reference

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

## Continuous integration

lockhawk runs in any pipeline without slowing it down. Warm the cached database once, then scan offline in well under a second. The snippets below are the short version; full, copy-paste recipes for all three platforms are in [docs/ci-cd.md](https://github.com/lockhawk/lockhawk/blob/main/docs/ci-cd.md).

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

## Configuration

Add a `.lockhawkrc`, a `lockhawk.config.js`, or a `"lockhawk"` key in `package.json`:

```json
{
  "mode": "auto",
  "failOn": "high",
  "prodOnly": false,
  "ignore": ["GHSA-xxxx-xxxx-xxxx"]
}
```

`failOn` is a severity gate: the scan exits non-zero when any finding is at or above that level. With `"failOn": "high"`, a single high or critical finding fails the build, while `"critical"` tolerates highs and `"none"` never fails on findings (report-only). CLI flags always override config-file values.

## Programmatic API

To embed the scanner in your own tooling, use the engine package [`@lockhawk/core`](https://www.npmjs.com/package/@lockhawk/core):

```ts
import { scan } from '@lockhawk/core';

const result = await scan({ path: '.', mode: 'auto', failOn: 'high' });
console.log(result.summary, result.findings);
```

## Full documentation

Full docs, CI recipes, the configuration reference, and the contributing guide live in the main repository: **https://github.com/lockhawk/lockhawk**

## License

[MIT](https://github.com/lockhawk/lockhawk/blob/main/LICENSE). Free to use, modify, and distribute.
