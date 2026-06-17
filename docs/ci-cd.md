# Using npm-scanner in CI/CD

`npm-scanner` is built to run in any pipeline without slowing it down: warm a
cached OSV database once, then every scan runs offline in well under a second.
It is **fail-open** — a transient network problem never breaks your build — and
its [exit codes](#exit-codes) give you precise control over gating.

## GitHub Actions

The simplest path is the bundled action (see [`apps/action`](../apps/action)):

```yaml
permissions:
  contents: read
  security-events: write
jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: npm-scanner/npm-scanner@v1
        with:
          fail-on: high
```

Or wire it up by hand for full control:

```yaml
- uses: actions/cache@v4
  with:
    path: ~/.cache/npm-scanner
    key: npm-scanner-osv-${{ runner.os }}-${{ github.run_id }}
    restore-keys: npm-scanner-osv-${{ runner.os }}-
- run: npx npm-scanner db update
- run: npx npm-scanner scan --offline --format sarif --output scan.sarif --fail-on high
- if: always()
  uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: scan.sarif
```

## Azure DevOps

```yaml
- task: Cache@2
  inputs:
    key: 'npm-scanner-osv | "$(Agent.OS)" | "$(Build.StartTime)"'
    path: '$(HOME)/.cache/npm-scanner'
- script: npx npm-scanner db update
  displayName: 'Warm OSV database'
- script: >
    npx npm-scanner scan
    --offline --format sarif
    --output "$(Build.ArtifactStagingDir)/scan.sarif"
    --fail-on high
  displayName: 'Scan dependencies'
- task: PublishBuildArtifacts@1
  condition: always()
  inputs:
    pathToPublish: '$(Build.ArtifactStagingDir)/scan.sarif'
    artifactName: 'security-scan'
```

Install the **SARIF SAST Scans Tab** marketplace extension to view results in
the build summary.

## GitLab CI

```yaml
dependency_scan:
  image: node:22
  cache:
    key: npm-scanner-osv
    paths: ['.npm-scanner-cache/']
  variables:
    NPM_SCANNER_CACHE: '.npm-scanner-cache'
  script:
    - npx npm-scanner db update
    - npx npm-scanner scan --offline --format html --output scan-report.html --fail-on high
  artifacts:
    when: always
    paths: ['scan-report.html']
```

## Exit codes

| Code | Meaning                                                      |
| ---- | ------------------------------------------------------------ |
| `0`  | Scan completed; no finding at or above `--fail-on`           |
| `1`  | Scan completed; at least one finding at or above `--fail-on` |
| `2`  | Usage error (e.g. no lockfile found)                         |
| `3`  | Internal error                                               |
| `4`  | Network error while `--strict-network` is set                |

Plain network failures **never** produce a failing exit code unless you opt in
with `--strict-network`.

## Keeping scans fast

- Run `db update` once per pipeline (or let `actions/cache` restore it) and scan
  with `--offline` — a warm scan does zero network I/O.
- The offline database is stored as a bounded set of shard files, so caching and
  restoring it is cheap.
- Without a warm DB, `auto` mode falls back to live OSV.dev queries (with an
  on-disk per-advisory cache), then to a stale DB if the network is down.
