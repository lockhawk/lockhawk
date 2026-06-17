# Using lockhawk in CI/CD

`lockhawk` is built to run in any pipeline without slowing it down: warm a
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
      - uses: lockhawk/lockhawk@v1
        with:
          fail-on: high
```

Or wire it up by hand for full control:

```yaml
- uses: actions/cache@v4
  with:
    path: ~/.cache/lockhawk
    key: lockhawk-osv-${{ runner.os }}-${{ github.run_id }}
    restore-keys: lockhawk-osv-${{ runner.os }}-
- run: npx lockhawk db update
- run: npx lockhawk scan --offline --format sarif --output scan.sarif --fail-on high
- if: always()
  uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: scan.sarif
```

## Azure DevOps

The most useful way to see results **inside** Azure DevOps is the native **Tests**
tab: emit JUnit XML (each vulnerability is a failed test, with severity, CVSS, fix
and dependency path in the failure detail; a clean scan is one passing test) and
publish it with `PublishTestResults`. Also publish the self-contained HTML report
as an artifact for the full interactive dashboard.

```yaml
- task: Cache@2
  inputs:
    key: 'lockhawk-osv | "$(Agent.OS)" | "$(Build.StartTime)"'
    path: '$(HOME)/.cache/lockhawk'
- script: npx lockhawk db update
  displayName: 'Warm OSV database'

# Build report (do not fail the step here — let the Tests tab show results first)
- script: >
    npx lockhawk scan
    --offline --format junit
    --output "$(Build.ArtifactStagingDir)/lockhawk.junit.xml"
    --fail-on none
  displayName: 'Scan dependencies (JUnit)'

# Renders in the native Tests tab — failed tests = vulnerabilities
- task: PublishTestResults@2
  condition: always()
  inputs:
    testResultsFormat: 'JUnit'
    testResultsFiles: '$(Build.ArtifactStagingDir)/lockhawk.junit.xml'
    testRunTitle: 'Dependency vulnerabilities'
    failTaskOnFailedTests: true # fail the pipeline when there are findings

# Full interactive dashboard, downloadable from the build's Artifacts
- script: >
    npx lockhawk scan . --offline --format html
    --output "$(Build.ArtifactStagingDir)/lockhawk-report.html"
    --fail-on none
  displayName: 'Generate HTML report'
  condition: always()
- task: PublishBuildArtifacts@1
  condition: always()
  inputs:
    pathToPublish: '$(Build.ArtifactStagingDir)/lockhawk-report.html'
    artifactName: 'security-report'
```

This gives you findings rendered **natively in the Tests tab** (no extension
needed), gating via `failTaskOnFailedTests`, and the full HTML dashboard as a
downloadable artifact. Prefer the GitHub Security tab? Use `--format sarif` and
the **SARIF SAST Scans Tab** marketplace extension instead.

> The JUnit reporter works the same way in GitHub Actions (via a test-reporter
> action) and GitLab CI (`artifacts:reports:junit:` surfaces it in the pipeline
> and merge-request test widget).

## GitLab CI

```yaml
dependency_scan:
  image: node:22
  cache:
    key: lockhawk-osv
    paths: ['.lockhawk-cache/']
  variables:
    LOCKHAWK_CACHE: '.lockhawk-cache'
  script:
    - npx lockhawk db update
    # JUnit for the pipeline/MR test widget…
    - npx lockhawk scan --offline --format junit --output scan.junit.xml --fail-on none
    # …and the full HTML dashboard as a browsable artifact.
    - npx lockhawk scan --offline --format html --output scan-report.html --fail-on high
  artifacts:
    when: always
    paths: ['scan-report.html']
    reports:
      junit: scan.junit.xml
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
