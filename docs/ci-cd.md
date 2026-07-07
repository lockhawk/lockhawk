# Using lockhawk in CI/CD

`lockhawk` is built to run in any pipeline without slowing it down: warm a
cached OSV database once, then every scan runs offline in well under a second.
It is **fail-open** — a transient network problem never breaks your build — and
its [exit codes](#exit-codes) give you precise control over gating.

## GitHub Actions

The simplest path is the bundled action (see [`action.yml`](../action.yml)):

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

Install lockhawk, run it on every build, fail the build on high-severity
vulnerabilities, and publish **all** findings so the team can review them after
the run — both in the native **Tests** tab and as the full interactive dashboard.

### Install lockhawk

Add it as a dev dependency so the version is tracked in your repo (and updated
like any other package):

```bash
npm install --save-dev lockhawk
```

Optionally expose a script in `package.json`:

```json
{ "scripts": { "scan:deps": "lockhawk scan ." } }
```

The pipeline below installs it with `npm ci`. Prefer no install? Drop the
`npm ci` step and replace every `npx lockhawk` with `npx -y lockhawk@0.2.8`
(pin a version for reproducible, supply-chain-safe runs).

### The pipeline

The scan runs **once** to a JSON result and applies the gate (`--fail-on high`
exits non-zero → the build turns red). JUnit and HTML are then re-rendered from
that saved result — no re-scan — and every publish step is `condition: always()`
so findings are still published when a high-severity finding fails the build.

```yaml
trigger: [main]
pool: { vmImage: 'ubuntu-latest' }

steps:
  - task: NodeTool@0
    inputs: { versionSpec: '20.x' }

  - script: npm ci
    displayName: 'Install dependencies (incl. lockhawk)'

  # Warm the OSV database once, cached daily, so scans run fully offline in <1s.
  - bash: echo "##vso[task.setvariable variable=LOCKHAWK_DB_DATE]$(date -u +%Y-%m-%d)"
    displayName: 'Compute OSV cache date'
  - task: Cache@2
    inputs:
      key: 'lockhawk-osv | "$(Agent.OS)" | "$(LOCKHAWK_DB_DATE)"'
      restoreKeys: 'lockhawk-osv | "$(Agent.OS)"'
      path: '$(HOME)/.cache/lockhawk'
  - script: npx lockhawk db update
    displayName: 'Warm OSV database'

  # Scan once → JSON. Writes the result file, then exits 1 on any high+ finding,
  # which fails the build. Every finding is captured regardless of severity.
  - script: >
      npx lockhawk scan .
      --offline --format json
      --output "$(Build.ArtifactStagingDir)/lockhawk-result.json"
      --fail-on high
    displayName: 'Scan dependencies (fails the build on high+)'

  # Re-render JUnit + HTML from the saved result (no re-scan, no network).
  # always() so they run even after the scan step failed the build.
  - script: >
      npx lockhawk report
      -i "$(Build.ArtifactStagingDir)/lockhawk-result.json"
      -f junit -o "$(Build.ArtifactStagingDir)/lockhawk.junit.xml"
    displayName: 'Render JUnit'
    condition: always()
  - script: >
      npx lockhawk report
      -i "$(Build.ArtifactStagingDir)/lockhawk-result.json"
      -f html -o "$(Build.ArtifactStagingDir)/lockhawk-report.html"
    displayName: 'Render HTML dashboard'
    condition: always()
  - script: >
      npx lockhawk report
      -i "$(Build.ArtifactStagingDir)/lockhawk-result.json"
      -f markdown -o "$(Build.ArtifactStagingDir)/lockhawk-summary.md"
    displayName: 'Render Markdown summary'
    condition: always()

  # Publish the Markdown summary as a native build-summary tab (no extension).
  - bash: echo "##vso[task.uploadsummary]$(Build.ArtifactStagingDir)/lockhawk-summary.md"
    displayName: 'Publish summary to the build page'
    condition: always()

  # Every vulnerability in the native Tests tab (the scan step is the gate, so
  # leave failTaskOnFailedTests off here to avoid failing on every finding).
  - task: PublishTestResults@2
    condition: always()
    inputs:
      testResultsFormat: 'JUnit'
      testResultsFiles: '$(Build.ArtifactStagingDir)/lockhawk.junit.xml'
      testRunTitle: 'Dependency vulnerabilities'
      failTaskOnFailedTests: false

  # The full interactive dashboard, rendered inline as a "LockHawk" tab on the
  # run's results page. Requires the free Publish HTML Report extension (below).
  - task: PublishHtmlReport@1
    condition: always()
    inputs:
      reportDir: '$(Build.ArtifactStagingDir)/lockhawk-report.html'
      tabName: 'LockHawk'

  # …and the same HTML as a downloadable artifact (works without any extension).
  - task: PublishBuildArtifacts@1
    condition: always()
    inputs:
      pathToPublish: '$(Build.ArtifactStagingDir)/lockhawk-report.html'
      artifactName: 'security-report'
```

### Where the results show up (and stay viewable after the run)

- **The build-summary tab** — the Markdown summary (`##vso[task.uploadsummary]`)
  renders inline on the build's summary page **natively, with no extension** —
  the fastest at-a-glance view, refreshed each run.
- **Tests tab** — every vulnerability is a failed test, with severity, CVSS
  vector, fixed version and dependency path in the failure detail; a clean scan
  is one passing test. Native — no extension required.
- **A "LockHawk" tab** on the run's results page shows the full interactive
  dashboard **inline**. This needs the free
  [Publish HTML Report](https://marketplace.visualstudio.com/items?itemName=blakyaks.azure-pipelines-html-reports)
  extension (a one-time install by an org admin). lockhawk's HTML report is a
  single self-contained file — exactly the self-contained, single-page report
  the extension expects — so it renders with no CORS or broken-link issues.
- **Artifacts** — the same `lockhawk-report.html` is published as a downloadable
  artifact, so the dashboard is available even if the extension isn't installed.

Because they're attached to the build, all three persist for the pipeline's
retention window — developers can open them long after the run finishes.

### View vulnerability trends on a team dashboard

The JUnit results also feed Azure DevOps' **native test dashboards** — no
extension or hosting required. Because each vulnerability is a test (and a clean
scan is a passing test), the built-in **Test Results Trend** widget charts your
vulnerability count and pass rate **over time**, aggregated across every run and
viewable on a team dashboard long after any single build.

To add it (a one-time UI step, after the pipeline has run at least once):

1. Open **Overview → Dashboards** and pick or create a team dashboard.
2. **Edit → Add a widget → Test Results Trend** (or **Test Results Trend
   (Advanced)** for filtering by outcome/branch/stage across pipelines).
3. Configure it to point at this pipeline and save.

The trend tile shows counts, pass rate and failure trends — "how many
vulnerabilities over time." For the per-finding detail (which CVE, CVSS, fix,
dependency path), drill into the **Tests** tab or the **LockHawk** dashboard tab
above. See the
[widget catalog](https://learn.microsoft.com/en-us/azure/devops/report/dashboards/widget-catalog)
and [Configure the Test Results Trend (Advanced) widget](https://learn.microsoft.com/en-us/azure/devops/report/dashboards/configure-test-results-trend).

### Tuning the gate

The build fails when the `scan` step finds anything at or above `--fail-on`
(default `high`, so a single high or critical finding turns the build red). The
report still lists **every** finding — `--fail-on` controls only the exit code.

- `--fail-on critical` — only critical findings break the build.
- `--prod-only` — ignore dev dependencies.
- `--severity-threshold medium` — drop low-severity noise from the report itself.
- Report without ever failing the build: add `continueOnError: true` to the scan
  step (the result file is still written, so the Tests tab and dashboard populate).

Prefer the GitHub Security tab? Use `--format sarif` and the **SARIF SAST Scans
Tab** marketplace extension instead.

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
    # Scan once → JSON. On a high+ finding it exits non-zero; note that and gate at
    # the end so the JUnit + HTML reports below still render and publish.
    - npx lockhawk scan . --offline --format json --output result.json --fail-on high || echo 1 > .lockhawk-failed
    # Re-render from the saved result — no re-scan, no network.
    - npx lockhawk report -i result.json -f junit -o scan.junit.xml # pipeline/MR test widget
    - npx lockhawk report -i result.json -f html -o scan-report.html # browsable dashboard artifact
    # Fail the job on high+ findings (the reports are already written and published).
    - if [ -f .lockhawk-failed ]; then exit 1; fi
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
