# lockhawk GitHub Action

Scan your npm/JavaScript dependencies for known vulnerabilities on every push or
pull request, fail the build on high-severity issues, and surface findings in the
GitHub **Security → Code scanning** tab.

The action warms a date-keyed cache of the OSV database (so the scan runs
offline and near-instantly), runs the scan, emits SARIF, and uploads it.

## Usage

```yaml
name: Security
on:
  push:
  pull_request:

permissions:
  contents: read
  security-events: write # required to upload SARIF

jobs:
  lockhawk:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: lockhawk/lockhawk@v1
        with:
          fail-on: high
```

## Inputs

| Input                | Default  | Description                                              |
| -------------------- | -------- | -------------------------------------------------------- |
| `path`               | `.`      | Project directory to scan                                |
| `fail-on`            | `high`   | Minimum severity that fails the build                    |
| `severity-threshold` | `low`    | Minimum severity to include in the report                |
| `offline`            | `true`   | Warm + use the cached offline OSV DB (fast, recommended) |
| `upload-sarif`       | `true`   | Upload SARIF to the Security tab                         |
| `prod-only`          | `false`  | Ignore dev dependencies                                  |
| `version`            | `latest` | lockhawk version to run                                  |

## Outputs

| Output       | Description                                           |
| ------------ | ----------------------------------------------------- |
| `sarif-file` | Path to the generated SARIF file                      |
| `exit-code`  | Scanner exit code (`0` clean, `1` findings ≥ fail-on) |

## Notes

- `security-events: write` permission is required for SARIF upload.
- Set `offline: false` to query OSV.dev live instead of using the cached DB.
