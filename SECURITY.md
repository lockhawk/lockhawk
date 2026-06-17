# Security Policy

## Reporting a vulnerability

If you find a security vulnerability **in npm-scanner itself**, please report it privately —
**do not open a public issue**.

- Preferred: use GitHub's [private vulnerability reporting](https://github.com/npm-scanner/npm-scanner/security/advisories/new)
  ("Report a vulnerability" on the repository's **Security** tab).
- Alternatively, email the maintainers at **security@example.com** _(update this address before publishing)_.

Please include:

- a description of the issue and its impact,
- steps to reproduce (or a proof of concept),
- the affected version(s).

We'll acknowledge your report as quickly as we can, keep you updated on the fix, and credit you in
the advisory unless you prefer to remain anonymous.

## Scope

This policy covers the npm-scanner code (the CLI, core engine, dashboard, and GitHub Action). It
does **not** cover vulnerabilities in the third-party packages that npm-scanner _reports on_ — those
belong to their respective maintainers and the [OSV.dev](https://osv.dev) database.

## Supported versions

npm-scanner is pre-1.0; security fixes are released against the latest published version.
