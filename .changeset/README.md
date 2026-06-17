# Changesets

This directory holds [changesets](https://github.com/changesets/changesets) — one file
per pending change describing the version bump and a changelog entry.

- Add one: `pnpm changeset`
- Apply pending changesets (bump versions + write changelogs): `pnpm version-packages`
- Build and publish to npm: `pnpm release`

`@npm-scanner/core` and `npm-scanner` are versioned together (`fixed`). The
`@npm-scanner/report-ui` and action packages are private and not published.
