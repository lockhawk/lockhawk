# @lockhawk/core

The scanning engine behind [**lockhawk**](https://github.com/lockhawk/lockhawk): lockfile parsing,
dependency graph building, [OSV.dev](https://osv.dev) matching, CVSS v3 and v4 scoring, and report
generation (table, JSON, SARIF, JUnit, HTML).

> **Most people want the CLI, not this package.** To scan a project, use
> [`lockhawk`](https://www.npmjs.com/package/lockhawk) and run `npx lockhawk scan`. Install
> `@lockhawk/core` only if you are building a tool on top of the engine.

## Install

```bash
npm install @lockhawk/core
```

## Usage

```ts
import { scan } from '@lockhawk/core';

const result = await scan({ path: '.', mode: 'auto', failOn: 'high' });
console.log(result.summary, result.findings);
```

`scan()` reads the project's lockfile (`package-lock.json`, `yarn.lock`, or `pnpm-lock.yaml`),
resolves the full dependency tree including transitive dependencies, queries OSV.dev (offline from a
cached database or online via the batch API), and returns scored, de-duplicated findings.

## Documentation

Full docs, CLI usage, and CI/CD recipes live in the main repository:
**https://github.com/lockhawk/lockhawk**

## License

[MIT](https://github.com/lockhawk/lockhawk/blob/main/LICENSE)
