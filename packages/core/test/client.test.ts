import { mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { http, HttpResponse } from 'msw';
import { setupServer } from 'msw/node';
import { afterAll, afterEach, beforeAll, describe, expect, it } from 'vitest';
import { OsvClient } from '../src/osv/client.js';
import { OnlineSource } from '../src/osv/source.js';

const API = 'https://api.osv.dev/v1';
let vulnCalls = 0;

const server = setupServer();
beforeAll(() => server.listen({ onUnhandledRequest: 'error' }));
afterEach(() => {
  server.resetHandlers();
  vulnCalls = 0;
});
afterAll(() => server.close());

const cacheDir = (): string => mkdtempSync(join(tmpdir(), 'lockhawk-client-'));

const vulnHandler = http.get(`${API}/vulns/:id`, ({ params }) => {
  vulnCalls += 1;
  return HttpResponse.json({
    id: params.id,
    summary: `advisory ${String(params.id)}`,
    affected: [
      {
        package: { ecosystem: 'npm', name: 'lodash' },
        ranges: [{ type: 'SEMVER', events: [{ introduced: '0' }] }],
      },
    ],
  });
});

describe('OsvClient', () => {
  it('batch-queries, then hydrates only matched ids', async () => {
    server.use(
      http.post(`${API}/querybatch`, async ({ request }) => {
        const body = (await request.json()) as { queries: { package: { name: string } }[] };
        return HttpResponse.json({
          results: body.queries.map((q) =>
            q.package.name === 'lodash' ? { vulns: [{ id: 'GHSA-1' }] } : {},
          ),
        });
      }),
      vulnHandler,
    );

    const map = await new OsvClient({ cacheDir: cacheDir() }).fetchAdvisories([
      { name: 'lodash', version: '4.17.11' },
      { name: 'safe-pkg', version: '1.0.0' },
    ]);

    expect(map.get('lodash')?.[0]?.id).toBe('GHSA-1');
    expect(map.has('safe-pkg')).toBe(false);
    expect(vulnCalls).toBe(1);
  });

  it('caches hydrated records by id across scans', async () => {
    server.use(
      http.post(`${API}/querybatch`, () =>
        HttpResponse.json({ results: [{ vulns: [{ id: 'GHSA-1' }] }] }),
      ),
      vulnHandler,
    );
    const dir = cacheDir();
    await new OsvClient({ cacheDir: dir }).fetchAdvisories([
      { name: 'lodash', version: '4.17.11' },
    ]);
    await new OsvClient({ cacheDir: dir }).fetchAdvisories([
      { name: 'lodash', version: '4.17.11' },
    ]);
    expect(vulnCalls).toBe(1); // second scan served the record from the on-disk cache
  });

  it('queries OSV by package name only, leaving version matching to lockhawk', async () => {
    let captured: { queries: { package: { name: string; ecosystem: string }; version?: string }[] };
    server.use(
      http.post(`${API}/querybatch`, async ({ request }) => {
        captured = (await request.json()) as typeof captured;
        return HttpResponse.json({
          results: captured.queries.map(() => ({ vulns: [{ id: 'GHSA-1' }] })),
        });
      }),
      vulnHandler,
    );
    // Two versions of the same package — coverage must not depend on OSV's
    // server-side version filter, so the query carries the bare name (no version)
    // and the package is queried once. lockhawk re-validates the match itself.
    await new OsvClient({ cacheDir: cacheDir() }).fetchAdvisories([
      { name: 'lodash', version: '4.17.11' },
      { name: 'lodash', version: '3.0.0' },
    ]);
    expect(captured!.queries).toHaveLength(1);
    expect(captured!.queries[0]).toEqual({ package: { name: 'lodash', ecosystem: 'npm' } });
    expect(captured!.queries[0]!.version).toBeUndefined();
  });

  it('follows pagination via next_page_token', async () => {
    server.use(
      http.post(`${API}/querybatch`, () =>
        HttpResponse.json({ results: [{ vulns: [{ id: 'GHSA-1' }], next_page_token: 'tok' }] }),
      ),
      http.post(`${API}/query`, () => HttpResponse.json({ vulns: [{ id: 'GHSA-2' }] })),
      vulnHandler,
    );
    const map = await new OsvClient({ cacheDir: cacheDir() }).fetchAdvisories([
      { name: 'lodash', version: '4.17.11' },
    ]);
    expect(
      map
        .get('lodash')
        ?.map((v) => v.id)
        .sort(),
    ).toEqual(['GHSA-1', 'GHSA-2']);
  });
});

describe('OnlineSource fail-open', () => {
  it('degrades to empty results with a warning on a client error', async () => {
    server.use(http.post(`${API}/querybatch`, () => new HttpResponse(null, { status: 400 })));
    const resolved = await new OnlineSource({ cacheDir: cacheDir() }).prepare([
      { name: 'lodash', version: '4.17.11' },
    ]);
    expect(resolved.candidatesFor('lodash')).toEqual([]);
    expect(resolved.database.warnings.length).toBeGreaterThan(0);
  });

  it('rethrows under strictNetwork', async () => {
    server.use(http.post(`${API}/querybatch`, () => new HttpResponse(null, { status: 400 })));
    await expect(
      new OnlineSource({ cacheDir: cacheDir(), strictNetwork: true }).prepare([
        { name: 'lodash', version: '4.17.11' },
      ]),
    ).rejects.toThrow();
  });
});
