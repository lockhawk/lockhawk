import { useMemo, useState } from 'react';
import type { CSSProperties } from 'react';
import type { Finding, ScanResult, Severity } from '@lockhawk/core';
import { decodeCvss } from './cvss.js';

/** Build a style object that includes CSS custom properties (`--x`). */
function vars(obj: Record<string, string | number>): CSSProperties {
  return obj as CSSProperties;
}

const SEVERITIES: Severity[] = ['critical', 'high', 'medium', 'low', 'unknown'];
const SEV_COLOR: Record<Severity, string> = {
  critical: 'var(--crit)',
  high: 'var(--high)',
  medium: 'var(--med)',
  low: 'var(--low)',
  unknown: 'var(--unknown)',
  none: 'var(--brand)',
};

export function App({ result }: { result: ScanResult }): JSX.Element {
  const [query, setQuery] = useState('');
  const [active, setActive] = useState<Set<Severity>>(new Set());
  const [scope, setScope] = useState<'all' | 'prod'>('all');
  const [selectedId, setSelectedId] = useState<string | null>(result.findings[0]?.id ?? null);

  const filtered = useMemo(() => {
    const q = query.trim().toLowerCase();
    return result.findings.filter((f) => {
      if (active.size && !active.has(f.severity.level)) return false;
      if (scope === 'prod' && f.scope === 'dev') return false;
      if (
        q &&
        !`${f.packageName} ${f.id} ${f.summary} ${f.aliases.join(' ')}`.toLowerCase().includes(q)
      )
        return false;
      return true;
    });
  }, [result.findings, query, active, scope]);

  const selected = filtered.find((f) => f.id === selectedId) ?? filtered[0] ?? null;

  const toggle = (sev: Severity): void => {
    const next = new Set(active);
    next.has(sev) ? next.delete(sev) : next.add(sev);
    setActive(next);
  };

  return (
    <div className="shell">
      <Masthead result={result} />
      <Threat result={result} />

      {result.findings.length === 0 ? (
        <Clean />
      ) : (
        <>
          <Toolbar
            query={query}
            setQuery={setQuery}
            active={active}
            toggle={toggle}
            scope={scope}
            setScope={setScope}
            summary={result.summary}
          />
          <div className="workspace">
            <FindingsList
              findings={filtered}
              selectedId={selected?.id ?? null}
              onSelect={setSelectedId}
            />
            <Detail finding={selected} manager={result.target.manager} />
          </div>
        </>
      )}

      <Warnings warnings={result.database.warnings} />
      <Footer result={result} />
    </div>
  );
}

function Masthead({ result }: { result: ScanResult }): JSX.Element {
  const { target, stats, database } = result;
  const age = database.ageHours;
  return (
    <header className="masthead">
      <div className="brand">
        <span className="glyph">
          <ShieldIcon />
        </span>
        <div>
          <div className="wordmark">
            lock<b>hawk</b>
          </div>
          <div className="tagline">dependency vulnerability report</div>
        </div>
      </div>
      <div className="meta-grid">
        <Meta
          k="Project"
          v={`${target.root.name}${target.root.version ? `@${target.root.version}` : ''}`}
        />
        <Meta k="Manager" v={target.manager} />
        <Meta k="Packages" v={String(stats.totalPackages)} />
        <Meta k="Direct" v={String(stats.directDependencies)} />
        <Meta
          k="Database"
          v={`${database.source}${age !== undefined ? ` · ${age}h` : ''}`}
          tone={database.stale ? 'warn' : 'ok'}
        />
      </div>
    </header>
  );
}

function Meta({ k, v, tone }: { k: string; v: string; tone?: 'ok' | 'warn' }): JSX.Element {
  return (
    <div className="meta-cell">
      <div className="k">{k}</div>
      <div className={`v${tone ? ` ${tone}` : ''}`}>{v}</div>
    </div>
  );
}

function Threat({ result }: { result: ScanResult }): JSX.Element {
  const { summary } = result;
  const worst: Severity = SEVERITIES.find((s) => summary[s] > 0) ?? 'none';
  const accent = SEV_COLOR[worst];
  const verdict =
    summary.total === 0 ? 'CLEAR' : worst === 'critical' || worst === 'high' ? 'AT RISK' : 'REVIEW';

  return (
    <section className="threat" style={accentVars(worst)}>
      <div className="verdict" style={vars({ '--accent': accent, '--accent-glow': glow(worst) })}>
        <span className="pulse" />
        <div className="label">Threat assessment</div>
        <div className="level">{verdict}</div>
        <div className="sub">
          {summary.total === 0
            ? 'No known vulnerabilities in the dependency tree.'
            : `${summary.total} ${summary.total === 1 ? 'finding' : 'findings'} across ${summary.vulnerablePackages} ${
                summary.vulnerablePackages === 1 ? 'package' : 'packages'
              } · ${summary.fixable} fixable`}
        </div>
      </div>

      <div className="gauges">
        {SEVERITIES.map((sev) => (
          <div
            key={sev}
            className={`gauge${summary[sev] === 0 ? ' zero' : ''}`}
            style={vars({ '--c': SEV_COLOR[sev] })}
          >
            <div className="n">{summary[sev]}</div>
            <div className="t">{sev}</div>
          </div>
        ))}
        <div className="bar">
          {SEVERITIES.map((sev) =>
            summary[sev] > 0 ? (
              <span key={sev} style={{ flexGrow: summary[sev], background: SEV_COLOR[sev] }} />
            ) : null,
          )}
          {summary.total === 0 ? (
            <span style={{ flexGrow: 1, background: 'var(--brand)' }} />
          ) : null}
        </div>
      </div>
    </section>
  );
}

interface ToolbarProps {
  query: string;
  setQuery: (q: string) => void;
  active: Set<Severity>;
  toggle: (s: Severity) => void;
  scope: 'all' | 'prod';
  setScope: (s: 'all' | 'prod') => void;
  summary: ScanResult['summary'];
}

function Toolbar({
  query,
  setQuery,
  active,
  toggle,
  scope,
  setScope,
  summary,
}: ToolbarProps): JSX.Element {
  return (
    <div className="toolbar">
      <label className="search">
        <SearchIcon />
        <input
          value={query}
          onChange={(e) => setQuery(e.target.value)}
          placeholder="filter by package, advisory, summary…"
          spellCheck={false}
        />
      </label>
      <div className="chips">
        {SEVERITIES.map((sev) => (
          <button
            key={sev}
            type="button"
            className={`chip${active.has(sev) ? ' on' : ''}`}
            style={vars({ '--cc': SEV_COLOR[sev] })}
            onClick={() => toggle(sev)}
          >
            <span className="dot" />
            {sev} {summary[sev]}
          </button>
        ))}
      </div>
      <div className="scope-toggle">
        <button
          type="button"
          className={scope === 'all' ? 'on' : ''}
          onClick={() => setScope('all')}
        >
          all
        </button>
        <button
          type="button"
          className={scope === 'prod' ? 'on' : ''}
          onClick={() => setScope('prod')}
        >
          prod only
        </button>
      </div>
    </div>
  );
}

interface ListProps {
  findings: Finding[];
  selectedId: string | null;
  onSelect: (id: string) => void;
}

function FindingsList({ findings, selectedId, onSelect }: ListProps): JSX.Element {
  return (
    <div className="list">
      <div className="list-head">
        <span>Severity</span>
        <span>Package</span>
        <span>Advisory</span>
        <span style={{ textAlign: 'right' }}>Fix</span>
      </div>
      {findings.length === 0 ? (
        <div className="empty">No findings match the current filters.</div>
      ) : (
        findings.map((f, i) => (
          <div
            key={f.id}
            className={`row${f.id === selectedId ? ' sel' : ''}`}
            style={vars({
              '--c': SEV_COLOR[f.severity.level],
              animationDelay: `${Math.min(i, 12) * 0.025}s`,
            })}
            onClick={() => onSelect(f.id)}
          >
            <div>
              <span className="sev-tag">
                <span className="blip" />
                {f.severity.level}
              </span>
              {f.severity.score !== undefined ? (
                <div className="sev-score">{f.severity.score.toFixed(1)}</div>
              ) : null}
            </div>
            <div className="pkg">
              <div className="name">{f.packageName}</div>
              <div className="ver">
                {f.version}
                {f.direct ? ' · direct' : ''}
              </div>
            </div>
            <div>
              <div className="adv">{f.id}</div>
              <span className="tagline-scope">{f.scope}</span>
            </div>
            <div className={`fix ${f.fixedVersions[0] ? 'has' : 'none'}`}>
              {f.fixedVersions[0] ?? '—'}
            </div>
          </div>
        ))
      )}
    </div>
  );
}

function Detail({ finding, manager }: { finding: Finding | null; manager: string }): JSX.Element {
  if (!finding) {
    return (
      <aside className="detail">
        <div className="detail-empty">
          <ShieldIcon />
          <div>Select a finding to inspect its CVSS breakdown, dependency path and fix.</div>
        </div>
      </aside>
    );
  }

  const sev = finding.severity;
  const accent = SEV_COLOR[sev.level];
  const metrics = decodeCvss(sev.vector);
  const path = finding.dependencyPaths[0] ?? [`${finding.packageName}@${finding.version}`];

  return (
    <aside
      className="detail"
      style={vars({ '--accent': accent, '--accent-glow': glow(sev.level) })}
    >
      <div className="detail-top">
        <span className="sev-tag" style={vars({ '--c': accent })}>
          <span className="blip" />
          {sev.level}
          {sev.score !== undefined ? ` · ${sev.score.toFixed(1)}` : ''}
        </span>
        <h2>{finding.summary}</h2>
        <div className="pkgline">
          <b>{finding.packageName}</b>@{finding.version} · {finding.scope}
          {finding.direct ? ' · direct' : ' · transitive'}
        </div>
      </div>

      <div className="detail-body">
        <div className="sec id-chips">
          {[finding.id, ...finding.aliases].map((id) => (
            <span key={id} className="idc">
              {id}
            </span>
          ))}
        </div>

        {finding.details || finding.summary ? (
          <div className="sec">
            <h3>Description</h3>
            <p className="desc">{finding.details ?? finding.summary}</p>
          </div>
        ) : null}

        {sev.source === 'cvss' && sev.score !== undefined ? (
          <div className="sec">
            <h3>CVSS {sev.cvssVersion?.replace('CVSS:', '') ?? ''}</h3>
            <div className="score-readout">
              <span className="big">{sev.score.toFixed(1)}</span>
              <span className="of">/ 10</span>
              <span className="src">{sev.cvssVersion ?? 'cvss'}</span>
            </div>
            {metrics.length ? (
              <div className="cvss-grid">
                {metrics.map((m) => (
                  <div key={m.key} className={`cvss-metric${m.hot ? ' hot' : ''}`}>
                    <div className="ml">{m.label}</div>
                    <div className="mv">{m.value}</div>
                  </div>
                ))}
              </div>
            ) : null}
            {sev.vector ? <div className="vector">{sev.vector}</div> : null}
          </div>
        ) : (
          <div className="sec">
            <h3>Severity</h3>
            <p className="desc">
              Rated <b style={{ color: accent }}>{sev.level}</b> from the advisory database (no CVSS
              vector provided).
            </p>
          </div>
        )}

        <div className="sec">
          <h3>Dependency path</h3>
          <div className="path">
            {path.map((node, i) => (
              <span key={`${node}-${i}`} style={{ display: 'contents' }}>
                <span
                  className={`node${i === 0 ? ' root' : ''}${i === path.length - 1 ? ' leaf' : ''}`}
                >
                  {node}
                </span>
                {i < path.length - 1 ? <span className="arrow">›</span> : null}
              </span>
            ))}
          </div>
        </div>

        <div className="sec">
          <h3>Mitigation</h3>
          <div className={`fixbox${finding.fixedVersions.length ? '' : ' nofix'}`}>
            {finding.fixedVersions.length ? (
              <div className="fixv">Fixed in {finding.fixedVersions.join(', ')}</div>
            ) : null}
            <div className="rec" dangerouslySetInnerHTML={{ __html: recHtml(finding, manager) }} />
          </div>
        </div>

        {finding.references.length ? (
          <div className="sec">
            <h3>References</h3>
            <div className="refs">
              {finding.references.map((ref) => {
                const safe = safeHref(ref);
                return safe ? (
                  <a key={ref} href={safe} target="_blank" rel="noopener noreferrer">
                    {ref}
                  </a>
                ) : (
                  // Non-http(s) URLs are shown as inert text, never as a link.
                  <span key={ref}>{ref}</span>
                );
              })}
            </div>
          </div>
        ) : null}
      </div>
    </aside>
  );
}

function Warnings({ warnings }: { warnings: string[] }): JSX.Element | null {
  if (!warnings.length) return null;
  return (
    <div className="warnings">
      {warnings.map((w) => (
        <div key={w} className="warning">
          <WarnIcon />
          <span>{w}</span>
        </div>
      ))}
    </div>
  );
}

function Clean(): JSX.Element {
  return (
    <div className="clean">
      <div className="ring">
        <CheckIcon />
      </div>
      <h2>No known vulnerabilities</h2>
      <p>Every scanned dependency is clear against the OSV.dev database.</p>
    </div>
  );
}

function Footer({ result }: { result: ScanResult }): JSX.Element {
  return (
    <footer className="foot">
      <span>lockhawk v{result.tool.version}</span>
      <span>data: OSV.dev</span>
      <span>scanned {new Date(result.scannedAt).toLocaleString()}</span>
      {result.stats.durationMs !== undefined ? <span>{result.stats.durationMs}ms</span> : null}
      {result.stats.unscannable > 0 ? <span>{result.stats.unscannable} unscannable</span> : null}
    </footer>
  );
}

// --- helpers ---------------------------------------------------------------

function recHtml(finding: Finding, _manager: string): string {
  const text = finding.recommendation ?? 'No mitigation guidance available.';
  return escapeHtml(text).replace(/`([^`]+)`/g, '<code>$1</code>');
}

function escapeHtml(s: string): string {
  return s.replace(/[&<>]/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;' })[c]!);
}

/** Return the URL only if it is an http(s) link — guards against javascript:/data: hrefs. */
function safeHref(url: string): string | undefined {
  try {
    const u = new URL(url);
    return u.protocol === 'http:' || u.protocol === 'https:' ? url : undefined;
  } catch {
    return undefined;
  }
}

function glow(sev: Severity): string {
  const map: Record<Severity, string> = {
    critical: 'rgba(255,77,109,0.20)',
    high: 'rgba(255,159,69,0.18)',
    medium: 'rgba(245,203,92,0.16)',
    low: 'rgba(92,200,255,0.16)',
    unknown: 'rgba(139,149,167,0.12)',
    none: 'rgba(52,226,160,0.16)',
  };
  return map[sev];
}

function accentVars(sev: Severity): CSSProperties {
  return vars({ '--accent': SEV_COLOR[sev], '--accent-glow': glow(sev) });
}

// --- inline icons (no external assets) -------------------------------------

function ShieldIcon(): JSX.Element {
  return (
    <svg
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth="1.6"
      strokeLinecap="round"
      strokeLinejoin="round"
    >
      <path d="M12 2 4 5v6c0 5 3.5 8.5 8 11 4.5-2.5 8-6 8-11V5l-8-3Z" />
      <path d="m9 12 2 2 4-4" />
    </svg>
  );
}

function SearchIcon(): JSX.Element {
  return (
    <svg
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth="1.8"
      strokeLinecap="round"
    >
      <circle cx="11" cy="11" r="7" />
      <path d="m20 20-3.5-3.5" />
    </svg>
  );
}

function CheckIcon(): JSX.Element {
  return (
    <svg
      width="26"
      height="26"
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth="2.2"
      strokeLinecap="round"
      strokeLinejoin="round"
    >
      <path d="m5 13 4 4 10-10" />
    </svg>
  );
}

function WarnIcon(): JSX.Element {
  return (
    <svg
      width="16"
      height="16"
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth="1.8"
      strokeLinecap="round"
      strokeLinejoin="round"
      style={{ flex: 'none', marginTop: 1 }}
    >
      <path d="M12 3 2 20h20L12 3Z" />
      <path d="M12 10v4M12 17h.01" />
    </svg>
  );
}
