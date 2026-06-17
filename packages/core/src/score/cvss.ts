import type { OsvVulnerability, Severity, SeverityInfo } from '../types.js';

// CVSS v3.0 / v3.1 base-score computation from a vector string.
// We compute v3 natively (the formula is stable and public) and prefer it for
// numeric scoring. CVSS v4 base scoring requires a large lookup table; when only
// a v4 vector is available we fall back to the advisory's qualitative severity.

const AV: Record<string, number> = { N: 0.85, A: 0.62, L: 0.55, P: 0.2 };
const AC: Record<string, number> = { L: 0.77, H: 0.44 };
const UI: Record<string, number> = { N: 0.85, R: 0.62 };
const PR_UNCHANGED: Record<string, number> = { N: 0.85, L: 0.62, H: 0.27 };
const PR_CHANGED: Record<string, number> = { N: 0.85, L: 0.68, H: 0.5 };
const CIA: Record<string, number> = { H: 0.56, L: 0.22, N: 0 };

export interface CvssResult {
  score: number;
  level: Severity;
  /** e.g. `CVSS:3.1`. */
  version: string;
}

/** Map a numeric CVSS base score to its qualitative band. */
export function levelFromScore(score: number): Severity {
  if (score <= 0) return 'none';
  if (score < 4) return 'low';
  if (score < 7) return 'medium';
  if (score < 9) return 'high';
  return 'critical';
}

/** Map a qualitative label (GHSA-style) to a {@link Severity}. */
export function levelFromLabel(label: string): Severity {
  switch (label.trim().toUpperCase()) {
    case 'CRITICAL':
      return 'critical';
    case 'HIGH':
      return 'high';
    case 'MODERATE':
    case 'MEDIUM':
      return 'medium';
    case 'LOW':
      return 'low';
    case 'NONE':
      return 'none';
    default:
      return 'unknown';
  }
}

/** CVSS 3.1 Roundup: smallest one-decimal number ≥ input (integer-math, float-safe). */
function roundUp(input: number): number {
  const scaled = Math.round(input * 100000);
  if (scaled % 10000 === 0) return scaled / 100000;
  return (Math.floor(scaled / 10000) + 1) / 10;
}

/** Compute a base score from a CVSS v3.0/v3.1 vector string, or null if unparseable. */
export function scoreFromVector(vector: string): CvssResult | null {
  const parts = vector.split('/');
  const header = parts[0] ?? '';
  if (!/^CVSS:3\.[01]$/.test(header)) return null;

  const m: Record<string, string> = {};
  for (const part of parts.slice(1)) {
    const [k, v] = part.split(':');
    if (k && v) m[k] = v;
  }
  const av = AV[m.AV ?? ''];
  const ac = AC[m.AC ?? ''];
  const ui = UI[m.UI ?? ''];
  const scopeChanged = m.S === 'C';
  const pr = (scopeChanged ? PR_CHANGED : PR_UNCHANGED)[m.PR ?? ''];
  const c = CIA[m.C ?? ''];
  const i = CIA[m.I ?? ''];
  const a = CIA[m.A ?? ''];
  if ([av, ac, ui, pr, c, i, a].some((x) => x === undefined)) return null;

  const iss = 1 - (1 - c!) * (1 - i!) * (1 - a!);
  const impact = scopeChanged ? 7.52 * (iss - 0.029) - 3.25 * Math.pow(iss - 0.02, 15) : 6.42 * iss;
  const exploitability = 8.22 * av! * ac! * pr! * ui!;

  let score: number;
  if (impact <= 0) score = 0;
  else if (scopeChanged) score = roundUp(Math.min(1.08 * (impact + exploitability), 10));
  else score = roundUp(Math.min(impact + exploitability, 10));

  return { score, level: levelFromScore(score), version: header };
}

/**
 * Resolve the severity of a whole advisory, with provenance. Prefers a computed
 * CVSS v3 score (highest across all vectors), then the advisory's qualitative
 * `database_specific.severity`, then `unknown`.
 */
export function resolveSeverity(vuln: OsvVulnerability): SeverityInfo {
  const vectors: string[] = [];
  for (const s of vuln.severity ?? []) if (s.score) vectors.push(s.score);
  for (const affected of vuln.affected ?? []) {
    for (const s of affected.severity ?? []) if (s.score) vectors.push(s.score);
  }

  let best: CvssResult | null = null;
  for (const vector of vectors) {
    const result = scoreFromVector(vector);
    if (result && (!best || result.score > best.score)) best = result;
  }
  if (best) {
    return {
      level: best.level,
      score: best.score,
      vector: vectorFor(best, vectors),
      cvssVersion: best.version,
      source: 'cvss',
    };
  }

  const label = qualitativeLabel(vuln);
  if (label) return { level: levelFromLabel(label), source: 'database' };

  return { level: 'unknown', source: 'unknown' };
}

function vectorFor(best: CvssResult, vectors: string[]): string | undefined {
  return vectors.find((v) => v.startsWith(best.version));
}

function qualitativeLabel(vuln: OsvVulnerability): string | undefined {
  const fromRecord = (db: Record<string, unknown> | undefined): string | undefined => {
    const sev = db?.severity;
    return typeof sev === 'string' ? sev : undefined;
  };
  const top = fromRecord(vuln.database_specific);
  if (top) return top;
  for (const affected of vuln.affected ?? []) {
    const label = fromRecord(affected.database_specific);
    if (label) return label;
  }
  return undefined;
}
