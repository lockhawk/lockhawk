// CVSS v4.0 base-score computation, ported faithfully from the FIRST.org
// reference calculator (BSD-2-Clause). We compute the base score (CVSS-B):
// threat/environmental metrics are absent and therefore default to their
// worst case (E:A, CR/IR/AR:H), exactly as the reference does.
import { CVSS4_LOOKUP, CVSS4_MAX_COMPOSED, CVSS4_MAX_SEVERITY } from './cvss4-data.js';

const BASE_METRICS = ['AV', 'AC', 'AT', 'PR', 'UI', 'VC', 'VI', 'VA', 'SC', 'SI', 'SA'] as const;

type Sel = Record<string, string>;

const AV_levels: Record<string, number> = { N: 0.0, A: 0.1, L: 0.2, P: 0.3 };
const PR_levels: Record<string, number> = { N: 0.0, L: 0.1, H: 0.2 };
const UI_levels: Record<string, number> = { N: 0.0, P: 0.1, A: 0.2 };
const AC_levels: Record<string, number> = { L: 0.0, H: 0.1 };
const AT_levels: Record<string, number> = { N: 0.0, P: 0.1 };
const VC_levels: Record<string, number> = { H: 0.0, L: 0.1, N: 0.2 };
const VI_levels: Record<string, number> = { H: 0.0, L: 0.1, N: 0.2 };
const VA_levels: Record<string, number> = { H: 0.0, L: 0.1, N: 0.2 };
const SC_levels: Record<string, number> = { H: 0.1, L: 0.2, N: 0.3 };
const SI_levels: Record<string, number> = { S: 0.0, H: 0.1, L: 0.2, N: 0.3 };
const SA_levels: Record<string, number> = { S: 0.0, H: 0.1, L: 0.2, N: 0.3 };
const CR_levels: Record<string, number> = { H: 0.0, M: 0.1, L: 0.2 };
const IR_levels: Record<string, number> = { H: 0.0, M: 0.1, L: 0.2 };
const AR_levels: Record<string, number> = { H: 0.0, M: 0.1, L: 0.2 };

/** Compute the CVSS v4.0 base score from a vector string, or null if invalid. */
export function scoreV4(vector: string): number | null {
  const sel = parseV4(vector);
  if (!sel) return null;
  const macro = macroVector(sel);
  if (CVSS4_LOOKUP[macro] === undefined) return null;
  return cvssScore(sel, macro);
}

function parseV4(vector: string): Sel | null {
  const parts = vector.split('/');
  if (parts[0] !== 'CVSS:4.0') return null;
  const sel: Sel = {};
  for (const part of parts.slice(1)) {
    const [k, v] = part.split(':');
    if (k && v) sel[k] = v;
  }
  for (const metric of BASE_METRICS) if (!(metric in sel)) return null;
  for (const metric of ['E', 'CR', 'IR', 'AR']) if (!(metric in sel)) sel[metric] = 'X';
  return sel;
}

/** Effective metric value, applying modified-metric and worst-case-default rules. */
function m(sel: Sel, metric: string): string {
  const selected = sel[metric];
  if (metric === 'E' && selected === 'X') return 'A';
  if ((metric === 'CR' || metric === 'IR' || metric === 'AR') && selected === 'X') return 'H';
  const modified = sel[`M${metric}`];
  if (modified !== undefined && modified !== 'X') return modified;
  return selected ?? '';
}

function macroVector(sel: Sel): string {
  const av = m(sel, 'AV');
  const pr = m(sel, 'PR');
  const ui = m(sel, 'UI');
  let eq1 = '2';
  if (av === 'N' && pr === 'N' && ui === 'N') eq1 = '0';
  else if ((av === 'N' || pr === 'N' || ui === 'N') && av !== 'P') eq1 = '1';

  const eq2 = m(sel, 'AC') === 'L' && m(sel, 'AT') === 'N' ? '0' : '1';

  const vc = m(sel, 'VC');
  const vi = m(sel, 'VI');
  const va = m(sel, 'VA');
  let eq3 = '2';
  if (vc === 'H' && vi === 'H') eq3 = '0';
  else if (vc === 'H' || vi === 'H' || va === 'H') eq3 = '1';

  const msi = m(sel, 'MSI');
  const msa = m(sel, 'MSA');
  let eq4 = '2';
  if (msi === 'S' || msa === 'S') eq4 = '0';
  else if (m(sel, 'SC') === 'H' || m(sel, 'SI') === 'H' || m(sel, 'SA') === 'H') eq4 = '1';

  const e = m(sel, 'E');
  const eq5 = e === 'A' ? '0' : e === 'P' ? '1' : '2';

  const cr = m(sel, 'CR');
  const ir = m(sel, 'IR');
  const ar = m(sel, 'AR');
  const eq6 =
    (cr === 'H' && vc === 'H') || (ir === 'H' && vi === 'H') || (ar === 'H' && va === 'H')
      ? '0'
      : '1';

  return `${eq1}${eq2}${eq3}${eq4}${eq5}${eq6}`;
}

function lvl(map: Record<string, number>, key: string): number {
  return map[key] ?? 0;
}

function eqMaxes(macro: string, eq: number): string[] {
  const group = CVSS4_MAX_COMPOSED[`eq${eq}`] as Record<string, string[]>;
  return group[macro[eq - 1]!] ?? [];
}

function extractValueMetric(metric: string, str: string): string {
  const start = str.indexOf(metric) + metric.length + 1;
  const rest = str.slice(start);
  const slash = rest.indexOf('/');
  return slash > 0 ? rest.substring(0, slash) : rest;
}

function cvssScore(sel: Sel, macro: string): number {
  if (BASE_METRICS.slice(5).every((metric) => m(sel, metric) === 'N')) return 0; // VC..SA all None

  let value = CVSS4_LOOKUP[macro]!;

  const eq1 = Number(macro[0]);
  const eq3 = Number(macro[2]);
  const eq6 = Number(macro[5]);

  const lower = (parts: [number, number, number, number, number, number]): number =>
    CVSS4_LOOKUP[parts.join('')] ?? NaN;

  const d = macro.split('').map(Number) as [number, number, number, number, number, number];
  const scoreEq1Lower = lower([d[0] + 1, d[1], d[2], d[3], d[4], d[5]]);
  const scoreEq2Lower = lower([d[0], d[1] + 1, d[2], d[3], d[4], d[5]]);

  let scoreEq3Eq6Lower: number;
  if (eq3 === 1 && eq6 === 1) scoreEq3Eq6Lower = lower([d[0], d[1], d[2] + 1, d[3], d[4], d[5]]);
  else if (eq3 === 0 && eq6 === 1)
    scoreEq3Eq6Lower = lower([d[0], d[1], d[2] + 1, d[3], d[4], d[5]]);
  else if (eq3 === 1 && eq6 === 0)
    scoreEq3Eq6Lower = lower([d[0], d[1], d[2], d[3], d[4], d[5] + 1]);
  else if (eq3 === 0 && eq6 === 0) {
    const left = lower([d[0], d[1], d[2], d[3], d[4], d[5] + 1]);
    const right = lower([d[0], d[1], d[2] + 1, d[3], d[4], d[5]]);
    scoreEq3Eq6Lower = left > right ? left : right;
  } else scoreEq3Eq6Lower = lower([d[0], d[1], d[2] + 1, d[3], d[4], d[5] + 1]);

  const scoreEq4Lower = lower([d[0], d[1], d[2], d[3] + 1, d[4], d[5]]);
  const scoreEq5Lower = lower([d[0], d[1], d[2], d[3], d[4] + 1, d[5]]);

  const eq1Maxes = eqMaxes(macro, 1);
  const eq2Maxes = eqMaxes(macro, 2);
  const eq3Eq6Maxes = (CVSS4_MAX_COMPOSED.eq3 as Record<string, Record<string, string[]>>)[
    macro[2]!
  ]![macro[5]!]!;
  const eq4Maxes = eqMaxes(macro, 4);
  const eq5Maxes = eqMaxes(macro, 5);

  const maxVectors: string[] = [];
  for (const a of eq1Maxes)
    for (const b of eq2Maxes)
      for (const c of eq3Eq6Maxes)
        for (const e of eq4Maxes) for (const f of eq5Maxes) maxVectors.push(a + b + c + e + f);

  let sdAV = 0,
    sdPR = 0,
    sdUI = 0,
    sdAC = 0,
    sdAT = 0,
    sdVC = 0,
    sdVI = 0,
    sdVA = 0,
    sdSC = 0,
    sdSI = 0,
    sdSA = 0,
    sdCR = 0,
    sdIR = 0,
    sdAR = 0;

  for (const maxVector of maxVectors) {
    sdAV = lvl(AV_levels, m(sel, 'AV')) - lvl(AV_levels, extractValueMetric('AV', maxVector));
    sdPR = lvl(PR_levels, m(sel, 'PR')) - lvl(PR_levels, extractValueMetric('PR', maxVector));
    sdUI = lvl(UI_levels, m(sel, 'UI')) - lvl(UI_levels, extractValueMetric('UI', maxVector));
    sdAC = lvl(AC_levels, m(sel, 'AC')) - lvl(AC_levels, extractValueMetric('AC', maxVector));
    sdAT = lvl(AT_levels, m(sel, 'AT')) - lvl(AT_levels, extractValueMetric('AT', maxVector));
    sdVC = lvl(VC_levels, m(sel, 'VC')) - lvl(VC_levels, extractValueMetric('VC', maxVector));
    sdVI = lvl(VI_levels, m(sel, 'VI')) - lvl(VI_levels, extractValueMetric('VI', maxVector));
    sdVA = lvl(VA_levels, m(sel, 'VA')) - lvl(VA_levels, extractValueMetric('VA', maxVector));
    sdSC = lvl(SC_levels, m(sel, 'SC')) - lvl(SC_levels, extractValueMetric('SC', maxVector));
    sdSI = lvl(SI_levels, m(sel, 'SI')) - lvl(SI_levels, extractValueMetric('SI', maxVector));
    sdSA = lvl(SA_levels, m(sel, 'SA')) - lvl(SA_levels, extractValueMetric('SA', maxVector));
    sdCR = lvl(CR_levels, m(sel, 'CR')) - lvl(CR_levels, extractValueMetric('CR', maxVector));
    sdIR = lvl(IR_levels, m(sel, 'IR')) - lvl(IR_levels, extractValueMetric('IR', maxVector));
    sdAR = lvl(AR_levels, m(sel, 'AR')) - lvl(AR_levels, extractValueMetric('AR', maxVector));

    const distances = [
      sdAV,
      sdPR,
      sdUI,
      sdAC,
      sdAT,
      sdVC,
      sdVI,
      sdVA,
      sdSC,
      sdSI,
      sdSA,
      sdCR,
      sdIR,
      sdAR,
    ];
    if (distances.some((x) => x < 0)) continue;
    break;
  }

  const csdEq1 = sdAV + sdPR + sdUI;
  const csdEq2 = sdAC + sdAT;
  const csdEq3Eq6 = sdVC + sdVI + sdVA + sdCR + sdIR + sdAR;
  const csdEq4 = sdSC + sdSI + sdSA;

  const step = 0.1;
  const availEq1 = value - scoreEq1Lower;
  const availEq2 = value - scoreEq2Lower;
  const availEq3Eq6 = value - scoreEq3Eq6Lower;
  const availEq4 = value - scoreEq4Lower;
  const availEq5 = value - scoreEq5Lower;

  const maxSev = CVSS4_MAX_SEVERITY;
  const maxSevEq1 = (maxSev.eq1 as Record<string, number>)[String(eq1)]! * step;
  const maxSevEq2 = (maxSev.eq2 as Record<string, number>)[macro[1]!]! * step;
  const maxSevEq3Eq6 =
    (maxSev.eq3eq6 as Record<string, Record<string, number>>)[String(eq3)]![String(eq6)]! * step;
  const maxSevEq4 = (maxSev.eq4 as Record<string, number>)[macro[3]!]! * step;

  let n = 0;
  let nsEq1 = 0,
    nsEq2 = 0,
    nsEq3Eq6 = 0,
    nsEq4 = 0;
  if (!Number.isNaN(availEq1)) {
    n++;
    nsEq1 = availEq1 * (csdEq1 / maxSevEq1);
  }
  if (!Number.isNaN(availEq2)) {
    n++;
    nsEq2 = availEq2 * (csdEq2 / maxSevEq2);
  }
  if (!Number.isNaN(availEq3Eq6)) {
    n++;
    nsEq3Eq6 = availEq3Eq6 * (csdEq3Eq6 / maxSevEq3Eq6);
  }
  if (!Number.isNaN(availEq4)) {
    n++;
    nsEq4 = availEq4 * (csdEq4 / maxSevEq4);
  }
  if (!Number.isNaN(availEq5)) {
    n++; // eq5 proportion is always 0
  }

  const meanDistance = n === 0 ? 0 : (nsEq1 + nsEq2 + nsEq3Eq6 + nsEq4) / n;
  value -= meanDistance;
  if (value < 0) value = 0;
  if (value > 10) value = 10;
  return Math.round(value * 10) / 10;
}
