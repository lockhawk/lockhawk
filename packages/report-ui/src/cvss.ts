// Decode a CVSS v3 or v4 vector string into labelled metrics for the detail panel.

const LABELS: Record<string, string> = {
  // v3 + shared
  AV: 'Attack Vector',
  AC: 'Attack Complexity',
  PR: 'Privileges Required',
  UI: 'User Interaction',
  S: 'Scope',
  C: 'Confidentiality',
  I: 'Integrity',
  A: 'Availability',
  // v4-specific
  AT: 'Attack Requirements',
  VC: 'Confidentiality (Vuln.)',
  VI: 'Integrity (Vuln.)',
  VA: 'Availability (Vuln.)',
  SC: 'Confidentiality (Subseq.)',
  SI: 'Integrity (Subseq.)',
  SA: 'Availability (Subseq.)',
};

const CIA = { H: 'High', L: 'Low', N: 'None' } as const;
const SUBSEQ = { S: 'Safety', H: 'High', L: 'Low', N: 'None' } as const;

const VALUES: Record<string, Record<string, string>> = {
  AV: { N: 'Network', A: 'Adjacent', L: 'Local', P: 'Physical' },
  AC: { L: 'Low', H: 'High' },
  AT: { N: 'None', P: 'Present' },
  PR: { N: 'None', L: 'Low', H: 'High' },
  UI: { N: 'None', R: 'Required', P: 'Passive', A: 'Active' },
  S: { U: 'Unchanged', C: 'Changed' },
  C: CIA,
  I: CIA,
  A: CIA,
  VC: CIA,
  VI: CIA,
  VA: CIA,
  SC: CIA,
  SI: SUBSEQ,
  SA: SUBSEQ,
};

// Metric/value combinations that read as "worse" (tinted in the UI).
const HOT: Record<string, string[]> = {
  AV: ['N'],
  AC: ['L'],
  AT: ['N'],
  PR: ['N'],
  UI: ['N'],
  S: ['C'],
  C: ['H'],
  I: ['H'],
  A: ['H'],
  VC: ['H'],
  VI: ['H'],
  VA: ['H'],
  SC: ['H', 'S'],
  SI: ['H', 'S'],
  SA: ['H', 'S'],
};

export interface CvssMetric {
  key: string;
  label: string;
  code: string;
  value: string;
  hot: boolean;
}

export function decodeCvss(vector?: string): CvssMetric[] {
  if (!vector) return [];
  const metrics: CvssMetric[] = [];
  for (const part of vector.split('/').slice(1)) {
    const [key, code] = part.split(':');
    if (!key || !code || !LABELS[key]) continue;
    const value = VALUES[key]?.[code] ?? code;
    const hot = HOT[key]?.includes(code) ?? false;
    metrics.push({ key, label: LABELS[key]!, code, value, hot });
  }
  return metrics;
}
