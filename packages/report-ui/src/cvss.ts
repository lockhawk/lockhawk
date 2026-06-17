// Decode a CVSS v3 vector string into labelled metrics for the detail panel.

const LABELS: Record<string, string> = {
  AV: 'Attack Vector',
  AC: 'Attack Complexity',
  PR: 'Privileges Required',
  UI: 'User Interaction',
  S: 'Scope',
  C: 'Confidentiality',
  I: 'Integrity',
  A: 'Availability',
};

const VALUES: Record<string, Record<string, string>> = {
  AV: { N: 'Network', A: 'Adjacent', L: 'Local', P: 'Physical' },
  AC: { L: 'Low', H: 'High' },
  PR: { N: 'None', L: 'Low', H: 'High' },
  UI: { N: 'None', R: 'Required' },
  S: { U: 'Unchanged', C: 'Changed' },
  C: { H: 'High', L: 'Low', N: 'None' },
  I: { H: 'High', L: 'Low', N: 'None' },
  A: { H: 'High', L: 'Low', N: 'None' },
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
    const hot =
      (key === 'AV' && code === 'N') ||
      (key === 'AC' && code === 'L') ||
      (key === 'PR' && code === 'N') ||
      (key === 'UI' && code === 'N') ||
      (key === 'S' && code === 'C') ||
      (['C', 'I', 'A'].includes(key) && code === 'H');
    metrics.push({ key, label: LABELS[key]!, code, value, hot });
  }
  return metrics;
}
