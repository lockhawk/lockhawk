import type { Finding, ScanResult, Severity } from '../types.js';

// Minimal SARIF 2.1.0 shapes (avoids a dependency on the `sarif` types package).
interface SarifRule {
  id: string;
  name?: string;
  shortDescription: { text: string };
  fullDescription?: { text: string };
  helpUri?: string;
  properties?: Record<string, unknown>;
}
interface SarifResult {
  ruleId: string;
  level: 'error' | 'warning' | 'note';
  message: { text: string };
  locations: unknown[];
  partialFingerprints: Record<string, string>;
  properties?: Record<string, unknown>;
}
export interface SarifLog {
  $schema: string;
  version: '2.1.0';
  runs: unknown[];
}

const INFO_URI = 'https://github.com/lockhawk/lockhawk';

/** GitHub renders findings by `security-severity` (a CVSS-like number 0–10). */
function securitySeverity(finding: Finding): number {
  if (typeof finding.severity.score === 'number') return finding.severity.score;
  switch (finding.severity.level) {
    case 'critical':
      return 9.5;
    case 'high':
      return 7.5;
    case 'medium':
      return 5;
    case 'low':
      return 2;
    default:
      return 0;
  }
}

function sarifLevel(severity: Severity): 'error' | 'warning' | 'note' {
  if (severity === 'critical' || severity === 'high') return 'error';
  if (severity === 'medium') return 'warning';
  return 'note';
}

/**
 * Convert a scan result to SARIF 2.1.0 for GitHub code scanning / Azure DevOps.
 * One rule per advisory; results carry stable `partialFingerprints` so the same
 * finding is not re-flagged as new on every run.
 */
export function toSarif(result: ScanResult): SarifLog {
  const lockfileUri = result.target.lockfile || 'package-lock.json';

  const rules = new Map<string, SarifRule>();
  const results: SarifResult[] = [];

  for (const finding of result.findings) {
    if (!rules.has(finding.id)) {
      rules.set(finding.id, {
        id: finding.id,
        name: `${finding.packageName} ${finding.id}`,
        shortDescription: { text: finding.summary },
        fullDescription: finding.details ? { text: finding.details } : undefined,
        helpUri: finding.references[0],
        properties: {
          'security-severity': String(securitySeverity(finding)),
          tags: ['security', 'dependency', finding.severity.level],
        },
      });
    }

    const path = finding.dependencyPaths[0]?.join(' › ') ?? finding.packageName;
    const fix = finding.fixedVersions[0] ? ` Fixed in ${finding.fixedVersions[0]}.` : '';
    results.push({
      ruleId: finding.id,
      level: sarifLevel(finding.severity.level),
      message: {
        text: `${finding.severity.level.toUpperCase()}: ${finding.packageName}@${finding.version} — ${finding.summary}.${fix} Path: ${path}.`,
      },
      locations: [
        {
          physicalLocation: {
            artifactLocation: { uri: lockfileUri },
            region: { startLine: 1 },
          },
        },
      ],
      partialFingerprints: {
        lockhawkFinding: `${finding.packageName}@${finding.version}@${finding.id}`,
      },
      properties: {
        package: finding.packageName,
        version: finding.version,
        scope: finding.scope,
        fixedVersions: finding.fixedVersions,
      },
    });
  }

  return {
    $schema: 'https://json.schemastore.org/sarif-2.1.0.json',
    version: '2.1.0',
    runs: [
      {
        tool: {
          driver: {
            name: result.tool.name,
            version: result.tool.version,
            informationUri: INFO_URI,
            rules: [...rules.values()],
          },
        },
        results,
        properties: {
          scannedAt: result.scannedAt,
          databaseSource: result.database.source,
          databaseAgeHours: result.database.ageHours,
          databaseStale: result.database.stale,
        },
      },
    ],
  };
}

/** Stringified SARIF log. */
export function toSarifString(result: ScanResult): string {
  return JSON.stringify(toSarif(result), null, 2);
}
