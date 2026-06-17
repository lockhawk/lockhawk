import type { OsvAffected, OsvReference, OsvSeverity, OsvVulnerability } from '../types.js';

/** All identifiers a record is known by (its id plus aliases). */
function tokensOf(vuln: OsvVulnerability): string[] {
  return [vuln.id, ...(vuln.aliases ?? [])];
}

/** Pick the human-facing id: prefer CVE, then GHSA, then the raw OSV id. */
export function canonicalId(ids: Iterable<string>): string {
  const list = [...ids];
  return (
    list.find((id) => id.startsWith('CVE-')) ??
    list.find((id) => id.startsWith('GHSA-')) ??
    list[0]!
  );
}

/**
 * Collapse advisories that describe the same vulnerability. Records are grouped
 * by the connected components of their shared ids/aliases (a CVE surfaced under
 * both a GHSA and an OSV id becomes one finding), then each group is merged into
 * a single representative carrying the union of aliases, references and severity.
 */
export function dedupeVulnerabilities(vulns: OsvVulnerability[]): OsvVulnerability[] {
  if (vulns.length <= 1) return vulns;

  const parent = new Map<string, string>();
  const find = (x: string): string => {
    let root = x;
    while (parent.get(root) !== undefined && parent.get(root) !== root) root = parent.get(root)!;
    parent.set(x, root);
    return root;
  };
  const union = (a: string, b: string): void => {
    parent.set(find(a), find(b));
  };

  for (const vuln of vulns) {
    const tokens = tokensOf(vuln);
    if (!parent.has(tokens[0]!)) parent.set(tokens[0]!, tokens[0]!);
    for (const token of tokens.slice(1)) {
      if (!parent.has(token)) parent.set(token, token);
      union(tokens[0]!, token);
    }
  }

  const groups = new Map<string, OsvVulnerability[]>();
  for (const vuln of vulns) {
    const root = find(vuln.id);
    const group = groups.get(root);
    if (group) group.push(vuln);
    else groups.set(root, [vuln]);
  }

  return [...groups.values()].map(mergeGroup);
}

function mergeGroup(group: OsvVulnerability[]): OsvVulnerability {
  if (group.length === 1) return group[0]!;

  const allIds = new Set<string>();
  const references = new Map<string, OsvReference>();
  const severity: OsvSeverity[] = [];
  const affected: OsvAffected[] = [];
  let summary: string | undefined;
  let details: string | undefined;
  let database_specific: Record<string, unknown> | undefined;

  for (const vuln of group) {
    for (const token of tokensOf(vuln)) allIds.add(token);
    for (const ref of vuln.references ?? []) references.set(ref.url, ref);
    for (const sev of vuln.severity ?? []) severity.push(sev);
    for (const aff of vuln.affected ?? []) affected.push(aff);
    summary ??= vuln.summary;
    details ??= vuln.details;
    database_specific ??= vuln.database_specific;
  }

  const id = canonicalId(allIds);
  return {
    id,
    aliases: [...allIds].filter((token) => token !== id),
    summary,
    details,
    references: [...references.values()],
    severity,
    affected,
    database_specific,
  };
}
