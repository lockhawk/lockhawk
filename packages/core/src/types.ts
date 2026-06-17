// ---------------------------------------------------------------------------
// Shared data model for lockhawk.
//
// Every package (CLI, report UI, GitHub Action) depends on these types — this
// is the contract that keeps the pipeline stages and the reporters in sync.
// ---------------------------------------------------------------------------

/** Qualitative severity bands (CVSS-aligned, plus `unknown` for un-scored advisories). */
export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'none' | 'unknown';

/** Ordering used for `--severity-threshold` and `--fail-on` comparisons. */
export const SEVERITY_RANK: Record<Severity, number> = {
  none: 0,
  unknown: 1,
  low: 2,
  medium: 3,
  high: 4,
  critical: 5,
};

/** `true` when `level` is at least as severe as `threshold`. */
export function severityAtLeast(level: Severity, threshold: Severity): boolean {
  return SEVERITY_RANK[level] >= SEVERITY_RANK[threshold];
}

export type PackageManager = 'npm' | 'yarn' | 'pnpm';

/** How a dependency is reachable from the project root. */
export type DepScope = 'prod' | 'dev' | 'optional' | 'peer';

/** Unique identity of an installed package: `name@version`. */
export type PkgKey = string;

/** Build a {@link PkgKey} from a name and version. */
export function pkgKey(name: string, version: string): PkgKey {
  return `${name}@${version}`;
}

/** A single installed package in the dependency graph. */
export interface DepNode {
  /** `name@version` — the node's key in {@link DependencyGraph.nodes}. */
  key: PkgKey;
  name: string;
  version: string;
  /** Strongest scope by which this node is reachable (prod beats dev/optional). */
  scope: DepScope;
  /** Whether this is a direct dependency of the project root. */
  direct: boolean;
  /** Keys of packages this node depends on (edges out). */
  dependencies: PkgKey[];
  /** Set when the package has no queryable registry version (file:/link:/git:). */
  unscannable?: { reason: string };
}

/** The normalized dependency tree, independent of which package manager produced it. */
export interface DependencyGraph {
  manager: PackageManager;
  lockfilePath: string;
  lockfileVersion?: string | number;
  root: { name: string; version?: string };
  /** All installed packages, keyed by {@link PkgKey}. */
  nodes: Record<PkgKey, DepNode>;
  /** Keys of the project's direct dependencies. */
  directKeys: PkgKey[];
}

// --- OSV schema (the subset we consume) -----------------------------------
// https://ossf.github.io/osv-schema/

export interface OsvEvent {
  introduced?: string;
  fixed?: string;
  last_affected?: string;
  limit?: string;
}

export interface OsvRange {
  type: 'SEMVER' | 'ECOSYSTEM' | 'GIT';
  events: OsvEvent[];
  repo?: string;
}

export interface OsvSeverity {
  /** e.g. `CVSS_V3`, `CVSS_V4`. */
  type: string;
  /** CVSS vector string. */
  score: string;
}

export interface OsvAffected {
  package?: { ecosystem?: string; name?: string; purl?: string };
  ranges?: OsvRange[];
  versions?: string[];
  severity?: OsvSeverity[];
  ecosystem_specific?: Record<string, unknown>;
  database_specific?: Record<string, unknown>;
}

export interface OsvReference {
  type?: string;
  url: string;
}

export interface OsvVulnerability {
  id: string;
  modified?: string;
  published?: string;
  /** RFC3339 timestamp; when present the advisory has been retracted and must be ignored. */
  withdrawn?: string;
  aliases?: string[];
  related?: string[];
  summary?: string;
  details?: string;
  severity?: OsvSeverity[];
  affected?: OsvAffected[];
  references?: OsvReference[];
  database_specific?: Record<string, unknown>;
}

// --- Scan results ----------------------------------------------------------

/** Resolved severity for a finding, with provenance so the UI never shows a bare number. */
export interface SeverityInfo {
  level: Severity;
  /** Numeric CVSS base score (0–10) when computable. */
  score?: number;
  /** CVSS vector string the score was derived from. */
  vector?: string;
  /** e.g. `CVSS:3.1`, `CVSS:4.0`. */
  cvssVersion?: string;
  source: 'cvss' | 'database' | 'unknown';
}

/** One vulnerability affecting one installed package version. */
export interface Finding {
  /** Canonical id (prefers CVE, then GHSA, then the OSV id). */
  id: string;
  /** All known identifiers for this advisory, including the canonical one. */
  aliases: string[];
  packageName: string;
  version: string;
  scope: DepScope;
  direct: boolean;
  severity: SeverityInfo;
  summary: string;
  details?: string;
  references: string[];
  /** Versions that resolve this advisory (derived from OSV `fixed` events). */
  fixedVersions: string[];
  /** Human-readable mitigation guidance. */
  recommendation?: string;
  /** Each path runs root → … → `name@version`, explaining why the package is present. */
  dependencyPaths: PkgKey[][];
  source: string;
}

export interface DatabaseInfo {
  source: 'offline' | 'online' | 'mixed';
  recordCount?: number;
  /** ISO timestamp of when the offline DB was last refreshed. */
  lastUpdated?: string;
  ageHours?: number;
  stale: boolean;
  warnings: string[];
}

export interface ScanSummary {
  total: number;
  critical: number;
  high: number;
  medium: number;
  low: number;
  unknown: number;
  none: number;
  /** Number of distinct vulnerable packages (not advisories). */
  vulnerablePackages: number;
  /** Number of findings that have at least one known fixed version. */
  fixable: number;
}

export interface ScanStats {
  totalPackages: number;
  uniquePackages: number;
  directDependencies: number;
  unscannable: number;
  durationMs?: number;
}

export interface UnscannablePackage {
  name: string;
  version: string;
  reason: string;
}

/** The complete output of a scan — what reporters serialize and the dashboard renders. */
export interface ScanResult {
  schemaVersion: 1;
  tool: { name: string; version: string };
  /** ISO timestamp. */
  scannedAt: string;
  target: {
    path: string;
    manager: PackageManager;
    lockfile: string;
    root: { name: string; version?: string };
  };
  database: DatabaseInfo;
  summary: ScanSummary;
  stats: ScanStats;
  findings: Finding[];
  unscannable: UnscannablePackage[];
}

// --- Engine options --------------------------------------------------------

export type SourceMode = 'auto' | 'offline' | 'online';

export interface ScanOptions {
  /** Project directory to scan (defaults to cwd). */
  path?: string;
  /** Vulnerability-source strategy. */
  mode?: SourceMode;
  cacheDir?: string;
  cacheTtlHours?: number;
  noCache?: boolean;
  concurrency?: number;
  /** Ignore dev dependencies. */
  prodOnly?: boolean;
  /** Advisory ids (CVE/GHSA/OSV) to suppress. */
  ignore?: string[];
  /** Fail hard on network errors instead of degrading to cache (fail-open). */
  strictNetwork?: boolean;
  /** Limit the scan to a single workspace by name. */
  workspace?: string;
  /** Drop findings below this severity from the report. */
  severityThreshold?: Severity;
  /** Progress callback (used by the CLI spinner). */
  onProgress?: (message: string) => void;
}
