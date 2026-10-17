import type { Finding, ReportSummary, Severity } from './types.js';

export const SEVERITIES: readonly Severity[] = ['critical', 'high', 'medium', 'low', 'info'];

const RANK: Record<Severity, number> = { critical: 4, high: 3, medium: 2, low: 1, info: 0 };

export function severityRank(s: Severity): number {
  return RANK[s];
}

export function isSeverity(value: unknown): value is Severity {
  return typeof value === 'string' && value in RANK;
}

/** Accepts common aliases ("moderate", "serious", "error", "warning", ...). */
export function parseSeverity(value: string): Severity {
  const v = value.trim().toLowerCase();
  if (isSeverity(v)) return v;
  const aliases: Record<string, Severity> = {
    moderate: 'medium',
    serious: 'high',
    minor: 'low',
    error: 'high',
    warning: 'medium',
    warn: 'medium',
    note: 'low',
    none: 'info',
  };
  const s = aliases[v];
  if (!s) throw new Error(`Unknown severity "${value}". Use one of: ${SEVERITIES.join(', ')}`);
  return s;
}

/** True when `severity` is at least as severe as `threshold`. */
export function meetsThreshold(severity: Severity, threshold: Severity): boolean {
  return RANK[severity] >= RANK[threshold];
}

export function filterBySeverity(findings: Finding[], min: Severity): Finding[] {
  return findings.filter((f) => meetsThreshold(f.severity, min));
}

export function sortFindings(findings: Finding[]): Finding[] {
  return [...findings].sort(
    (a, b) =>
      RANK[b.severity] - RANK[a.severity] ||
      (a.location?.file ?? a.location?.url ?? '').localeCompare(b.location?.file ?? b.location?.url ?? '') ||
      (a.location?.line ?? 0) - (b.location?.line ?? 0) ||
      a.ruleId.localeCompare(b.ruleId),
  );
}

export function summarize(findings: Finding[]): ReportSummary {
  const bySeverity: Record<Severity, number> = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  for (const f of findings) bySeverity[f.severity]++;
  return { total: findings.length, bySeverity };
}
