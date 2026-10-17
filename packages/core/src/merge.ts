import { createReport } from './report.js';
import type { Report } from './types.js';

/** Checks that a value is a devchecks report (any tool) and returns it typed. */
export function parseReport(json: string | unknown, source = 'report'): Report {
  const data = (typeof json === 'string' ? JSON.parse(json) : json) as Partial<Report>;
  if (!data || typeof data !== 'object' || data.schemaVersion !== 1 || typeof data.tool !== 'string' || !Array.isArray(data.findings)) {
    throw new Error(`${source} is not a devchecks report (expected schemaVersion 1 with "tool" and "findings"). Generate it with --format json.`);
  }
  return data as Report;
}

/**
 * Combines reports from several tools into one. The tools never import each other;
 * they only agree on the report format, so this is the single integration point.
 */
export function mergeReports(reports: Report[], version = __VERSION__): Report {
  const findings = reports.flatMap((r) => r.findings.map((f) => ({ tool: r.tool, ...f })));
  const notes = [...new Set(reports.flatMap((r) => (r.notes ?? []).map((n) => `${r.tool}: ${n}`)))];
  const merged = createReport('devchecks', version, findings, { notes });
  const withBaseline = reports.filter((r) => r.baseline);
  if (withBaseline.length) {
    merged.baseline = withBaseline.reduce(
      (acc, r) => ({ new: acc.new + r.baseline!.new, existing: acc.existing + r.baseline!.existing, fixed: acc.fixed + r.baseline!.fixed }),
      { new: 0, existing: 0, fixed: 0 },
    );
  }
  return merged;
}
