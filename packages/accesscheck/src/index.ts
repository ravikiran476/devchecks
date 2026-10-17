// Browser entry: bundles axe-core and scans the current document (or part of it).
//
//   <script src="https://cdn.jsdelivr.net/gh/ravikiran476/devchecks@v0.1.0/cdn/accesscheck.min.js"></script>
//   <script>AccessCheck.scan().then((r) => console.table(r.findings))</script>
import axe from 'axe-core';
import { diffBaseline, type Baseline, type Finding, type Report } from '@devchecks/core';
import { DEFAULT_TAGS, mapAxeResults, toReport, type AxeResults } from './map.js';

export * from './map.js';
export { suggestFix } from './fixes.js';
export { createBaseline, diffBaseline, formatReport, type Finding, type Report } from '@devchecks/core';

export interface ScanOptions {
  /** WCAG / axe tags to run. Default WCAG 2.0–2.2 A and AA. */
  tags?: string[];
  /** Rule ids to skip. */
  disableRules?: string[];
  /** CSS selectors to leave out (third-party widgets you cannot fix). */
  exclude?: string[];
  includeIncomplete?: boolean;
  baseline?: Baseline;
}

export interface ScanResult {
  findings: Finding[];
  /** Findings not present in the baseline (all findings when no baseline is given). */
  newFindings: Finding[];
  report: Report;
}

/** Runs axe-core in the page and returns findings with selectors and fix suggestions. */
export async function scan(context: Element | Document | string = document, options: ScanOptions = {}): Promise<ScanResult> {
  const include = typeof context === 'string' ? context : (context as Element | Document);
  const ctx = options.exclude?.length ? ({ include: [include], exclude: options.exclude.map((s) => [s]) } as unknown as axe.ElementContext) : (include as axe.ElementContext);
  const results = (await axe.run(ctx, {
    runOnly: { type: 'tag', values: options.tags ?? DEFAULT_TAGS },
    rules: Object.fromEntries((options.disableRules ?? []).map((id) => [id, { enabled: false }])),
    resultTypes: ['violations', 'incomplete'],
  })) as unknown as AxeResults;
  const findings = mapAxeResults(results, { includeIncomplete: options.includeIncomplete, url: typeof location !== 'undefined' ? location.href : undefined });
  const diff = diffBaseline(findings, options.baseline);
  return { findings, newFindings: diff.newFindings, report: toReport(diff.newFindings, options.baseline ? diff : undefined) };
}

/** Logs findings to the console as a table. Handy from a bookmarklet or DevTools. */
export async function audit(options: ScanOptions = {}): Promise<ScanResult> {
  const result = await scan(document, options);
  console.table(result.newFindings.map((f) => ({ severity: f.severity, rule: f.ruleId, selector: f.location?.selector, fix: f.remediation })));
  return result;
}
