// Browser entry: measure the current page and check budgets.
//
//   <script src="https://cdn.jsdelivr.net/gh/ravikiran476/devchecks@v0.1.0/cdn/perfcheck.min.js"></script>
//   <script>PerfCheck.measure({ budgets: { lcp: 2500, scriptBytes: '300kB' } }).then((r) => console.table(r.vitals))</script>
//
// Load it early (in <head>) so it sees every layout shift and interaction.
import { createReport, type BaselineDiff, type Finding, type Report } from '@devchecks/core';
import { checkPage, type PageBudgets } from './budgets.js';
import { collectResources, installVitalsObserver, type ResourceSummary, type VitalsSnapshot } from './vitals.js';

export { checkPage, formatBytes, parseSize, THRESHOLDS, type BundleBudget, type BundleFile, type PageBudgets } from './budgets.js';
export { collectResources, installVitalsObserver, type ResourceSummary, type VitalsHandle, type VitalsSnapshot } from './vitals.js';
export { createBaseline, diffBaseline, formatReport, type Finding, type Report } from '@devchecks/core';

export const TOOL = 'perfcheck';
export const VERSION = __VERSION__;

// Start observing as soon as the bundle is evaluated.
if (typeof window !== 'undefined' && typeof PerformanceObserver !== 'undefined') installVitalsObserver();

export interface MeasureOptions {
  budgets?: PageBudgets;
  /** Wait this long after load before reading metrics. Default 3000 ms. */
  settleMs?: number;
}

export interface MeasureResult {
  url: string;
  vitals: VitalsSnapshot;
  resources: ResourceSummary;
  findings: Finding[];
  report: Report;
}

/** Waits for load plus a settle period, then returns Web Vitals, resource weight and budget findings. */
export async function measure(options: MeasureOptions = {}): Promise<MeasureResult> {
  const handle = installVitalsObserver();
  if (document.readyState !== 'complete') await new Promise((r) => window.addEventListener('load', r, { once: true }));
  await new Promise((r) => setTimeout(r, options.settleMs ?? 3000));
  const vitals = handle.get();
  const resources = collectResources();
  const findings = checkPage(location.href, vitals, resources, options.budgets);
  return { url: location.href, vitals, resources, findings, report: toReport(findings) };
}

/** Reports metrics when the page is hidden (real-user monitoring). Calls back at most once per page view. */
export function onPageHidden(callback: (vitals: VitalsSnapshot, resources: ResourceSummary) => void): void {
  const handle = installVitalsObserver();
  let sent = false;
  addEventListener('visibilitychange', () => {
    if (document.visibilityState !== 'hidden' || sent) return;
    sent = true;
    callback(handle.get(), collectResources());
  });
}

export function toReport(findings: Finding[], baseline?: BaselineDiff): Report {
  return createReport(TOOL, VERSION, findings, {
    baseline,
    notes: ['Lab measurements vary between runs and machines; use several runs and field data (RUM/CrUX) for decisions.'],
  });
}
