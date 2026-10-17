// Browser-safe entry. From a CDN on (a staging copy of) your payment page:
//
//   <script src="https://cdn.jsdelivr.net/gh/ravikiran476/devchecks@v0.1.0/cdn/pci-pagecheck.min.js"></script>
//   <script>PCIPageCheck.check({ baseline }).then((r) => console.table(r.inventory))</script>
import { createReport, type BaselineDiff, type Finding, type Report } from '@devchecks/core';
import { analyzePage, buildSnapshot, type AnalysisResult, type AnalyzeOptions } from './analyze.js';
import { DISCLAIMER } from './controls.js';
import { collectDom, type PageSnapshot } from './snapshot.js';

export * from './analyze.js';
export { analyzeCsp, parseCsp, type CspIssue } from './csp.js';
export { luhn, scanSourceForCardData } from './carddata.js';
export { CONTROLS, DISCLAIMER, type Control } from './controls.js';
export { collectDom, type CardField, type FrameEntry, type PageSnapshot, type RawDom, type ScriptEntry } from './snapshot.js';
export { createBaseline, diffBaseline, formatReport, type Finding, type Report } from '@devchecks/core';

export const TOOL = 'pci-pagecheck';
export const VERSION = __VERSION__;

export interface BrowserSnapshotOptions {
  /** Re-fetch the page to read its CSP and security headers (same-origin). Default true. */
  fetchHeaders?: boolean;
  /** Fetch external script bodies to hash them; cross-origin scripts need CORS. Default true. */
  fetchScripts?: boolean;
}

/** Captures the current page in the browser. */
export async function snapshotDocument(options: BrowserSnapshotOptions = {}): Promise<PageSnapshot> {
  const dom = collectDom();
  let headers: Record<string, string> | undefined;
  if (options.fetchHeaders !== false) {
    try {
      const res = await fetch(location.href, { cache: 'no-store', credentials: 'same-origin' });
      headers = {};
      res.headers.forEach((v, k) => (headers![k.toLowerCase()] = v));
    } catch {
      headers = undefined;
    }
  }
  const bodies = new Map<string, string>();
  if (options.fetchScripts !== false) {
    const srcs = [...new Set([...dom.scripts.map((s) => s.src).filter(Boolean), ...dom.resourceScripts] as string[])];
    await Promise.all(
      srcs.map(async (src) => {
        try {
          const res = await fetch(src, { mode: 'cors', credentials: 'omit', cache: 'force-cache' });
          if (res.ok) bodies.set(src, await res.text());
        } catch {
          // cross-origin without CORS: inventoried without a hash
        }
      }),
    );
  }
  return buildSnapshot(dom, { headers, bodies });
}

/** Snapshot + analysis of the current page. */
export async function check(options: AnalyzeOptions & BrowserSnapshotOptions = {}): Promise<AnalysisResult & { report: Report }> {
  const result = analyzePage(await snapshotDocument(options), options);
  return { ...result, report: toReport(result.findings) };
}

export function toReport(findings: Finding[], baseline?: BaselineDiff): Report {
  return createReport(TOOL, VERSION, findings, { baseline, notes: [DISCLAIMER] });
}
