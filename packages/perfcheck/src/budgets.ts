import { fingerprint, type Finding, type Severity } from '@devchecks/core';
import type { ResourceSummary, VitalsSnapshot } from './vitals.js';

/** "170kB" → 170000, "1.5MB" → 1500000, "200KiB" → 204800, 1234 → 1234. */
export function parseSize(size: string | number): number {
  if (typeof size === 'number') return size;
  const m = /^\s*([\d.]+)\s*(b|kb|kib|mb|mib|gb|gib)?\s*$/i.exec(size);
  if (!m) throw new Error(`Invalid size "${size}". Use e.g. 170kB, 1.5MB or 200KiB.`);
  const units: Record<string, number> = { b: 1, kb: 1e3, kib: 1024, mb: 1e6, mib: 1024 ** 2, gb: 1e9, gib: 1024 ** 3 };
  return Math.round(Number(m[1]) * units[(m[2] ?? 'b').toLowerCase()]!);
}

export function formatBytes(bytes: number): string {
  if (bytes >= 1e6) return `${(bytes / 1e6).toFixed(2)} MB`;
  if (bytes >= 1e3) return `${(bytes / 1e3).toFixed(1)} kB`;
  return `${bytes} B`;
}

export interface PageBudgets {
  lcp?: number;
  cls?: number;
  inp?: number;
  fcp?: number;
  ttfb?: number;
  tbt?: number;
  totalBytes?: string | number;
  scriptBytes?: string | number;
  stylesheetBytes?: string | number;
  imageBytes?: string | number;
  fontBytes?: string | number;
  thirdPartyBytes?: string | number;
  requests?: number;
}

/** Google's Core Web Vitals thresholds: [good, poor]. Between them is "needs improvement". */
export const THRESHOLDS: Record<'lcp' | 'cls' | 'inp' | 'fcp' | 'ttfb' | 'tbt', [number, number]> = {
  lcp: [2500, 4000],
  cls: [0.1, 0.25],
  inp: [200, 500],
  fcp: [1800, 3000],
  ttfb: [800, 1800],
  tbt: [200, 600],
};

const NAMES: Record<string, string> = { lcp: 'Largest Contentful Paint', cls: 'Cumulative Layout Shift', inp: 'Interaction to Next Paint', fcp: 'First Contentful Paint', ttfb: 'Time to First Byte', tbt: 'Total Blocking Time' };

const ADVICE: Record<string, string> = {
  lcp: 'Serve the LCP image/text early: preload it, avoid lazy-loading it, use fetchpriority="high", compress images, and cut render-blocking CSS/JS and slow server responses.',
  cls: 'Reserve space for images, embeds and ads (width/height or aspect-ratio), avoid inserting content above existing content, and use font-display: optional or matched fallback fonts.',
  inp: 'Break up long tasks (yield to the main thread), debounce expensive handlers, move work off the main thread, and avoid large re-renders on input.',
  fcp: 'Reduce render-blocking resources, inline critical CSS, and improve server response time.',
  ttfb: 'Cache HTML at the edge/CDN, reduce server work and redirects, and keep the origin close to users.',
  tbt: 'Split and defer JavaScript, remove unused code, and break up long tasks.',
  bytes: 'Code-split routes, remove unused dependencies, compress (brotli), serve modern image formats (AVIF/WebP) at the right size, and lazy-load below-the-fold content.',
};

function make(ruleId: string, severity: Severity, url: string, metric: string, message: string, remediation: string, meta: Record<string, unknown>): Finding {
  let path = url;
  try {
    path = new URL(url).pathname;
  } catch {
    // keep as is
  }
  return { fingerprint: fingerprint('perfcheck', ruleId, path, metric), ruleId, severity, message, location: { url }, remediation, meta: { metric, ...meta } };
}

const fmt = (metric: string, v: number) => (metric === 'cls' ? v.toFixed(3) : `${Math.round(v)} ms`);

/** Compares measured metrics with explicit budgets, falling back to Core Web Vitals thresholds. */
export function checkPage(url: string, vitals: VitalsSnapshot, resources: ResourceSummary | undefined, budgets: PageBudgets = {}, options: { useDefaultThresholds?: boolean } = {}): Finding[] {
  const findings: Finding[] = [];
  for (const metric of ['lcp', 'cls', 'inp', 'fcp', 'ttfb', 'tbt'] as const) {
    const value = vitals[metric];
    if (value === undefined || (metric === 'inp' && !vitals.interactions)) continue;
    const budget = budgets[metric];
    const extra = metric === 'lcp' && vitals.lcpElement ? ` (LCP element: ${vitals.lcpElement})` : '';
    if (budget !== undefined) {
      if (value > budget) {
        const ratio = budget > 0 ? value / budget : Infinity;
        findings.push(make('budget-exceeded', ratio >= 1.5 ? 'high' : 'medium', url, metric, `${NAMES[metric]} is ${fmt(metric, value)}, over the budget of ${fmt(metric, budget)}${extra}.`, ADVICE[metric]!, { value, budget }));
      }
      continue;
    }
    if (options.useDefaultThresholds === false) continue;
    const [good, poor] = THRESHOLDS[metric];
    if (value > poor) findings.push(make('web-vital-poor', 'high', url, metric, `${NAMES[metric]} is ${fmt(metric, value)} (poor: over ${fmt(metric, poor)})${extra}.`, ADVICE[metric]!, { value, threshold: poor }));
    else if (value > good) findings.push(make('web-vital-needs-improvement', 'medium', url, metric, `${NAMES[metric]} is ${fmt(metric, value)} (good is ${fmt(metric, good)} or less)${extra}.`, ADVICE[metric]!, { value, threshold: good }));
  }
  if (resources) {
    const sizes: Array<[keyof PageBudgets, number, string]> = [
      ['totalBytes', resources.totalBytes, 'Total page weight'],
      ['scriptBytes', resources.byType.script, 'JavaScript'],
      ['stylesheetBytes', resources.byType.stylesheet, 'CSS'],
      ['imageBytes', resources.byType.image, 'Images'],
      ['fontBytes', resources.byType.font, 'Fonts'],
      ['thirdPartyBytes', resources.thirdPartyBytes, 'Third-party resources'],
    ];
    for (const [key, value, label] of sizes) {
      const raw = budgets[key];
      if (raw === undefined) continue;
      const budget = parseSize(raw as string | number);
      if (value > budget) {
        findings.push(make('budget-exceeded', value / budget >= 1.5 ? 'high' : 'medium', url, key, `${label} is ${formatBytes(value)} (transferred), over the budget of ${formatBytes(budget)}.`, ADVICE.bytes!, { value, budget, largest: resources.largest }));
      }
    }
    if (budgets.requests !== undefined && resources.requests > budgets.requests) {
      findings.push(make('budget-exceeded', 'medium', url, 'requests', `${resources.requests} requests, over the budget of ${budgets.requests}.`, 'Bundle small files, remove unused third-party tags, and lazy-load non-critical resources.', { value: resources.requests, budget: budgets.requests }));
    }
  }
  return findings;
}

export interface BundleBudget {
  /** Glob of files relative to the build directory, or "total:js" / "total:css" / "total". */
  path: string;
  maxSize?: string | number;
  maxGzip?: string | number;
  maxBrotli?: string | number;
}

export interface BundleFile {
  path: string;
  size: number;
  gzip: number;
  brotli?: number;
}
