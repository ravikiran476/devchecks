import { readdirSync, readFileSync, statSync } from 'node:fs';
import { join, relative, resolve } from 'node:path';
import { brotliCompressSync, constants, gzipSync } from 'node:zlib';
import { fingerprint, matchGlob, normalizePath, type Finding } from '@devchecks/core';
import { checkPage, formatBytes, parseSize, type BundleBudget, type BundleFile, type PageBudgets } from './budgets.js';
import { collectResources, installVitalsObserver, type ResourceSummary, type VitalsSnapshot } from './vitals.js';

export * from './index.js';

const ASSETS = /\.(m?js|cjs|css|html|svg|json|wasm)$/;

/** Sizes of every text asset in a build directory: raw, gzip and brotli. */
export function measureBundles(dir: string, options: { brotli?: boolean } = {}): BundleFile[] {
  const root = resolve(dir);
  const out: BundleFile[] = [];
  const walk = (d: string) => {
    for (const e of readdirSync(d, { withFileTypes: true })) {
      const full = join(d, e.name);
      if (e.isDirectory()) walk(full);
      else if (ASSETS.test(e.name) && !e.name.endsWith('.map')) {
        const buf = readFileSync(full);
        out.push({
          path: normalizePath(relative(root, full)),
          size: buf.length,
          gzip: gzipSync(buf, { level: 9 }).length,
          brotli: options.brotli === false ? undefined : brotliCompressSync(buf, { params: { [constants.BROTLI_PARAM_QUALITY]: 11 } }).length,
        });
      }
    }
  };
  walk(root);
  return out.sort((a, b) => b.gzip - a.gzip);
}

/**
 * Removes bundler content hashes ("index-BXk3Yq9a.js", "main.3f9a1c2b.js") so a finding keeps
 * its fingerprint across rebuilds. A segment counts as a hash if it has a digit, or is
 * exactly 8 mixed-case characters (Vite/Rollup default).
 */
export function stripContentHash(file: string): string {
  return file.replace(/[.-]([A-Za-z0-9_]{8,})(?=\.[a-z]+$)/, (m, seg: string) =>
    /\d/.test(seg) || (seg.length === 8 && /[a-z]/.test(seg) && /[A-Z]/.test(seg)) ? '' : m,
  );
}

/** Checks build output against size budgets. */
export function checkBundles(dir: string, budgets: BundleBudget[]): { files: BundleFile[]; findings: Finding[] } {
  const files = measureBundles(dir, { brotli: budgets.some((b) => b.maxBrotli !== undefined) });
  const findings: Finding[] = [];
  for (const b of budgets) {
    let targets: Array<{ name: string; file?: string; size: number; gzip: number; brotli?: number }>;
    const total = /^total(:(js|css))?$/.exec(b.path);
    if (total) {
      const pick = files.filter((f) => !total[2] || (total[2] === 'js' ? /\.(m?js|cjs)$/.test(f.path) : f.path.endsWith('.css')));
      targets = [{ name: b.path, size: pick.reduce((s, f) => s + f.size, 0), gzip: pick.reduce((s, f) => s + f.gzip, 0), brotli: pick.every((f) => f.brotli !== undefined) ? pick.reduce((s, f) => s + (f.brotli ?? 0), 0) : undefined }];
    } else {
      targets = files.filter((f) => matchGlob(b.path, f.path)).map((f) => ({ name: f.path, file: f.path, ...f }));
    }
    for (const t of targets) {
      for (const [kind, limit, actual] of [
        ['size', b.maxSize, t.size],
        ['gzip', b.maxGzip, t.gzip],
        ['brotli', b.maxBrotli, t.brotli],
      ] as const) {
        if (limit === undefined || actual === undefined) continue;
        const max = parseSize(limit);
        if (actual <= max) continue;
        findings.push({
          fingerprint: fingerprint('perfcheck', 'bundle-size-exceeded', b.path, stripContentHash(t.name), kind),
          ruleId: 'bundle-size-exceeded',
          severity: actual / max >= 1.25 ? 'high' : 'medium',
          message: `${t.name} is ${formatBytes(actual)} ${kind === 'size' ? 'uncompressed' : kind}, over the ${formatBytes(max)} budget (+${formatBytes(actual - max)}).`,
          location: { file: t.file ? normalizePath(join(dir, t.file)) : dir },
          remediation: 'Find what grew with a bundle analyzer (e.g. rollup-plugin-visualizer, source-map-explorer), lazy-load routes and heavy components, and replace large dependencies.',
          meta: { budget: b.path, kind, actual, max },
        });
      }
    }
  }
  return { files, findings };
}

export interface LabOptions {
  runs?: number;
  /** CPU slowdown factor (Chromium only), e.g. 4 for a mid-range phone. Default 1. */
  cpuThrottle?: number;
  /** Network profile (Chromium only). */
  network?: 'none' | 'fast-4g' | 'slow-4g' | '3g';
  viewport?: { width: number; height: number };
  settleMs?: number;
  storageState?: string;
}

const NETWORKS = {
  'fast-4g': { latency: 40, downloadThroughput: (9 * 1024 * 1024) / 8, uploadThroughput: (1.5 * 1024 * 1024) / 8 },
  'slow-4g': { latency: 150, downloadThroughput: (1.6 * 1024 * 1024) / 8, uploadThroughput: (750 * 1024) / 8 },
  '3g': { latency: 300, downloadThroughput: (700 * 1024) / 8, uploadThroughput: (700 * 1024) / 8 },
} as const;

const median = (xs: number[]) => {
  const s = [...xs].sort((a, b) => a - b);
  const m = Math.floor(s.length / 2);
  return s.length % 2 ? s[m]! : (s[m - 1]! + s[m]!) / 2;
};

type PwPage = {
  addInitScript(script: { content: string }): Promise<void>;
  goto(url: string, o: object): Promise<unknown>;
  waitForTimeout(ms: number): Promise<void>;
  evaluate<T>(fn: string | (() => T)): Promise<T>;
  close(): Promise<void>;
};

/** Loads a page several times in Playwright and returns median lab metrics. */
export async function measurePage(url: string, options: LabOptions = {}): Promise<{ url: string; vitals: VitalsSnapshot; resources: ResourceSummary; runs: VitalsSnapshot[] }> {
  let pw: { chromium: { launch(): Promise<{ newContext(o: object): Promise<{ newPage(): Promise<PwPage>; newCDPSession(p: PwPage): Promise<{ send(m: string, p?: object): Promise<unknown> }>; close(): Promise<void> }>; close(): Promise<void> }> } };
  try {
    pw = (await import('playwright')) as never;
  } catch {
    throw new Error('PerfCheck needs Playwright for page measurements. Install it with: npm i -D playwright && npx playwright install chromium');
  }
  const browser = await pw.chromium.launch();
  const runs: VitalsSnapshot[] = [];
  let resources: ResourceSummary | undefined;
  try {
    for (let i = 0; i < (options.runs ?? 3); i++) {
      // Fresh context per run: cold cache, like a first visit.
      const context = await browser.newContext({ viewport: options.viewport ?? { width: 1350, height: 940 }, storageState: options.storageState });
      const page = await context.newPage();
      const cdp = await context.newCDPSession(page);
      if (options.cpuThrottle && options.cpuThrottle > 1) await cdp.send('Emulation.setCPUThrottlingRate', { rate: options.cpuThrottle });
      if (options.network && options.network !== 'none') await cdp.send('Network.emulateNetworkConditions', { offline: false, ...NETWORKS[options.network] });
      await page.addInitScript({ content: `(${installVitalsObserver.toString()})();` });
      await page.goto(url, { waitUntil: 'load', timeout: 60000 });
      await page.waitForTimeout(options.settleMs ?? 2500);
      runs.push(await page.evaluate<VitalsSnapshot>('window.__perfcheck.get()'));
      if (i === 0) resources = await page.evaluate<ResourceSummary>(`(${collectResources.toString()})()`);
      await context.close();
    }
  } finally {
    await browser.close();
  }
  const pick = (k: keyof VitalsSnapshot) => {
    const xs = runs.map((r) => r[k]).filter((v): v is number => typeof v === 'number');
    return xs.length ? median(xs) : undefined;
  };
  const vitals: VitalsSnapshot = { lcp: pick('lcp'), cls: pick('cls'), fcp: pick('fcp'), ttfb: pick('ttfb'), tbt: pick('tbt'), inp: undefined, interactions: 0, lcpElement: runs[0]?.lcpElement };
  return { url, vitals, resources: resources!, runs };
}

export async function checkUrls(urls: string[], budgets: PageBudgets = {}, options: LabOptions = {}): Promise<{ results: Awaited<ReturnType<typeof measurePage>>[]; findings: Finding[] }> {
  const results = [];
  const findings: Finding[] = [];
  for (const url of urls) {
    const r = await measurePage(url, options);
    results.push(r);
    findings.push(...checkPage(url, r.vitals, r.resources, budgets));
  }
  return { results, findings };
}
