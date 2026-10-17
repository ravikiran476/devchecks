// Node entry: load the payment page in Playwright, capture every script the browser
// actually executes (including ones injected by tag managers) and the real response headers.
import { readdirSync, readFileSync, statSync } from 'node:fs';
import { join, relative } from 'node:path';
import { normalizePath, type Finding } from '@devchecks/core';
import { analyzePage, buildSnapshot, type AnalysisResult, type AnalyzeOptions } from './analyze.js';
import { scanSourceForCardData } from './carddata.js';
import { collectDom, type PageSnapshot, type RawDom } from './snapshot.js';

export * from './index.js';

export interface CaptureOptions {
  browser?: 'chromium' | 'firefox' | 'webkit';
  storageState?: string;
  /** Wait for this selector (e.g. the payment form) before capturing. */
  waitFor?: string;
  /** Extra time to let tag managers inject scripts. Default 2000 ms. */
  settleMs?: number;
  timeoutMs?: number;
}

interface PwResponse {
  url(): string;
  request(): { resourceType(): string };
  body(): Promise<Buffer>;
  headers(): Record<string, string>;
}

export async function capturePage(url: string, options: CaptureOptions = {}): Promise<PageSnapshot> {
  let pw: Record<string, { launch(): Promise<{ newContext(o: object): Promise<{ newPage(): Promise<{ on(e: string, cb: (r: PwResponse) => void): void; goto(u: string, o: object): Promise<PwResponse | null>; waitForSelector(s: string, o: object): Promise<unknown>; waitForTimeout(ms: number): Promise<void>; evaluate<T>(fn: () => T): Promise<T> }> }>; close(): Promise<void> }> }>;
  try {
    pw = (await import('playwright')) as never;
  } catch {
    throw new Error('PCI PageCheck needs Playwright to capture pages. Install it with: npm i -D playwright && npx playwright install chromium');
  }
  const browser = await pw[options.browser ?? 'chromium']!.launch();
  try {
    const context = await browser.newContext({ storageState: options.storageState });
    const page = await context.newPage();
    const bodies = new Map<string, Uint8Array | string>();
    const pending: Promise<void>[] = [];
    page.on('response', (res) => {
      if (res.request().resourceType() !== 'script') return;
      pending.push(
        res.body().then(
          (b) => void bodies.set(res.url(), b.toString('utf8')),
          () => undefined,
        ),
      );
    });
    const main = await page.goto(url, { waitUntil: 'load', timeout: options.timeoutMs ?? 30000 });
    if (options.waitFor) await page.waitForSelector(options.waitFor, { timeout: options.timeoutMs ?? 30000 });
    await page.waitForTimeout(options.settleMs ?? 2000);
    await Promise.all(pending);
    const dom = (await page.evaluate(collectDom)) as RawDom;
    const headers = main ? Object.fromEntries(Object.entries(main.headers()).map(([k, v]) => [k.toLowerCase(), v])) : undefined;
    return await buildSnapshot(dom, { headers, bodies });
  } finally {
    await browser.close();
  }
}

export async function checkUrl(url: string, options: AnalyzeOptions & CaptureOptions = {}): Promise<AnalysisResult> {
  return analyzePage(await capturePage(url, options), options);
}

const CODE = /\.(m|c)?[jt]sx?$|\.(vue|svelte|html)$/;

/** Scans checkout/payment source code for card data exposure. */
export function scanSourceDir(dir: string, cwd = process.cwd()): Finding[] {
  const findings: Finding[] = [];
  const walk = (d: string) => {
    for (const e of readdirSync(d, { withFileTypes: true })) {
      if (e.name.startsWith('.') || ['node_modules', 'dist', 'build', 'coverage'].includes(e.name)) continue;
      const full = join(d, e.name);
      if (e.isDirectory()) walk(full);
      else if (CODE.test(e.name) && statSync(full).size < 2_000_000) {
        findings.push(...scanSourceForCardData(readFileSync(full, 'utf8'), normalizePath(relative(cwd, full))));
      }
    }
  };
  walk(dir);
  return findings;
}
