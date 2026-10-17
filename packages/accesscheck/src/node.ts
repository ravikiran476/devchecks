// Node entry: drives a real browser with Playwright (optional peer dependency) and
// injects axe-core into each page, so dynamic, client-rendered pages are tested as users see them.
import { readFileSync } from 'node:fs';
import { createRequire } from 'node:module';
import type { Finding } from '@devchecks/core';
import { DEFAULT_TAGS, mapAxeResults, type AxeResults } from './map.js';

export * from './map.js';
export { suggestFix } from './fixes.js';
export { createBaseline, diffBaseline, formatReport, type Finding, type Report } from '@devchecks/core';

export interface PageTarget {
  url: string;
  /** Wait for this selector before scanning (e.g. "#app [data-ready]"). */
  waitFor?: string;
  /** Click, type or otherwise prepare the page before scanning. */
  setup?: (page: unknown) => Promise<void>;
}

export interface NodeScanOptions {
  /** Prepended to relative page paths ("/about"). */
  baseUrl?: string;
  browser?: 'chromium' | 'firefox' | 'webkit';
  tags?: string[];
  disableRules?: string[];
  /** CSS selectors to leave out of the scan. */
  exclude?: string[];
  includeIncomplete?: boolean;
  viewport?: { width: number; height: number };
  /** Playwright storage state file, for pages behind a login. */
  storageState?: string;
  headers?: Record<string, string>;
  timeoutMs?: number;
  waitUntil?: 'load' | 'domcontentloaded' | 'networkidle';
  onPage?: (url: string, findings: Finding[]) => void;
}

interface PwPage {
  goto(url: string, o: { waitUntil: string; timeout: number }): Promise<{ status(): number } | null>;
  waitForSelector(s: string, o: { timeout: number }): Promise<unknown>;
  addScriptTag(o: { content: string }): Promise<unknown>;
  evaluate<T, A>(fn: (arg: A) => Promise<T> | T, arg: A): Promise<T>;
  url(): string;
  close(): Promise<void>;
}

async function loadPlaywright(): Promise<Record<string, { launch(o?: object): Promise<{ newContext(o?: object): Promise<{ newPage(): Promise<PwPage>; close(): Promise<void> }>; close(): Promise<void> }> }>> {
  try {
    return (await import('playwright')) as never;
  } catch {
    throw new Error('AccessCheck needs Playwright to scan URLs. Install it with: npm i -D playwright && npx playwright install chromium');
  }
}

export function axeSource(): string {
  const require = createRequire(import.meta.url);
  return readFileSync(require.resolve('axe-core/axe.min.js'), 'utf8');
}

export function resolveUrl(target: string, baseUrl?: string): string {
  if (/^[a-z]+:\/\//i.test(target) || target.startsWith('file:')) return target;
  if (!baseUrl) throw new Error(`"${target}" is a relative path: pass --base-url (e.g. http://localhost:3000)`);
  return new URL(target, baseUrl.endsWith('/') ? baseUrl : `${baseUrl}/`).href;
}

/** Scans each page in a fresh tab and returns all findings. */
export async function scanUrls(targets: Array<string | PageTarget>, options: NodeScanOptions = {}): Promise<{ findings: Finding[]; pages: Array<{ url: string; status?: number; findings: number; error?: string }> }> {
  const pw = await loadPlaywright();
  const browserType = pw[options.browser ?? 'chromium'];
  if (!browserType) throw new Error(`Unknown browser "${options.browser}"`);
  const browser = await browserType.launch();
  const context = await browser.newContext({
    viewport: options.viewport ?? { width: 1280, height: 800 },
    storageState: options.storageState,
    extraHTTPHeaders: options.headers,
  });
  const source = axeSource();
  const findings: Finding[] = [];
  const pages: Array<{ url: string; status?: number; findings: number; error?: string }> = [];
  try {
    for (const t of targets) {
      const target = typeof t === 'string' ? { url: t } : t;
      const url = resolveUrl(target.url, options.baseUrl);
      const page = await context.newPage();
      try {
        const res = await page.goto(url, { waitUntil: options.waitUntil ?? 'load', timeout: options.timeoutMs ?? 30000 });
        if (target.waitFor) await page.waitForSelector(target.waitFor, { timeout: options.timeoutMs ?? 30000 });
        if (target.setup) await target.setup(page);
        await page.addScriptTag({ content: source });
        const results = await page.evaluate(
          async (o: { tags: string[]; disable: string[]; exclude: string[] }) => {
            const axe = (window as unknown as { axe: { run(c: unknown, o: unknown): Promise<unknown> } }).axe;
            const ctx = o.exclude.length ? { include: [document], exclude: o.exclude.map((s) => [s]) } : document;
            const r = (await axe.run(ctx, {
              runOnly: { type: 'tag', values: o.tags },
              rules: Object.fromEntries(o.disable.map((id) => [id, { enabled: false }])),
              resultTypes: ['violations', 'incomplete'],
            })) as { violations: unknown[]; incomplete: unknown[] };
            // Return only what we need: full axe results are large.
            const slim = (rules: unknown[]) =>
              (rules as Array<{ id: string; impact: string; help: string; helpUrl: string; tags: string[]; nodes: Array<{ target: unknown; html: string; failureSummary: string; impact: string }> }>).map((x) => ({
                id: x.id,
                impact: x.impact,
                help: x.help,
                helpUrl: x.helpUrl,
                tags: x.tags,
                nodes: x.nodes.map((n) => ({ target: n.target, html: n.html, failureSummary: n.failureSummary, impact: n.impact })),
              }));
            return { violations: slim(r.violations), incomplete: slim(r.incomplete) };
          },
          { tags: options.tags ?? DEFAULT_TAGS, disable: options.disableRules ?? [], exclude: options.exclude ?? [] },
        );
        const pageFindings = mapAxeResults(results as AxeResults, { url: page.url(), includeIncomplete: options.includeIncomplete });
        findings.push(...pageFindings);
        pages.push({ url, status: res?.status(), findings: pageFindings.length });
        options.onPage?.(url, pageFindings);
      } catch (err) {
        pages.push({ url, findings: 0, error: (err as Error).message.split('\n')[0] });
      } finally {
        await page.close();
      }
    }
  } finally {
    await context.close();
    await browser.close();
  }
  return { findings, pages };
}
