import { existsSync } from 'node:fs';
import { createServer, type Server } from 'node:http';
import type { AddressInfo } from 'node:net';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { scanUrls } from '../src/node.js';

// Needs a real browser. Skipped where Playwright's Chromium is not installed.
let chromium: string | undefined;
try {
  chromium = (await import('playwright')).chromium.executablePath();
} catch {
  chromium = undefined;
}
const hasBrowser = !!chromium && existsSync(chromium);

const PAGE = `<!doctype html><html lang="en"><head><title>Checkout</title></head>
<body><main><h1>Checkout</h1><button id="pay"><svg aria-hidden="true"></svg></button></main></body></html>`;

describe.skipIf(!hasBrowser)('scanUrls (Playwright)', () => {
  let server: Server;
  let base: string;

  beforeAll(async () => {
    server = createServer((req, res) => {
      // A strict policy: no inline scripts, no eval.
      if (req.url === '/strict') res.setHeader('Content-Security-Policy', "default-src 'self'; script-src 'self'");
      res.setHeader('Content-Type', 'text/html');
      res.end(PAGE);
    });
    await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
    base = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
  });

  afterAll(() => new Promise<void>((resolve) => void server.close(() => resolve())));

  it('scans a page whose Content-Security-Policy forbids inline scripts', async () => {
    const { findings, pages } = await scanUrls(['/strict', '/plain'], { baseUrl: base });
    expect(pages.map((p) => [p.error, p.status])).toEqual([
      [undefined, 200],
      [undefined, 200],
    ]);
    expect(findings.filter((f) => f.ruleId === 'button-name').map((f) => f.location?.url)).toEqual([`${base}/strict`, `${base}/plain`]);
  });

  it('reports a page it could not load instead of treating it as clean', async () => {
    const closed = createServer();
    await new Promise<void>((resolve) => closed.listen(0, '127.0.0.1', resolve));
    const dead = `http://127.0.0.1:${(closed.address() as AddressInfo).port}/`;
    await new Promise<void>((resolve) => void closed.close(() => resolve()));

    const { pages } = await scanUrls(['/plain', dead], { baseUrl: base, timeoutMs: 5000 });
    expect(pages[0]).toMatchObject({ findings: 1 });
    expect(pages[0]!.error).toBeUndefined();
    expect(pages[1]!.error).toBeTruthy();
    expect(pages[1]!.findings).toBe(0);
  });
});
