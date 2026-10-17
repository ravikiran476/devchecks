// @vitest-environment jsdom
import { describe, expect, it } from 'vitest';
import {
  analyzeCsp,
  analyzePage,
  baselineFromInventory,
  buildEvidence,
  buildSnapshot,
  collectDom,
  evidenceToMarkdown,
  luhn,
  scanSourceForCardData,
  type PageSnapshot,
} from '../src/index.js';

const STRONG_CSP =
  "default-src 'self'; script-src 'nonce-abc' 'strict-dynamic'; object-src 'none'; base-uri 'none'; form-action 'self' https://api.stripe.com; frame-ancestors 'self'; connect-src 'self' https://api.stripe.com; report-to csp";

function page(overrides: Partial<PageSnapshot> = {}): PageSnapshot {
  return {
    url: 'https://shop.example.com/checkout',
    capturedAt: '2026-10-17T00:00:00Z',
    scripts: [
      { src: 'https://shop.example.com/app.js', hash: 'sha256-app', loadedBy: 'html' },
      { src: 'https://js.stripe.com/v3/', hash: 'sha256-stripe', loadedBy: 'html' },
      { src: 'https://www.googletagmanager.com/gtm.js?id=GTM-1', hash: 'sha256-gtm', loadedBy: 'html' },
    ],
    headers: { 'content-security-policy': STRONG_CSP, 'strict-transport-security': 'max-age=31536000' },
    metaCsp: [],
    cardFields: [],
    frames: [{ src: 'https://js.stripe.com/v3/elements-inner-card.html', title: 'Secure card input' }],
    ...overrides,
  };
}

describe('script inventory', () => {
  it('categorizes scripts and flags third parties without SRI', () => {
    const r = analyzePage(page());
    expect(r.inventory.map((i) => [i.category, i.thirdParty, i.status])).toEqual([
      ['first-party', false, 'no-baseline'],
      ['payment-provider', true, 'no-baseline'],
      ['tag-manager', true, 'no-baseline'],
    ]);
    expect(r.findings.map((f) => f.ruleId)).toEqual(['third-party-no-sri']);
  });

  it('compares with the approved baseline: unapproved, changed, unjustified and absent', () => {
    const initial = analyzePage(page());
    const baseline = baselineFromInventory(initial);
    baseline.scripts.forEach((s) => (s.justification = 'needed'));
    baseline.scripts[0]!.justification = '';
    baseline.scripts.push({ id: 'https://old.example.com/legacy.js', justification: 'legacy' });

    const tampered = page();
    tampered.scripts[1]!.hash = 'sha256-EVIL';
    tampered.scripts.push({ src: 'https://evil.example.net/skim.js', loadedBy: 'dynamic' });
    const r = analyzePage(tampered, { baseline });
    const byRule = Object.fromEntries(r.findings.map((f) => [f.ruleId, f]));
    expect(byRule['script-integrity-changed']?.severity).toBe('critical');
    expect(byRule['unauthorized-script']?.message).toMatch(/skim\.js.*loaded dynamically/);
    expect(byRule['script-missing-justification']).toBeDefined();
    expect(byRule['approved-script-absent']?.severity).toBe('info');
    expect(byRule['script-integrity-changed']?.tags).toEqual(['PCI DSS 6.4.3', 'PCI DSS 11.6.1']);
  });

  it('ignores query strings in script identity so cache busters do not break the baseline', () => {
    const baseline = baselineFromInventory(analyzePage(page()));
    const next = page();
    next.scripts[0]!.src = 'https://shop.example.com/app.js?v=2';
    expect(analyzePage(next, { baseline }).inventory[0]!.status).toBe('approved');
  });
});

describe('CSP review', () => {
  it('accepts a strong nonce-based policy', () => {
    expect(analyzeCsp(STRONG_CSP)).toEqual([]);
  });

  it('flags missing and weak policies', () => {
    expect(analyzeCsp(undefined).map((i) => i.ruleId)).toEqual(['csp-missing']);
    const weak = analyzeCsp("script-src 'self' 'unsafe-inline' 'unsafe-eval' https: cdn.jsdelivr.net").map((i) => i.ruleId);
    expect(weak).toEqual(
      expect.arrayContaining(['csp-unsafe-inline', 'csp-unsafe-eval', 'csp-wildcard-source', 'csp-bypassable-host', 'csp-object-src', 'csp-base-uri', 'csp-form-action', 'csp-frame-ancestors', 'csp-no-reporting']),
    );
  });

  it('does not flag unsafe-inline when nonces make browsers ignore it', () => {
    expect(analyzeCsp("script-src 'nonce-x' 'unsafe-inline'; object-src 'none'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'; connect-src 'self'; report-uri /r").map((i) => i.ruleId)).toEqual([]);
  });

  it('treats report-only as not enforcing', () => {
    expect(analyzeCsp(undefined, { reportOnly: STRONG_CSP }).map((i) => i.ruleId)).toEqual(['csp-report-only']);
  });
});

describe('card data exposure', () => {
  it('flags card fields in the page DOM and insecure or unknown form targets', () => {
    const r = analyzePage(
      page({
        cardFields: [
          { kind: 'pan', selector: '#cc', formAction: 'http://pay.example.com/charge', formMethod: 'post' },
          { kind: 'cvv', selector: '#cvv', formAction: 'https://collect.evil.example/x', formMethod: 'get' },
        ],
      }),
    );
    expect(r.findings.map((f) => f.ruleId).filter((id) => id.startsWith('card'))).toEqual([
      'card-field-in-page',
      'card-form-insecure-action',
      'card-field-in-page',
      'card-form-third-party-action',
      'card-form-get',
    ]);
  });

  it('finds card data in logs, storage and analytics in first-party code', () => {
    const code = [
      'console.log("pay", form.cardNumber);',
      'localStorage.setItem("cvv", cvv);',
      'dataLayer.push({ event: "pay", card_number: n });',
      'const total = price * qty; console.log(total);',
    ].join('\n');
    expect(scanSourceForCardData(code, 'checkout.js').map((f) => [f.ruleId, f.location?.line])).toEqual([
      ['card-data-logging', 1],
      ['card-data-storage', 2],
      ['card-data-analytics', 3],
    ]);
  });

  it('flags real-looking PANs but not documented test cards', () => {
    expect(luhn('4111111111111111')).toBe(true);
    const findings = scanSourceForCardData('const a = "4111111111111111"; const b = "4532015112830366";', 'x.js');
    expect(findings).toHaveLength(1);
    expect(findings[0]!.message).toContain('453201******0366');
    expect(findings[0]!.snippet).not.toContain('4532015112830366');
  });
});

describe('DOM snapshot and evidence', () => {
  it('collects scripts, card fields and frames from a real DOM', async () => {
    document.body.innerHTML = `
      <script src="https://cdn.example.net/lib.js" integrity="sha384-x" crossorigin="anonymous"></script>
      <script>window.checkout = { amount: 10 };</script>
      <script type="application/json">{"not":"code"}</script>
      <form action="/pay" method="post">
        <input id="card" autocomplete="cc-number">
        <input name="security_code">
        <input name="email" type="email">
      </form>
      <iframe src="https://js.stripe.com/v3/frame.html" title="card"></iframe>`;
    const snap = await buildSnapshot(collectDom());
    expect(snap.scripts.map((s) => [s.src ?? 'inline', s.integrity])).toEqual([
      ['https://cdn.example.net/lib.js', 'sha384-x'],
      ['inline', undefined],
    ]);
    expect(snap.scripts[1]!.hash).toMatch(/^sha256-/);
    expect(snap.cardFields.map((f) => [f.kind, f.selector])).toEqual([
      ['pan', '#card'],
      ['cvv', 'body > form > input[name="security_code"]'],
    ]);
    expect(snap.frames).toHaveLength(1);
  });

  it('maps findings to PCI DSS requirements with a disclaimer', () => {
    const r = analyzePage(page({ headers: {} }));
    const evidence = buildEvidence(r);
    expect(evidence.disclaimer).toMatch(/not a PCI DSS assessment/);
    expect(evidence.controls.find((c) => c.id === '6.4.3')?.status).toBe('findings');
    const md = evidenceToMarkdown(evidence);
    expect(md).toContain('### 11.6.1');
    expect(md).toContain('| no-baseline | https://www.googletagmanager.com/gtm.js?id=GTM-1 | tag-manager |');
  });
});
