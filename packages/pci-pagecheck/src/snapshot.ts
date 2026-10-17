// A serializable description of a payment page. Built in the browser (snapshotDocument)
// or by Playwright in Node, then analyzed by the same pure functions.

export interface ScriptEntry {
  /** Absolute URL for external scripts. */
  src?: string;
  inline?: boolean;
  /** Script text (inline scripts, or external bodies captured over the network). */
  content?: string;
  /** CSP/SRI style "sha256-..." of the script body, when it could be read. */
  hash?: string;
  /** The integrity attribute, if any. */
  integrity?: string;
  crossorigin?: string;
  type?: string;
  hasNonce?: boolean;
  /** "html": in the DOM; "dynamic": seen only in the network/resource timing (added by other scripts). */
  loadedBy: 'html' | 'dynamic';
}

export type CardFieldKind = 'pan' | 'cvv' | 'expiry' | 'cardholder';

export interface CardField {
  kind: CardFieldKind;
  selector: string;
  name?: string;
  autocomplete?: string;
  type?: string;
  formAction?: string;
  formMethod?: string;
}

export interface FrameEntry {
  src: string;
  title?: string;
  sandbox?: string;
}

export interface PageSnapshot {
  url: string;
  capturedAt: string;
  scripts: ScriptEntry[];
  /** Response headers of the page (lower-case names), when available. */
  headers?: Record<string, string>;
  /** CSP delivered via <meta http-equiv>. */
  metaCsp: string[];
  cardFields: CardField[];
  frames: FrameEntry[];
}

export interface RawDom {
  url: string;
  scripts: Array<{ src?: string; text?: string; integrity?: string; crossorigin?: string; type?: string; hasNonce: boolean }>;
  resourceScripts: string[];
  metaCsp: string[];
  cardFields: CardField[];
  frames: FrameEntry[];
}

/**
 * Collects DOM facts. Self-contained on purpose (no imports, no closures) so Playwright
 * can serialize it into the page with page.evaluate(collectDom).
 */
export function collectDom(): RawDom {
  const abs = (u: string) => {
    try {
      return new URL(u, document.baseURI).href;
    } catch {
      return u;
    }
  };
  const esc = (v: string) => (typeof CSS !== 'undefined' && CSS.escape ? CSS.escape(v) : v.replace(/[^\w-]/g, (c) => `\\${c}`));
  const cssPath = (el: Element): string => {
    if (el.id) return `#${esc(el.id)}`;
    const parts: string[] = [];
    let cur: Element | null = el;
    while (cur && cur !== document.documentElement && parts.length < 5) {
      let part = cur.tagName.toLowerCase();
      const name = cur.getAttribute('name');
      if (name) part += `[name="${name}"]`;
      else if (cur.parentElement) {
        const same = Array.from(cur.parentElement.children).filter((c) => c.tagName === cur!.tagName);
        if (same.length > 1) part += `:nth-of-type(${same.indexOf(cur) + 1})`;
      }
      parts.unshift(part);
      if (cur.id) {
        parts[0] = `#${esc(cur.id)}`;
        break;
      }
      cur = cur.parentElement;
    }
    return parts.join(' > ');
  };
  const kindOf = (el: HTMLInputElement): 'pan' | 'cvv' | 'expiry' | 'cardholder' | undefined => {
    const ac = (el.getAttribute('autocomplete') ?? '').toLowerCase();
    if (/cc-number/.test(ac)) return 'pan';
    if (/cc-csc/.test(ac)) return 'cvv';
    if (/cc-exp/.test(ac)) return 'expiry';
    if (/cc-name/.test(ac)) return 'cardholder';
    const hint = `${el.name} ${el.id} ${el.getAttribute('placeholder') ?? ''} ${el.getAttribute('aria-label') ?? ''} ${el.getAttribute('data-stripe') ?? ''}`.toLowerCase();
    if (/(card.?number|cc.?num|credit.?card|\bpan\b|cardno|ccnumber|card_no)/.test(hint)) return 'pan';
    if (/(cvv|cvc|csc|security.?code|card.?code|cid\b)/.test(hint)) return 'cvv';
    if (/(exp(iry|iration)?.?(date|month|year)|\bmm.?yy\b|cc.?exp)/.test(hint)) return 'expiry';
    if (/(card.?holder|name.?on.?card|cc.?name)/.test(hint)) return 'cardholder';
    return undefined;
  };

  const scripts = Array.from(document.scripts).map((s) => ({
    src: s.src ? abs(s.getAttribute('src')!) : undefined,
    text: s.src ? undefined : s.textContent ?? '',
    integrity: s.getAttribute('integrity') || undefined,
    crossorigin: s.getAttribute('crossorigin') ?? undefined,
    type: s.type || undefined,
    hasNonce: !!(s.nonce || s.getAttribute('nonce')),
  }));
  const resourceScripts =
    typeof performance !== 'undefined' && performance.getEntriesByType
      ? (performance.getEntriesByType('resource') as PerformanceResourceTiming[]).filter((e) => e.initiatorType === 'script').map((e) => e.name)
      : [];
  const metaCsp = Array.from(document.querySelectorAll('meta[http-equiv]'))
    .filter((m) => m.getAttribute('http-equiv')!.toLowerCase() === 'content-security-policy')
    .map((m) => m.getAttribute('content') ?? '');
  const cardFields = Array.from(document.querySelectorAll('input, select'))
    .map((el) => ({ el: el as HTMLInputElement, kind: kindOf(el as HTMLInputElement) }))
    .filter((x) => x.kind && (x.el as HTMLInputElement).type !== 'hidden')
    .map(({ el, kind }) => ({
      kind: kind!,
      selector: cssPath(el),
      name: el.name || undefined,
      autocomplete: el.getAttribute('autocomplete') ?? undefined,
      type: el.type,
      formAction: el.form ? abs(el.form.getAttribute('action') ?? document.URL) : undefined,
      formMethod: el.form ? (el.form.getAttribute('method') ?? 'get').toLowerCase() : undefined,
    }));
  const frames = Array.from(document.querySelectorAll('iframe')).map((f) => ({
    src: f.src ? abs(f.getAttribute('src')!) : 'about:blank',
    title: f.title || undefined,
    sandbox: f.getAttribute('sandbox') ?? undefined,
  }));
  return { url: document.URL, scripts, resourceScripts, metaCsp, cardFields, frames };
}
