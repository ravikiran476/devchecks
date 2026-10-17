import { fingerprint, sha256Integrity, type Finding, type Severity } from '@devchecks/core';
import { scanSourceForCardData } from './carddata.js';
import { CONTROLS, DISCLAIMER } from './controls.js';
import { analyzeCsp } from './csp.js';
import type { PageSnapshot, RawDom, ScriptEntry } from './snapshot.js';

export interface ApprovedScript {
  /** Script identity: origin + path for external scripts, "inline:<hash>" for inline scripts. */
  id: string;
  /** Expected "sha256-..." of the body. Omit for scripts whose content legitimately changes (then rely on SRI/vendor controls). */
  hash?: string;
  /** Why the script is needed on the payment page (required by PCI DSS 6.4.3). */
  justification?: string;
  approvedBy?: string;
  approvedAt?: string;
}

export interface ScriptBaseline {
  version: 1;
  page?: string;
  scripts: ApprovedScript[];
}

export interface AnalyzeOptions {
  baseline?: ScriptBaseline;
  /** Origins treated as first-party in addition to the page origin. */
  firstPartyOrigins?: string[];
  /** Payment provider origins allowed to receive card data and host card iframes. */
  paymentOrigins?: string[];
}

/** Origins of common payment providers that host card fields in their own iframes. */
export const KNOWN_PAYMENT_ORIGINS = [
  'https://js.stripe.com', 'https://checkout.stripe.com', 'https://m.stripe.network',
  'https://www.paypal.com', 'https://www.paypalobjects.com', 'https://js.braintreegateway.com', 'https://assets.braintreegateway.com',
  'https://checkoutshopper-live.adyen.com', 'https://checkoutshopper-test.adyen.com',
  'https://js.squareup.com', 'https://web.squarecdn.com', 'https://checkout.razorpay.com', 'https://api.razorpay.com',
  'https://flex.cybersource.com', 'https://secure.authorize.net', 'https://js.authorize.net', 'https://pay.google.com', 'https://applepay.cdn-apple.com',
  'https://cdn.checkout.com', 'https://js.chargebee.com', 'https://js.recurly.com',
];

const CATEGORIES: Array<[RegExp, string]> = [
  [/stripe|paypal|braintree|adyen|square|razorpay|cybersource|authorize\.net|checkout\.com|recurly|chargebee|pay\.google|apple/, 'payment-provider'],
  [/googletagmanager|tagmanager|tealium|segment\.(com|io)|ensighten/, 'tag-manager'],
  [/google-analytics|analytics|mixpanel|amplitude|heap|plausible|matomo|posthog/, 'analytics'],
  [/hotjar|fullstory|logrocket|clarity\.ms|mouseflow|smartlook|contentsquare/, 'session-replay'],
  [/doubleclick|facebook|fbcdn|connect\.facebook|ads|adservice|criteo|taboola|outbrain|tiktok|snap/, 'advertising'],
  [/intercom|zendesk|drift|livechat|crisp|tawk/, 'chat-support'],
  [/jsdelivr|cdnjs|unpkg|cloudflare|jquery|bootstrapcdn|googleapis|gstatic/, 'cdn'],
  [/sentry|bugsnag|datadog|newrelic|rollbar/, 'monitoring'],
  [/recaptcha|hcaptcha|captcha|forter|riskified|sift|signifyd|kount/, 'fraud-bot-protection'],
];

export interface InventoryItem {
  id: string;
  src?: string;
  inline: boolean;
  thirdParty: boolean;
  origin?: string;
  category: string;
  hash?: string;
  integrity?: string;
  loadedBy: ScriptEntry['loadedBy'];
  status: 'approved' | 'unapproved' | 'changed' | 'no-baseline';
  justification?: string;
}

export interface AnalysisResult {
  snapshot: PageSnapshot;
  inventory: InventoryItem[];
  findings: Finding[];
}

export function scriptId(s: ScriptEntry): string {
  if (s.src) {
    try {
      const u = new URL(s.src);
      return `${u.origin}${u.pathname}`;
    } catch {
      return s.src;
    }
  }
  return `inline:${s.hash ?? 'unhashed'}`;
}

function originOf(url: string): string | undefined {
  try {
    return new URL(url).origin;
  } catch {
    return undefined;
  }
}

export function categorize(src: string | undefined, firstParty: boolean): string {
  if (!src) return 'inline';
  if (firstParty) return 'first-party';
  const host = (() => {
    try {
      return new URL(src).hostname;
    } catch {
      return src;
    }
  })();
  return CATEGORIES.find(([re]) => re.test(host))?.[1] ?? 'third-party';
}

/** Builds a snapshot from raw DOM data, hashing inline scripts and any captured script bodies. */
export async function buildSnapshot(
  dom: RawDom,
  extra: { headers?: Record<string, string>; bodies?: Map<string, string | Uint8Array> } = {},
): Promise<PageSnapshot> {
  const scripts: ScriptEntry[] = [];
  const seen = new Set<string>();
  for (const s of dom.scripts) {
    if (s.type && !/^(module|text\/javascript|application\/javascript|text\/ecmascript)$/i.test(s.type)) continue; // JSON, templates
    if (s.src) {
      seen.add(s.src);
      const body = extra.bodies?.get(s.src);
      scripts.push({ src: s.src, integrity: s.integrity, crossorigin: s.crossorigin, type: s.type, hasNonce: s.hasNonce, loadedBy: 'html', hash: body !== undefined ? await sha256Integrity(body) : undefined, content: typeof body === 'string' ? body : undefined });
    } else if (s.text?.trim()) {
      scripts.push({ inline: true, content: s.text, hash: await sha256Integrity(s.text), hasNonce: s.hasNonce, type: s.type, loadedBy: 'html' });
    }
  }
  const dynamic = new Set([...dom.resourceScripts, ...(extra.bodies?.keys() ?? [])]);
  for (const src of dynamic) {
    if (seen.has(src)) continue;
    seen.add(src);
    const body = extra.bodies?.get(src);
    scripts.push({ src, loadedBy: 'dynamic', hash: body !== undefined ? await sha256Integrity(body) : undefined, content: typeof body === 'string' ? body : undefined });
  }
  return {
    url: dom.url,
    capturedAt: new Date().toISOString(),
    scripts,
    headers: extra.headers,
    metaCsp: dom.metaCsp,
    cardFields: dom.cardFields,
    frames: dom.frames,
  };
}

/** Local development URLs are exempt from transport checks; staging and production are not. */
function isLocal(url: string): boolean {
  return /^https?:\/\/(localhost|127\.0\.0\.1|\[::1\])(:\d+)?\//.test(url);
}

function finding(ruleId: string, severity: Severity, message: string, remediation: string, controls: string[], where: { url?: string; selector?: string; file?: string }, extra: Record<string, unknown> = {}): Finding {
  const path = (() => {
    try {
      return where.url ? new URL(where.url).pathname : '';
    } catch {
      return where.url ?? '';
    }
  })();
  return {
    fingerprint: fingerprint('pci-pagecheck', ruleId, path, where.selector ?? where.file ?? '', String(extra.scriptId ?? '')),
    ruleId,
    severity,
    message,
    location: where,
    remediation,
    tags: controls.map((c) => `PCI DSS ${c}`),
    meta: { controls, ...extra },
  };
}

/** Analyzes a payment page snapshot: script inventory, CSP and headers, and card data exposure. */
export function analyzePage(snapshot: PageSnapshot, options: AnalyzeOptions = {}): AnalysisResult {
  const pageOrigin = originOf(snapshot.url);
  const firstParty = new Set([pageOrigin, ...(options.firstPartyOrigins ?? [])].filter(Boolean) as string[]);
  const paymentOrigins = new Set([...KNOWN_PAYMENT_ORIGINS, ...(options.paymentOrigins ?? [])]);
  const approved = new Map((options.baseline?.scripts ?? []).map((s) => [s.id, s]));
  const findings: Finding[] = [];
  const at = { url: snapshot.url };

  // --- Script inventory (6.4.3, 11.6.1)
  const inventory: InventoryItem[] = snapshot.scripts.map((s) => {
    const id = scriptId(s);
    const origin = s.src ? originOf(s.src) : pageOrigin;
    const isThird = !!s.src && !!origin && !firstParty.has(origin);
    const entry = approved.get(id);
    let status: InventoryItem['status'] = options.baseline ? 'unapproved' : 'no-baseline';
    if (entry) status = entry.hash && s.hash && entry.hash !== s.hash ? 'changed' : 'approved';
    return { id, src: s.src, inline: !!s.inline, thirdParty: isThird, origin, category: categorize(s.src, !isThird), hash: s.hash, integrity: s.integrity, loadedBy: s.loadedBy, status, justification: entry?.justification };
  });

  for (const item of inventory) {
    const label = item.src ?? `inline script ${item.hash?.slice(0, 19) ?? ''}…`;
    if (item.status === 'unapproved') {
      findings.push(finding('unauthorized-script', item.thirdParty ? 'high' : 'medium', `Script not in the approved inventory: ${label} (${item.category}, ${item.loadedBy === 'dynamic' ? 'loaded dynamically' : 'in HTML'}).`, 'Review it. If it is needed, add it to the approved baseline with a business justification; otherwise remove it from the payment page.', ['6.4.3', '11.6.1'], at, { scriptId: item.id }));
    } else if (item.status === 'changed') {
      findings.push(finding('script-integrity-changed', 'critical', `Approved script content changed: ${label}. Expected ${approved.get(item.id)!.hash}, got ${item.hash}.`, 'Treat as possible tampering until explained. Confirm the change with the owner, then re-approve the new hash. Investigate immediately if nobody expected it.', ['6.4.3', '11.6.1'], at, { scriptId: item.id }));
    } else if (item.status === 'approved' && !item.justification?.trim()) {
      findings.push(finding('script-missing-justification', 'low', `Approved script has no written justification: ${label}.`, 'Add a business justification to the baseline entry (PCI DSS 6.4.3 requires one for every script).', ['6.4.3'], at, { scriptId: item.id }));
    }
    if (item.thirdParty && item.src && item.loadedBy === 'html' && !item.integrity && item.category !== 'payment-provider') {
      findings.push(finding('third-party-no-sri', 'medium', `Third-party script without Subresource Integrity: ${item.src}.`, `Add integrity="${item.hash ?? 'sha384-…'}" crossorigin="anonymous", or self-host a reviewed copy. If the vendor changes the file without notice, use the baseline hash check instead.`, ['6.4.3'], at, { scriptId: item.id }));
    }
    if (item.src && item.src.startsWith('http:') && !isLocal(item.src)) {
      findings.push(finding('script-over-http', 'critical', `Script loaded over plain HTTP: ${item.src}.`, 'Serve every script over HTTPS.', ['4.2.1', '6.4.3'], at, { scriptId: item.id }));
    }
  }
  if (options.baseline) {
    const present = new Set(inventory.map((i) => i.id));
    for (const s of options.baseline.scripts) {
      if (!present.has(s.id)) {
        findings.push(finding('approved-script-absent', 'info', `Approved script was not seen on the page: ${s.id}.`, 'Remove it from the baseline if it is no longer used, so the inventory stays accurate.', ['6.4.3'], at, { scriptId: s.id }));
      }
    }
  }

  // --- CSP and security headers (6.4.3, 11.6.1, 4.2.1)
  const h = snapshot.headers ?? {};
  const policy = [h['content-security-policy'], ...snapshot.metaCsp].filter(Boolean).join('; ') || undefined;
  for (const issue of analyzeCsp(policy, { reportOnly: h['content-security-policy-report-only'], xFrameOptions: h['x-frame-options'] })) {
    findings.push(finding(issue.ruleId, issue.severity, issue.message, issue.remediation, issue.controls, at));
  }
  if (snapshot.url.startsWith('http:') && !isLocal(snapshot.url)) {
    findings.push(finding('page-over-http', 'critical', 'Payment page is served over plain HTTP.', 'Serve the page only over HTTPS and redirect HTTP to HTTPS.', ['4.2.1'], at));
  }
  if (snapshot.headers && snapshot.url.startsWith('https:') && !h['strict-transport-security']) {
    findings.push(finding('missing-hsts', 'medium', 'No Strict-Transport-Security header, so the first request can be downgraded.', 'Add Strict-Transport-Security: max-age=31536000; includeSubDomains.', ['4.2.1'], at));
  }

  // --- Card data exposure (3.3.1, 3.5.1, 4.2.1, 6.4.3)
  for (const f of snapshot.cardFields) {
    const where = { url: snapshot.url, selector: f.selector };
    if (f.kind === 'pan' || f.kind === 'cvv') {
      findings.push(finding('card-field-in-page', 'medium', `${f.kind === 'pan' ? 'Card number' : 'Card security code'} field is part of the merchant page DOM, so every script on the page can read it.`, "Use your payment provider's hosted fields / iframe (card data never touches your page) or a full redirect. This also reduces PCI scope (e.g. SAQ A instead of SAQ A-EP).", ['6.4.3', '3.3.1'], where));
    }
    if (f.formAction) {
      const target = originOf(f.formAction);
      if (f.formAction.startsWith('http:')) {
        findings.push(finding('card-form-insecure-action', 'critical', `Card form posts to ${f.formAction} over plain HTTP.`, 'Post card data only over HTTPS, preferably directly to the payment provider.', ['4.2.1'], where));
      } else if (target && !firstParty.has(target) && !paymentOrigins.has(target)) {
        findings.push(finding('card-form-third-party-action', 'high', `Card form posts to an unrecognized origin: ${target}.`, 'Confirm this is your payment processor and add it to paymentOrigins; otherwise this may be a skimming redirect.', ['6.4.3', '4.2.1'], where));
      }
      if (f.formMethod === 'get' && (f.kind === 'pan' || f.kind === 'cvv')) {
        findings.push(finding('card-form-get', 'high', 'Card form uses GET, so card data ends up in URLs, server logs and browser history.', 'Use method="post".', ['3.3.1', '3.5.1'], where));
      }
    }
  }

  // Code paths: inline scripts and captured first-party script bodies
  for (const s of snapshot.scripts) {
    if (!s.content) continue;
    const isFirstParty = !s.src || firstParty.has(originOf(s.src) ?? '');
    if (!isFirstParty) continue;
    const file = s.src ?? `${snapshot.url} (inline ${s.hash?.slice(0, 15) ?? ''})`;
    findings.push(...scanSourceForCardData(s.content, file));
  }

  return { snapshot, inventory, findings };
}

/** Creates an approved-script baseline from the current page, with justifications to fill in. */
export function baselineFromInventory(result: AnalysisResult, existing?: ScriptBaseline): ScriptBaseline {
  const prior = new Map((existing?.scripts ?? []).map((s) => [s.id, s]));
  return {
    version: 1,
    page: result.snapshot.url,
    scripts: result.inventory.map((i) => ({
      id: i.id,
      hash: i.hash,
      justification: prior.get(i.id)?.justification ?? '',
      approvedBy: prior.get(i.id)?.approvedBy ?? '',
      approvedAt: prior.get(i.id)?.approvedAt ?? new Date().toISOString().slice(0, 10),
    })),
  };
}

export interface Evidence {
  disclaimer: string;
  page: string;
  capturedAt: string;
  controls: Array<{ id: string; title: string; status: 'findings' | 'no-automated-findings'; findings: Array<{ ruleId: string; severity: Severity; message: string }>; automated: string; manual: string }>;
  inventory: InventoryItem[];
  headers: Record<string, string>;
  cardFields: PageSnapshot['cardFields'];
  frames: PageSnapshot['frames'];
}

const EVIDENCE_HEADERS = ['content-security-policy', 'content-security-policy-report-only', 'strict-transport-security', 'x-frame-options', 'referrer-policy', 'permissions-policy', 'x-content-type-options'];

export function buildEvidence(result: AnalysisResult): Evidence {
  const headers = Object.fromEntries(EVIDENCE_HEADERS.filter((k) => result.snapshot.headers?.[k]).map((k) => [k, result.snapshot.headers![k]!]));
  return {
    disclaimer: DISCLAIMER,
    page: result.snapshot.url,
    capturedAt: result.snapshot.capturedAt,
    controls: Object.values(CONTROLS).map((c) => {
      const related = result.findings.filter((f) => (f.meta?.controls as string[] | undefined)?.includes(c.id));
      return {
        id: c.id,
        title: c.title,
        status: related.length ? 'findings' : 'no-automated-findings',
        findings: related.map((f) => ({ ruleId: f.ruleId, severity: f.severity, message: f.message })),
        automated: c.automated,
        manual: c.manual,
      };
    }),
    inventory: result.inventory,
    headers,
    cardFields: result.snapshot.cardFields,
    frames: result.snapshot.frames,
  };
}

const esc = (s: string) => s.replace(/\|/g, '\\|').replace(/\r?\n/g, ' ');

export function evidenceToMarkdown(e: Evidence): string {
  const out = [`# PCI payment page evidence`, '', `> ${e.disclaimer}`, '', `- **Page:** ${e.page}`, `- **Captured:** ${e.capturedAt}`, ''];
  out.push('## Requirements', '');
  for (const c of e.controls) {
    out.push(`### ${c.id} — ${c.title}`, '', `**Automated result:** ${c.status === 'findings' ? `${c.findings.length} finding(s)` : 'no automated findings'}`, '');
    for (const f of c.findings) out.push(`- **${f.severity}** \`${f.ruleId}\`: ${f.message}`);
    if (c.findings.length) out.push('');
    out.push(`*Collected automatically:* ${c.automated}`, '', `*Still needs manual evidence:* ${c.manual}`, '');
  }
  out.push('## Script inventory', '', '| Status | Script | Category | Loaded | SRI | SHA-256 | Justification |', '|---|---|---|---|---|---|---|');
  for (const i of e.inventory) {
    out.push(`| ${i.status} | ${esc(i.src ?? 'inline')} | ${i.category} | ${i.loadedBy} | ${i.integrity ? 'yes' : 'no'} | ${i.hash ? `\`${i.hash.slice(0, 22)}…\`` : 'n/a'} | ${esc(i.justification ?? '')} |`);
  }
  out.push('', '## Security headers', '');
  if (Object.keys(e.headers).length) for (const [k, v] of Object.entries(e.headers)) out.push(`- \`${k}\`: \`${esc(v)}\``);
  else out.push('- None captured (run from Node/Playwright to capture response headers).');
  out.push('', '## Card data fields in the page DOM', '');
  if (e.cardFields.length) for (const f of e.cardFields) out.push(`- ${f.kind}: \`${f.selector}\`${f.formAction ? ` → ${f.formAction}` : ''}`);
  else out.push('- None (card fields are hosted in provider iframes, or not on this page).');
  out.push('', '## Frames', '');
  if (e.frames.length) for (const f of e.frames) out.push(`- ${f.src}${f.title ? ` (${f.title})` : ''}`);
  else out.push('- None');
  return out.join('\n');
}
