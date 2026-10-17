import type { Severity } from '@devchecks/core';

export type Directives = Map<string, string[]>;

export function parseCsp(policy: string): Directives {
  const map: Directives = new Map();
  for (const part of policy.split(';')) {
    const [name, ...values] = part.trim().split(/\s+/);
    if (!name) continue;
    const key = name.toLowerCase();
    if (!map.has(key)) map.set(key, values); // first occurrence wins, like browsers
  }
  return map;
}

export interface CspIssue {
  ruleId: string;
  severity: Severity;
  message: string;
  remediation: string;
  controls: string[];
}

// Hosts that serve JSONP endpoints or arbitrary user content, which defeat a host allowlist.
const BYPASS_HOSTS = [
  /(^|\.)googleapis\.com$/,
  /^www\.google\.com$/,
  /(^|\.)gstatic\.com$/,
  /^cdn\.jsdelivr\.net$/,
  /^cdnjs\.cloudflare\.com$/,
  /^unpkg\.com$/,
  /^raw\.githubusercontent\.com$/,
  /(^|\.)github\.io$/,
  /(^|\.)herokuapp\.com$/,
  /(^|\.)appspot\.com$/,
  /(^|\.)firebaseapp\.com$/,
  /(^|\.)azurewebsites\.net$/,
  /(^|\.)cloudfront\.net$/,
  /(^|\.)amazonaws\.com$/,
];

function hostOf(source: string): string | undefined {
  if (source.startsWith("'")) return undefined;
  const m = /^(?:[a-z][a-z0-9+.-]*:\/\/)?(\*\.)?([^/:]+)/i.exec(source);
  return m ? `${m[1] ?? ''}${m[2]}`.replace(/^\*\./, '') : undefined;
}

/** Reviews a CSP for weaknesses that matter on a payment page. */
export function analyzeCsp(policy: string | undefined, options: { reportOnly?: string; xFrameOptions?: string } = {}): CspIssue[] {
  const issues: CspIssue[] = [];
  const push = (ruleId: string, severity: Severity, message: string, remediation: string, controls = ['6.4.3', '11.6.1']) =>
    issues.push({ ruleId, severity, message, remediation, controls });

  if (!policy) {
    if (options.reportOnly) {
      push('csp-report-only', 'medium', 'CSP is only in report-only mode, so it does not block unauthorized scripts.', 'Promote the policy to Content-Security-Policy once the reports are clean; keep report-to for monitoring.');
      return [...issues, ...analyzeCsp(options.reportOnly, { xFrameOptions: options.xFrameOptions }).map((i) => ({ ...i, severity: 'low' as Severity, message: `(report-only) ${i.message}` }))];
    }
    push('csp-missing', 'high', 'No Content-Security-Policy on the payment page.', "Add a CSP with script-src using nonces or hashes (e.g. script-src 'nonce-…' 'strict-dynamic'), object-src 'none', base-uri 'none', form-action and frame-ancestors, plus report-to.");
    return issues;
  }

  const d = parseCsp(policy);
  const scriptSrc = d.get('script-src-elem') ?? d.get('script-src') ?? d.get('default-src');
  if (!scriptSrc) {
    push('csp-no-script-src', 'high', 'CSP has neither script-src nor default-src, so scripts are unrestricted.', "Add script-src with nonces or hashes and 'strict-dynamic'.");
  } else {
    const hasNonceOrHash = scriptSrc.some((s) => /^'(nonce|sha256|sha384|sha512)-/.test(s));
    const strictDynamic = scriptSrc.includes("'strict-dynamic'");
    if (scriptSrc.includes("'unsafe-inline'") && !hasNonceOrHash) {
      push('csp-unsafe-inline', 'high', "script-src allows 'unsafe-inline', so injected inline scripts run.", "Replace 'unsafe-inline' with nonces or hashes for inline scripts.", ['6.4.3', '6.2.4']);
    }
    if (scriptSrc.includes("'unsafe-eval'")) {
      push('csp-unsafe-eval', 'high', "script-src allows 'unsafe-eval'.", "Remove 'unsafe-eval'; refactor code that uses eval/new Function, or allow only 'wasm-unsafe-eval' if WebAssembly needs it.", ['6.4.3', '6.2.4']);
    }
    if (!strictDynamic) {
      const broad = scriptSrc.filter((s) => s === '*' || /^(https?|data|blob|filesystem):$/i.test(s) || s === 'http://*' || s === 'https://*');
      if (broad.length) {
        push('csp-wildcard-source', 'high', `script-src allows any script from ${broad.join(', ')}.`, 'List exact script origins, or move to nonces with strict-dynamic.');
      }
      const bypass = scriptSrc.filter((s) => {
        const h = hostOf(s);
        return h && BYPASS_HOSTS.some((r) => r.test(h));
      });
      if (bypass.length) {
        push('csp-bypassable-host', 'medium', `script-src allowlists hosts that serve user content or JSONP (${bypass.join(', ')}), which can bypass the policy.`, 'Pin full script paths or use hashes/SRI, or switch to nonces with strict-dynamic.');
      }
      if (scriptSrc.some((s) => /^http:\/\//i.test(s))) {
        push('csp-insecure-source', 'medium', 'script-src allows scripts over plain HTTP.', 'Only allow https: script sources.', ['4.2.1', '6.4.3']);
      }
    }
  }
  const objectSrc = d.get('object-src') ?? d.get('default-src');
  if (!objectSrc || !objectSrc.includes("'none'")) {
    push('csp-object-src', 'medium', "object-src is not 'none', allowing plugin content.", "Add object-src 'none'.", ['6.2.4']);
  }
  if (!d.has('base-uri')) {
    push('csp-base-uri', 'medium', 'base-uri is not set: an injected <base> tag can redirect relative script URLs.', "Add base-uri 'none' (or 'self').");
  }
  if (!d.has('form-action')) {
    push('csp-form-action', 'medium', 'form-action is not set: injected markup could post card data to another origin.', "Add form-action 'self' plus your payment provider's origin.", ['6.4.3', '4.2.1']);
  }
  if (!d.has('frame-ancestors') && !/deny|sameorigin/i.test(options.xFrameOptions ?? '')) {
    push('csp-frame-ancestors', 'medium', 'The payment page can be framed by any site (no frame-ancestors / X-Frame-Options).', "Add frame-ancestors 'self' (or 'none').", ['6.2.4']);
  }
  const connect = d.get('connect-src') ?? d.get('default-src');
  if (!connect || connect.includes('*') || connect.some((s) => /^https?:$/.test(s))) {
    push('csp-connect-src', 'low', 'connect-src is unrestricted, so a skimmer could send data anywhere with fetch/XHR.', 'Restrict connect-src to your API and payment provider origins.');
  }
  if (!d.has('report-to') && !d.has('report-uri')) {
    push('csp-no-reporting', 'low', 'CSP violations are not reported, so blocked tampering attempts go unnoticed.', 'Add report-to / report-uri and alert on violations from the payment page.', ['11.6.1']);
  }
  return issues;
}
