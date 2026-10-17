// Static checks for code paths that expose card data on the client.
import { fingerprint, type Finding, type Severity } from '@devchecks/core';

const CARD_TERMS = /\b(card_?number|cardNumber|cc_?num(ber)?|ccNumber|credit_?card(Number)?|creditCard|pan|primaryAccountNumber|cvv2?|cvc2?|csc|securityCode|security_code|cardCode|card_code|cardExpiry|expiry(Date)?|expDate)\b/i;
const SAD_TERMS = /\b(cvv2?|cvc2?|csc|securityCode|security_code|cardCode|card_code)\b/i;

interface Sink {
  id: string;
  re: RegExp;
  what: string;
  severity: Severity;
  controls: string[];
  fix: string;
}

const SINKS: Sink[] = [
  {
    id: 'card-data-storage',
    re: /\b(localStorage|sessionStorage)\s*\.\s*setItem\s*\(|\b(localStorage|sessionStorage)\s*\[[^\]]+\]\s*=|document\.cookie\s*=/,
    what: 'stores card data in the browser',
    severity: 'critical',
    controls: ['3.3.1', '3.5.1'],
    fix: 'Never persist card numbers or security codes client-side. Tokenize with your payment provider and keep only the token.',
  },
  {
    id: 'card-data-logging',
    re: /\bconsole\s*\.\s*(log|info|debug|warn|error|trace|dir)\s*\(|\b(Sentry\s*\.\s*(captureMessage|captureException|setContext|setExtra|addBreadcrumb)|LogRocket\s*\.\s*(log|track)|logger\s*\.\s*(log|info|debug|warn|error))\s*\(/,
    what: 'writes card data to logs or error tracking',
    severity: 'high',
    controls: ['3.3.1', '3.5.1'],
    fix: 'Remove card fields from log statements and configure error tracking to scrub card data (e.g. Sentry beforeSend / data scrubbing).',
  },
  {
    id: 'card-data-analytics',
    re: /\b(gtag|fbq|_paq\s*\.\s*push|dataLayer\s*\.\s*push|analytics\s*\.\s*(track|identify|page)|mixpanel\s*\.\s*(track|register)|amplitude\s*\.\s*(track|logEvent)|hj|heap\s*\.\s*track|posthog\s*\.\s*capture)\s*\(/,
    what: 'sends card data to analytics',
    severity: 'high',
    controls: ['3.3.1', '3.5.1', '6.4.3'],
    fix: 'Do not include card fields in analytics events; mask payment fields in session-replay tools.',
  },
  {
    id: 'card-data-insecure-transport',
    re: /\b(fetch|axios\s*\.\s*(post|put)|\.open)\s*\(\s*['"`]http:\/\//,
    what: 'sends card data over plain HTTP',
    severity: 'critical',
    controls: ['4.2.1'],
    fix: 'Send payment data only over HTTPS, preferably directly to your payment provider.',
  },
];

const TEST_PANS = new Set([
  '4111111111111111', '4242424242424242', '4000056655665556', '5555555555554444', '5105105105105100', '2223003122003222',
  '378282246310005', '371449635398431', '6011111111111117', '6011000990139424', '3056930009020004', '36227206271667',
  '3566002020360505', '6200000000000005', '4012888888881881', '4000000000000002', '4000000000009995', '5200828282828210',
]);

export function luhn(digits: string): boolean {
  let sum = 0;
  for (let i = 0; i < digits.length; i++) {
    let d = Number(digits[digits.length - 1 - i]);
    if (i % 2 === 1) {
      d *= 2;
      if (d > 9) d -= 9;
    }
    sum += d;
  }
  return sum % 10 === 0;
}

function maskPan(pan: string): string {
  return `${pan.slice(0, 6)}${'*'.repeat(pan.length - 10)}${pan.slice(-4)}`;
}

/** Looks for card fields flowing into storage, logs, analytics and insecure transport, plus hard-coded PANs. */
export function scanSourceForCardData(source: string, file: string): Finding[] {
  const findings: Finding[] = [];
  const lines = source.split(/\r?\n/);
  lines.forEach((line, i) => {
    if (line.length > 2000) return; // minified bundles: use the network inventory instead
    if (CARD_TERMS.test(line)) {
      for (const sink of SINKS) {
        if (!sink.re.test(line)) continue;
        const sad = SAD_TERMS.test(line);
        const snippet = line.trim().slice(0, 160);
        findings.push({
          fingerprint: fingerprint('pci-pagecheck', sink.id, file, snippet),
          ruleId: sink.id,
          severity: sink.severity,
          message: `Code ${sink.what}${sad ? ' (including the card security code, which must never be retained)' : ''}.`,
          location: { file, line: i + 1 },
          snippet,
          remediation: sink.fix,
          meta: { controls: sink.controls },
        });
      }
    }
    for (const m of line.matchAll(/(?<![\d.])(\d{13,19}|\d{4}(?:[ -]\d{4}){3})(?![\d.])/g)) {
      const pan = m[1]!.replace(/[ -]/g, '');
      if (pan.length < 13 || !luhn(pan) || TEST_PANS.has(pan) || /^(\d)\1+$/.test(pan) || !/^[2-6]/.test(pan)) continue;
      findings.push({
        fingerprint: fingerprint('pci-pagecheck', 'pan-literal', file, maskPan(pan)),
        ruleId: 'pan-literal',
        severity: 'high',
        message: `Hard-coded value that looks like a real card number (${maskPan(pan)}).`,
        location: { file, line: i + 1, column: (m.index ?? 0) + 1 },
        snippet: line.replace(m[1]!, maskPan(pan)).trim().slice(0, 160),
        remediation: "Remove it. Use your payment provider's documented test card numbers in test code.",
        meta: { controls: ['3.5.1'] },
      });
    }
  });
  return findings;
}
