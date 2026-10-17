import { fingerprint, type Finding, type Severity } from '@devchecks/core';
import type { Entry, ParsedConfig } from './parse.js';

export interface FileContext {
  file: string;
  /** Production configuration: stricter severities. */
  production: boolean;
}

const truthy = (v: unknown) => v === true || v === 1 || (typeof v === 'string' && /^(true|1|yes|on)$/i.test(v.trim()));
const falsy = (v: unknown) => v === false || v === 0 || (typeof v === 'string' && /^(false|0|no|off)$/i.test(v.trim()));
const isReference = (v: string) => /^\$\{.+\}$|^\$[A-Z_]+$|^%\(.+\)s$|^\{\{.+\}\}$|^<.+>$|^env\(|process\.env/.test(v.trim());

const WEAK_VALUES = new Set(['admin', 'password', 'passw0rd', 'changeme', 'change_me', 'root', 'secret', '123456', '12345678', 'test', 'default', 'letmein', 'qwerty', 'postgres', 'guest', 'example', 'mysql', 'redis', 'pass', 'demo']);

export function isProductionFile(file: string, parsed: ParsedConfig): boolean {
  if (/(^|[./_-])(prod|production|live|prd)([./_-]|$)/i.test(file.replace(/\\/g, '/').split('/').pop() ?? file)) return true;
  return parsed.entries.some((e) => /^(NODE_ENV|APP_ENV|ENV|ENVIRONMENT|RAILS_ENV|FLASK_ENV|ASPNETCORE_ENVIRONMENT|environment)$/i.test(e.key) && typeof e.value === 'string' && /^prod(uction)?$/i.test(e.value));
}

interface Rule {
  id: string;
  test(e: Entry, all: Entry[]): { severity: Severity; message: string } | undefined;
  remediation: string;
}

const inPath = (e: Entry, re: RegExp) => e.keys.some((k) => re.test(k));

export function rules(ctx: FileContext): Rule[] {
  const sev = (prod: Severity, dev: Severity) => (ctx.production ? prod : dev);
  return [
    {
      id: 'tls-verification-disabled',
      remediation: 'Keep certificate verification on. Trust a private CA with NODE_EXTRA_CA_CERTS / a CA bundle instead of disabling checks.',
      test(e) {
        if (/^NODE_TLS_REJECT_UNAUTHORIZED$/i.test(e.key) && String(e.value).trim() === '0') return { severity: 'high', message: 'NODE_TLS_REJECT_UNAUTHORIZED=0 disables TLS certificate verification for every request.' };
        if (/insecure.?skip.?(tls.?)?verify|^insecure$|^allow.?insecure|^tls.?insecure/i.test(e.key) && truthy(e.value)) return { severity: 'high', message: `${e.path} disables TLS certificate verification.` };
        if (/^(reject.?unauthorized|strict.?ssl|verify.?(ssl|tls|certs?|peer)|ssl.?verify(.?peer)?|tls.?verify|check.?certificate)$/i.test(e.key) && falsy(e.value)) return { severity: 'high', message: `${e.path} is off, so TLS certificates are not verified.` };
        return undefined;
      },
    },
    {
      id: 'debug-enabled',
      remediation: 'Turn debug mode off outside local development; it exposes stack traces, internals and sometimes interactive consoles.',
      test(e) {
        if (/^(debug|app_debug|flask_debug|django_debug|debug_mode|debugmode|enable_debug)$/i.test(e.key) && truthy(e.value)) return { severity: sev('high', 'low'), message: `${e.path} enables debug mode${ctx.production ? ' in a production configuration' : ''}.` };
        return undefined;
      },
    },
    {
      id: 'cors-wildcard',
      remediation: 'List the exact origins that may call the API. Never combine a wildcard or reflected origin with credentials.',
      test(e, all) {
        const corsish = /^(cors|origins?|allowed.?origins?|allow.?origins?|access.?control.?allow.?origin|cors.?origins?)$/i.test(e.key) || (inPath(e, /cors/i) && /origin/i.test(e.key));
        if (!corsish || e.value !== '*') return undefined;
        const creds = all.some((x) => /^(credentials|allow.?credentials|access.?control.?allow.?credentials|supports.?credentials)$/i.test(x.key) && truthy(x.value));
        return { severity: creds ? 'high' : 'medium', message: `${e.path} allows any origin${creds ? ' together with credentials' : ''}.` };
      },
    },
    {
      id: 'insecure-cookie',
      remediation: 'Set cookies with Secure, HttpOnly and SameSite=Lax (or Strict). SameSite=None requires Secure.',
      test(e, all) {
        if (!inPath(e, /cookie|session/i)) return undefined;
        if (/^secure$/i.test(e.key) && falsy(e.value)) return { severity: sev('high', 'medium'), message: `${e.path} sends the cookie over plain HTTP.` };
        if (/^http.?only$/i.test(e.key) && falsy(e.value)) return { severity: 'medium', message: `${e.path} lets JavaScript read the cookie (XSS can steal it).` };
        if (/^same.?site$/i.test(e.key) && typeof e.value === 'string' && /^none$/i.test(e.value)) {
          const secure = all.some((x) => inPath(x, /cookie|session/i) && /^secure$/i.test(x.key) && truthy(x.value));
          if (!secure) return { severity: 'medium', message: `${e.path} is None without Secure.` };
        }
        return undefined;
      },
    },
    {
      id: 'default-credentials',
      remediation: 'Use a strong, unique credential from your secret manager. Never ship default passwords.',
      test(e) {
        if (!/(password|passwd|pwd|secret|token|api.?key|pass)$/i.test(e.key) || typeof e.value !== 'string') return undefined;
        if (WEAK_VALUES.has(e.value.trim().toLowerCase())) return { severity: sev('critical', 'high'), message: `${e.path} uses a default or well-known value.` };
        return undefined;
      },
    },
    {
      id: 'weak-secret',
      remediation: 'Use at least 32 random bytes (e.g. `openssl rand -base64 48`) and load the value from a secret manager.',
      test(e) {
        if (!/(jwt.?secret|secret.?key(.?base)?|session.?secret|signing.?(key|secret)|app.?key|cookie.?secret|encryption.?key|hmac.?(key|secret))$/i.test(e.key) || typeof e.value !== 'string') return undefined;
        const v = e.value.trim();
        if (!v || isReference(v) || WEAK_VALUES.has(v.toLowerCase())) return undefined;
        if (v.length < 32) return { severity: sev('high', 'medium'), message: `${e.path} is shorter than 32 characters, which is too weak for a signing or encryption key.` };
        return undefined;
      },
    },
    {
      id: 'insecure-url',
      remediation: 'Use https:// for services reached over a network you do not fully control.',
      test(e) {
        if (!/(url|uri|endpoint|host|origin|base.?url|api|issuer|callback|redirect)$/i.test(e.key) || typeof e.value !== 'string') return undefined;
        const m = /^http:\/\/([^/:]+)/i.exec(e.value.trim());
        if (!m) return undefined;
        const host = m[1]!.toLowerCase();
        if (/^(localhost|127\.|0\.0\.0\.0|\[::1\]|host\.docker\.internal)/.test(host) || !host.includes('.') || /\.(local|internal|svc|cluster\.local|test|example)$/.test(host) || /^(10|192\.168|172\.(1[6-9]|2\d|3[01]))\./.test(host)) return undefined;
        return { severity: sev('medium', 'low'), message: `${e.path} uses plain HTTP to ${host}.` };
      },
    },
    {
      id: 'privileged-container',
      remediation: 'Drop privileges: privileged: false, allowPrivilegeEscalation: false, runAsNonRoot: true, readOnlyRootFilesystem: true, and avoid host namespaces.',
      test(e) {
        if (/^privileged$/i.test(e.key) && truthy(e.value)) return { severity: 'high', message: `${e.path} runs the container privileged (full host access).` };
        if (/^allowPrivilegeEscalation$/i.test(e.key) && truthy(e.value)) return { severity: 'medium', message: `${e.path} allows privilege escalation.` };
        if (/^(hostNetwork|hostPID|hostIPC)$/i.test(e.key) && truthy(e.value)) return { severity: 'medium', message: `${e.path} shares a host namespace with the container.` };
        if (/^runAsUser$/i.test(e.key) && e.value === 0) return { severity: 'medium', message: `${e.path} runs the container as root.` };
        if (/^runAsNonRoot$/i.test(e.key) && falsy(e.value)) return { severity: 'medium', message: `${e.path} allows running as root.` };
        return undefined;
      },
    },
    {
      id: 'verbose-logging',
      remediation: 'Use info or warn in production; debug/trace logs often contain request bodies, tokens and personal data.',
      test(e) {
        if (!ctx.production || !/^(log.?level|loglevel|level|logging.?level)$/i.test(e.key) || typeof e.value !== 'string') return undefined;
        if (e.key.toLowerCase() === 'level' && !inPath(e, /log/i)) return undefined;
        return /^(debug|trace|verbose|silly|all)$/i.test(e.value) ? { severity: 'low', message: `${e.path} is "${e.value}" in a production configuration.` } : undefined;
      },
    },
  ];
}

export const RULE_IDS = ['tls-verification-disabled', 'debug-enabled', 'cors-wildcard', 'insecure-cookie', 'default-credentials', 'weak-secret', 'insecure-url', 'privileged-container', 'verbose-logging'] as const;

/** Applies the risky-setting rules to one parsed file. Messages never include setting values. */
export function checkEntries(parsed: ParsedConfig, ctx: FileContext, disabled: ReadonlySet<string> = new Set()): Finding[] {
  const findings: Finding[] = [];
  for (const rule of rules(ctx)) {
    if (disabled.has(rule.id)) continue;
    for (const e of parsed.entries) {
      const hit = rule.test(e, parsed.entries);
      if (!hit) continue;
      findings.push({
        fingerprint: fingerprint('configcheck', rule.id, ctx.file, e.path),
        ruleId: rule.id,
        severity: hit.severity,
        message: hit.message,
        location: { file: ctx.file, line: e.line },
        remediation: rule.remediation,
        meta: { setting: e.path, production: ctx.production },
      });
    }
  }
  return findings;
}
