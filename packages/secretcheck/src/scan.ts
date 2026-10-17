import { fingerprint, matchAny, normalizePath, type Finding } from '@devchecks/core';
import { DEFAULT_ENTROPY, isHighEntropy, type EntropyOptions } from './entropy.js';
import { BUILTIN_RULES, CONFIDENCE_SEVERITY, ROTATE_ADVICE, type Confidence, type SecretRule } from './rules.js';

export interface CustomRuleConfig {
  id: string;
  description?: string;
  /** JavaScript regular expression source. Use a named group "secret" to mark the secret part. */
  pattern: string;
  flags?: string;
  confidence?: Confidence;
}

export interface SecretCheckConfig {
  /** Built-in rule ids to turn off. */
  disableRules?: string[];
  customRules?: CustomRuleConfig[];
  /** Entropy detection for quoted strings. false disables it. */
  entropy?: false | Partial<EntropyOptions>;
  /** Extra glob patterns to skip, added to the generated/vendored defaults. */
  exclude?: string[];
  /** Set to false to scan lockfiles, build output, minified files, etc. */
  useDefaultExcludes?: boolean;
  allowlist?: {
    /** Glob patterns of files whose findings are accepted (fixtures, docs). */
    paths?: string[];
    /** Regular expressions; a finding is accepted if one matches the secret or its line. */
    patterns?: string[];
    /** Finding fingerprints that were reviewed and accepted. */
    fingerprints?: string[];
  };
  /** Lowest confidence that blocks a commit. Default "high". */
  failOn?: Confidence;
  /** Files larger than this many bytes are skipped. Default 1 MiB. */
  maxFileSize?: number;
}

export const DEFAULT_EXCLUDES: readonly string[] = [
  '**/node_modules/**',
  '**/dist/**',
  '**/build/**',
  '**/out/**',
  '**/coverage/**',
  '**/vendor/**',
  '**/.next/**',
  '**/.nuxt/**',
  '**/__generated__/**',
  '*.generated.*',
  '*.min.js',
  '*.min.css',
  '*.map',
  '*.snap',
  'package-lock.json',
  'npm-shrinkwrap.json',
  'yarn.lock',
  'pnpm-lock.yaml',
  'bun.lockb',
  'composer.lock',
  'Cargo.lock',
  'poetry.lock',
  'Gemfile.lock',
  'go.sum',
  '*.{png,jpg,jpeg,gif,webp,ico,bmp,pdf,zip,gz,tgz,jar,woff,woff2,ttf,otf,eot,mp3,mp4,mov,wasm}',
];

const CONF_RANK: Record<Confidence, number> = { high: 3, medium: 2, low: 1 };
const ALLOW_LINE = /secretcheck[:-]allow(?!-next-line)/;
const ALLOW_NEXT = /secretcheck[:-]allow-next-line/;
const ENTROPY_SKIP_LINE = /integrity|sha\d*|hash|checksum|digest|commit|sourceMappingURL|data:[\w/+.-]+;base64|uuid|guid/i;

export interface SecretFinding extends Finding {
  meta: { confidence: Confidence; description: string };
}

export interface ScanResult {
  findings: SecretFinding[];
  /** Findings at or above the failOn confidence — these should block the commit. */
  blocking: SecretFinding[];
  skipped: Array<{ file: string; reason: string }>;
}

/** Shows at most a short prefix and a fixed-width mask, so output reveals neither the secret nor its length. */
export function redact(secret: string): string {
  const visible = secret.length >= 16 ? 4 : secret.length >= 10 ? 2 : 0;
  return `${secret.slice(0, visible)}********`;
}

export function compileRules(config: SecretCheckConfig = {}): SecretRule[] {
  const disabled = new Set(config.disableRules ?? []);
  const rules = BUILTIN_RULES.filter((r) => !disabled.has(r.id));
  for (const c of config.customRules ?? []) {
    const flags = new Set((c.flags ?? '').split(''));
    flags.add('g');
    rules.push({
      id: c.id,
      description: c.description ?? c.id,
      pattern: new RegExp(c.pattern, [...flags].join('')),
      confidence: c.confidence ?? 'medium',
    });
  }
  return rules;
}

/** Decides whether a path should be skipped before reading it. */
export function isExcluded(file: string, config: SecretCheckConfig = {}): boolean {
  const path = normalizePath(file);
  if (config.useDefaultExcludes !== false && matchAny(DEFAULT_EXCLUDES, path)) return true;
  return matchAny(config.exclude, path);
}

interface Candidate {
  rule: { id: string; description: string; confidence: Confidence; remediation?: string };
  start: number;
  end: number;
  secret: string;
}

function findCandidates(line: string, rules: SecretRule[], entropy: EntropyOptions | false): Candidate[] {
  const out: Candidate[] = [];
  for (const rule of rules) {
    rule.pattern.lastIndex = 0;
    for (const m of line.matchAll(rule.pattern)) {
      const secret = m.groups?.secret ?? m[0];
      if (!secret || (rule.validate && !rule.validate(secret, line))) continue;
      const offset = m.groups?.secret ? m[0].lastIndexOf(secret) : 0;
      const start = (m.index ?? 0) + offset;
      out.push({ rule, start, end: start + secret.length, secret });
    }
  }
  if (entropy && line.length < 5000 && !ENTROPY_SKIP_LINE.test(line)) {
    for (const m of line.matchAll(/(["'`])([^"'`\s]{16,})\1/g)) {
      const secret = m[2]!;
      if (!isHighEntropy(secret, entropy)) continue;
      const start = (m.index ?? 0) + 1;
      out.push({
        rule: {
          id: 'high-entropy-string',
          description: 'High-entropy string that may be a credential',
          confidence: 'low',
          remediation: 'If this is a credential, move it to a secret manager. If not, add it to the allowlist.',
        },
        start,
        end: start + secret.length,
        secret,
      });
    }
  }
  // Keep the most confident, longest match for any overlapping span.
  out.sort((a, b) => CONF_RANK[b.rule.confidence] - CONF_RANK[a.rule.confidence] || b.end - b.start - (a.end - a.start));
  const kept: Candidate[] = [];
  for (const c of out) if (!kept.some((k) => c.start < k.end && k.start < c.end)) kept.push(c);
  return kept.sort((a, b) => a.start - b.start);
}

function redactLine(line: string, spans: Candidate[]): string {
  let result = '';
  let pos = 0;
  for (const s of spans) {
    result += line.slice(pos, s.start) + redact(s.secret);
    pos = s.end;
  }
  result += line.slice(pos);
  result = result.trim();
  return result.length > 160 ? `${result.slice(0, 157)}...` : result;
}

/**
 * Scans text content for secrets. Pure and synchronous, so it works the same in
 * the browser (via CDN), in Node and in editors.
 */
export function scanText(
  content: string,
  file = '<input>',
  config: SecretCheckConfig = {},
  /** When given, only these 1-based line numbers are reported (e.g. lines added in a diff). */
  onlyLines?: ReadonlySet<number>,
): SecretFinding[] {
  if (content.includes('\u0000')) return [];
  const rules = compileRules(config);
  const entropy = config.entropy === false ? false : { ...DEFAULT_ENTROPY, ...config.entropy };
  const allowPatterns = (config.allowlist?.patterns ?? []).map((p) => new RegExp(p));
  const allowFingerprints = new Set(config.allowlist?.fingerprints ?? []);
  const path = normalizePath(file);
  if (matchAny(config.allowlist?.paths, path)) return [];

  const findings: SecretFinding[] = [];
  const lines = content.split(/\r?\n/);
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i]!;
    if (onlyLines && !onlyLines.has(i + 1)) continue;
    if (ALLOW_LINE.test(line) || (i > 0 && ALLOW_NEXT.test(lines[i - 1]!))) continue;
    const candidates = findCandidates(line, rules, entropy).filter(
      (c) => !allowPatterns.some((re) => re.test(c.secret) || re.test(line)),
    );
    if (!candidates.length) continue;
    const snippet = redactLine(line, candidates);
    for (const c of candidates) {
      // Fingerprint uses the redacted line, never the secret, so baselines and allowlists are safe to commit.
      const fp = fingerprint('secretcheck', c.rule.id, path, snippet);
      if (allowFingerprints.has(fp)) continue;
      findings.push({
        fingerprint: fp,
        ruleId: c.rule.id,
        severity: CONFIDENCE_SEVERITY[c.rule.confidence],
        message: `${c.rule.description} (${c.rule.confidence} confidence): ${redact(c.secret)}`,
        location: { file: path, line: i + 1, column: c.start + 1 },
        snippet,
        remediation: c.rule.remediation ?? ROTATE_ADVICE,
        meta: { confidence: c.rule.confidence, description: c.rule.description },
      });
    }
  }
  return findings;
}

export function isBlocking(f: SecretFinding, failOn: Confidence = 'high'): boolean {
  return CONF_RANK[f.meta.confidence] >= CONF_RANK[failOn];
}

/** Scans several in-memory files, applying excludes, size limits and generated-file detection. */
export function scanFiles(
  files: Array<{ path: string; content: string; onlyLines?: ReadonlySet<number> }>,
  config: SecretCheckConfig = {}): ScanResult {
  const maxSize = config.maxFileSize ?? 1024 * 1024;
  const findings: SecretFinding[] = [];
  const skipped: ScanResult['skipped'] = [];
  for (const f of files) {
    if (isExcluded(f.path, config)) {
      skipped.push({ file: f.path, reason: 'excluded' });
      continue;
    }
    if (f.content.length > maxSize) {
      skipped.push({ file: f.path, reason: `larger than ${maxSize} bytes` });
      continue;
    }
    if (f.content.includes('\u0000')) {
      skipped.push({ file: f.path, reason: 'binary' });
      continue;
    }
    if (/@generated\b/.test(f.content.slice(0, 500))) {
      skipped.push({ file: f.path, reason: 'marked @generated' });
      continue;
    }
    findings.push(...scanText(f.content, f.path, config, f.onlyLines));
  }
  return { findings, blocking: findings.filter((x) => isBlocking(x, config.failOn)), skipped };
}
