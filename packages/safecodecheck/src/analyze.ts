import { parse, type ParserPlugin } from '@babel/parser';
import { fingerprint, normalizePath, type Finding, type Severity } from '@devchecks/core';
import type { Node } from './ast.js';
import { RULES, runRules, type RawFinding, type RuleId } from './rules.js';

export interface SafeCodeCheckOptions {
  /** Rule ids to turn off. */
  disable?: RuleId[];
  /** Override the severity of a rule. */
  severity?: Partial<Record<RuleId, Severity>>;
}

export interface FileResult {
  findings: Finding[];
  /** Set when the file could not be parsed. */
  error?: string;
}

export const SCRIPT_EXTENSIONS = /\.(m|c)?[jt]sx?$/;
export const TEMPLATE_EXTENSIONS = /\.(vue|svelte|html?)$/;

function pluginsFor(file: string): ParserPlugin[] {
  const ts = /\.(m|c)?tsx?$/.test(file);
  const jsx = !/\.(m|c)?ts$/.test(file);
  const plugins: ParserPlugin[] = ['estree'];
  if (ts) plugins.push('typescript', 'decorators-legacy');
  if (jsx) plugins.push('jsx');
  return plugins;
}

/** Parses JS/TS/JSX into an ESTree AST with locations and comments. */
export function parseSource(code: string, file = 'input.tsx'): { ast: Node; comments: Array<{ value: string; line: number; endLine: number }> } {
  const ast = parse(code, {
    sourceType: 'unambiguous',
    errorRecovery: true,
    allowReturnOutsideFunction: true,
    allowAwaitOutsideFunction: true,
    allowImportExportEverywhere: true,
    allowUndeclaredExports: true,
    plugins: pluginsFor(file),
  }) as unknown as Node & { comments?: Array<{ value: string; loc: { start: { line: number }; end: { line: number } } }> };
  const comments = (ast.comments ?? []).map((c) => ({ value: c.value, line: c.loc.start.line, endLine: c.loc.end.line }));
  return { ast: ((ast as Node).program as Node) ?? ast, comments };
}

/** `// safecodecheck-disable-next-line [rule ...]` and `// safecodecheck-disable-line [rule ...]`. */
function suppressions(comments: Array<{ value: string; line: number; endLine: number }>): Map<number, Set<string>> {
  const map = new Map<number, Set<string>>();
  for (const c of comments) {
    const m = /safecodecheck-disable-(next-line|line)\b([^\n]*)/.exec(c.value);
    if (!m) continue;
    const line = m[1] === 'next-line' ? c.endLine + 1 : c.line;
    const rules = m[2]!.split(/[\s,]+/).filter((r) => r && !r.startsWith('--'));
    const set = map.get(line) ?? new Set<string>();
    if (!rules.length) set.add('*');
    rules.forEach((r) => set.add(r));
    map.set(line, set);
  }
  return map;
}

function lineAt(src: string, line: number): string {
  const text = src.split(/\r?\n/)[line - 1]?.trim() ?? '';
  return text.length > 160 ? `${text.slice(0, 157)}...` : text;
}

function toFinding(raw: RawFinding, file: string, source: string, options: SafeCodeCheckOptions): Finding {
  const info = RULES[raw.rule];
  const snippet = lineAt(source, raw.line);
  return {
    // Fingerprint by rule, file and code text (not line number) so baselines survive edits elsewhere.
    fingerprint: fingerprint('safecodecheck', raw.rule, file, snippet),
    ruleId: raw.rule,
    severity: options.severity?.[raw.rule] ?? raw.severity,
    message: raw.message,
    location: { file, line: raw.line, column: raw.column },
    snippet,
    remediation: info.remediation,
    helpUrl: `https://cwe.mitre.org/data/definitions/${info.cwe.slice(4)}.html`,
    tags: [info.cwe],
  };
}

/** Line-preserving extraction of <script> blocks from Vue/Svelte/HTML files. */
function scriptBlocks(source: string): Array<{ code: string; ts: boolean }> {
  const blocks: Array<{ code: string; ts: boolean }> = [];
  for (const m of source.matchAll(/<script\b([^>]*)>([\s\S]*?)<\/script>/gi)) {
    if (/\bsrc\s*=/.test(m[1]!) || /type\s*=\s*["'](?!module|text\/javascript|application\/javascript)/i.test(m[1]!)) continue;
    const start = (m.index ?? 0) + m[0].indexOf('>') + 1;
    const prefix = source.slice(0, start).replace(/[^\n]/g, ' ');
    blocks.push({ code: prefix + m[2], ts: /lang\s*=\s*["']ts/.test(m[1]!) });
  }
  return blocks;
}

function templateFindings(source: string, file: string): RawFinding[] {
  const out: RawFinding[] = [];
  const patterns: Array<[RegExp, string]> = [
    [/\bv-html\s*=\s*["']([^"']*)["']/g, 'v-html renders raw HTML'],
    [/\{@html\s+([^}]*)\}/g, '{@html} renders raw HTML'],
    [/\[innerHTML\]\s*=\s*["']([^"']*)["']/g, '[innerHTML] binding renders raw HTML'],
  ];
  for (const [re, what] of patterns) {
    for (const m of source.matchAll(re)) {
      const expr = m[1] ?? '';
      if (/sanitize|purify/i.test(expr)) continue;
      const before = source.slice(0, m.index);
      const line = before.split('\n').length;
      const column = (m.index ?? 0) - before.lastIndexOf('\n');
      out.push({
        rule: 'framework-unsafe-html',
        severity: /\$route|route\.|query|params|location/.test(expr) ? 'critical' : 'medium',
        message: `${what} (${expr.trim() || 'expression'}). Make sure the value is sanitized.`,
        line,
        column,
      });
    }
  }
  return file.endsWith('.html') && !/\[innerHTML\]/.test(source) ? [] : out;
}

/** Analyzes one file's source text. Pure: works in browsers, Node and editor integrations. */
export function analyzeSource(source: string, file = 'input.tsx', options: SafeCodeCheckOptions = {}): FileResult {
  const path = normalizePath(file);
  const raw: RawFinding[] = [];
  const allComments: Array<{ value: string; line: number; endLine: number }> = [];
  let error: string | undefined;
  const run = (code: string, parseAs: string) => {
    try {
      const { ast, comments } = parseSource(code, parseAs);
      allComments.push(...comments);
      raw.push(...runRules(ast, code));
    } catch (err) {
      error = (err as Error).message;
    }
  };
  if (TEMPLATE_EXTENSIONS.test(path)) {
    for (const b of scriptBlocks(source)) run(b.code, b.ts ? 'x.ts' : 'x.js');
    raw.push(...templateFindings(source, path));
    for (const m of source.matchAll(/<!--([\s\S]*?)-->/g)) {
      const line = source.slice(0, m.index).split('\n').length;
      allComments.push({ value: m[1]!, line, endLine: line + m[0].split('\n').length - 1 });
    }
  } else {
    run(source, path);
  }
  const disabled = new Set<string>(options.disable ?? []);
  const supp = suppressions(allComments);
  const seen = new Set<string>();
  const findings = raw
    .filter((r) => !disabled.has(r.rule))
    .filter((r) => {
      const s = supp.get(r.line);
      return !s || !(s.has('*') || s.has(r.rule));
    })
    .filter((r) => {
      const key = `${r.rule}:${r.line}:${r.column}`;
      if (seen.has(key)) return false;
      seen.add(key);
      return true;
    })
    .map((r) => toFinding(r, path, source, options));
  return { findings, error };
}
