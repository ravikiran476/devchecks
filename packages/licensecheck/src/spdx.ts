// SPDX license expressions: parsing (https://spdx.github.io/spdx-spec/v2.3/SPDX-license-expressions/)
// and normalization of the messy values found in package.json files.

export type Expr = { license: string; exception?: string } | { and: Expr[] } | { or: Expr[] };

function tokenize(s: string): string[] {
  return s.replace(/\(/g, ' ( ').replace(/\)/g, ' ) ').trim().split(/\s+/).filter(Boolean);
}

/** Parses an SPDX expression. Operator precedence: WITH > AND > OR. Throws on malformed input. */
export function parseExpression(input: string): Expr {
  const tokens = tokenize(input);
  let i = 0;
  const peek = () => tokens[i];
  const next = () => tokens[i++];
  const primary = (): Expr => {
    const t = next();
    if (t === undefined) throw new Error(`Unexpected end of license expression "${input}"`);
    if (t === '(') {
      const e = or();
      if (next() !== ')') throw new Error(`Missing ")" in license expression "${input}"`);
      return e;
    }
    if (/^(AND|OR|WITH|\))$/i.test(t)) throw new Error(`Unexpected "${t}" in license expression "${input}"`);
    if (peek()?.toUpperCase() === 'WITH') {
      next();
      const exc = next();
      if (!exc) throw new Error(`Missing exception after WITH in "${input}"`);
      return { license: t, exception: exc };
    }
    return { license: t };
  };
  const and = (): Expr => {
    const parts = [primary()];
    while (peek()?.toUpperCase() === 'AND') {
      next();
      parts.push(primary());
    }
    return parts.length === 1 ? parts[0]! : { and: parts };
  };
  const or = (): Expr => {
    const parts = [and()];
    while (peek()?.toUpperCase() === 'OR') {
      next();
      parts.push(and());
    }
    return parts.length === 1 ? parts[0]! : { or: parts };
  };
  const e = or();
  if (i < tokens.length) throw new Error(`Unexpected "${tokens[i]}" in license expression "${input}"`);
  return e;
}

export function formatExpression(e: Expr): string {
  if ('license' in e) return e.exception ? `${e.license} WITH ${e.exception}` : e.license;
  if ('and' in e) return e.and.map((x) => ('or' in x ? `(${formatExpression(x)})` : formatExpression(x))).join(' AND ');
  return e.or.map(formatExpression).join(' OR ');
}

export function leaves(e: Expr): Array<{ license: string; exception?: string }> {
  if ('license' in e) return [e];
  return ('and' in e ? e.and : e.or).flatMap(leaves);
}

// Common non-SPDX spellings seen in the npm registry.
const ALIASES: Record<string, string> = {
  mit: 'MIT',
  'mit license': 'MIT',
  'the mit license': 'MIT',
  'mit/x11': 'MIT',
  x11: 'X11',
  isc: 'ISC',
  'isc license': 'ISC',
  'apache 2': 'Apache-2.0',
  'apache 2.0': 'Apache-2.0',
  'apache-2': 'Apache-2.0',
  'apache license 2.0': 'Apache-2.0',
  'apache license, version 2.0': 'Apache-2.0',
  'apache2': 'Apache-2.0',
  'apache v2': 'Apache-2.0',
  bsd: 'BSD-3-Clause',
  'new bsd': 'BSD-3-Clause',
  'bsd 3-clause': 'BSD-3-Clause',
  'bsd-3': 'BSD-3-Clause',
  'simplified bsd': 'BSD-2-Clause',
  'bsd 2-clause': 'BSD-2-Clause',
  'bsd-2': 'BSD-2-Clause',
  gpl: 'GPL-3.0-or-later',
  'gplv2': 'GPL-2.0-only',
  'gpl-2.0': 'GPL-2.0-only',
  'gpl-2.0+': 'GPL-2.0-or-later',
  'gplv3': 'GPL-3.0-only',
  'gpl-3.0': 'GPL-3.0-only',
  'gpl-3.0+': 'GPL-3.0-or-later',
  'lgpl-2.1': 'LGPL-2.1-only',
  'lgpl-2.1+': 'LGPL-2.1-or-later',
  'lgpl-3.0': 'LGPL-3.0-only',
  'lgpl-3.0+': 'LGPL-3.0-or-later',
  'agpl-3.0': 'AGPL-3.0-only',
  'mpl 2.0': 'MPL-2.0',
  'mpl-2': 'MPL-2.0',
  unlicense: 'Unlicense',
  'public domain': 'LicenseRef-Public-Domain',
  'cc0': 'CC0-1.0',
  wtfpl: 'WTFPL',
  'python-2.0': 'Python-2.0',
  'blueoak-1.0.0': 'BlueOak-1.0.0',
};

const UPPER_IDS = new Set(['MIT', 'ISC', 'MIT-0', '0BSD', 'WTFPL', 'X11', 'BSL-1.0', 'MPL-2.0', 'EPL-2.0', 'CDDL-1.0', 'OFL-1.1', 'SSPL-1.0', 'BUSL-1.1', 'EUPL-1.2', 'OSL-3.0', 'CC0-1.0', 'CC-BY-4.0', 'CC-BY-3.0', 'Zlib', 'Unlicense', 'Apache-2.0']);

function normalizeId(id: string): string {
  const alias = ALIASES[id.toLowerCase()];
  if (alias) return alias;
  for (const known of UPPER_IDS) if (known.toLowerCase() === id.toLowerCase()) return known;
  // Deprecated SPDX ids: GPL-2.0 → GPL-2.0-only, GPL-2.0+ → GPL-2.0-or-later
  const m = /^(A?GPL|LGPL)-(\d\.\d)(\+)?$/i.exec(id);
  if (m) return `${m[1]!.toUpperCase()}-${m[2]}${m[3] ? '-or-later' : '-only'}`;
  return id;
}

export interface NormalizedLicense {
  /** SPDX expression, or a LicenseRef-* for non-SPDX cases. undefined when the package declares nothing. */
  expression?: string;
  /** The raw value(s) found. */
  raw?: string;
  /** True when the value could not be understood as SPDX. */
  invalid?: boolean;
}

/** Normalizes package.json "license" / legacy "licenses" values into an SPDX expression. */
export function normalizeLicense(license: unknown, licenses?: unknown): NormalizedLicense {
  const collect = (v: unknown): string[] => {
    if (!v) return [];
    if (typeof v === 'string') return [v];
    if (Array.isArray(v)) return v.flatMap(collect);
    if (typeof v === 'object' && typeof (v as { type?: unknown }).type === 'string') return [(v as { type: string }).type];
    return [];
  };
  const values = [...collect(license), ...collect(licenses)];
  if (!values.length) return {};
  const raw = values.join(' OR ');
  if (values.length === 1 && /^UNLICEN[SC]ED$/i.test(values[0]!.trim())) return { expression: 'LicenseRef-Proprietary', raw };
  if (values.length === 1 && /^SEE LICEN[SC]E IN /i.test(values[0]!.trim())) return { expression: 'LicenseRef-Custom', raw };
  const parts: string[] = [];
  for (const v of values) {
    const trimmed = v.trim();
    const alias = ALIASES[trimmed.toLowerCase()];
    if (alias) {
      parts.push(alias);
      continue;
    }
    try {
      const expr = parseExpression(trimmed.replace(/\s*\/\s*/g, ' OR '));
      const map = (e: Expr): Expr =>
        'license' in e ? { license: normalizeId(e.license), exception: e.exception } : 'and' in e ? { and: e.and.map(map) } : { or: e.or.map(map) };
      const s = formatExpression(map(expr));
      parts.push(values.length > 1 && /\s/.test(s) ? `(${s})` : s);
    } catch {
      return { expression: 'LicenseRef-Unknown', raw, invalid: true };
    }
  }
  return { expression: parts.join(' OR '), raw };
}
