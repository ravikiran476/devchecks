import { fingerprint, type Finding, type Severity } from '@devchecks/core';
import { categoriesOf, DEFAULT_POLICY, evaluate, type Category, type LicensePolicy } from './policy.js';
import { normalizeLicense } from './spdx.js';

export interface PackageLicense {
  name: string;
  version: string;
  /** SPDX expression (already normalized), or undefined when the package declares none. */
  license?: string;
  /** Raw declared value, for the report. */
  declared?: string;
  dev?: boolean;
  /** Where the package came from (lockfile path, node_modules path...). */
  path?: string;
  /** Full license text, when it was read from the package. */
  licenseText?: string;
  repository?: string;
  author?: string;
}

export interface CheckOptions {
  policy?: LicensePolicy;
  /** Skip packages only used in development (not distributed). Default false. */
  production?: boolean;
  /** Location reported for findings (lockfile or project path). */
  source?: string;
}

export interface LicenseFinding extends Finding {
  meta: { package: string; version: string; license?: string; declared?: string; category: Category | 'missing'; dev: boolean };
}

const ADVICE: Record<Category | 'missing', string> = {
  permissive: 'No action needed beyond keeping the attribution notice.',
  'weak-copyleft': 'Usually fine if you use the package unmodified as a separate library. If you modify its files, publish those changes under the same license. Confirm with your legal policy.',
  'strong-copyleft': 'Distributing software that includes this package may require releasing your source under the same license. Replace it, isolate it (separate process), or get legal approval.',
  'network-copyleft': 'Offering this software over a network may require releasing your source. Replace it or get legal approval.',
  'source-available': 'Not an open-source license; it restricts some uses (often competing hosted services). Check the terms or replace the package.',
  'non-commercial': 'Commercial use is not permitted. Replace the package or obtain a commercial license.',
  proprietary: 'The package is marked UNLICENSED/proprietary. Make sure you have a license agreement, or remove it.',
  unknown: 'The license could not be identified. Read the package license file and add an explicit allow/deny entry or an exception.',
  missing: 'The package declares no license, which legally means all rights reserved. Ask the maintainer, check the repository, or replace it.',
};

/** Applies a license policy to an inventory of packages. */
export function checkLicenses(packages: PackageLicense[], options: CheckOptions = {}): LicenseFinding[] {
  const policy = options.policy ?? DEFAULT_POLICY;
  const findings: LicenseFinding[] = [];
  for (const p of packages) {
    if (options.production && p.dev) continue;
    const exception = policy.exceptions?.find((e) => e.package === p.name && (!e.version || e.version === p.version));
    if (exception) continue;
    const base = { package: p.name, version: p.version, license: p.license, declared: p.declared, dev: !!p.dev };
    const at = options.source ?? p.path;
    const make = (ruleId: string, severity: Severity, message: string, category: Category | 'missing'): LicenseFinding => ({
      fingerprint: fingerprint('licensecheck', ruleId, p.name, p.version, p.license ?? ''),
      ruleId,
      severity,
      message,
      location: at ? { file: at } : undefined,
      remediation: ADVICE[category],
      meta: { ...base, category },
    });
    if (!p.license) {
      findings.push(make('license-missing', 'medium', `${p.name}@${p.version} declares no license.`, 'missing'));
      continue;
    }
    let result;
    try {
      result = evaluate(p.license, policy);
    } catch {
      findings.push(make('license-unknown', 'medium', `${p.name}@${p.version}: license "${p.declared ?? p.license}" is not a valid SPDX expression.`, 'unknown'));
      continue;
    }
    const dev = p.dev ? ' (dev dependency)' : '';
    if (result.verdict === 'denied') {
      findings.push(make('license-denied', p.dev ? 'medium' : 'high', `${p.name}@${p.version}${dev}: ${p.license} (${result.category}) is not allowed by the license policy.`, result.category));
    } else if (result.verdict === 'review') {
      const ruleId = result.category === 'unknown' ? 'license-unknown' : 'license-review';
      findings.push(make(ruleId, p.dev ? 'low' : 'medium', `${p.name}@${p.version}${dev}: ${p.license} (${result.category}) needs review.`, result.category));
    }
  }
  return findings;
}

export interface LicenseSummary {
  license: string;
  categories: Category[];
  count: number;
  packages: string[];
}

export function summarizeLicenses(packages: PackageLicense[]): LicenseSummary[] {
  const by = new Map<string, string[]>();
  for (const p of packages) {
    const key = p.license ?? '(none)';
    by.set(key, [...(by.get(key) ?? []), `${p.name}@${p.version}`]);
  }
  return [...by.entries()]
    .map(([license, pkgs]) => ({ license, categories: license === '(none)' ? [] : categoriesOf(license), count: pkgs.length, packages: pkgs.sort() }))
    .sort((a, b) => b.count - a.count || a.license.localeCompare(b.license));
}

interface LockEntry {
  name?: string;
  version?: string;
  license?: unknown;
  dev?: boolean;
  link?: boolean;
}

/** npm package-lock.json v2/v3 records each package's license, so no network or install is needed. */
export function fromPackageLock(text: string, source = 'package-lock.json'): PackageLicense[] {
  const lock = JSON.parse(text) as { lockfileVersion?: number; packages?: Record<string, LockEntry> };
  if (!lock.packages) throw new Error(`${source} is lockfileVersion ${lock.lockfileVersion ?? 1}; licenses need lockfileVersion 2 or 3 (npm 7+), or scan node_modules instead.`);
  const seen = new Set<string>();
  const out: PackageLicense[] = [];
  for (const [key, e] of Object.entries(lock.packages)) {
    const idx = key.lastIndexOf('node_modules/');
    if (!key || idx === -1 || e.link || !e.version) continue;
    const name = e.name ?? key.slice(idx + 13);
    const id = `${name}@${e.version}`;
    if (seen.has(id)) continue;
    seen.add(id);
    const n = normalizeLicense(e.license);
    out.push({ name, version: e.version, license: n.expression, declared: n.raw, dev: !!e.dev, path: key });
  }
  return out;
}

export type FetchLike = (url: string) => Promise<{ ok: boolean; status: number; json(): Promise<unknown> }>;

/** Fills in missing licenses from the npm registry (CORS-enabled, so this also works in a browser). */
export async function fetchMissingLicenses(
  packages: PackageLicense[],
  options: { fetch?: FetchLike; registry?: string; concurrency?: number } = {},
): Promise<PackageLicense[]> {
  const f = options.fetch ?? (globalThis.fetch.bind(globalThis) as unknown as FetchLike);
  const registry = (options.registry ?? 'https://registry.npmjs.org').replace(/\/$/, '');
  const queue = packages.filter((p) => !p.license);
  const worker = async () => {
    for (let p = queue.shift(); p; p = queue.shift()) {
      try {
        const res = await f(`${registry}/${p.name.replace('/', '%2F')}/${encodeURIComponent(p.version)}`);
        if (!res.ok) continue;
        const doc = (await res.json()) as { license?: unknown; licenses?: unknown };
        const n = normalizeLicense(doc.license, doc.licenses);
        p.license = n.expression;
        p.declared = n.raw;
      } catch {
        // offline or blocked: leave as missing
      }
    }
  };
  await Promise.all(Array.from({ length: options.concurrency ?? 8 }, worker));
  return packages;
}

/** THIRD-PARTY-NOTICES style attribution, grouped by license. */
export function attributionMarkdown(packages: PackageLicense[], options: { title?: string; includeDev?: boolean } = {}): string {
  const list = packages.filter((p) => options.includeDev || !p.dev).sort((a, b) => a.name.localeCompare(b.name));
  const out = [`# ${options.title ?? 'Third-party notices'}`, '', `This product includes the following ${list.length} third-party packages.`, ''];
  for (const s of summarizeLicenses(list)) out.push(`- **${s.license}**: ${s.count}`);
  out.push('');
  for (const p of list) {
    out.push(`## ${p.name}@${p.version}`, '', `License: ${p.license ?? 'not declared'}${p.repository ? `  \nSource: ${p.repository}` : ''}${p.author ? `  \nAuthor: ${p.author}` : ''}`, '');
    if (p.licenseText) out.push('```', p.licenseText.trim(), '```', '');
  }
  return out.join('\n');
}
