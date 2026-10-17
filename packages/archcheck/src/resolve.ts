import { normalizePath } from '@devchecks/core';

export type Resolution =
  | { kind: 'internal'; path: string }
  | { kind: 'external'; name: string }
  | { kind: 'unresolved' }
  | { kind: 'asset' };

export interface ResolverOptions {
  /** tsconfig-style path aliases, e.g. { "@/*": ["src/*"], "~utils": ["src/utils/index.ts"] }. */
  aliases?: Record<string, string | string[]>;
  /** Like tsconfig baseUrl: bare specifiers are tried relative to this directory first. */
  baseUrl?: string;
  extensions?: string[];
}

export const CODE_EXTENSIONS = ['.ts', '.tsx', '.mts', '.cts', '.js', '.jsx', '.mjs', '.cjs', '.vue', '.svelte'];
const ASSET = /\.(css|scss|sass|less|styl|svg|png|jpe?g|gif|webp|avif|ico|woff2?|ttf|eot|json|md|html|txt|wasm)(\?.*)?$/i;

function dirname(p: string): string {
  const i = p.lastIndexOf('/');
  return i === -1 ? '' : p.slice(0, i);
}

export function joinPath(...parts: string[]): string {
  const out: string[] = [];
  for (const seg of parts.join('/').split('/')) {
    if (!seg || seg === '.') continue;
    if (seg === '..') out.pop();
    else out.push(seg);
  }
  return out.join('/');
}

export function packageName(spec: string): string {
  if (spec.startsWith('node:')) return spec;
  const parts = spec.split('/');
  return spec.startsWith('@') ? parts.slice(0, 2).join('/') : parts[0]!;
}

export class Resolver {
  private readonly files: Set<string>;
  private readonly aliases: Array<{ prefix: string; wildcard: boolean; targets: string[] }>;
  private readonly baseUrl?: string;
  private readonly extensions: string[];

  constructor(files: Iterable<string>, options: ResolverOptions = {}) {
    this.files = new Set([...files].map(normalizePath));
    this.extensions = options.extensions ?? CODE_EXTENSIONS;
    this.baseUrl = options.baseUrl ? normalizePath(options.baseUrl).replace(/\/$/, '') : undefined;
    this.aliases = Object.entries(options.aliases ?? {})
      .map(([key, value]) => ({
        prefix: key.replace(/\*$/, ''),
        wildcard: key.endsWith('*'),
        targets: (Array.isArray(value) ? value : [value]).map((t) => normalizePath(t).replace(/\*$/, '')),
      }))
      // Longest prefix first, so "@/components/*" beats "@/*".
      .sort((a, b) => b.prefix.length - a.prefix.length);
  }

  private probe(base: string): string | undefined {
    const p = joinPath(base);
    if (this.files.has(p)) return p;
    // TypeScript ESM style: "./util.js" refers to "./util.ts".
    const swapped = p.replace(/\.(m|c)?jsx?$/, '');
    if (swapped !== p) {
      for (const ext of this.extensions) if (this.files.has(swapped + ext)) return swapped + ext;
    }
    for (const ext of this.extensions) if (this.files.has(p + ext)) return p + ext;
    for (const ext of this.extensions) if (this.files.has(`${p}/index${ext}`)) return `${p}/index${ext}`;
    return undefined;
  }

  resolve(specifier: string, fromFile: string): Resolution {
    const spec = specifier.split('?')[0]!;
    const from = normalizePath(fromFile);
    if (spec.startsWith('.') || spec.startsWith('/')) {
      const target = spec.startsWith('/') ? spec.slice(1) : joinPath(dirname(from), spec);
      const hit = this.probe(target);
      if (hit) return { kind: 'internal', path: hit };
      return ASSET.test(spec) ? { kind: 'asset' } : { kind: 'unresolved' };
    }
    for (const a of this.aliases) {
      const matches = a.wildcard ? spec.startsWith(a.prefix) : spec === a.prefix;
      if (!matches) continue;
      const rest = a.wildcard ? spec.slice(a.prefix.length) : '';
      for (const t of a.targets) {
        const hit = this.probe(this.baseUrl && !t.startsWith('.') ? joinPath(this.baseUrl, t + rest) : t + rest);
        if (hit) return { kind: 'internal', path: hit };
      }
      return ASSET.test(spec) ? { kind: 'asset' } : { kind: 'unresolved' };
    }
    if (this.baseUrl) {
      const hit = this.probe(joinPath(this.baseUrl, spec));
      if (hit) return { kind: 'internal', path: hit };
    }
    if (ASSET.test(spec) && !spec.includes('/')) return { kind: 'asset' };
    return { kind: 'external', name: packageName(spec) };
  }
}
