import { existsSync, readdirSync, readFileSync } from 'node:fs';
import { join, relative, resolve } from 'node:path';
import { matchAny, normalizePath } from '@devchecks/core';
import { analyze, type AnalysisResult, type ArchCheckConfig } from './analyze.js';
import { presets } from './presets.js';
import { CODE_EXTENSIONS } from './resolve.js';

export * from './index.js';

export const DEFAULT_EXCLUDES = ['**/node_modules/**', '**/dist/**', '**/build/**', '**/coverage/**', '**/.next/**', '**/.nuxt/**', '**/*.d.ts'];

export interface ProjectConfig extends ArchCheckConfig {
  /** Start from a built-in preset; your settings are merged over it. */
  preset?: keyof typeof presets;
  /** Directories to scan, relative to the project root. Default ["src"] if it exists, else ["."]. */
  roots?: string[];
}

/** Reads JSON with comments and trailing commas (tsconfig.json style). */
export function readJsonc<T>(path: string): T {
  const text = readFileSync(path, 'utf8')
    .replace(/^\uFEFF/, '')
    .replace(/("(?:\\.|[^"\\])*")|\/\/[^\n]*|\/\*[\s\S]*?\*\//g, (_m, str: string | undefined) => str ?? '')
    .replace(/,(\s*[}\]])/g, '$1');
  return JSON.parse(text) as T;
}

/** Picks up compilerOptions.paths / baseUrl from tsconfig.json or jsconfig.json. */
export function readTsconfigAliases(projectDir: string): Pick<ArchCheckConfig, 'aliases' | 'baseUrl'> {
  for (const name of ['tsconfig.json', 'jsconfig.json']) {
    const file = join(projectDir, name);
    if (!existsSync(file)) continue;
    try {
      const cfg = readJsonc<{ compilerOptions?: { paths?: Record<string, string[]>; baseUrl?: string } }>(file);
      const base = cfg.compilerOptions?.baseUrl ? normalizePath(cfg.compilerOptions.baseUrl) : undefined;
      const paths = cfg.compilerOptions?.paths;
      if (!paths) return base && base !== '.' ? { baseUrl: base } : {};
      const prefix = base && base !== '.' ? `${base.replace(/\/$/, '')}/` : '';
      return { aliases: Object.fromEntries(Object.entries(paths).map(([k, v]) => [k, v.map((t) => normalizePath(prefix + t))])) };
    } catch {
      return {};
    }
  }
  return {};
}

export function collectFiles(projectDir: string, roots: string[], exclude: string[]): Record<string, string> {
  const files: Record<string, string> = {};
  const walk = (dir: string) => {
    for (const entry of readdirSync(dir, { withFileTypes: true })) {
      if (entry.name.startsWith('.')) continue;
      const full = join(dir, entry.name);
      const rel = normalizePath(relative(projectDir, full));
      if (entry.isDirectory()) {
        if (!matchAny(exclude, `${rel}/x`)) walk(full);
      } else if (CODE_EXTENSIONS.some((e) => entry.name.endsWith(e)) && !matchAny(exclude, rel)) {
        files[rel] = readFileSync(full, 'utf8');
      }
    }
  };
  for (const r of roots) {
    const abs = resolve(projectDir, r);
    if (existsSync(abs)) walk(abs);
  }
  return files;
}

export function resolveConfig(projectDir: string, config: ProjectConfig = {}): ProjectConfig {
  const base: ArchCheckConfig = config.preset ? presets[config.preset] : {};
  if (config.preset && !base) throw new Error(`Unknown preset "${config.preset}". Use one of: ${Object.keys(presets).join(', ')}`);
  const fromTs = readTsconfigAliases(projectDir);
  return {
    ...base,
    ...config,
    aliases: { ...base.aliases, ...fromTs.aliases, ...config.aliases },
    baseUrl: config.baseUrl ?? fromTs.baseUrl,
  };
}

export function analyzeProject(projectDir = '.', config: ProjectConfig = {}): AnalysisResult & { config: ProjectConfig } {
  const dir = resolve(projectDir);
  const resolved = resolveConfig(dir, config);
  const roots = resolved.roots ?? (existsSync(join(dir, 'src')) ? ['src'] : ['.']);
  const exclude = [...DEFAULT_EXCLUDES, ...(resolved.exclude ?? [])];
  const files = collectFiles(dir, roots, exclude);
  return { ...analyze(files, { ...resolved, exclude }), config: resolved };
}
