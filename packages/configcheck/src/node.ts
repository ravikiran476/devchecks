import { existsSync, readdirSync, readFileSync, statSync } from 'node:fs';
import { basename, dirname, join, relative, resolve } from 'node:path';
import { matchAny, normalizePath, type Finding } from '@devchecks/core';
import { checkConfigText, checkEnvDrift, validateEnv, type ConfigCheckOptions, type EnvSchema } from './index.js';
import { formatFor } from './parse.js';

export * from './index.js';

export const DEFAULT_EXCLUDES = [
  '**/node_modules/**', '**/dist/**', '**/build/**', '**/coverage/**', '**/.next/**', '**/.nuxt/**', '**/vendor/**',
  'package-lock.json', 'npm-shrinkwrap.json', 'pnpm-lock.yaml', 'yarn.lock', 'composer.lock', '*.min.json', '**/__snapshots__/**',
];

export interface ScanOptions extends ConfigCheckOptions {
  cwd?: string;
  exclude?: string[];
  maxFileSize?: number;
}

const TEMPLATES = ['.env.example', '.env.sample', '.env.template', '.env.dist', 'example.env'];

/** Finds and checks every config file under the targets, plus .env drift against templates. */
export function scanPaths(targets: string[], options: ScanOptions = {}): { findings: Finding[]; files: string[] } {
  const cwd = options.cwd ?? process.cwd();
  const exclude = [...DEFAULT_EXCLUDES, ...(options.exclude ?? [])];
  const maxSize = options.maxFileSize ?? 512 * 1024;
  const files: string[] = [];
  const walk = (dir: string) => {
    for (const e of readdirSync(dir, { withFileTypes: true })) {
      if (e.name === '.git') continue;
      const full = join(dir, e.name);
      const rel = normalizePath(relative(cwd, full));
      if (e.isDirectory()) {
        if (!matchAny(exclude, `${rel}/x`)) walk(full);
      } else if (e.isFile() && formatFor(e.name) && !matchAny(exclude, rel) && statSync(full).size <= maxSize) {
        files.push(full);
      }
    }
  };
  for (const t of targets) {
    const abs = resolve(cwd, t);
    if (statSync(abs).isDirectory()) walk(abs);
    else files.push(abs);
  }
  const findings: Finding[] = [];
  for (const f of files) findings.push(...checkConfigText(readFileSync(f, 'utf8'), normalizePath(relative(cwd, f)), options));

  // .env drift: compare each .env* file with a template in the same directory.
  for (const f of files) {
    const name = basename(f);
    if (!/^\.env(\.[\w-]+)?$/.test(name) || TEMPLATES.includes(name)) continue;
    const template = TEMPLATES.map((t) => join(dirname(f), t)).find((t) => existsSync(t));
    if (!template) continue;
    findings.push(...checkEnvDrift(readFileSync(template, 'utf8'), readFileSync(f, 'utf8'), { template: normalizePath(relative(cwd, template)), actual: normalizePath(relative(cwd, f)) }));
  }
  return { findings, files: files.map((f) => normalizePath(relative(cwd, f))) };
}

/** Validates the current process environment (e.g. in CI or a container entrypoint). */
export function checkRuntimeEnv(schema: EnvSchema, env: Record<string, string | undefined> = process.env): Finding[] {
  return validateEnv(env, schema, 'environment');
}
