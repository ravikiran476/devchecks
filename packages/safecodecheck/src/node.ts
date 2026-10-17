import { readdirSync, readFileSync, statSync } from 'node:fs';
import { isAbsolute, join, relative, resolve } from 'node:path';
import { matchAny, normalizePath, type Finding } from '@devchecks/core';
import { analyzeSource, SCRIPT_EXTENSIONS, TEMPLATE_EXTENSIONS, type SafeCodeCheckOptions } from './analyze.js';

export * from './index.js';

export const DEFAULT_EXCLUDES = ['**/node_modules/**', '**/dist/**', '**/build/**', '**/coverage/**', '**/.next/**', '**/.nuxt/**', '*.min.js', '*.d.ts', '**/vendor/**'];

export interface ProjectOptions extends SafeCodeCheckOptions {
  cwd?: string;
  exclude?: string[];
  /** Also scan test files (*.test.*, *.spec.*, __tests__). Default false. */
  includeTests?: boolean;
}

const TESTS = ['*.test.*', '*.spec.*', '**/__tests__/**', '**/test/**', '**/tests/**', '**/e2e/**'];

export function scanPaths(targets: string[], options: ProjectOptions = {}): { findings: Finding[]; files: number; errors: Array<{ file: string; error: string }> } {
  const cwd = options.cwd ?? process.cwd();
  const exclude = [...DEFAULT_EXCLUDES, ...(options.includeTests ? [] : TESTS), ...(options.exclude ?? [])];
  const files: string[] = [];
  const walk = (dir: string) => {
    for (const entry of readdirSync(dir, { withFileTypes: true })) {
      if (entry.name.startsWith('.')) continue;
      const full = join(dir, entry.name);
      const rel = normalizePath(relative(cwd, full));
      if (entry.isDirectory()) {
        if (!matchAny(exclude, `${rel}/x`)) walk(full);
      } else if ((SCRIPT_EXTENSIONS.test(entry.name) || TEMPLATE_EXTENSIONS.test(entry.name)) && !matchAny(exclude, rel)) {
        files.push(full);
      }
    }
  };
  for (const t of targets) {
    const abs = isAbsolute(t) ? t : resolve(cwd, t);
    if (statSync(abs).isDirectory()) walk(abs);
    else files.push(abs);
  }
  const findings: Finding[] = [];
  const errors: Array<{ file: string; error: string }> = [];
  for (const f of files) {
    const rel = normalizePath(relative(cwd, f));
    const result = analyzeSource(readFileSync(f, 'utf8'), rel, options);
    findings.push(...result.findings);
    if (result.error) errors.push({ file: rel, error: result.error });
  }
  return { findings, files: files.length, errors };
}
