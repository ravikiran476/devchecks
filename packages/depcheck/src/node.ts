import { existsSync, readdirSync, readFileSync, realpathSync } from 'node:fs';
import { join, relative, resolve } from 'node:path';
import { normalizePath } from '@devchecks/core';
import { checkDependencies, type CheckOptions, type VulnerabilityFinding } from './analyze.js';
import { parseLockfile, type Dependency } from './lockfiles.js';

export * from './index.js';

export const LOCKFILES = ['package-lock.json', 'npm-shrinkwrap.json', 'pnpm-lock.yaml', 'yarn.lock'] as const;

export function findLockfile(dir: string): string | undefined {
  for (const name of LOCKFILES) {
    const p = join(dir, name);
    if (existsSync(p)) return p;
  }
  return undefined;
}

/**
 * Reads what is actually installed by walking node_modules (npm, Yarn classic and pnpm layouts).
 * This catches drift between the lockfile and the installed tree.
 */
export function readInstalledTree(projectDir: string): Dependency[] {
  const root = resolve(projectDir);
  const map = new Map<string, Dependency>();
  const visited = new Set<string>();

  const visitPackage = (dir: string) => {
    let real: string;
    try {
      real = realpathSync(dir);
    } catch {
      return;
    }
    if (visited.has(real)) return;
    visited.add(real);
    const manifest = join(dir, 'package.json');
    if (existsSync(manifest)) {
      try {
        const pkg = JSON.parse(readFileSync(manifest, 'utf8')) as { name?: string; version?: string; private?: boolean };
        if (pkg.name && pkg.version) {
          const key = `${pkg.name}@${pkg.version}`;
          const rel = normalizePath(relative(root, dir));
          const existing = map.get(key);
          if (existing) existing.paths!.push(rel);
          else map.set(key, { name: pkg.name, version: pkg.version, ecosystem: 'npm', paths: [rel] });
        }
      } catch {
        // unreadable manifest: skip
      }
    }
    visitModules(join(dir, 'node_modules'));
  };

  const visitModules = (dir: string) => {
    if (!existsSync(dir)) return;
    for (const entry of readdirSync(dir, { withFileTypes: true })) {
      if (!entry.isDirectory() && !entry.isSymbolicLink()) continue;
      const full = join(dir, entry.name);
      if (entry.name === '.bin' || entry.name === '.cache') continue;
      if (entry.name === '.pnpm') {
        for (const store of readdirSync(full, { withFileTypes: true })) {
          if (store.isDirectory()) visitModules(join(full, store.name, 'node_modules'));
        }
      } else if (entry.name.startsWith('@')) {
        for (const scoped of readdirSync(full)) visitPackage(join(full, scoped));
      } else if (!entry.name.startsWith('.')) {
        visitPackage(full);
      }
    }
  };

  visitModules(join(root, 'node_modules'));
  return [...map.values()];
}

export interface ProjectCheckOptions extends CheckOptions {
  /** Explicit lockfile. Defaults to the first lockfile found in the project directory. */
  lockfile?: string;
  /** Check the installed node_modules tree instead of the lockfile. */
  installed?: boolean;
}

export async function checkProject(
  projectDir = '.',
  options: ProjectCheckOptions = {},
): Promise<{ source: string; dependencies: Dependency[]; findings: VulnerabilityFinding[] }> {
  const dir = resolve(projectDir);
  let source: string;
  let deps: Dependency[];
  if (options.installed) {
    source = normalizePath(relative(process.cwd(), join(dir, 'node_modules'))) || 'node_modules';
    deps = readInstalledTree(dir);
    if (!deps.length) throw new Error(`No installed packages found under ${join(dir, 'node_modules')}`);
  } else {
    const lockfile = options.lockfile ? resolve(options.lockfile) : findLockfile(dir);
    if (!lockfile) throw new Error(`No lockfile found in ${dir} (looked for ${LOCKFILES.join(', ')}). Use --installed to scan node_modules.`);
    source = normalizePath(relative(process.cwd(), lockfile));
    deps = parseLockfile(lockfile, readFileSync(lockfile, 'utf8'));
  }
  const findings = await checkDependencies(deps, { source, ...options });
  return { source, dependencies: deps, findings };
}
