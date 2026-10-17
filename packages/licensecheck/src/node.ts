import { existsSync, readdirSync, readFileSync, realpathSync } from 'node:fs';
import { join, relative, resolve } from 'node:path';
import { normalizePath } from '@devchecks/core';
import { checkLicenses, fetchMissingLicenses, fromPackageLock, type CheckOptions, type LicenseFinding, type PackageLicense } from './check.js';
import { normalizeLicense } from './spdx.js';

export * from './index.js';

const LICENSE_FILE = /^(licen[cs]e|copying|notice)(\.(md|txt|markdown))?$/i;

interface Manifest {
  name?: string;
  version?: string;
  license?: unknown;
  licenses?: unknown;
  repository?: string | { url?: string };
  author?: string | { name?: string };
}

/** Walks node_modules (npm, Yarn classic and pnpm layouts), reading licenses and license texts. */
export function readInstalledLicenses(projectDir: string, options: { texts?: boolean } = {}): PackageLicense[] {
  const root = resolve(projectDir);
  const out = new Map<string, PackageLicense>();
  const visited = new Set<string>();
  const devNames = devOnlyNames(root);

  const visitPackage = (dir: string) => {
    let real: string;
    try {
      real = realpathSync(dir);
    } catch {
      return;
    }
    if (visited.has(real)) return;
    visited.add(real);
    const manifestPath = join(dir, 'package.json');
    if (existsSync(manifestPath)) {
      try {
        const m = JSON.parse(readFileSync(manifestPath, 'utf8')) as Manifest;
        if (m.name && m.version && !out.has(`${m.name}@${m.version}`)) {
          const n = normalizeLicense(m.license, m.licenses);
          let licenseText: string | undefined;
          if (options.texts) {
            const file = readdirSync(dir).find((f) => LICENSE_FILE.test(f));
            if (file) licenseText = readFileSync(join(dir, file), 'utf8').slice(0, 20000);
          }
          out.set(`${m.name}@${m.version}`, {
            name: m.name,
            version: m.version,
            license: n.expression,
            declared: n.raw,
            path: normalizePath(relative(root, dir)),
            dev: devNames?.has(m.name),
            licenseText,
            repository: typeof m.repository === 'string' ? m.repository : m.repository?.url,
            author: typeof m.author === 'string' ? m.author : m.author?.name,
          });
        }
      } catch {
        // unreadable manifest
      }
    }
    visitModules(join(dir, 'node_modules'));
  };
  const visitModules = (dir: string) => {
    if (!existsSync(dir)) return;
    for (const e of readdirSync(dir, { withFileTypes: true })) {
      if (!e.isDirectory() && !e.isSymbolicLink()) continue;
      const full = join(dir, e.name);
      if (e.name === '.bin' || e.name === '.cache') continue;
      if (e.name === '.pnpm') {
        for (const s of readdirSync(full, { withFileTypes: true })) if (s.isDirectory()) visitModules(join(full, s.name, 'node_modules'));
      } else if (e.name.startsWith('@')) {
        for (const s of readdirSync(full)) visitPackage(join(full, s));
      } else if (!e.name.startsWith('.')) visitPackage(full);
    }
  };
  visitModules(join(root, 'node_modules'));
  return [...out.values()];
}

/** Names that package-lock marks as dev-only, used to label packages found in node_modules. */
function devOnlyNames(root: string): Set<string> | undefined {
  const lock = join(root, 'package-lock.json');
  if (!existsSync(lock)) return undefined;
  try {
    const pkgs = fromPackageLock(readFileSync(lock, 'utf8'));
    const prod = new Set(pkgs.filter((p) => !p.dev).map((p) => p.name));
    return new Set(pkgs.filter((p) => p.dev && !prod.has(p.name)).map((p) => p.name));
  } catch {
    return undefined;
  }
}

export interface ProjectOptions extends CheckOptions {
  /** "node_modules" (default when installed), "lockfile" (package-lock.json) or "auto". */
  from?: 'auto' | 'node_modules' | 'lockfile';
  /** Look up licenses missing from the lockfile in the npm registry. Default true for lockfiles. */
  registry?: boolean;
  texts?: boolean;
}

export async function inventoryProject(projectDir = '.', options: ProjectOptions = {}): Promise<{ packages: PackageLicense[]; source: string }> {
  const dir = resolve(projectDir);
  const hasModules = existsSync(join(dir, 'node_modules'));
  const lock = join(dir, 'package-lock.json');
  const from = options.from ?? 'auto';
  if (from === 'node_modules' || (from === 'auto' && hasModules)) {
    return { packages: readInstalledLicenses(dir, { texts: options.texts }), source: normalizePath(relative(process.cwd(), join(dir, 'node_modules'))) || 'node_modules' };
  }
  if (!existsSync(lock)) throw new Error(`No node_modules or package-lock.json in ${dir}. Install dependencies first (yarn and pnpm projects need node_modules).`);
  const packages = fromPackageLock(readFileSync(lock, 'utf8'));
  if (options.registry !== false) await fetchMissingLicenses(packages);
  return { packages, source: normalizePath(relative(process.cwd(), lock)) };
}

export async function checkProject(projectDir = '.', options: ProjectOptions = {}): Promise<{ packages: PackageLicense[]; findings: LicenseFinding[]; source: string }> {
  const { packages, source } = await inventoryProject(projectDir, options);
  return { packages, source, findings: checkLicenses(packages, { source, ...options }) };
}
