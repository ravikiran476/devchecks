import { isSemver } from './semver.js';

export interface Dependency {
  name: string;
  version: string;
  ecosystem: 'npm';
  /** True when the package is only reachable through devDependencies. */
  dev?: boolean;
  /** Where the package appears (lockfile keys or install paths). */
  paths?: string[];
}

export type LockfileKind = 'package-lock' | 'yarn' | 'pnpm' | 'npm-ls';

function add(map: Map<string, Dependency>, name: string, version: string, dev: boolean, path?: string): void {
  if (!name || !isSemver(version)) return; // skip git, file:, link: and tarball URLs
  const key = `${name}@${version}`;
  const existing = map.get(key);
  if (existing) {
    existing.dev = existing.dev && dev;
    if (path) (existing.paths ??= []).push(path);
  } else {
    map.set(key, { name, version, ecosystem: 'npm', dev, paths: path ? [path] : [] });
  }
}

interface PackageLockEntry {
  name?: string;
  version?: string;
  dev?: boolean;
  link?: boolean;
  dependencies?: Record<string, PackageLockEntry>;
}

/** package-lock.json / npm-shrinkwrap.json, lockfileVersion 1, 2 and 3. */
export function parsePackageLock(text: string): Dependency[] {
  const lock = JSON.parse(text) as { packages?: Record<string, PackageLockEntry>; dependencies?: Record<string, PackageLockEntry> };
  const map = new Map<string, Dependency>();
  if (lock.packages) {
    for (const [key, entry] of Object.entries(lock.packages)) {
      if (!key || entry.link || !entry.version) continue;
      const idx = key.lastIndexOf('node_modules/');
      if (idx === -1) continue; // workspace package, not a dependency
      add(map, entry.name ?? key.slice(idx + 'node_modules/'.length), entry.version, !!entry.dev, key);
    }
  } else if (lock.dependencies) {
    const walk = (deps: Record<string, PackageLockEntry>, prefix: string) => {
      for (const [name, entry] of Object.entries(deps)) {
        const path = `${prefix}node_modules/${name}`;
        if (entry.version) add(map, name, entry.version, !!entry.dev, path);
        if (entry.dependencies) walk(entry.dependencies, `${path}/`);
      }
    };
    walk(lock.dependencies, '');
  }
  return [...map.values()];
}

function nameFromSpec(spec: string): string {
  const s = spec.trim().replace(/^"|"$/g, '');
  const at = s.indexOf('@', 1);
  return at === -1 ? s : s.slice(0, at);
}

/** yarn.lock for Yarn classic (v1) and Yarn Berry (v2+). */
export function parseYarnLock(text: string): Dependency[] {
  const map = new Map<string, Dependency>();
  let name: string | undefined;
  let header = '';
  for (const line of text.split(/\r?\n/)) {
    if (!line || line.startsWith('#')) continue;
    if (!/^\s/.test(line)) {
      header = line.replace(/:$/, '');
      const specs = header.split(/,\s*/).map((s) => s.replace(/^"|"$/g, ''));
      const local = specs.some((s) => /@(?:workspace|link|portal|file):/.test(s));
      name = header === '__metadata' || local ? undefined : nameFromSpec(specs[0] ?? '');
      continue;
    }
    const v = /^\s+version:?\s+"?([^"\s]+)"?\s*$/.exec(line);
    if (v && name) {
      add(map, name, v[1]!, false, header);
      name = undefined;
    }
  }
  return [...map.values()];
}

/** pnpm-lock.yaml, lockfile versions 5.x, 6.x and 9.x. */
export function parsePnpmLock(text: string): Dependency[] {
  const map = new Map<string, Dependency>();
  let inPackages = false;
  let current: { name: string; version: string; key: string } | undefined;
  let dev = false;
  const flush = () => {
    if (current) add(map, current.name, current.version, dev, current.key);
    current = undefined;
    dev = false;
  };
  for (const line of text.split(/\r?\n/)) {
    if (/^\S/.test(line)) {
      flush();
      inPackages = /^packages:\s*$/.test(line);
      continue;
    }
    if (!inPackages) continue;
    const key = /^ {2}['"]?([^\s'"][^'"]*?)['"]?:\s*$/.exec(line);
    if (key) {
      flush();
      let id = key[1]!.replace(/^\//, '').replace(/\(.*$/, '');
      let name: string;
      let version: string;
      const at = id.lastIndexOf('@');
      if (at > 0) {
        name = id.slice(0, at);
        version = id.slice(at + 1);
      } else {
        // v5 style: /name/1.2.3 or /@scope/name/1.2.3_peer@1.0.0
        id = id.replace(/_.*$/, '');
        const slash = id.lastIndexOf('/');
        name = id.slice(0, slash);
        version = id.slice(slash + 1);
      }
      current = { name, version, key: key[1]! };
      continue;
    }
    if (current && /^ {4}dev: true\s*$/.test(line)) dev = true;
  }
  flush();
  return [...map.values()];
}

interface NpmLsNode {
  version?: string;
  dev?: boolean;
  dependencies?: Record<string, NpmLsNode>;
}

/** Output of `npm ls --all --json` (the installed tree). */
export function parseNpmLs(text: string): Dependency[] {
  const root = JSON.parse(text) as NpmLsNode;
  const map = new Map<string, Dependency>();
  const walk = (deps: Record<string, NpmLsNode> | undefined, path: string) => {
    for (const [name, node] of Object.entries(deps ?? {})) {
      const p = path ? `${path} > ${name}` : name;
      if (node.version) add(map, name, node.version, !!node.dev, p);
      walk(node.dependencies, p);
    }
  };
  walk(root.dependencies, '');
  return [...map.values()];
}

export function detectLockfileKind(filename: string, text: string): LockfileKind {
  const base = filename.replace(/\\/g, '/').split('/').pop() ?? filename;
  if (base === 'yarn.lock') return 'yarn';
  if (base === 'pnpm-lock.yaml' || base === 'pnpm-lock.yml') return 'pnpm';
  if (base === 'package-lock.json' || base === 'npm-shrinkwrap.json') return 'package-lock';
  const t = text.trimStart();
  if (t.startsWith('{')) return /"lockfileVersion"/.test(t) ? 'package-lock' : 'npm-ls';
  if (/^lockfileVersion:/m.test(t)) return 'pnpm';
  return 'yarn';
}

export function parseLockfile(filename: string, text: string): Dependency[] {
  switch (detectLockfileKind(filename, text)) {
    case 'yarn':
      return parseYarnLock(text);
    case 'pnpm':
      return parsePnpmLock(text);
    case 'npm-ls':
      return parseNpmLs(text);
    default:
      return parsePackageLock(text);
  }
}
