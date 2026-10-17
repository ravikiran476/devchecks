import { existsSync, readdirSync, readFileSync, statSync, writeFileSync, chmodSync, mkdirSync } from 'node:fs';
import { isAbsolute, join, relative, resolve } from 'node:path';
import { normalizePath } from '@devchecks/core';
import { hooksDir, readStagedBlobs, repoRoot, stagedAddedLines, stagedPaths } from './git.js';
import { isExcluded, scanFiles, type ScanResult, type SecretCheckConfig } from './scan.js';

export * from './index.js';
export { repoRoot, stagedPaths } from './git.js';

export interface StagedScanOptions {
  cwd?: string;
  config?: SecretCheckConfig;
  /** Only report secrets on lines added by this commit. Default false (scan whole staged files). */
  changedLinesOnly?: boolean;
}

/** Scans the content staged for the next commit (the Git index), not the working tree. */
export function scanStaged(options: StagedScanOptions = {}): ScanResult & { files: string[] } {
  const root = repoRoot(options.cwd);
  const config = options.config ?? {};
  const paths = stagedPaths(root);
  const wanted = paths.filter((p) => !isExcluded(p, config));
  const blobs = readStagedBlobs(root, wanted);
  const added = options.changedLinesOnly ? stagedAddedLines(root) : undefined;
  const files = wanted.flatMap((p) => {
    const blob = blobs.get(p);
    if (!blob) return [];
    return [{ path: p, content: blob.includes(0) ? '\u0000' : blob.toString('utf8'), onlyLines: added?.get(p) ?? (added ? new Set<number>() : undefined) }];
  });
  const result = scanFiles(files, config);
  result.skipped.unshift(...paths.filter((p) => !wanted.includes(p)).map((file) => ({ file, reason: 'excluded' })));
  return { ...result, files: paths };
}

function walk(dir: string, root: string, config: SecretCheckConfig, out: string[]): void {
  for (const entry of readdirSync(dir, { withFileTypes: true })) {
    if (entry.name === '.git') continue;
    const full = join(dir, entry.name);
    const rel = normalizePath(relative(root, full));
    if (entry.isDirectory()) {
      if (!isExcluded(`${rel}/x`, config)) walk(full, root, config, out);
    } else if (entry.isFile() && !isExcluded(rel, config)) {
      out.push(full);
    }
  }
}

/** Scans files or directories on disk (useful for CI or a one-off audit of the working tree). */
export function scanPaths(targets: string[], options: { cwd?: string; config?: SecretCheckConfig } = {}): ScanResult {
  const cwd = options.cwd ?? process.cwd();
  const config = options.config ?? {};
  const maxSize = config.maxFileSize ?? 1024 * 1024;
  const files: string[] = [];
  for (const t of targets) {
    const abs = isAbsolute(t) ? t : resolve(cwd, t);
    if (statSync(abs).isDirectory()) walk(abs, cwd, config, files);
    else files.push(abs);
  }
  const tooLarge: ScanResult['skipped'] = [];
  const contents = files.flatMap((f) => {
    const path = normalizePath(relative(cwd, f));
    if (statSync(f).size > maxSize) {
      tooLarge.push({ file: path, reason: `larger than ${maxSize} bytes` });
      return [];
    }
    return [{ path, content: readFileSync(f, 'utf8') }];
  });
  const result = scanFiles(contents, config);
  result.skipped.push(...tooLarge);
  return result;
}

const HOOK_MARKER = '# installed by @devchecks/secretcheck';

/** Installs a Git pre-commit hook that runs `secretcheck staged`. */
export function installHook(options: { cwd?: string; force?: boolean } = {}): string {
  const root = repoRoot(options.cwd);
  const dir = resolve(root, hooksDir(root));
  const hook = join(dir, 'pre-commit');
  if (existsSync(hook) && !readFileSync(hook, 'utf8').includes(HOOK_MARKER) && !options.force) {
    throw new Error(
      `${hook} already exists. Add "npx --no-install secretcheck staged" to it (or to your husky/lefthook config), or re-run with --force to replace it.`,
    );
  }
  mkdirSync(dir, { recursive: true });
  writeFileSync(hook, `#!/bin/sh\n${HOOK_MARKER}\nnpx --no-install secretcheck staged || exit $?\n`);
  try {
    chmodSync(hook, 0o755);
  } catch {
    // chmod is a no-op on some Windows filesystems; Git for Windows runs hooks regardless.
  }
  return hook;
}
