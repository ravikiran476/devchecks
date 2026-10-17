// Reads staged (index) content from Git. Node only.
import { execFileSync } from 'node:child_process';

function git(args: string[], cwd: string, input?: string): Buffer {
  return execFileSync('git', ['-c', 'core.quotePath=false', ...args], {
    cwd,
    input,
    maxBuffer: 512 * 1024 * 1024,
    stdio: ['pipe', 'pipe', 'pipe'],
  });
}

export function repoRoot(cwd = process.cwd()): string {
  try {
    return git(['rev-parse', '--show-toplevel'], cwd).toString('utf8').trim();
  } catch {
    throw new Error(`${cwd} is not inside a Git repository`);
  }
}

/** Paths (relative to the repo root) that are added, copied, modified or renamed in the index. */
export function stagedPaths(root: string): string[] {
  const out = git(['diff', '--cached', '--name-only', '-z', '--diff-filter=ACMR'], root).toString('utf8');
  return out.split('\0').filter(Boolean);
}

/**
 * Reads the staged blob for each path in one `git cat-file --batch` call.
 * This is what will actually be committed, which can differ from the working tree.
 */
export function readStagedBlobs(root: string, paths: string[]): Map<string, Buffer> {
  const result = new Map<string, Buffer>();
  if (!paths.length) return result;
  const out = git(['cat-file', '--batch'], root, paths.map((p) => `:${p}`).join('\n') + '\n');
  let pos = 0;
  for (const p of paths) {
    const nl = out.indexOf(0x0a, pos);
    if (nl === -1) break;
    const header = out.subarray(pos, nl).toString('utf8');
    pos = nl + 1;
    if (header.endsWith(' missing')) continue;
    const size = Number(header.split(' ')[2]);
    result.set(p, out.subarray(pos, pos + size));
    pos += size + 1; // content is followed by a newline
  }
  return result;
}

/** Line numbers added or changed in the staged diff, per path. */
export function stagedAddedLines(root: string): Map<string, Set<number>> {
  const diff = git(['diff', '--cached', '-U0', '--no-color', '--no-ext-diff', '--diff-filter=ACMR'], root).toString('utf8');
  const result = new Map<string, Set<number>>();
  let current: Set<number> | undefined;
  for (const line of diff.split('\n')) {
    if (line.startsWith('+++ ')) {
      const path = line.slice(4).replace(/^b\//, '').replace(/\t$/, '');
      current = path === '/dev/null' ? undefined : new Set();
      if (current) result.set(path, current);
      continue;
    }
    const hunk = /^@@ -\d+(?:,\d+)? \+(\d+)(?:,(\d+))? @@/.exec(line);
    if (hunk && current) {
      const start = Number(hunk[1]);
      const count = hunk[2] === undefined ? 1 : Number(hunk[2]);
      for (let i = 0; i < count; i++) current.add(start + i);
    }
  }
  return result;
}

export function hooksDir(root: string): string {
  return git(['rev-parse', '--git-path', 'hooks'], root).toString('utf8').trim();
}
