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

/** Undoes Git's C-style quoting of unusual paths ("b/tab\there.js"). */
function unquotePath(path: string): string {
  if (!path.startsWith('"') || !path.endsWith('"')) return path;
  const bytes: number[] = [];
  const body = path.slice(1, -1);
  const simple: Record<string, number> = { n: 10, t: 9, r: 13, a: 7, b: 8, f: 12, v: 11, '"': 34, '\\': 92 };
  for (let i = 0; i < body.length; i++) {
    if (body[i] !== '\\') {
      bytes.push(...Buffer.from(body[i]!, 'utf8'));
      continue;
    }
    const octal = /^[0-7]{3}/.exec(body.slice(i + 1));
    if (octal) {
      bytes.push(parseInt(octal[0], 8));
      i += 3;
    } else {
      bytes.push(simple[body[i + 1]!] ?? body.charCodeAt(i + 1));
      i++;
    }
  }
  return Buffer.from(bytes).toString('utf8');
}

/** Line numbers added or changed in the staged diff, per path. */
export function stagedAddedLines(root: string): Map<string, Set<number>> {
  // The prefixes are set explicitly: diff.noprefix and diff.mnemonicPrefix in a user's Git
  // config change them, and a path that fails to match would mean its lines are never scanned.
  const diff = git(
    ['diff', '--cached', '-U0', '--no-color', '--no-ext-diff', '--src-prefix=a/', '--dst-prefix=b/', '--diff-filter=ACMR'],
    root,
  ).toString('utf8');
  const result = new Map<string, Set<number>>();
  let current: Set<number> | undefined;
  for (const line of diff.split('\n')) {
    if (line.startsWith('+++ ')) {
      const path = unquotePath(line.slice(4).replace(/\t$/, '')).replace(/^b\//, '');
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
