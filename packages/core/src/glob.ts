// Small, dependency-free glob matcher that behaves the same in browsers and Node.
// Supports **, *, ?, [abc], [!abc] and {a,b}. Patterns without a "/" match the
// basename at any depth (like .gitignore), so "*.min.js" matches "a/b/c.min.js".

const cache = new Map<string, RegExp>();

function escape(ch: string): string {
  return /[\\^$.+()|{}[\]*?/]/.test(ch) ? `\\${ch}` : ch;
}

function splitTopLevel(body: string): string[] {
  const parts: string[] = [];
  let depth = 0;
  let cur = '';
  for (const ch of body) {
    if (ch === '{') depth++;
    if (ch === '}') depth--;
    if (ch === ',' && depth === 0) {
      parts.push(cur);
      cur = '';
    } else cur += ch;
  }
  parts.push(cur);
  return parts;
}

function convert(glob: string): string {
  let re = '';
  for (let i = 0; i < glob.length; i++) {
    const ch = glob[i]!;
    if (ch === '*') {
      if (glob[i + 1] === '*') {
        i++;
        if (glob[i + 1] === '/') {
          i++;
          re += '(?:.*/)?';
        } else re += '.*';
      } else re += '[^/]*';
    } else if (ch === '?') {
      re += '[^/]';
    } else if (ch === '[') {
      const end = glob.indexOf(']', i + 1);
      if (end === -1) {
        re += '\\[';
        continue;
      }
      let cls = glob.slice(i + 1, end).replace(/\\/g, '\\\\');
      if (cls.startsWith('!')) cls = `^${cls.slice(1)}`;
      re += `[${cls}]`;
      i = end;
    } else if (ch === '{') {
      let depth = 1;
      let j = i + 1;
      for (; j < glob.length && depth > 0; j++) {
        if (glob[j] === '{') depth++;
        if (glob[j] === '}') depth--;
      }
      if (depth !== 0) {
        re += '\\{';
        continue;
      }
      const body = glob.slice(i + 1, j - 1);
      re += `(?:${splitTopLevel(body).map(convert).join('|')})`;
      i = j - 1;
    } else {
      re += escape(ch);
    }
  }
  return re;
}

export function normalizePath(p: string): string {
  return p.replace(/\\/g, '/').replace(/^\.\//, '');
}

export function globToRegExp(pattern: string): RegExp {
  let cached = cache.get(pattern);
  if (cached) return cached;
  let p = normalizePath(pattern);
  if (p.endsWith('/')) p += '**';
  if (!p.includes('/')) p = `**/${p}`;
  if (p.startsWith('/')) p = p.slice(1);
  cached = new RegExp(`^${convert(p)}$`);
  cache.set(pattern, cached);
  return cached;
}

export function matchGlob(pattern: string, path: string): boolean {
  return globToRegExp(pattern).test(normalizePath(path));
}

export function matchAny(patterns: readonly string[] | undefined, path: string): boolean {
  return !!patterns?.some((p) => matchGlob(p, path));
}
