// Extracts module specifiers from JS/TS/JSX source without a full parser.
// A small tokenizer skips comments, strings, template literals and regex literals,
// so specifiers inside them are never mistaken for imports.

export type ImportKind = 'import' | 'export' | 'dynamic' | 'require';

export interface ImportRecord {
  specifier: string;
  kind: ImportKind;
  /** `import type` / `export type`: erased at compile time, so not a runtime dependency. */
  typeOnly: boolean;
  line: number;
}

interface Token {
  t: 'id' | 'str' | 'punct';
  v: string;
  line: number;
}

const REGEX_PREV = new Set(['(', ',', '=', ':', '[', '!', '&', '|', '?', '{', '}', ';', '+', '-', '*', '%', '<', '>', '~', '^', '=>']);
const REGEX_KEYWORDS = new Set(['return', 'typeof', 'instanceof', 'in', 'of', 'new', 'delete', 'void', 'throw', 'case', 'do', 'else', 'yield', 'await']);

function tokenize(src: string): Token[] {
  const tokens: Token[] = [];
  let line = 1;
  let i = 0;
  const n = src.length;
  const prev = () => tokens[tokens.length - 1];
  // Template literal nesting: each entry counts open braces inside a ${...}.
  const templateStack: number[] = [];

  const readTemplate = () => {
    // Positioned just after ` or after the } that closes a ${...}
    while (i < n) {
      const ch = src[i]!;
      if (ch === '\\') {
        i += 2;
        continue;
      }
      if (ch === '\n') line++;
      if (ch === '`') {
        i++;
        tokens.push({ t: 'str', v: '`', line });
        return;
      }
      if (ch === '$' && src[i + 1] === '{') {
        i += 2;
        templateStack.push(0);
        tokens.push({ t: 'punct', v: '${', line });
        return;
      }
      i++;
    }
  };

  while (i < n) {
    const ch = src[i]!;
    if (ch === '\n') {
      line++;
      i++;
      continue;
    }
    if (ch === ' ' || ch === '\t' || ch === '\r') {
      i++;
      continue;
    }
    if (ch === '/' && src[i + 1] === '/') {
      while (i < n && src[i] !== '\n') i++;
      continue;
    }
    if (ch === '/' && src[i + 1] === '*') {
      const end = src.indexOf('*/', i + 2);
      const stop = end === -1 ? n : end + 2;
      for (let j = i; j < stop; j++) if (src[j] === '\n') line++;
      i = stop;
      continue;
    }
    if (ch === "'" || ch === '"') {
      let j = i + 1;
      let value = '';
      while (j < n && src[j] !== ch && src[j] !== '\n') {
        if (src[j] === '\\') {
          value += src[j + 1] ?? '';
          j += 2;
          continue;
        }
        value += src[j];
        j++;
      }
      tokens.push({ t: 'str', v: value, line });
      i = j + 1;
      continue;
    }
    if (ch === '`') {
      i++;
      // A template with no ${} is a plain string; record its raw text for import(`./x`).
      const start = i;
      readTemplate();
      const last = prev();
      if (last?.t === 'str' && last.v === '`') last.v = src.slice(start, i - 1).includes('${') ? '`' : src.slice(start, i - 1);
      continue;
    }
    if (ch === '}' && templateStack.length) {
      const depth = templateStack[templateStack.length - 1]!;
      if (depth === 0) {
        templateStack.pop();
        i++;
        readTemplate();
        continue;
      }
      templateStack[templateStack.length - 1] = depth - 1;
    }
    if (ch === '{' && templateStack.length) templateStack[templateStack.length - 1]!++;
    if (ch === '/') {
      const p = prev();
      const regexAllowed = !p || (p.t === 'punct' && REGEX_PREV.has(p.v)) || (p.t === 'id' && REGEX_KEYWORDS.has(p.v));
      if (regexAllowed) {
        let j = i + 1;
        let inClass = false;
        while (j < n && src[j] !== '\n') {
          const c = src[j]!;
          if (c === '\\') j++;
          else if (c === '[') inClass = true;
          else if (c === ']') inClass = false;
          else if (c === '/' && !inClass) break;
          j++;
        }
        i = j + 1;
        while (i < n && /[a-z]/i.test(src[i]!)) i++;
        tokens.push({ t: 'str', v: '/regex/', line });
        continue;
      }
    }
    if (/[A-Za-z_$]/.test(ch)) {
      let j = i + 1;
      while (j < n && /[\w$]/.test(src[j]!)) j++;
      tokens.push({ t: 'id', v: src.slice(i, j), line });
      i = j;
      continue;
    }
    if (ch === '=' && src[i + 1] === '>') {
      tokens.push({ t: 'punct', v: '=>', line });
      i += 2;
      continue;
    }
    tokens.push({ t: 'punct', v: ch, line });
    i++;
  }
  return tokens;
}

const isDot = (t: Token | undefined) => t?.t === 'punct' && t.v === '.';

export function extractImports(source: string): ImportRecord[] {
  const tokens = tokenize(source);
  const out: ImportRecord[] = [];
  for (let k = 0; k < tokens.length; k++) {
    const tok = tokens[k]!;
    if (tok.t !== 'id' || isDot(tokens[k - 1])) continue;
    const next = tokens[k + 1];

    if (tok.v === 'import') {
      if (!next || isDot(next)) continue; // import.meta
      if (next.t === 'punct' && next.v === '(') {
        const arg = tokens[k + 2];
        const close = tokens[k + 3];
        if (arg?.t === 'str' && arg.v !== '`' && close?.v === ')') {
          out.push({ specifier: arg.v, kind: 'dynamic', typeOnly: tokens[k - 1]?.v === 'typeof', line: tok.line });
        }
        continue;
      }
      if (next.t === 'str') {
        out.push({ specifier: next.v, kind: 'import', typeOnly: false, line: tok.line });
        continue;
      }
      const typeOnly = next.t === 'id' && next.v === 'type' && tokens[k + 2]?.v !== 'from' && tokens[k + 2]?.v !== ',';
      // Scan to `from '<spec>'`, stopping at statement boundaries.
      for (let j = k + 1; j < Math.min(tokens.length, k + 400); j++) {
        const t = tokens[j]!;
        if (t.t === 'id' && t.v === 'from' && tokens[j + 1]?.t === 'str') {
          out.push({ specifier: tokens[j + 1]!.v, kind: 'import', typeOnly, line: tok.line });
          k = j + 1;
          break;
        }
        if (t.t === 'punct' && (t.v === ';' || t.v === '(' || t.v === '=')) {
          // `import x = require('y')` is picked up by the require branch.
          break;
        }
      }
      continue;
    }

    if (tok.v === 'export') {
      let j = k + 1;
      let typeOnly = false;
      if (tokens[j]?.v === 'type' && (tokens[j + 1]?.v === '{' || tokens[j + 1]?.v === '*')) {
        typeOnly = true;
        j++;
      }
      const first = tokens[j];
      if (first?.v === '*') {
        j++;
        if (tokens[j]?.v === 'as') j += 2;
      } else if (first?.v === '{') {
        while (j < tokens.length && tokens[j]!.v !== '}') j++;
        j++;
      } else continue;
      if (tokens[j]?.v === 'from' && tokens[j + 1]?.t === 'str') {
        out.push({ specifier: tokens[j + 1]!.v, kind: 'export', typeOnly, line: tok.line });
        k = j + 1;
      }
      continue;
    }

    if (tok.v === 'require' && next?.v === '(') {
      const arg = tokens[k + 2];
      if (arg?.t === 'str' && arg.v !== '`' && tokens[k + 3]?.v === ')') {
        out.push({ specifier: arg.v, kind: 'require', typeOnly: false, line: tok.line });
      }
    }
  }
  return out;
}

/** For Vue / Svelte single-file components: blank out everything except <script> blocks, keeping line numbers. */
export function scriptBlocks(source: string): string {
  let out = '';
  let pos = 0;
  const re = /<script\b[^>]*>([\s\S]*?)<\/script>/gi;
  for (const m of source.matchAll(re)) {
    const start = (m.index ?? 0) + m[0].indexOf('>') + 1;
    out += source.slice(pos, start).replace(/[^\n]/g, ' ');
    out += m[1];
    pos = start + m[1]!.length;
  }
  out += source.slice(pos).replace(/[^\n]/g, ' ');
  return out;
}

export function importsForFile(path: string, source: string): ImportRecord[] {
  return extractImports(/\.(vue|svelte|astro)$/.test(path) ? scriptBlocks(source) : source);
}
