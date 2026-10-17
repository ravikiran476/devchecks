import { isMap, isScalar, isSeq, LineCounter, parseDocument, type Node as YamlNode } from 'yaml';

/** One scalar setting with its location. Values never leave the tool except as booleans/lengths. */
export interface Entry {
  /** Dotted path, e.g. "server.cors.origin[0]". */
  path: string;
  /** Nearest object key (array items inherit their parent's key). */
  key: string;
  /** Keys from the root to this entry. */
  keys: string[];
  value: unknown;
  line: number;
}

export interface ParsedConfig {
  format: 'env' | 'json' | 'yaml' | 'ini';
  entries: Entry[];
  errors: Array<{ message: string; line: number }>;
  /** Plain data, for structural checks. */
  data?: unknown;
}

export function formatFor(file: string): ParsedConfig['format'] | undefined {
  const base = file.replace(/\\/g, '/').split('/').pop()!.toLowerCase();
  if (base === '.env' || base.startsWith('.env.') || base.endsWith('.env')) return 'env';
  if (base === '.npmrc' || base === '.yarnrc' || base.endsWith('.ini') || base.endsWith('.properties')) return 'ini';
  if (/\.(json|jsonc|json5)$/.test(base) || /^\.(eslintrc|babelrc|prettierrc|swcrc)$/.test(base)) return 'json';
  if (/\.(ya?ml)$/.test(base)) return 'yaml';
  return undefined;
}

const unquote = (v: string) => {
  const t = v.trim();
  if ((t.startsWith('"') && t.endsWith('"')) || (t.startsWith("'") && t.endsWith("'"))) return t.slice(1, -1);
  return t;
};

/** .env files: KEY=value, `export KEY=value`, quotes, # comments. */
export function parseDotenv(text: string): ParsedConfig {
  const entries: Entry[] = [];
  const errors: ParsedConfig['errors'] = [];
  text.split(/\r?\n/).forEach((raw, i) => {
    const line = raw.trim();
    if (!line || line.startsWith('#')) return;
    const m = /^(?:export\s+)?([A-Za-z_][A-Za-z0-9_.-]*)\s*=\s*(.*)$/.exec(line);
    if (!m) {
      errors.push({ message: `Not a KEY=value line`, line: i + 1 });
      return;
    }
    let value = m[2]!;
    if (!/^["']/.test(value)) value = value.replace(/\s+#.*$/, '');
    entries.push({ path: m[1]!, key: m[1]!, keys: [m[1]!], value: unquote(value), line: i + 1 });
  });
  return { format: 'env', entries, errors };
}

function parseIni(text: string): ParsedConfig {
  const entries: Entry[] = [];
  let section = '';
  text.split(/\r?\n/).forEach((raw, i) => {
    const line = raw.trim();
    if (!line || /^[;#]/.test(line)) return;
    const s = /^\[(.+)\]$/.exec(line);
    if (s) {
      section = s[1]!;
      return;
    }
    const m = /^([^=:\s]+)\s*[=:]\s*(.*)$/.exec(line);
    if (m) entries.push({ path: section ? `${section}.${m[1]}` : m[1]!, key: m[1]!, keys: section ? [section, m[1]!] : [m[1]!], value: coerce(unquote(m[2]!)), line: i + 1 });
  });
  return { format: 'ini', entries, errors: [] };
}

function coerce(v: string): unknown {
  if (/^(true|false)$/i.test(v)) return v.toLowerCase() === 'true';
  if (/^-?\d+(\.\d+)?$/.test(v)) return Number(v);
  return v;
}

/** Blanks out // and /* comments and trailing commas without moving any characters. */
function stripJsonc(text: string): string {
  return text
    .replace(/("(?:\\.|[^"\\])*")|\/\/[^\n]*|\/\*[\s\S]*?\*\//g, (m, str: string | undefined) => str ?? m.replace(/[^\n]/g, ' '))
    .replace(/,(\s*[}\]])/g, ' $1');
}

/** Offset of the first JSON syntax error (V8 messages no longer always include a position). */
export function jsonErrorOffset(text: string): number {
  let i = 0;
  const fail = (): never => {
    throw i;
  };
  const ws = () => {
    while (i < text.length && /\s/.test(text[i]!)) i++;
  };
  const str = () => {
    i++;
    while (i < text.length && text[i] !== '"') {
      if (text[i] === '\n') fail();
      i += text[i] === '\\' ? 2 : 1;
    }
    if (text[i] !== '"') fail();
    i++;
  };
  const value = (): void => {
    ws();
    const c = text[i];
    if (c === '{') {
      i++;
      ws();
      if (text[i] === '}') return void i++;
      for (;;) {
        ws();
        if (text[i] !== '"') fail();
        str();
        ws();
        if (text[i] !== ':') fail();
        i++;
        value();
        ws();
        if (text[i] === ',') i++;
        else if (text[i] === '}') return void i++;
        else fail();
      }
    }
    if (c === '[') {
      i++;
      ws();
      if (text[i] === ']') return void i++;
      for (;;) {
        value();
        ws();
        if (text[i] === ',') i++;
        else if (text[i] === ']') return void i++;
        else fail();
      }
    }
    if (c === '"') return str();
    const m = /^(-?\d+(\.\d+)?([eE][+-]?\d+)?|true|false|null)/.exec(text.slice(i, i + 400));
    if (!m) fail();
    i += m![0].length;
  };
  try {
    value();
    ws();
    return i < text.length ? i : -1;
  } catch (pos) {
    return pos as number;
  }
}

function jsonErrorLine(text: string): number {
  const pos = jsonErrorOffset(text);
  return pos < 0 ? 1 : text.slice(0, pos).split('\n').length;
}

function flatten(node: YamlNode | null | undefined, keys: string[], path: string, lc: LineCounter, out: Entry[]): void {
  if (!node) return;
  if (isMap(node)) {
    for (const pair of node.items) {
      const k = isScalar(pair.key) ? String(pair.key.value) : String(pair.key);
      flatten(pair.value as YamlNode, [...keys, k], path ? `${path}.${k}` : k, lc, out);
    }
  } else if (isSeq(node)) {
    node.items.forEach((item, i) => flatten(item as YamlNode, keys, `${path}[${i}]`, lc, out));
  } else if (isScalar(node)) {
    out.push({ path, key: keys[keys.length - 1] ?? '', keys, value: node.value, line: node.range ? lc.linePos(node.range[0]).line : 1 });
  }
}

function parseStructured(text: string, format: 'json' | 'yaml', file: string): ParsedConfig {
  const errors: ParsedConfig['errors'] = [];
  let source = text;
  if (format === 'json') {
    const lenient = /\.(jsonc|json5)$|tsconfig|jsconfig|\.eslintrc|\.vscode|devcontainer|\.babelrc|\.swcrc/i.test(file);
    if (lenient) source = stripJsonc(text);
    try {
      JSON.parse(source);
    } catch (err) {
      const message = (err as Error).message;
      return { format, entries: [], errors: [{ message: `Invalid JSON: ${message}`, line: jsonErrorLine(source) }] };
    }
  }
  const docs = format === 'yaml' && /(^|\n)---\s*(\n|$)/.test(source) ? splitDocs(source) : [source];
  const entries: Entry[] = [];
  const data: unknown[] = [];
  let offset = 0;
  for (const part of docs) {
    const lc = new LineCounter();
    const doc = parseDocument(part, { lineCounter: lc, uniqueKeys: true, prettyErrors: false });
    for (const e of doc.errors) errors.push({ message: e.message.split('\n')[0]!, line: lc.linePos(e.pos[0]).line + offset });
    const before = entries.length;
    flatten(doc.contents as YamlNode, [], '', lc, entries);
    for (let i = before; i < entries.length; i++) entries[i]!.line += offset;
    data.push(doc.toJS({ maxAliasCount: 100 }));
    offset += part.split('\n').length;
  }
  return { format, entries, errors, data: data.length === 1 ? data[0] : data };
}

/** Splits multi-document YAML (Kubernetes manifests) while keeping line offsets. */
function splitDocs(text: string): string[] {
  const parts: string[] = [];
  let cur: string[] = [];
  for (const line of text.split('\n')) {
    if (/^---\s*$/.test(line) && cur.length) {
      parts.push(cur.join('\n'));
      cur = [''];
    } else cur.push(line);
  }
  parts.push(cur.join('\n'));
  return parts;
}

export function parseConfig(text: string, file: string): ParsedConfig | undefined {
  const format = formatFor(file);
  if (!format) return undefined;
  if (format === 'env') return parseDotenv(text);
  if (format === 'ini') return parseIni(text);
  return parseStructured(text, format, file);
}
