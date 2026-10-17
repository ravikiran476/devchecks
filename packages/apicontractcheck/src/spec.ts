import { parse as parseYaml } from 'yaml';

export type Schema = Record<string, unknown> & { $ref?: string };

export interface Operation {
  operationId?: string;
  summary?: string;
  deprecated?: boolean;
  parameters?: Parameter[];
  requestBody?: { required?: boolean; content?: Record<string, { schema?: Schema }>; $ref?: string };
  responses?: Record<string, Response>;
}

export interface Parameter {
  name: string;
  in: 'query' | 'header' | 'path' | 'cookie';
  required?: boolean;
  schema?: Schema;
  $ref?: string;
}

export interface Response {
  description?: string;
  content?: Record<string, { schema?: Schema }>;
  headers?: Record<string, { required?: boolean; schema?: Schema; $ref?: string }>;
  $ref?: string;
}

export interface OpenAPISpec {
  openapi: string;
  info?: { title?: string; version?: string };
  servers?: Array<{ url: string; variables?: Record<string, { default: string }> }>;
  paths?: Record<string, Record<string, unknown>>;
  components?: Record<string, Record<string, unknown>>;
}

export const METHODS = ['get', 'put', 'post', 'delete', 'options', 'head', 'patch', 'trace'] as const;
export type Method = (typeof METHODS)[number];

/** Accepts a parsed object, JSON text or YAML text. Swagger 2.0 is rejected with a hint. */
export function loadSpec(input: string | object): OpenAPISpec {
  const spec = (typeof input === 'string' ? (input.trimStart().startsWith('{') ? JSON.parse(input) : parseYaml(input)) : input) as OpenAPISpec & { swagger?: string };
  if (spec?.swagger) throw new Error('Swagger 2.0 is not supported. Convert it to OpenAPI 3 (e.g. with swagger2openapi).');
  if (!spec?.openapi || !/^3\./.test(spec.openapi)) throw new Error('Not an OpenAPI 3.x document (missing "openapi: 3.x").');
  return spec;
}

export function isOpenApi31(spec: OpenAPISpec): boolean {
  return spec.openapi.startsWith('3.1');
}

/** Resolves a local JSON pointer ($ref: "#/components/schemas/User"). */
export function resolveRef<T = unknown>(spec: OpenAPISpec, ref: string): T | undefined {
  if (!ref.startsWith('#/')) return undefined; // external refs need bundling first
  let cur: unknown = spec;
  for (const raw of ref.slice(2).split('/')) {
    const key = decodeURIComponent(raw.replace(/~1/g, '/').replace(/~0/g, '~'));
    if (cur === null || typeof cur !== 'object') return undefined;
    cur = (cur as Record<string, unknown>)[key];
  }
  return cur as T | undefined;
}

/** Follows $ref chains on objects such as parameters and responses. */
export function deref<T extends { $ref?: string }>(spec: OpenAPISpec, value: T | undefined): T | undefined {
  let cur = value;
  for (let i = 0; cur?.$ref && i < 20; i++) cur = resolveRef<T>(spec, cur.$ref);
  return cur;
}

export interface MatchedOperation {
  template: string;
  method: Method;
  operation: Operation;
  pathParams: Record<string, string>;
  parameters: Parameter[];
}

function serverPrefixes(spec: OpenAPISpec): string[] {
  const prefixes = (spec.servers ?? []).map((s) => {
    let url = s.url;
    for (const [k, v] of Object.entries(s.variables ?? {})) url = url.replace(`{${k}}`, v.default);
    try {
      return new URL(url, 'http://placeholder').pathname.replace(/\/$/, '');
    } catch {
      return '';
    }
  });
  return [...new Set(prefixes.filter(Boolean))].sort((a, b) => b.length - a.length);
}

interface CompiledPath {
  template: string;
  re: RegExp;
  names: string[];
}

const compiledCache = new WeakMap<OpenAPISpec, CompiledPath[]>();

function compile(spec: OpenAPISpec): CompiledPath[] {
  let c = compiledCache.get(spec);
  if (c) return c;
  c = Object.keys(spec.paths ?? {})
    .map((template) => {
      const names: string[] = [];
      const re = new RegExp(`^${template.replace(/[.*+?^$()|[\]\\]/g, '\\$&').replace(/\{([^}]+)\}/g, (_m, n: string) => (names.push(n), '([^/]+)'))}/?$`);
      return { template, re, names };
    })
    // Literal segments win over templated ones: /users/me before /users/{id}.
    .sort((a, b) => a.names.length - b.names.length || b.template.length - a.template.length);
  compiledCache.set(spec, c);
  return c;
}

/** Finds the operation for a method and URL (absolute or path), honouring server base paths. */
export function matchOperation(spec: OpenAPISpec, method: string, url: string): { path: string; match?: MatchedOperation; pathFound: boolean } {
  let path: string;
  try {
    path = new URL(url, 'http://placeholder').pathname;
  } catch {
    path = url.split('?')[0]!;
  }
  path = decodeURI(path);
  const candidates = [path, ...serverPrefixes(spec).filter((p) => path.startsWith(`${p}/`) || path === p).map((p) => path.slice(p.length) || '/')];
  const m = method.toLowerCase() as Method;
  let pathFound = false;
  for (const p of candidates) {
    for (const c of compile(spec)) {
      const hit = c.re.exec(p);
      if (!hit) continue;
      pathFound = true;
      const item = spec.paths![c.template]!;
      const operation = item[m] as Operation | undefined;
      if (!operation) continue;
      const pathParams = Object.fromEntries(c.names.map((n, i) => [n, decodeURIComponent(hit[i + 1]!)]));
      const merged = new Map<string, Parameter>();
      for (const raw of [...((item.parameters as Parameter[]) ?? []), ...(operation.parameters ?? [])]) {
        const prm = deref(spec, raw);
        if (prm) merged.set(`${prm.in}:${prm.name}`, prm);
      }
      return { path: p, pathFound, match: { template: c.template, method: m, operation, pathParams, parameters: [...merged.values()] } };
    }
  }
  return { path, pathFound };
}

/** Picks the response object for a status: exact, then 2XX-style range, then default. */
export function responseFor(spec: OpenAPISpec, operation: Operation, status: number): { key: string; response: Response } | undefined {
  const responses = operation.responses ?? {};
  const keys = [String(status), `${String(status)[0]}XX`, `${String(status)[0]}xx`, 'default'];
  for (const k of keys) {
    const r = deref(spec, responses[k] as Response | undefined);
    if (r) return { key: k, response: r };
  }
  return undefined;
}

/** Picks the media type entry for a Content-Type header, honouring wildcards. */
export function mediaFor<T>(content: Record<string, T> | undefined, contentType: string | undefined): { type: string; entry: T } | undefined {
  if (!content) return undefined;
  const ct = (contentType ?? '').split(';')[0]!.trim().toLowerCase();
  const keys = Object.keys(content);
  const exact = keys.find((k) => k.toLowerCase() === ct);
  if (exact) return { type: exact, entry: content[exact]! };
  const [major] = ct.split('/');
  const wild = keys.find((k) => k.toLowerCase() === `${major}/*`) ?? keys.find((k) => k === '*/*');
  if (wild) return { type: wild, entry: content[wild]! };
  // application/problem+json etc. against application/json
  if (/\+json$/.test(ct)) {
    const json = keys.find((k) => k.toLowerCase() === 'application/json');
    if (json) return { type: json, entry: content[json]! };
  }
  return undefined;
}
