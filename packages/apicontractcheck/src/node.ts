import { readFileSync } from 'node:fs';
import type { Finding } from '@devchecks/core';
import { fromHar } from './index.js';
import { deref, loadSpec, METHODS, type OpenAPISpec, type Operation } from './spec.js';
import { validateExchanges, type Exchange, type ValidateOptions } from './validate.js';

export * from './index.js';

export function loadSpecFile(path: string): OpenAPISpec {
  return loadSpec(readFileSync(path, 'utf8'));
}

export function validateHarFile(spec: OpenAPISpec, harPath: string, options: ValidateOptions & { include?: (url: string) => boolean } = {}): { exchanges: number; findings: Finding[] } {
  const exchanges = fromHar(readFileSync(harPath, 'utf8'), { include: options.include });
  return { exchanges: exchanges.length, findings: validateExchanges(spec, exchanges, options) };
}

/** Example value for a parameter: example, default, first enum value, or a type-appropriate placeholder. */
function exampleFor(spec: OpenAPISpec, schema: Record<string, unknown> | undefined, example?: unknown): string | undefined {
  const s = deref(spec, schema as { $ref?: string } | undefined) as Record<string, unknown> | undefined;
  const v = example ?? s?.example ?? s?.default ?? (Array.isArray(s?.enum) ? s!.enum[0] : undefined);
  return v === undefined ? undefined : String(v);
}

/**
 * Calls every safe (GET) operation whose required parameters have examples or defaults,
 * and validates the responses. Never sends POST/PUT/PATCH/DELETE.
 */
export async function probe(spec: OpenAPISpec, baseUrl: string, options: ValidateOptions & { headers?: Record<string, string>; fetch?: typeof fetch; onSkip?: (op: string, reason: string) => void } = {}): Promise<{ exchanges: Exchange[]; findings: Finding[] }> {
  const f = options.fetch ?? fetch;
  const exchanges: Exchange[] = [];
  for (const [template, item] of Object.entries(spec.paths ?? {})) {
    for (const method of METHODS) {
      if (method !== 'get') continue;
      const op = item[method] as Operation | undefined;
      if (!op) continue;
      let path = template;
      const query = new URLSearchParams();
      let skip: string | undefined;
      const all = [...((item.parameters as Operation['parameters']) ?? []), ...(op.parameters ?? [])].map((p) => deref(spec, p)!).filter(Boolean);
      for (const p of all) {
        const value = exampleFor(spec, p.schema, (p as { example?: unknown }).example);
        if (p.in === 'path') {
          if (value === undefined) skip = `no example for path parameter "${p.name}"`;
          else path = path.replace(`{${p.name}}`, encodeURIComponent(value));
        } else if (p.in === 'query' && (p.required || value !== undefined)) {
          if (value === undefined) skip = `no example for required query parameter "${p.name}"`;
          else if (p.required) query.set(p.name, value);
        } else if (p.in === 'header' && p.required && value === undefined) skip = `no example for required header "${p.name}"`;
      }
      if (skip) {
        options.onSkip?.(`GET ${template}`, skip);
        continue;
      }
      const url = `${baseUrl.replace(/\/$/, '')}${path}${query.size ? `?${query}` : ''}`;
      const res = await f(url, { headers: { accept: 'application/json', ...options.headers } });
      const headers: Record<string, string> = {};
      res.headers.forEach((v, k) => (headers[k.toLowerCase()] = v));
      exchanges.push({ method: 'GET', url, status: res.status, headers, body: await res.text() });
    }
  }
  return { exchanges, findings: validateExchanges(spec, exchanges, options) };
}
