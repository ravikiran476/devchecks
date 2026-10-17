// Browser-safe entry. Validate API traffic in the browser during development:
//
//   <script src="https://cdn.jsdelivr.net/gh/ravikiran476/devchecks@v0.1.0/cdn/apicontractcheck.min.js"></script>
//   <script>
//     fetch('/openapi.json').then((r) => r.json()).then((spec) => {
//       window.fetch = APIContractCheck.createValidatingFetch(spec, { onFinding: (f) => console.warn(f.message) });
//     });
//   </script>
import { createReport, type BaselineDiff, type Finding, type Report } from '@devchecks/core';
import { loadSpec, type OpenAPISpec } from './spec.js';
import { validateExchange, type Exchange, type ValidateOptions } from './validate.js';

export { diffSpecs, type DiffResult } from './diff.js';
export { coerceParam, validateSchema, type SchemaError, type ValidateContext } from './schema.js';
export { deref, isOpenApi31, loadSpec, matchOperation, mediaFor, METHODS, resolveRef, responseFor, type Method, type OpenAPISpec, type Operation, type Parameter, type Response, type Schema } from './spec.js';
export { validateExchange, validateExchanges, type Exchange, type ValidateOptions } from './validate.js';
export { createBaseline, diffBaseline, formatReport, type Finding, type Report } from '@devchecks/core';

export const TOOL = 'apicontractcheck';
export const VERSION = __VERSION__;

interface HarEntry {
  request: { method: string; url: string; headers?: Array<{ name: string; value: string }>; postData?: { mimeType?: string; text?: string } };
  response: { status: number; headers?: Array<{ name: string; value: string }>; content?: { mimeType?: string; text?: string; encoding?: string } };
}

const headerMap = (hs: Array<{ name: string; value: string }> | undefined) => Object.fromEntries((hs ?? []).map((h) => [h.name.toLowerCase(), h.value]));

/** Converts a HAR file (DevTools "Save all as HAR", Playwright recordHar) into exchanges. */
export function fromHar(har: string | { log: { entries: HarEntry[] } }, options: { include?: (url: string) => boolean } = {}): Exchange[] {
  const data = typeof har === 'string' ? (JSON.parse(har) as { log: { entries: HarEntry[] } }) : har;
  return (data.log?.entries ?? [])
    .filter((e) => (options.include ? options.include(e.request.url) : /json|xml|text\/plain|problem/i.test(e.response.content?.mimeType ?? '') || e.response.status === 204))
    .map((e) => {
      const text = e.response.content?.text;
      const body = text !== undefined && e.response.content?.encoding === 'base64' ? atob(text) : text;
      return {
        method: e.request.method,
        url: e.request.url,
        request: { headers: headerMap(e.request.headers), body: e.request.postData?.text },
        status: e.response.status,
        headers: headerMap(e.response.headers),
        body,
      };
    });
}

export interface ValidatingFetchOptions extends ValidateOptions {
  fetch?: typeof fetch;
  /** Only validate URLs for which this returns true. Default: same origin as the page, or all in Node. */
  include?: (url: string) => boolean;
  onFinding?: (finding: Finding) => void;
}

/** Wraps fetch so every API response is checked against the spec. The caller still gets the original response. */
export function createValidatingFetch(specInput: OpenAPISpec | string | object, options: ValidatingFetchOptions = {}): typeof fetch {
  const spec = loadSpec(specInput as object);
  const base = options.fetch ?? globalThis.fetch.bind(globalThis);
  const include =
    options.include ??
    ((url: string) => {
      if (typeof location === 'undefined') return true;
      try {
        return new URL(url, location.href).origin === location.origin;
      } catch {
        return false;
      }
    });
  const onFinding = options.onFinding ?? ((f: Finding) => console.warn(`[apicontractcheck] ${f.message}`));
  return async (input: RequestInfo | URL, init?: RequestInit) => {
    const res = await base(input, init);
    const url = typeof input === 'string' ? input : input instanceof URL ? input.href : input.url;
    if (!include(url)) return res;
    try {
      const contentType = res.headers.get('content-type') ?? undefined;
      const text = res.status === 204 ? undefined : await res.clone().text();
      const headers: Record<string, string> = {};
      res.headers.forEach((v, k) => (headers[k.toLowerCase()] = v));
      const method = init?.method ?? (typeof input === 'object' && 'method' in input ? input.method : 'GET');
      const reqHeaders: Record<string, string> = {};
      new Headers(init?.headers).forEach((v, k) => (reqHeaders[k] = v));
      const exchange: Exchange = { method, url: new URL(url, typeof location === 'undefined' ? 'http://localhost' : location.href).href, status: res.status, headers: { ...headers, 'content-type': contentType ?? '' }, body: text, request: { headers: reqHeaders, body: typeof init?.body === 'string' ? init.body : undefined } };
      for (const f of validateExchange(spec, exchange, options)) onFinding(f);
    } catch (err) {
      console.warn('[apicontractcheck] validation failed', err);
    }
    return res;
  };
}

export function toReport(findings: Finding[], baseline?: BaselineDiff): Report {
  return createReport(TOOL, VERSION, findings, { baseline });
}
