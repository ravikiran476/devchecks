import { fingerprint, type Finding, type Severity } from '@devchecks/core';
import { coerceParam, validateSchema } from './schema.js';
import { deref, matchOperation, mediaFor, responseFor, type OpenAPISpec, type Schema } from './spec.js';

/** One HTTP request/response pair, from a live call, a HAR file or a fetch wrapper. */
export interface Exchange {
  method: string;
  url: string;
  request?: { headers?: Record<string, string>; body?: unknown };
  status: number;
  /** Lower-case header names. */
  headers?: Record<string, string>;
  /** Parsed JSON or raw text. */
  body?: unknown;
}

export interface ValidateOptions {
  /** Also validate request parameters and body (useful for checking frontends). Default false. */
  requests?: boolean;
  /** Ignore requests whose path does not match the spec, e.g. static assets. Default: report them. */
  ignoreUnknownPaths?: boolean;
  maxErrorsPerExchange?: number;
}

function parseBody(body: unknown, contentType: string | undefined): unknown {
  if (typeof body !== 'string' || !/json/i.test(contentType ?? '')) return body;
  try {
    return body.trim() ? JSON.parse(body) : undefined;
  } catch {
    return body;
  }
}

export function validateExchange(spec: OpenAPISpec, ex: Exchange, options: ValidateOptions = {}): Finding[] {
  const findings: Finding[] = [];
  const { match, pathFound, path } = matchOperation(spec, ex.method, ex.url);
  const method = ex.method.toUpperCase();
  const label = match ? `${method} ${match.template}` : `${method} ${path}`;
  const add = (ruleId: string, severity: Severity, message: string, remediation: string, extra: Record<string, unknown> = {}, fpExtra = '') => {
    findings.push({
      fingerprint: fingerprint('apicontractcheck', ruleId, label, String(ex.status), fpExtra),
      ruleId,
      severity,
      message,
      location: { url: ex.url },
      remediation,
      meta: { method, path: match?.template ?? path, status: ex.status, operationId: match?.operation.operationId, ...extra },
    });
  };

  if (!match) {
    if (options.ignoreUnknownPaths) return findings;
    if (pathFound) add('undocumented-method', 'medium', `${method} is not documented for ${path}.`, 'Document the operation in the spec, or stop exposing it.');
    else add('undocumented-path', 'medium', `${label} is not in the API spec.`, 'Add the path to the OpenAPI document, or remove the endpoint if it is not meant to be public.');
    return findings;
  }

  if (options.requests) {
    let query: URLSearchParams | undefined;
    try {
      query = new URL(ex.url, 'http://placeholder').searchParams;
    } catch {
      query = undefined;
    }
    for (const p of match.parameters) {
      const raw = p.in === 'path' ? match.pathParams[p.name] : p.in === 'query' ? query?.get(p.name) ?? undefined : p.in === 'header' ? ex.request?.headers?.[p.name.toLowerCase()] : undefined;
      if (raw === undefined) {
        if (p.required && p.in !== 'cookie') add('request-parameter-missing', 'medium', `${label}: required ${p.in} parameter "${p.name}" was not sent.`, 'Send the parameter, or mark it optional in the spec.', { parameter: p.name }, p.name);
        continue;
      }
      for (const e of validateSchema(p.schema, coerceParam(raw, p.schema, spec), { spec, direction: 'request', maxErrors: 3 })) {
        add('request-schema-violation', 'medium', `${label}: ${p.in} parameter "${p.name}" ${e.message}.`, 'Fix the client or the parameter schema.', { parameter: p.name, keyword: e.keyword }, `${p.name}:${e.keyword}`);
      }
    }
    const body = deref(spec, match.operation.requestBody);
    const reqType = ex.request?.headers?.['content-type'];
    if (body && ex.request?.body !== undefined) {
      const media = mediaFor(body.content, reqType);
      if (media) {
        for (const e of validateSchema(media.entry.schema as Schema, parseBody(ex.request.body, reqType), { spec, direction: 'request', maxErrors: 5 })) {
          add('request-schema-violation', 'medium', `${label}: request body ${e.path} ${e.message}.`, 'Fix the client or the request body schema.', { pointer: e.path, keyword: e.keyword }, `${e.path}:${e.keyword}`);
        }
      }
    } else if (body?.required && ex.request?.body === undefined && !['GET', 'HEAD'].includes(method)) {
      add('request-body-missing', 'medium', `${label}: the request body is required but none was sent.`, 'Send a body or mark requestBody.required: false.');
    }
  }

  const resp = responseFor(spec, match.operation, ex.status);
  if (!resp) {
    add('undocumented-status', ex.status >= 500 ? 'high' : 'medium', `${label} returned ${ex.status}, which the spec does not document.`, `Document the ${ex.status} response (with its error schema), or fix the server so it returns a documented status.`);
    return findings;
  }
  const contentType = ex.headers?.['content-type'];
  const hasBody = ex.body !== undefined && ex.body !== '' && ex.status !== 204 && method !== 'HEAD';
  if (resp.response.content && hasBody) {
    const media = mediaFor(resp.response.content, contentType);
    if (!media) {
      add('undocumented-content-type', 'medium', `${label} ${ex.status} returned ${contentType ?? 'no Content-Type'}, but the spec documents ${Object.keys(resp.response.content).join(', ')}.`, 'Return a documented media type with the correct Content-Type header.');
    } else if (media.entry.schema) {
      const errors = validateSchema(media.entry.schema, parseBody(ex.body, contentType), { spec, direction: 'response', maxErrors: options.maxErrorsPerExchange ?? 10 });
      for (const e of errors) {
        add('response-schema-violation', 'high', `${label} ${ex.status}: ${e.path} ${e.message}.`, 'Fix the server so the response matches the contract, or update the spec (and version it) if the change is intended.', { pointer: e.path, keyword: e.keyword, response: resp.key }, `${e.path.replace(/\/\d+(?=\/|$)/g, '/*')}:${e.keyword}`);
      }
    }
  } else if (!resp.response.content && hasBody && /json/.test(contentType ?? '')) {
    add('undocumented-response-body', 'low', `${label} ${ex.status} returned a body, but the spec documents none.`, 'Document the response content in the spec.');
  }
  for (const [name, raw] of Object.entries(resp.response.headers ?? {})) {
    const h = deref(spec, raw);
    if (h?.required && ex.headers && ex.headers[name.toLowerCase()] === undefined) {
      add('missing-response-header', 'low', `${label} ${ex.status} is missing the required header ${name}.`, `Send the ${name} header or mark it optional.`, { header: name }, name);
    }
  }
  return findings;
}

/** Validates many exchanges; repeated findings for the same operation/rule are collapsed. */
export function validateExchanges(spec: OpenAPISpec, exchanges: Exchange[], options: ValidateOptions = {}): Finding[] {
  const seen = new Map<string, Finding>();
  for (const ex of exchanges) {
    for (const f of validateExchange(spec, ex, options)) {
      const existing = seen.get(f.fingerprint);
      if (existing) existing.meta = { ...existing.meta, occurrences: ((existing.meta?.occurrences as number) ?? 1) + 1 };
      else seen.set(f.fingerprint, f);
    }
  }
  return [...seen.values()];
}
