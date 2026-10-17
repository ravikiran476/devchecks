// JSON Schema validation for the OpenAPI dialects: 3.0 (nullable, boolean exclusive*) and
// 3.1 (JSON Schema 2020-12 style type arrays, const, numeric exclusive*). Dependency-free so
// it runs in the browser bundle.
import { resolveRef, type OpenAPISpec, type Schema } from './spec.js';

export interface SchemaError {
  /** JSON pointer into the validated value, e.g. "/items/0/price". */
  path: string;
  keyword: string;
  message: string;
}

export interface ValidateContext {
  spec: OpenAPISpec;
  /** Responses must not contain writeOnly properties; requests must not require readOnly ones. */
  direction: 'request' | 'response';
  maxErrors?: number;
}

const FORMATS: Record<string, (v: string) => boolean> = {
  'date-time': (v) => /^\d{4}-\d{2}-\d{2}[Tt ]\d{2}:\d{2}:\d{2}(\.\d+)?([Zz]|[+-]\d{2}:?\d{2})$/.test(v) && !Number.isNaN(Date.parse(v)),
  date: (v) => /^\d{4}-\d{2}-\d{2}$/.test(v) && !Number.isNaN(Date.parse(v)),
  time: (v) => /^\d{2}:\d{2}:\d{2}(\.\d+)?([Zz]|[+-]\d{2}:?\d{2})?$/.test(v),
  email: (v) => /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(v),
  uuid: (v) => /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(v),
  uri: (v) => {
    try {
      new URL(v);
      return true;
    } catch {
      return false;
    }
  },
  ipv4: (v) => /^(25[0-5]|2[0-4]\d|1?\d?\d)(\.(25[0-5]|2[0-4]\d|1?\d?\d)){3}$/.test(v),
  byte: (v) => /^[A-Za-z0-9+/]*={0,2}$/.test(v) && v.length % 4 === 0,
};

const typeOf = (v: unknown): string => (v === null ? 'null' : Array.isArray(v) ? 'array' : typeof v === 'number' ? (Number.isInteger(v) ? 'integer' : 'number') : typeof v);

const ptr = (base: string, key: string | number) => `${base}/${String(key).replace(/~/g, '~0').replace(/\//g, '~1')}`;

export function validateSchema(schema: Schema | boolean | undefined, value: unknown, ctx: ValidateContext, path = '', depth = 0): SchemaError[] {
  const errors: SchemaError[] = [];
  const max = ctx.maxErrors ?? 20;
  const push = (keyword: string, message: string, at = path) => {
    if (errors.length < max) errors.push({ path: at || '/', keyword, message });
  };
  if (schema === undefined || schema === true) return errors;
  if (schema === false) return [{ path: path || '/', keyword: 'false', message: 'no value is allowed here' }];
  if (depth > 64) return errors;

  if (schema.$ref) {
    const target = resolveRef<Schema>(ctx.spec, schema.$ref);
    if (!target) return [{ path: path || '/', keyword: '$ref', message: `cannot resolve ${schema.$ref}` }];
    // In 3.1, siblings of $ref apply too; in 3.0 they are ignored.
    const { $ref: _ref, ...rest } = schema;
    const siblings = ctx.spec.openapi.startsWith('3.1') && Object.keys(rest).length ? validateSchema(rest as Schema, value, ctx, path, depth + 1) : [];
    return [...validateSchema(target, value, ctx, path, depth + 1), ...siblings].slice(0, max);
  }

  const s = schema as Record<string, unknown>;
  const t = typeOf(value);

  // type / nullable
  if (s.type !== undefined) {
    const types = (Array.isArray(s.type) ? s.type : [s.type]) as string[];
    if (s.nullable === true) types.push('null');
    const ok = types.some((x) => x === t || (x === 'number' && t === 'integer'));
    if (!ok) {
      push('type', `expected ${types.join(' or ')}, got ${t}`);
      return errors;
    }
  } else if (value === null && s.nullable === false) {
    push('type', 'null is not allowed');
  }
  if (value === null) return errors;

  if (Array.isArray(s.enum) && !s.enum.some((e) => JSON.stringify(e) === JSON.stringify(value))) {
    push('enum', `must be one of ${s.enum.map((e) => JSON.stringify(e)).join(', ')}`);
  }
  if ('const' in s && JSON.stringify(s.const) !== JSON.stringify(value)) push('const', `must equal ${JSON.stringify(s.const)}`);

  if (typeof value === 'string') {
    if (typeof s.minLength === 'number' && value.length < s.minLength) push('minLength', `must be at least ${s.minLength} characters`);
    if (typeof s.maxLength === 'number' && value.length > s.maxLength) push('maxLength', `must be at most ${s.maxLength} characters`);
    if (typeof s.pattern === 'string') {
      try {
        if (!new RegExp(s.pattern, 'u').test(value)) push('pattern', `must match ${s.pattern}`);
      } catch {
        // invalid pattern in spec: ignore
      }
    }
    const check = typeof s.format === 'string' ? FORMATS[s.format] : undefined;
    if (check && !check(value)) push('format', `must be a valid ${s.format}`);
  }

  if (typeof value === 'number') {
    const exMin = s.exclusiveMinimum;
    const exMax = s.exclusiveMaximum;
    if (typeof s.minimum === 'number' && (exMin === true ? value <= s.minimum : value < s.minimum)) push('minimum', `must be ${exMin === true ? '>' : '>='} ${s.minimum}`);
    if (typeof s.maximum === 'number' && (exMax === true ? value >= s.maximum : value > s.maximum)) push('maximum', `must be ${exMax === true ? '<' : '<='} ${s.maximum}`);
    if (typeof exMin === 'number' && value <= exMin) push('exclusiveMinimum', `must be > ${exMin}`);
    if (typeof exMax === 'number' && value >= exMax) push('exclusiveMaximum', `must be < ${exMax}`);
    if (typeof s.multipleOf === 'number' && Math.abs(value / s.multipleOf - Math.round(value / s.multipleOf)) > 1e-9) push('multipleOf', `must be a multiple of ${s.multipleOf}`);
    if (s.format === 'int32' && (value < -(2 ** 31) || value > 2 ** 31 - 1)) push('format', 'must fit in int32');
  }

  if (Array.isArray(value)) {
    if (typeof s.minItems === 'number' && value.length < s.minItems) push('minItems', `must have at least ${s.minItems} items`);
    if (typeof s.maxItems === 'number' && value.length > s.maxItems) push('maxItems', `must have at most ${s.maxItems} items`);
    if (s.uniqueItems === true && new Set(value.map((v) => JSON.stringify(v))).size !== value.length) push('uniqueItems', 'items must be unique');
    if (s.items && typeof s.items === 'object') {
      value.forEach((item, i) => {
        if (errors.length < max) errors.push(...validateSchema(s.items as Schema, item, ctx, ptr(path, i), depth + 1).slice(0, max - errors.length));
      });
    }
  }

  if (t === 'object') {
    const obj = value as Record<string, unknown>;
    const props = (s.properties ?? {}) as Record<string, Schema>;
    for (const name of (s.required as string[] | undefined) ?? []) {
      const prop = props[name] ? (props[name].$ref ? resolveRef<Schema>(ctx.spec, props[name].$ref!) : props[name]) : undefined;
      if (ctx.direction === 'request' && prop?.readOnly) continue;
      if (ctx.direction === 'response' && prop?.writeOnly) continue;
      if (!(name in obj)) push('required', `missing required property "${name}"`, ptr(path, name));
    }
    for (const [key, v] of Object.entries(obj)) {
      if (props[key]) {
        const prop = props[key].$ref ? resolveRef<Schema>(ctx.spec, props[key].$ref!) : props[key];
        if (ctx.direction === 'response' && prop?.writeOnly) push('writeOnly', `writeOnly property "${key}" must not be returned`, ptr(path, key));
        if (errors.length < max) errors.push(...validateSchema(props[key], v, ctx, ptr(path, key), depth + 1).slice(0, max - errors.length));
        continue;
      }
      const patternHit = Object.entries((s.patternProperties ?? {}) as Record<string, Schema>).find(([re]) => new RegExp(re, 'u').test(key));
      if (patternHit) {
        errors.push(...validateSchema(patternHit[1], v, ctx, ptr(path, key), depth + 1));
        continue;
      }
      if (s.additionalProperties === false) push('additionalProperties', `unexpected property "${key}"`, ptr(path, key));
      else if (s.additionalProperties && typeof s.additionalProperties === 'object') errors.push(...validateSchema(s.additionalProperties as Schema, v, ctx, ptr(path, key), depth + 1));
    }
    const count = Object.keys(obj).length;
    if (typeof s.minProperties === 'number' && count < s.minProperties) push('minProperties', `must have at least ${s.minProperties} properties`);
    if (typeof s.maxProperties === 'number' && count > s.maxProperties) push('maxProperties', `must have at most ${s.maxProperties} properties`);
  }

  // Composition
  if (Array.isArray(s.allOf)) for (const sub of s.allOf as Schema[]) errors.push(...validateSchema(sub, value, ctx, path, depth + 1));
  const discriminated = discriminate(s, value, ctx);
  if (discriminated) {
    errors.push(...validateSchema(discriminated, value, ctx, path, depth + 1));
  } else {
    if (Array.isArray(s.anyOf) && !(s.anyOf as Schema[]).some((sub) => !validateSchema(sub, value, { ...ctx, maxErrors: 1 }, path, depth + 1).length)) {
      push('anyOf', `does not match any allowed schema (anyOf)`);
    }
    if (Array.isArray(s.oneOf)) {
      const passing = (s.oneOf as Schema[]).filter((sub) => !validateSchema(sub, value, { ...ctx, maxErrors: 1 }, path, depth + 1).length).length;
      if (passing !== 1) push('oneOf', passing === 0 ? 'does not match any allowed schema (oneOf)' : `matches ${passing} schemas; oneOf requires exactly one`);
    }
  }
  if (s.not && !validateSchema(s.not as Schema, value, { ...ctx, maxErrors: 1 }, path, depth + 1).length) push('not', 'matches a schema it must not match');
  return errors.slice(0, max);
}

/** With a discriminator, validate against the selected branch for precise error messages. */
function discriminate(s: Record<string, unknown>, value: unknown, ctx: ValidateContext): Schema | undefined {
  const d = s.discriminator as { propertyName?: string; mapping?: Record<string, string> } | undefined;
  const branches = (s.oneOf ?? s.anyOf) as Schema[] | undefined;
  if (!d?.propertyName || !branches || typeof value !== 'object' || value === null) return undefined;
  const tag = (value as Record<string, unknown>)[d.propertyName];
  if (typeof tag !== 'string') return undefined;
  const ref = d.mapping?.[tag] ?? branches.find((b) => b.$ref?.endsWith(`/${tag}`))?.$ref;
  if (!ref) return undefined;
  return ref.startsWith('#') ? { $ref: ref } : branches.find((b) => b.$ref?.endsWith(`/${ref}`));
}

/** Coerces a query/path/header string to the parameter's schema type before validation. */
export function coerceParam(raw: string, schema: Schema | undefined, spec: OpenAPISpec): unknown {
  const s = schema?.$ref ? resolveRef<Schema>(spec, schema.$ref) : schema;
  const type = Array.isArray(s?.type) ? (s!.type as string[]).find((x) => x !== 'null') : (s?.type as string | undefined);
  if (type === 'integer' || type === 'number') return raw.trim() !== '' && !Number.isNaN(Number(raw)) ? Number(raw) : raw;
  if (type === 'boolean') return raw === 'true' ? true : raw === 'false' ? false : raw;
  if (type === 'array') return raw.split(',');
  return raw;
}
