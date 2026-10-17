// Breaking-change detection between two OpenAPI versions. A change is breaking when an
// existing client could fail: requests it sends become invalid, or responses it parses change shape.
import { fingerprint, type Finding, type Severity } from '@devchecks/core';
import { deref, METHODS, resolveRef, type OpenAPISpec, type Operation, type Parameter, type Schema } from './spec.js';

interface Change {
  ruleId: string;
  severity: Severity;
  where: string;
  message: string;
}

const normalizeTemplate = (t: string) => t.replace(/\{[^}]+\}/g, '{}');

function resolve(spec: OpenAPISpec, s: Schema | undefined): Schema | undefined {
  let cur = s;
  for (let i = 0; cur?.$ref && i < 20; i++) cur = resolveRef<Schema>(spec, cur.$ref);
  return cur;
}

function types(s: Schema | undefined): Set<string> {
  if (!s) return new Set();
  const t = s.type === undefined ? [] : Array.isArray(s.type) ? (s.type as string[]) : [s.type as string];
  const out = new Set(t);
  if (s.nullable === true) out.add('null');
  if (out.has('integer') && out.has('number')) out.delete('integer');
  return out;
}

function diffSchema(oldSpec: OpenAPISpec, newSpec: OpenAPISpec, a: Schema | undefined, b: Schema | undefined, direction: 'request' | 'response', where: string, out: Change[], seen = new Set<string>(), depth = 0): void {
  const os = resolve(oldSpec, a);
  const ns = resolve(newSpec, b);
  if (!os || !ns || depth > 20) return;
  const key = `${a?.$ref ?? where}|${b?.$ref ?? where}|${direction}`;
  if (seen.has(key)) return;
  seen.add(key);

  const ot = types(os);
  const nt = types(ns);
  if (ot.size && nt.size) {
    const narrowed = [...ot].filter((t) => !nt.has(t) && !(t === 'integer' && nt.has('number')));
    const widened = [...nt].filter((t) => !ot.has(t) && !(t === 'integer' && ot.has('number')));
    if (direction === 'request' && narrowed.length) out.push({ ruleId: 'type-changed', severity: 'high', where, message: `${where} no longer accepts ${narrowed.join('/')} (now ${[...nt].join('/')}).` });
    if (direction === 'response' && widened.length) {
      out.push({ ruleId: widened.length === 1 && widened[0] === 'null' ? 'response-nullable' : 'type-changed', severity: widened[0] === 'null' && widened.length === 1 ? 'medium' : 'high', where, message: `${where} can now be ${widened.join('/')} (was ${[...ot].join('/')}).` });
    }
  }

  const oe = Array.isArray(os.enum) ? os.enum.map((e) => JSON.stringify(e)) : undefined;
  const ne = Array.isArray(ns.enum) ? ns.enum.map((e) => JSON.stringify(e)) : undefined;
  if (direction === 'request' && ne && (!oe || oe.some((v) => !ne.includes(v)))) {
    const removed = oe ? oe.filter((v) => !ne.includes(v)) : ['(any value)'];
    out.push({ ruleId: 'enum-narrowed', severity: 'high', where, message: `${where} no longer accepts ${removed.join(', ')}.` });
  }
  if (direction === 'response' && oe && (!ne || ne.some((v) => !oe.includes(v)))) {
    const added = ne ? ne.filter((v) => !oe.includes(v)) : ['(any value)'];
    out.push({ ruleId: 'enum-widened', severity: 'medium', where, message: `${where} can now return ${added.join(', ')}; clients with exhaustive handling may break.` });
  }

  if (direction === 'request') {
    for (const k of ['maxLength', 'maxItems', 'maximum'] as const) {
      if (typeof ns[k] === 'number' && (typeof os[k] !== 'number' || (ns[k] as number) < (os[k] as number))) out.push({ ruleId: 'constraint-tightened', severity: 'medium', where, message: `${where} ${k} tightened to ${ns[k]}${typeof os[k] === 'number' ? ` (was ${os[k]})` : ''}.` });
    }
    for (const k of ['minLength', 'minItems', 'minimum'] as const) {
      if (typeof ns[k] === 'number' && (typeof os[k] !== 'number' || (ns[k] as number) > (os[k] as number))) out.push({ ruleId: 'constraint-tightened', severity: 'medium', where, message: `${where} ${k} tightened to ${ns[k]}${typeof os[k] === 'number' ? ` (was ${os[k]})` : ''}.` });
    }
    if (ns.additionalProperties === false && os.additionalProperties !== false) out.push({ ruleId: 'constraint-tightened', severity: 'medium', where, message: `${where} no longer accepts unknown properties.` });
  }

  const op = (os.properties ?? {}) as Record<string, Schema>;
  const np = (ns.properties ?? {}) as Record<string, Schema>;
  const oreq = new Set((os.required as string[] | undefined) ?? []);
  const nreq = new Set((ns.required as string[] | undefined) ?? []);
  if (direction === 'request') {
    for (const name of nreq) {
      if (!oreq.has(name) && !resolve(newSpec, np[name])?.readOnly) out.push({ ruleId: 'required-property-added', severity: 'high', where: `${where}.${name}`, message: `${where}.${name} is now required in requests.` });
    }
    for (const name of Object.keys(op)) if (!(name in np) && ns.additionalProperties === false) out.push({ ruleId: 'property-removed', severity: 'high', where: `${where}.${name}`, message: `${where}.${name} was removed and unknown properties are rejected.` });
  } else {
    for (const name of Object.keys(op)) {
      if (!(name in np)) out.push({ ruleId: 'property-removed', severity: 'high', where: `${where}.${name}`, message: `${where}.${name} was removed from the response.` });
      else if (oreq.has(name) && !nreq.has(name)) out.push({ ruleId: 'property-optional', severity: 'medium', where: `${where}.${name}`, message: `${where}.${name} is no longer guaranteed in the response.` });
    }
  }
  for (const name of Object.keys(np)) if (name in op) diffSchema(oldSpec, newSpec, op[name], np[name], direction, `${where}.${name}`, out, seen, depth + 1);
  if (os.items && ns.items) diffSchema(oldSpec, newSpec, os.items as Schema, ns.items as Schema, direction, `${where}[]`, out, seen, depth + 1);
}

function params(spec: OpenAPISpec, pathItem: Record<string, unknown>, op: Operation): Map<string, Parameter> {
  const m = new Map<string, Parameter>();
  for (const raw of [...((pathItem.parameters as Parameter[]) ?? []), ...(op.parameters ?? [])]) {
    const p = deref(spec, raw);
    // Path parameters are covered by the (normalized) template; renaming them is not breaking.
    if (p && p.in !== 'path') m.set(`${p.in}:${p.name.toLowerCase()}`, p);
  }
  return m;
}

function jsonSchemaOf(content: Record<string, { schema?: Schema }> | undefined): Schema | undefined {
  if (!content) return undefined;
  const key = Object.keys(content).find((k) => /json/i.test(k)) ?? Object.keys(content)[0];
  return key ? content[key]?.schema : undefined;
}

export interface DiffResult {
  breaking: Finding[];
  nonBreaking: Finding[];
}

/** Compares two specs and classifies changes. Findings with severity info are non-breaking. */
export function diffSpecs(oldSpec: OpenAPISpec, newSpec: OpenAPISpec, options: { oldName?: string; newName?: string } = {}): DiffResult {
  const changes: Change[] = [];
  const info: Change[] = [];
  const index = (spec: OpenAPISpec) => {
    const m = new Map<string, { template: string; method: string; item: Record<string, unknown>; op: Operation }>();
    for (const [template, item] of Object.entries(spec.paths ?? {})) {
      for (const method of METHODS) {
        const op = item[method] as Operation | undefined;
        if (op) m.set(`${method} ${normalizeTemplate(template)}`, { template, method, item, op });
      }
    }
    return m;
  };
  const before = index(oldSpec);
  const after = index(newSpec);

  for (const [key, o] of before) {
    const label = `${o.method.toUpperCase()} ${o.template}`;
    const n = after.get(key);
    if (!n) {
      changes.push({ ruleId: 'endpoint-removed', severity: 'high', where: label, message: `${label} was removed.` });
      continue;
    }
    if (n.op.deprecated && !o.op.deprecated) info.push({ ruleId: 'endpoint-deprecated', severity: 'low', where: label, message: `${label} is now deprecated.` });

    // Parameters
    const op = params(oldSpec, o.item, o.op);
    const np = params(newSpec, n.item, n.op);
    for (const [k, p] of np) {
      const prev = op.get(k);
      if (p.required && (!prev || !prev.required)) changes.push({ ruleId: 'required-parameter-added', severity: 'high', where: label, message: `${label}: ${p.in} parameter "${p.name}" is now required.` });
      if (prev) diffSchema(oldSpec, newSpec, prev.schema, p.schema, 'request', `${label} ${p.in}.${p.name}`, changes);
    }
    for (const [k, p] of op) if (!np.has(k)) info.push({ ruleId: 'parameter-removed', severity: 'low', where: label, message: `${label}: ${p.in} parameter "${p.name}" was removed (clients still sending it are usually unaffected).` });

    // Request body
    const ob = deref(oldSpec, o.op.requestBody);
    const nb = deref(newSpec, n.op.requestBody);
    if (nb?.required && !ob?.required) changes.push({ ruleId: 'request-body-required', severity: 'high', where: label, message: `${label}: the request body is now required.` });
    if (ob && nb) diffSchema(oldSpec, newSpec, jsonSchemaOf(ob.content), jsonSchemaOf(nb.content), 'request', `${label} request`, changes);

    // Responses
    for (const [status, rawOld] of Object.entries(o.op.responses ?? {})) {
      const rawNew = n.op.responses?.[status];
      if (!rawNew) {
        if (/^2/.test(status)) changes.push({ ruleId: 'response-removed', severity: 'medium', where: label, message: `${label}: the ${status} response was removed.` });
        continue;
      }
      const or = deref(oldSpec, rawOld as { $ref?: string; content?: Record<string, { schema?: Schema }> });
      const nr = deref(newSpec, rawNew as { $ref?: string; content?: Record<string, { schema?: Schema }> });
      diffSchema(oldSpec, newSpec, jsonSchemaOf(or?.content), jsonSchemaOf(nr?.content), 'response', `${label} ${status}`, changes);
    }
  }
  for (const [key, n] of after) if (!before.has(key)) info.push({ ruleId: 'endpoint-added', severity: 'info', where: `${n.method.toUpperCase()} ${n.template}`, message: `${n.method.toUpperCase()} ${n.template} was added.` });

  const toFinding = (c: Change): Finding => ({
    fingerprint: fingerprint('apicontractcheck', c.ruleId, c.where),
    ruleId: c.ruleId,
    severity: c.severity,
    message: c.message,
    location: { file: options.newName ?? 'openapi (new)' },
    remediation:
      c.severity === 'info' || c.severity === 'low'
        ? 'No action needed for existing clients.'
        : 'Keep the old behaviour (make the change additive), version the API (e.g. /v2), or coordinate the change with every client before release.',
    meta: { where: c.where },
  });
  return { breaking: changes.map(toFinding), nonBreaking: info.map(toFinding) };
}
