import { fingerprint, type Finding } from '@devchecks/core';
import type { Entry } from './parse.js';

export type EnvType = 'string' | 'number' | 'integer' | 'boolean' | 'url' | 'email' | 'port' | 'json' | 'duration';

export interface EnvVarSpec {
  type?: EnvType;
  required?: boolean;
  enum?: string[];
  /** Regular expression the value must match. */
  pattern?: string;
  minLength?: number;
  /** For type "url": require https:// */
  https?: boolean;
  description?: string;
}

export interface EnvSchema {
  /** Shorthand for vars with { required: true }. */
  required?: string[];
  vars?: Record<string, EnvVarSpec>;
}

function validateValue(value: string, spec: EnvVarSpec): string | undefined {
  const v = value.trim();
  switch (spec.type) {
    case 'number':
      if (v === '' || Number.isNaN(Number(v))) return 'is not a number';
      break;
    case 'integer':
      if (!/^-?\d+$/.test(v)) return 'is not an integer';
      break;
    case 'port':
      if (!/^\d+$/.test(v) || Number(v) < 1 || Number(v) > 65535) return 'is not a valid port (1-65535)';
      break;
    case 'boolean':
      if (!/^(true|false|1|0|yes|no|on|off)$/i.test(v)) return 'is not a boolean (true/false)';
      break;
    case 'url':
      try {
        const u = new URL(v);
        if (spec.https && u.protocol !== 'https:') return 'must use https://';
      } catch {
        return 'is not a valid URL';
      }
      break;
    case 'email':
      if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(v)) return 'is not a valid email address';
      break;
    case 'json':
      try {
        JSON.parse(v);
      } catch {
        return 'is not valid JSON';
      }
      break;
    case 'duration':
      if (!/^\d+(\.\d+)?\s*(ms|s|m|h|d)?$/i.test(v)) return 'is not a duration (e.g. 30s, 5m)';
      break;
  }
  if (spec.enum && !spec.enum.includes(v)) return `must be one of: ${spec.enum.join(', ')}`;
  if (spec.pattern && !new RegExp(spec.pattern).test(v)) return `does not match ${spec.pattern}`;
  if (spec.minLength !== undefined && v.length < spec.minLength) return `is shorter than ${spec.minLength} characters`;
  return undefined;
}

/** Validates environment variables against a schema. Values are never included in messages. */
export function validateEnv(vars: Record<string, string | undefined> | Entry[], schema: EnvSchema, source = 'environment'): Finding[] {
  const map = new Map<string, { value: string; line?: number }>();
  if (Array.isArray(vars)) for (const e of vars) map.set(e.key, { value: String(e.value ?? ''), line: e.line });
  else for (const [k, v] of Object.entries(vars)) if (v !== undefined) map.set(k, { value: v });
  // Required-list variables first, so the most important problems lead the report.
  const specs: Record<string, EnvVarSpec> = {};
  for (const k of schema.required ?? []) specs[k] = { required: true };
  for (const [k, v] of Object.entries(schema.vars ?? {})) specs[k] = { ...specs[k], ...v, required: v.required || specs[k]?.required };

  const findings: Finding[] = [];
  for (const [key, spec] of Object.entries(specs)) {
    const found = map.get(key);
    if (!found || found.value.trim() === '') {
      if (spec.required) {
        findings.push({
          fingerprint: fingerprint('configcheck', 'env-missing-required', source, key),
          ruleId: 'env-missing-required',
          severity: 'high',
          message: `Required variable ${key} is ${found ? 'empty' : 'not set'}${spec.description ? ` (${spec.description})` : ''}.`,
          location: { file: source, line: found?.line },
          remediation: `Set ${key} in ${source === 'environment' ? 'the runtime environment' : source} (and document it in .env.example).`,
          meta: { variable: key },
        });
      }
      continue;
    }
    const problem = validateValue(found.value, spec);
    if (problem) {
      findings.push({
        fingerprint: fingerprint('configcheck', 'env-invalid-value', source, key),
        ruleId: 'env-invalid-value',
        severity: 'high',
        message: `${key} ${problem}.`,
        location: { file: source, line: found.line },
        remediation: `Fix the value of ${key}${spec.type ? ` (expected ${spec.type})` : ''}.`,
        meta: { variable: key, type: spec.type },
      });
    }
  }
  return findings;
}

/** Compares a .env file with its template (.env.example): missing and undocumented keys, duplicates. */
export function compareEnv(template: Entry[], actual: Entry[], files: { template: string; actual: string }): Finding[] {
  const findings: Finding[] = [];
  const t = new Map(template.map((e) => [e.key, e]));
  const a = new Map<string, Entry>();
  for (const e of actual) {
    if (a.has(e.key)) {
      findings.push({
        fingerprint: fingerprint('configcheck', 'env-duplicate-key', files.actual, e.key),
        ruleId: 'env-duplicate-key',
        severity: 'low',
        message: `${e.key} is defined more than once; only one value is used (which one depends on the loader).`,
        location: { file: files.actual, line: e.line },
        remediation: 'Keep a single definition.',
        meta: { variable: e.key },
      });
    }
    a.set(e.key, e);
  }
  for (const [key, e] of t) {
    if (!a.has(key)) {
      findings.push({
        fingerprint: fingerprint('configcheck', 'env-missing-var', files.actual, key),
        ruleId: 'env-missing-var',
        severity: 'medium',
        message: `${key} is listed in ${files.template} but missing from ${files.actual}.`,
        location: { file: files.actual },
        remediation: `Add ${key} to ${files.actual}, or remove it from ${files.template} if it is obsolete.`,
        meta: { variable: key, templateLine: e.line },
      });
    }
  }
  for (const [key, e] of a) {
    if (!t.has(key)) {
      findings.push({
        fingerprint: fingerprint('configcheck', 'env-undocumented-var', files.actual, key),
        ruleId: 'env-undocumented-var',
        severity: 'low',
        message: `${key} is set in ${files.actual} but not documented in ${files.template}.`,
        location: { file: files.actual, line: e.line },
        remediation: `Add ${key} (with a placeholder value) to ${files.template} so other developers and deployments know about it.`,
        meta: { variable: key },
      });
    }
  }
  return findings;
}

/** Throws at startup when the environment does not match the schema. Use it in your app's entry point. */
export function assertEnv(schema: EnvSchema, env: Record<string, string | undefined> = (globalThis as { process?: { env: Record<string, string | undefined> } }).process?.env ?? {}): void {
  const problems = validateEnv(env, schema);
  if (problems.length) throw new Error(`Invalid environment:\n${problems.map((p) => `  - ${p.message}`).join('\n')}`);
}
