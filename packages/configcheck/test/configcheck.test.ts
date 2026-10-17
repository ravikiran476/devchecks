import { mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import { formatReport } from '@devchecks/core';
import { assertEnv, checkConfigText, checkEnvDrift, parseDotenv, toReport, validateEnv } from '../src/index.js';
import { scanPaths } from '../src/node.js';

const ids = (findings: Array<{ ruleId: string; severity: string; location?: { line?: number } }>) => findings.map((f) => [f.ruleId, f.severity, f.location?.line]);

describe('parsing', () => {
  it('parses .env with export, quotes and comments', () => {
    const { entries } = parseDotenv('# c\nexport A=1\nB="two # not comment"\nC=three # comment\n');
    expect(entries.map((e) => [e.key, e.value, e.line])).toEqual([
      ['A', '1', 2],
      ['B', 'two # not comment', 3],
      ['C', 'three', 4],
    ]);
  });

  it('reports JSON and YAML syntax errors with line numbers', () => {
    expect(ids(checkConfigText('{\n  "a": 1,\n  "b": \n}', 'config/app.json'))).toEqual([['config-syntax-error', 'high', 4]]);
    expect(ids(checkConfigText('a: 1\na: 2\n', 'app.yml'))[0]?.[0]).toBe('config-syntax-error');
    expect(checkConfigText('{ // comment\n "compilerOptions": { "strict": true, }, }', 'tsconfig.json')).toEqual([]);
  });
});

describe('risky settings', () => {
  it('flags TLS, debug, CORS, cookies and default credentials', () => {
    const yaml = `
server:
  debug: true
  cors:
    origin: "*"
    credentials: true
session:
  cookie:
    secure: false
    httpOnly: false
db:
  password: changeme
http:
  rejectUnauthorized: false
`;
    expect(ids(checkConfigText(yaml, 'config/production.yaml'))).toEqual([
      ['tls-verification-disabled', 'high', 14],
      ['debug-enabled', 'high', 3],
      ['cors-wildcard', 'high', 5],
      ['insecure-cookie', 'high', 9],
      ['insecure-cookie', 'medium', 10],
      ['default-credentials', 'critical', 12],
    ]);
  });

  it('lowers severity for non-production files and infers production from NODE_ENV', () => {
    expect(ids(checkConfigText('DEBUG=true\n', '.env'))).toEqual([['debug-enabled', 'low', 1]]);
    expect(ids(checkConfigText('NODE_ENV=production\nDEBUG=true\n', '.env'))).toEqual([['debug-enabled', 'high', 2]]);
  });

  it('flags weak signing secrets and plain-HTTP endpoints without printing values', () => {
    const findings = checkConfigText('JWT_SECRET=short-secret-123\nAPI_URL=http://api.partner.com\nLOCAL_URL=http://localhost:3000\nNODE_TLS_REJECT_UNAUTHORIZED=0\n', '.env.production');
    expect(ids(findings)).toEqual([
      ['tls-verification-disabled', 'high', 4],
      ['weak-secret', 'high', 1],
      ['insecure-url', 'medium', 2],
    ]);
    const out = formatReport(toReport(findings), 'json');
    expect(out).not.toContain('short-secret-123');
  });

  it('checks Kubernetes manifests, including multi-document files', () => {
    const k8s = `apiVersion: v1\nkind: Pod\nspec:\n  hostNetwork: true\n---\napiVersion: v1\nkind: Pod\nspec:\n  containers:\n    - name: app\n      securityContext:\n        privileged: true\n`;
    expect(ids(checkConfigText(k8s, 'k8s/pod.yaml'))).toEqual([
      ['privileged-container', 'medium', 4],
      ['privileged-container', 'high', 12],
    ]);
  });
});

describe('environment variables', () => {
  const schema = {
    required: ['DATABASE_URL'],
    vars: { PORT: { type: 'port' as const }, API_URL: { type: 'url' as const, https: true }, MODE: { enum: ['a', 'b'] } },
  };

  it('validates against a schema', () => {
    const findings = validateEnv({ PORT: '99999', API_URL: 'http://x.com', MODE: 'c' }, schema);
    expect(findings.map((f) => f.message)).toEqual([
      'Required variable DATABASE_URL is not set.',
      'PORT is not a valid port (1-65535).',
      'API_URL must use https://.',
      'MODE must be one of: a, b.',
    ]);
    expect(() => assertEnv(schema, { DATABASE_URL: 'postgres://x', PORT: '8080' })).not.toThrow();
    expect(() => assertEnv(schema, {})).toThrow(/DATABASE_URL/);
  });

  it('detects drift between .env and .env.example', () => {
    expect(checkEnvDrift('A=\nB=\n', 'A=1\nC=2\nA=3\n').map((f) => [f.ruleId, f.meta?.variable])).toEqual([
      ['env-duplicate-key', 'A'],
      ['env-missing-var', 'B'],
      ['env-undocumented-var', 'C'],
    ]);
  });

  it('scans a project directory', () => {
    const dir = mkdtempSync(join(tmpdir(), 'configcheck-'));
    writeFileSync(join(dir, '.env.example'), 'DATABASE_URL=\nPORT=\n');
    writeFileSync(join(dir, '.env'), 'PORT=abc\n');
    writeFileSync(join(dir, 'package-lock.json'), '{ broken');
    const { findings, files } = scanPaths(['.'], { cwd: dir, env: schema });
    expect(files.sort()).toEqual(['.env', '.env.example']);
    expect(findings.map((f) => f.ruleId).sort()).toEqual(['env-invalid-value', 'env-missing-required', 'env-missing-var']);
  });
});
