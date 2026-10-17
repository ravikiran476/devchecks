import { execFileSync } from 'node:child_process';
import { mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import { formatReport } from '@devchecks/core';
import { isExcluded, redact, scanFiles, scanText, toReport } from '../src/index.js';
import { scanStaged } from '../src/node.js';

// Built at runtime so this test file never contains a literal credential.
const GH = 'ghp_' + 'A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8';
const AWS = 'AKIA' + 'Z7QX2LMN4PRS6TUV';
const STRIPE = 'sk_live_' + '51HxYzAbCdEfGhIjKlMnOpQr';
const PASSWORD = 'Tr0ub' + '4dor&3xyz';
const DB_PASSWORD = 's3cret' + 'Passw0rd';

describe('scanText', () => {
  it('detects provider tokens with high confidence', () => {
    const findings = scanText(`const token = "${GH}";\nconst k = '${AWS}';`, 'src/a.ts');
    expect(findings.map((f) => f.ruleId)).toEqual(['github-token', 'aws-access-key-id']);
    expect(findings.every((f) => f.meta.confidence === 'high')).toBe(true);
    expect(findings[0]!.location).toMatchObject({ file: 'src/a.ts', line: 1, column: 16 });
  });

  it('never includes the full secret in any output format', () => {
    const findings = scanText(`STRIPE_KEY=${STRIPE}\npassword = "${PASSWORD}"`, '.env');
    expect(findings.length).toBeGreaterThanOrEqual(2);
    const report = toReport(findings);
    for (const fmt of ['text', 'json', 'sarif', 'markdown'] as const) {
      const out = formatReport(report, fmt);
      expect(out).not.toContain(STRIPE);
      expect(out).not.toContain(PASSWORD);
    }
  });

  it('prefers the specific rule over the generic assignment rule', () => {
    const findings = scanText(`api_key = "${GH}"`, 'a.py');
    expect(findings).toHaveLength(1);
    expect(findings[0]!.ruleId).toBe('github-token');
  });

  it('detects credentials in connection strings', () => {
    const findings = scanText(`DATABASE_URL=postgres://app:${DB_PASSWORD}@db.internal:5432/app`, '.env');
    expect(findings[0]?.ruleId).toBe('credentials-in-url');
    expect(findings[0]?.snippet).not.toContain(DB_PASSWORD);
  });

  it('ignores placeholders and env lookups', () => {
    const src = [
      'password = "changeme"',
      'api_key = "${API_KEY}"',
      'secret: "<your-secret-here>"',
      'const token = process.env.TOKEN',
      'DATABASE_URL=postgres://user:${DB_PASSWORD}@localhost/db',
      "aws_key = 'AKIAIOSFODNN7EXAMPLE'",
      '"secretcheck": "./dist/cli.js"',
      'privateKeyPath: "certs/server.key"',
      'redis://user:pass@localhost:6379',
    ].join('\n');
    expect(scanText(src, 'config.ts')).toEqual([]);
  });

  it('flags high-entropy strings with low confidence only', () => {
    const findings = scanText('const x = "q8Zr3Lp0Vw7Kd2Nf5Hs9Tj4Bx6Mc1Ya"', 'a.ts');
    expect(findings).toHaveLength(1);
    expect(findings[0]!.meta.confidence).toBe('low');
    expect(scanText('const sha = "q8Zr3Lp0Vw7Kd2Nf5Hs9Tj4Bx6Mc1Ya"', 'a.ts')).toEqual([]);
  });

  it('honours inline and config allowlists', () => {
    expect(scanText(`t = "${GH}" // secretcheck:allow`, 'a.ts')).toEqual([]);
    expect(scanText(`// secretcheck:allow-next-line\nt = "${GH}"`, 'a.ts')).toEqual([]);
    expect(scanText(`t = "${GH}"`, 'test/fixtures/a.ts', { allowlist: { paths: ['test/fixtures/**'] } })).toEqual([]);
    const [first] = scanText(`t = "${GH}"`, 'a.ts');
    expect(scanText(`t = "${GH}"`, 'a.ts', { allowlist: { fingerprints: [first!.fingerprint] } })).toEqual([]);
  });

  it('supports custom rules', () => {
    const findings = scanText('key: acme_live_abcdef123456', 'x.yml', {
      customRules: [{ id: 'acme', pattern: '(?<secret>acme_live_[a-z0-9]{12})', confidence: 'high' }],
    });
    expect(findings[0]?.ruleId).toBe('acme');
  });

  it('redacts to a short prefix', () => {
    expect(redact(GH)).toBe('ghp_********');
    expect(redact('short')).toBe('********');
  });
});

describe('scanFiles', () => {
  it('skips generated, vendored and lock files', () => {
    expect(isExcluded('package-lock.json')).toBe(true);
    expect(isExcluded('web/dist/app.js')).toBe(true);
    expect(isExcluded('src/app.min.js')).toBe(true);
    expect(isExcluded('src/app.ts')).toBe(false);
    const result = scanFiles([
      { path: 'dist/bundle.js', content: `x="${GH}"` },
      { path: 'src/gen.ts', content: `// @generated\nx="${GH}"` },
      { path: 'src/real.ts', content: `x="${GH}"` },
    ]);
    expect(result.findings.map((f) => f.location?.file)).toEqual(['src/real.ts']);
    expect(result.blocking).toHaveLength(1);
    expect(result.skipped.map((s) => s.reason)).toEqual(['excluded', 'marked @generated']);
  });
});

describe('scanStaged', () => {
  const git = (cwd: string, ...args: string[]) =>
    execFileSync('git', ['-c', 'user.email=t@example.com', '-c', 'user.name=t', ...args], { cwd, stdio: 'pipe' });

  it('scans the index, not the working tree', () => {
    const dir = mkdtempSync(join(tmpdir(), 'secretcheck-'));
    git(dir, 'init', '-q');
    writeFileSync(join(dir, 'clean.ts'), 'export const a = 1;\n');
    writeFileSync(join(dir, 'leak.ts'), `export const t = "${GH}";\n`);
    git(dir, 'add', 'clean.ts', 'leak.ts');
    // Fix the leak in the working tree only: the staged copy still contains it.
    writeFileSync(join(dir, 'leak.ts'), 'export const t = process.env.TOKEN;\n');
    // A file that is not staged must be ignored even though it holds a secret.
    writeFileSync(join(dir, 'untracked.ts'), `x="${AWS}"\n`);

    const result = scanStaged({ cwd: dir });
    expect(result.files.sort()).toEqual(['clean.ts', 'leak.ts']);
    expect(result.blocking.map((f) => f.location?.file)).toEqual(['leak.ts']);
  });

  it('can limit findings to lines added in this commit', () => {
    const dir = mkdtempSync(join(tmpdir(), 'secretcheck-'));
    git(dir, 'init', '-q');
    writeFileSync(join(dir, 'a.ts'), `const old = "${GH}";\n`);
    git(dir, 'add', '.');
    git(dir, 'commit', '-qm', 'init');
    writeFileSync(join(dir, 'a.ts'), `const old = "${GH}";\nconst k = "${AWS}";\n`);
    git(dir, 'add', '.');
    const result = scanStaged({ cwd: dir, changedLinesOnly: true });
    expect(result.findings.map((f) => [f.ruleId, f.location?.line])).toEqual([['aws-access-key-id', 2]]);
  });
});
