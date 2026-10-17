import { describe, expect, it } from 'vitest';
import {
  attributionMarkdown,
  categorize,
  checkLicenses,
  checkPackageLock,
  evaluate,
  normalizeLicense,
  parseExpression,
  POLICIES,
  summarizeLicenses,
  type FetchLike,
  type PackageLicense,
} from '../src/index.js';

describe('SPDX expressions', () => {
  it('parses with WITH > AND > OR precedence', () => {
    expect(parseExpression('MIT OR Apache-2.0 AND BSD-3-Clause')).toEqual({
      or: [{ license: 'MIT' }, { and: [{ license: 'Apache-2.0' }, { license: 'BSD-3-Clause' }] }],
    });
    expect(parseExpression('(GPL-2.0-only WITH Classpath-exception-2.0)')).toEqual({ license: 'GPL-2.0-only', exception: 'Classpath-exception-2.0' });
    expect(() => parseExpression('MIT OR')).toThrow();
    expect(() => parseExpression('(MIT')).toThrow();
  });

  it('normalizes messy package.json values', () => {
    expect(normalizeLicense('mit').expression).toBe('MIT');
    expect(normalizeLicense('Apache 2.0').expression).toBe('Apache-2.0');
    expect(normalizeLicense('GPL-2.0+').expression).toBe('GPL-2.0-or-later');
    expect(normalizeLicense({ type: 'MIT' }).expression).toBe('MIT');
    expect(normalizeLicense(undefined, [{ type: 'MIT' }, { type: 'Apache-2.0' }]).expression).toBe('MIT OR Apache-2.0');
    expect(normalizeLicense('(MIT OR Apache-2.0) AND BSD-3-Clause').expression).toBe('(MIT OR Apache-2.0) AND BSD-3-Clause');
    expect(normalizeLicense('UNLICENSED').expression).toBe('LicenseRef-Proprietary');
    expect(normalizeLicense('SEE LICENSE IN LICENSE.md').expression).toBe('LicenseRef-Custom');
    expect(normalizeLicense(undefined)).toEqual({});
  });

  it('categorizes licenses', () => {
    expect(categorize('MIT')).toBe('permissive');
    expect(categorize('LGPL-3.0-only')).toBe('weak-copyleft');
    expect(categorize('GPL-3.0-or-later')).toBe('strong-copyleft');
    expect(categorize('GPL-2.0-only', 'Classpath-exception-2.0')).toBe('weak-copyleft');
    expect(categorize('AGPL-3.0-only')).toBe('network-copyleft');
    expect(categorize('BUSL-1.1')).toBe('source-available');
    expect(categorize('CC-BY-NC-4.0')).toBe('non-commercial');
    expect(categorize('Foo-1.0')).toBe('unknown');
  });
});

describe('policy evaluation', () => {
  it('OR takes the best alternative, AND the worst part', () => {
    expect(evaluate('GPL-3.0-only OR MIT').verdict).toBe('allowed');
    expect(evaluate('GPL-3.0-only OR MIT').license).toBe('MIT');
    expect(evaluate('MIT AND GPL-3.0-only').verdict).toBe('denied');
    expect(evaluate('MPL-2.0').verdict).toBe('review');
  });

  it('honours explicit allow/deny lists over categories', () => {
    expect(evaluate('MPL-2.0', { ...POLICIES.permissive, allow: ['MPL-2.0'] }).verdict).toBe('allowed');
    expect(evaluate('MIT', { deny: ['MIT'] }).verdict).toBe('denied');
    expect(evaluate('BSD-2-Clause', { allow: ['MIT'] }).verdict).toBe('review');
  });
});

const pkgs: PackageLicense[] = [
  { name: 'react', version: '18.3.1', license: 'MIT' },
  { name: 'gpl-lib', version: '1.0.0', license: 'GPL-3.0-only' },
  { name: 'gpl-tool', version: '2.0.0', license: 'GPL-3.0-only', dev: true },
  { name: 'mystery', version: '0.1.0' },
  { name: 'mpl-lib', version: '1.0.0', license: 'MPL-2.0' },
  { name: 'bsl', version: '1.0.0', license: 'BUSL-1.1' },
];

describe('checkLicenses', () => {
  it('reports denied, review and missing licenses with severity by dependency type', () => {
    const findings = checkLicenses(pkgs);
    expect(findings.map((f) => [f.ruleId, f.meta.package, f.severity])).toEqual([
      ['license-denied', 'gpl-lib', 'high'],
      ['license-denied', 'gpl-tool', 'medium'],
      ['license-missing', 'mystery', 'medium'],
      ['license-review', 'mpl-lib', 'medium'],
      ['license-review', 'bsl', 'medium'],
    ]);
    expect(findings[0]!.remediation).toMatch(/source/);
  });

  it('supports production-only checks and per-package exceptions', () => {
    const findings = checkLicenses(pkgs, { production: true, policy: { ...POLICIES.permissive, exceptions: [{ package: 'mystery', reason: 'internal' }] } });
    expect(findings.map((f) => f.meta.package)).toEqual(['gpl-lib', 'mpl-lib', 'bsl']);
  });

  it('summarizes and writes attribution', () => {
    expect(summarizeLicenses(pkgs)[0]).toMatchObject({ license: 'GPL-3.0-only', count: 2 });
    const md = attributionMarkdown([{ ...pkgs[0]!, licenseText: 'MIT License\n\nCopyright (c) Meta' }]);
    expect(md).toContain('## react@18.3.1');
    expect(md).toContain('Copyright (c) Meta');
  });
});

describe('checkPackageLock', () => {
  it('reads licenses from the lockfile and fills gaps from the registry', async () => {
    const lock = JSON.stringify({
      lockfileVersion: 3,
      packages: {
        '': { name: 'app' },
        'node_modules/react': { version: '18.3.1', license: 'MIT' },
        'node_modules/old-lib': { version: '1.0.0' },
      },
    });
    const calls: string[] = [];
    const fetch: FetchLike = async (url) => {
      calls.push(url);
      return { ok: true, status: 200, json: async () => ({ licenses: [{ type: 'GPL-2.0' }] }) };
    };
    const findings = await checkPackageLock(lock, { fetch });
    expect(calls).toEqual(['https://registry.npmjs.org/old-lib/1.0.0']);
    expect(findings.map((f) => [f.meta.package, f.meta.license])).toEqual([['old-lib', 'GPL-2.0-only']]);
  });
});
