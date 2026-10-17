import { describe, expect, it } from 'vitest';
import {
  createBaseline,
  createReport,
  diffBaseline,
  formatSARIF,
  matchGlob,
  meetsThreshold,
  parseSeverity,
  sha256Integrity,
  type Finding,
} from '@devchecks/core';

const f = (ruleId: string, fp: string, severity: Finding['severity'] = 'high'): Finding => ({
  fingerprint: fp,
  ruleId,
  severity,
  message: 'm',
  location: { file: 'src/a.ts', line: 3 },
});

describe('glob', () => {
  it.each([
    ['**/node_modules/**', 'a/node_modules/b/c.js', true],
    ['**/node_modules/**', 'node_modules/x.js', true],
    ['*.min.js', 'deep/dir/app.min.js', true],
    ['src/components/**', 'src/components/Button.tsx', true],
    ['src/components/**', 'src/services/api.ts', false],
    ['src/*.ts', 'src/a/b.ts', false],
    ['*.{png,jpg}', 'img/logo.jpg', true],
    ['package-lock.json', 'packages/x/package-lock.json', true],
    ['src/features/*/index.ts', 'src/features/cart/index.ts', true],
  ])('%s vs %s', (pattern, path, expected) => {
    expect(matchGlob(pattern, path)).toBe(expected);
  });

  it('normalizes Windows separators', () => {
    expect(matchGlob('src/**/*.ts', 'src\\a\\b.ts')).toBe(true);
  });
});

describe('severity', () => {
  it('parses aliases and compares thresholds', () => {
    expect(parseSeverity('moderate')).toBe('medium');
    expect(parseSeverity('SERIOUS')).toBe('high');
    expect(meetsThreshold('critical', 'high')).toBe(true);
    expect(meetsThreshold('low', 'medium')).toBe(false);
    expect(() => parseSeverity('bogus')).toThrow(/Unknown severity/);
  });
});

describe('baseline', () => {
  it('separates new, existing and fixed findings', () => {
    const baseline = createBaseline('t', [f('a', '1'), f('b', '2')]);
    const diff = diffBaseline([f('a', '1'), f('c', '3')], baseline);
    expect(diff.newFindings.map((x) => x.ruleId)).toEqual(['c']);
    expect(diff.existing.map((x) => x.ruleId)).toEqual(['a']);
    expect(diff.fixed.map((x) => x.ruleId)).toEqual(['b']);
  });
});

describe('reporters', () => {
  it('produces valid SARIF with one rule per ruleId', () => {
    const report = createReport('t', '1.0.0', [f('a', '1'), f('a', '2', 'low')]);
    const sarif = JSON.parse(formatSARIF(report));
    expect(sarif.version).toBe('2.1.0');
    expect(sarif.runs[0].tool.driver.rules).toHaveLength(1);
    expect(sarif.runs[0].results[0].locations[0].physicalLocation.region.startLine).toBe(3);
  });

  it('computes CSP/SRI-style hashes', async () => {
    expect(await sha256Integrity('alert(1)')).toBe('sha256-bhHHL3z2vDgxUt0W3dWQOrprscmda2Y5pLsLg4GF+pI=');
  });
});
