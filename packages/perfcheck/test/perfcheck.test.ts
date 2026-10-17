import { mkdirSync, mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import { checkPage, parseSize, type ResourceSummary } from '../src/index.js';
import { checkBundles, measureBundles, stripContentHash } from '../src/node.js';

describe('stripContentHash', () => {
  it('removes bundler hashes but keeps real names', () => {
    expect(stripContentHash('assets/index-BXk3Yq9a.js')).toBe('assets/index.js');
    expect(stripContentHash('static/js/main.3f9a1c2b.js')).toBe('static/js/main.js');
    expect(stripContentHash('assets/vendor-dashboard.js')).toBe('assets/vendor-dashboard.js');
  });
});

const resources: ResourceSummary = {
  requests: 40,
  totalBytes: 2_400_000,
  byType: { script: 900_000, stylesheet: 80_000, image: 1_300_000, font: 100_000, document: 20_000, other: 0 },
  thirdPartyBytes: 500_000,
  largest: [{ url: 'https://x/hero.png', bytes: 900_000, type: 'image' }],
};

describe('sizes', () => {
  it('parses decimal and binary units', () => {
    expect(parseSize('170kB')).toBe(170_000);
    expect(parseSize('1.5MB')).toBe(1_500_000);
    expect(parseSize('200KiB')).toBe(204_800);
    expect(parseSize(42)).toBe(42);
    expect(() => parseSize('big')).toThrow();
  });
});

describe('checkPage', () => {
  it('uses Core Web Vitals thresholds when no budget is set', () => {
    const findings = checkPage('https://shop.test/', { lcp: 4500, cls: 0.15, fcp: 1000, ttfb: 200, tbt: 100, interactions: 0, inp: 800, lcpElement: 'img.hero' }, undefined);
    expect(findings.map((f) => [f.ruleId, f.meta?.metric, f.severity])).toEqual([
      ['web-vital-poor', 'lcp', 'high'],
      ['web-vital-needs-improvement', 'cls', 'medium'],
    ]);
    expect(findings[0]!.message).toContain('img.hero');
  });

  it('checks explicit metric and weight budgets', () => {
    const findings = checkPage('https://shop.test/', { lcp: 2000, cls: 0, interactions: 0 }, resources, { lcp: 1800, scriptBytes: '400kB', imageBytes: '2MB', requests: 30 });
    expect(findings.map((f) => [f.meta?.metric, f.severity])).toEqual([
      ['lcp', 'medium'],
      ['scriptBytes', 'high'],
      ['requests', 'medium'],
    ]);
  });
});

describe('bundles', () => {
  it('measures gzip/brotli and enforces per-file and total budgets', () => {
    const dir = mkdtempSync(join(tmpdir(), 'perfcheck-'));
    mkdirSync(join(dir, 'assets'));
    const random = (n: number) => Array.from({ length: n }, (_, i) => `v${i}=${(i * 2654435761) % 1000003};`).join('');
    writeFileSync(join(dir, 'assets', 'index-a1b2c3d4e5.js'), random(20000));
    writeFileSync(join(dir, 'assets', 'small.js'), 'console.log(1)');
    writeFileSync(join(dir, 'assets', 'index.js.map'), 'x'.repeat(100000));
    const files = measureBundles(dir);
    expect(files.map((f) => f.path)).toEqual(['assets/index-a1b2c3d4e5.js', 'assets/small.js']);
    expect(files[0]!.gzip).toBeLessThan(files[0]!.size);
    const { findings } = checkBundles(dir, [{ path: 'assets/*.js', maxGzip: '20kB' }, { path: 'total:js', maxBrotli: '1MB' }]);
    expect(findings.map((f) => [f.ruleId, f.meta?.kind, f.location?.file])).toEqual([['bundle-size-exceeded', 'gzip', `${dir.replace(/\\/g, '/')}/assets/index-a1b2c3d4e5.js`]]);
  });
});
