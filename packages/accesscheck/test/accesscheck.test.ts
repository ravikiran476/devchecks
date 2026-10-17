// @vitest-environment jsdom
import { describe, expect, it } from 'vitest';
import { createBaseline } from '@devchecks/core';
import { mapAxeResults, scan, suggestFix, wcagCriteria } from '../src/index.js';

describe('mapAxeResults', () => {
  const results = {
    url: 'http://localhost:3000/checkout?step=2',
    violations: [
      {
        id: 'button-name',
        impact: 'critical',
        help: 'Buttons must have discernible text',
        helpUrl: 'https://dequeuniversity.com/rules/axe/4.10/button-name',
        tags: ['cat.name-role-value', 'wcag2a', 'wcag412'],
        nodes: [{ target: ['#pay > button'], html: '<button><svg></svg></button>', failureSummary: 'Element does not have inner text' }],
      },
    ],
    incomplete: [{ id: 'color-contrast', impact: 'serious', help: 'Contrast', tags: ['wcag2aa', 'wcag143'], nodes: [{ target: ['.hero h1'] }] }],
  };

  it('maps impact to severity and keeps selector, WCAG criteria and fix', () => {
    const [f] = mapAxeResults(results);
    expect(f).toMatchObject({
      ruleId: 'button-name',
      severity: 'critical',
      location: { url: results.url, selector: '#pay > button' },
      tags: ['WCAG 4.1.2'],
    });
    expect(f!.remediation).toMatch(/aria-label/);
  });

  it('includes incomplete checks as info only when asked', () => {
    expect(mapAxeResults(results)).toHaveLength(1);
    const all = mapAxeResults(results, { includeIncomplete: true });
    expect(all[1]).toMatchObject({ severity: 'info', tags: ['WCAG 1.4.3', 'needs-review'] });
  });

  it('fingerprints by path and selector so baselines work across hosts', () => {
    const local = mapAxeResults(results)[0]!;
    const staging = mapAxeResults({ ...results, url: 'https://staging.example.com/checkout?step=2' })[0]!;
    expect(local.fingerprint).toBe(staging.fingerprint);
  });

  it('parses WCAG criteria tags', () => {
    expect(wcagCriteria(['wcag2aa', 'wcag143', 'wcag1410', 'wcag412'])).toEqual(['1.4.3', '1.4.10', '4.1.2']);
    expect(suggestFix('unknown-rule', 'Fix any of the following')).toBe('Fix any of the following');
  });
});

describe('scan (axe-core in the DOM)', () => {
  it('finds missing names, alt text and invalid ARIA, and supports baselines', async () => {
    document.documentElement.lang = 'en';
    document.title = 'Test';
    document.body.innerHTML = `
      <main>
        <h1>Checkout</h1>
        <button id="icon"><svg aria-hidden="true"></svg></button>
        <img id="logo" src="logo.png">
        <div id="bad" aria-hiddn="true">typo</div>
        <label for="ok">Name</label><input id="ok">
      </main>`;
    const first = await scan(document);
    const ids = first.findings.map((f) => f.ruleId).sort();
    expect(ids).toEqual(expect.arrayContaining(['aria-valid-attr', 'button-name', 'image-alt']));
    expect(first.findings.find((f) => f.ruleId === 'image-alt')?.location?.selector).toBe('#logo');

    const baseline = createBaseline('accesscheck', first.findings);
    document.body.insertAdjacentHTML('beforeend', '<a href="/x" id="empty"></a>');
    const second = await scan(document, { baseline });
    expect(second.newFindings.map((f) => f.ruleId)).toEqual(['link-name']);
    expect(second.report.baseline).toEqual({ new: 1, existing: first.findings.length, fixed: 0 });
  });
});
