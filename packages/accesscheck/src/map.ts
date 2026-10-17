// Converts axe-core results into the shared finding format. No axe import here,
// so this module is cheap to load in Node and in the browser.
import { createReport, fingerprint, type BaselineDiff, type Finding, type Report, type Severity } from '@devchecks/core';
import { suggestFix } from './fixes.js';

export interface AxeNode {
  target: Array<string | string[]>;
  html?: string;
  failureSummary?: string;
  impact?: string | null;
}

export interface AxeRuleResult {
  id: string;
  impact?: string | null;
  help: string;
  description?: string;
  helpUrl?: string;
  tags: string[];
  nodes: AxeNode[];
}

export interface AxeResults {
  url?: string;
  violations: AxeRuleResult[];
  incomplete?: AxeRuleResult[];
}

export const TOOL = 'accesscheck';
export const VERSION = __VERSION__;

export const DEFAULT_TAGS = ['wcag2a', 'wcag2aa', 'wcag21a', 'wcag21aa', 'wcag22aa'];

export const LIMITATIONS =
  'Automated checks find roughly a third to a half of WCAG issues. Keyboard navigation, focus order, screen-reader output and meaningful content still need manual testing.';

const IMPACT: Record<string, Severity> = { critical: 'critical', serious: 'high', moderate: 'medium', minor: 'low' };

/** "wcag143" -> "1.4.3" */
export function wcagCriteria(tags: string[]): string[] {
  return tags.filter((t) => /^wcag\d{3,4}$/.test(t)).map((t) => t.slice(4).split('').join('.').replace(/^(\d)\.(\d)\.(\d)\.(\d)$/, '$1.$2.$3$4'));
}

function selectorOf(node: AxeNode): string {
  return node.target.map((t) => (Array.isArray(t) ? t.join(' >>> ') : t)).join(' | ');
}

function pathOf(url: string | undefined): string {
  if (!url) return '';
  try {
    const u = new URL(url);
    return u.pathname + u.search;
  } catch {
    return url;
  }
}

export interface MapOptions {
  /** Include axe "incomplete" results (need manual review) as info findings. Default false. */
  includeIncomplete?: boolean;
  url?: string;
}

export function mapAxeResults(results: AxeResults, options: MapOptions = {}): Finding[] {
  const url = options.url ?? results.url;
  const findings: Finding[] = [];
  const add = (rule: AxeRuleResult, node: AxeNode, review: boolean) => {
    const selector = selectorOf(node);
    const criteria = wcagCriteria(rule.tags);
    findings.push({
      // Path + selector rather than full URL, so the same baseline works on localhost and staging.
      fingerprint: fingerprint(TOOL, rule.id, pathOf(url), selector),
      ruleId: rule.id,
      severity: review ? 'info' : IMPACT[node.impact ?? rule.impact ?? ''] ?? 'medium',
      message: review ? `Needs review: ${rule.help}` : rule.help,
      location: { url, selector },
      snippet: node.html && node.html.length > 200 ? `${node.html.slice(0, 197)}...` : node.html,
      remediation: suggestFix(rule.id, node.failureSummary),
      helpUrl: rule.helpUrl,
      tags: [...criteria.map((c) => `WCAG ${c}`), ...(review ? ['needs-review'] : [])],
      meta: { impact: node.impact ?? rule.impact, wcag: criteria, axeTags: rule.tags },
    });
  };
  for (const rule of results.violations) for (const node of rule.nodes) add(rule, node, false);
  if (options.includeIncomplete) for (const rule of results.incomplete ?? []) for (const node of rule.nodes) add(rule, node, true);
  return findings;
}

export function toReport(findings: Finding[], baseline?: BaselineDiff): Report {
  return createReport(TOOL, VERSION, findings, { baseline, notes: [LIMITATIONS] });
}
