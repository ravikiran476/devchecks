// Browser-safe entry: analyze source text from a CDN playground, a bundler plugin or Node.
import { createReport, type BaselineDiff, type Finding, type Report } from '@devchecks/core';

export { analyzeSource, parseSource, SCRIPT_EXTENSIONS, TEMPLATE_EXTENSIONS, type FileResult, type SafeCodeCheckOptions } from './analyze.js';
export { RULES, classify, runRules, type RawFinding, type RuleId, type RuleInfo, type Taint } from './rules.js';
export { walk, type Node } from './ast.js';
export { createBaseline, diffBaseline, formatReport, type Finding, type Report } from '@devchecks/core';

export const TOOL = 'safecodecheck';
export const VERSION = __VERSION__;

export function toReport(findings: Finding[], baseline?: BaselineDiff): Report {
  return createReport(TOOL, VERSION, findings, {
    baseline,
    notes: ['Static analysis finds likely issues, not proof of exploitability. Review each finding in context.'],
  });
}
