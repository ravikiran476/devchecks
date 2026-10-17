// Browser-safe entry: everything here runs from a CDN, in Node, or in a bundler.
import { createReport, type BaselineDiff, type Report } from '@devchecks/core';
import type { SecretFinding } from './scan.js';

export { BUILTIN_RULES, isPlaceholder, type Confidence, type SecretRule } from './rules.js';
export { isHighEntropy, shannonEntropy, type EntropyOptions } from './entropy.js';
export {
  DEFAULT_EXCLUDES,
  compileRules,
  isBlocking,
  isExcluded,
  redact,
  scanFiles,
  scanText,
  type CustomRuleConfig,
  type ScanResult,
  type SecretCheckConfig,
  type SecretFinding,
} from './scan.js';
export { formatReport, createBaseline, diffBaseline, type Finding, type Report } from '@devchecks/core';

export const TOOL = 'secretcheck';
export const VERSION = __VERSION__;

export function toReport(findings: SecretFinding[], baseline?: BaselineDiff): Report {
  return createReport(TOOL, VERSION, findings, {
    baseline,
    notes: ['Secrets are redacted in all output. A detected secret must be treated as leaked: rotate it, do not just delete it.'],
  });
}
