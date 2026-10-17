// Browser-safe entry: check a package-lock.json or a package list from a page, a bundler or Node.
import { createReport, type BaselineDiff, type Finding, type Report } from '@devchecks/core';
import { checkLicenses, fetchMissingLicenses, fromPackageLock, type CheckOptions, type FetchLike, type LicenseFinding } from './check.js';

export * from './check.js';
export { categorize, categoriesOf, DEFAULT_POLICY, evaluate, POLICIES, type Category, type Evaluation, type LicensePolicy, type Verdict } from './policy.js';
export { formatExpression, leaves, normalizeLicense, parseExpression, type Expr, type NormalizedLicense } from './spdx.js';
export { createBaseline, diffBaseline, formatReport, type Finding, type Report } from '@devchecks/core';

export const TOOL = 'licensecheck';
export const VERSION = __VERSION__;

export const NOTE = 'License classification is guidance for engineers, not legal advice. Confirm policy decisions with your legal team.';

/** Reads licenses from package-lock.json text (looking up any missing ones in the npm registry) and applies the policy. */
export async function checkPackageLock(text: string, options: CheckOptions & { fetch?: FetchLike; offline?: boolean } = {}): Promise<LicenseFinding[]> {
  const packages = fromPackageLock(text);
  if (!options.offline) await fetchMissingLicenses(packages, { fetch: options.fetch });
  return checkLicenses(packages, { source: 'package-lock.json', ...options });
}

export function toReport(findings: Finding[], baseline?: BaselineDiff): Report {
  return createReport(TOOL, VERSION, findings, { baseline, notes: [NOTE] });
}
