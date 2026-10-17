// Browser-safe entry: parse a lockfile and query OSV from a page, a bundler or Node.
import { createReport, type BaselineDiff, type Report } from '@devchecks/core';
import { checkDependencies, type CheckOptions, type VulnerabilityFinding } from './analyze.js';
import { parseLockfile } from './lockfiles.js';

export {
  checkDependencies,
  fixedVersionFor,
  fromNpmAudit,
  toFinding,
  vulnerabilitySeverity,
  type CheckOptions,
  type IgnoreRule,
  type VulnerabilityFinding,
} from './analyze.js';
export {
  detectLockfileKind,
  parseLockfile,
  parseNpmLs,
  parsePackageLock,
  parsePnpmLock,
  parseYarnLock,
  type Dependency,
  type LockfileKind,
} from './lockfiles.js';
export { OsvClient, type FetchLike, type OsvClientOptions, type OsvVulnerability } from './osv.js';
export { cvss3BaseScore, scoreToSeverity } from './cvss.js';
export { compareSemver, parseSemver } from './semver.js';
export { createBaseline, diffBaseline, formatReport, type Finding, type Report } from '@devchecks/core';

export const TOOL = 'depcheck';
export const VERSION = __VERSION__;

/** Parses lockfile text and checks every resolved package against OSV. */
export async function checkLockfile(text: string, options: CheckOptions & { filename?: string } = {}): Promise<VulnerabilityFinding[]> {
  const filename = options.filename ?? 'package-lock.json';
  return checkDependencies(parseLockfile(filename, text), { source: filename, ...options });
}

export function toReport(findings: VulnerabilityFinding[], baseline?: BaselineDiff): Report {
  return createReport(TOOL, VERSION, findings, {
    baseline,
    notes: ['Vulnerability data from OSV.dev (GitHub Advisory Database, OpenSSF malicious packages and other sources).'],
  });
}
