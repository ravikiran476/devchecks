import { fingerprint, SEVERITIES, parseSeverity, type Finding, type Severity } from '@devchecks/core';
import { cvss3BaseScore, scoreToSeverity } from './cvss.js';
import type { Dependency } from './lockfiles.js';
import { OsvClient, type OsvClientOptions, type OsvEvent, type OsvVulnerability } from './osv.js';
import { compareSemver, isSemver } from './semver.js';

export interface IgnoreRule {
  /** Advisory id or alias (GHSA-..., CVE-...). */
  id: string;
  /** Limit the ignore to one package. */
  package?: string;
  reason?: string;
  /** ISO date after which the ignore stops applying, so accepted risk gets re-reviewed. */
  expires?: string;
}

export interface CheckOptions extends OsvClientOptions {
  /** Skip dependencies only reachable through devDependencies. */
  production?: boolean;
  ignore?: IgnoreRule[];
  /** Location reported for findings, usually the lockfile path. */
  source?: string;
  client?: OsvClient;
  now?: Date;
}

export interface VulnerabilityFinding extends Finding {
  meta: {
    package: string;
    version: string;
    fixedIn?: string;
    aliases: string[];
    cvssScore?: number;
    cvssVector?: string;
    dev: boolean;
    paths: string[];
    published?: string;
  };
}

const GHSA_SEVERITY: Record<string, Severity> = { CRITICAL: 'critical', HIGH: 'high', MODERATE: 'medium', MEDIUM: 'medium', LOW: 'low' };

export function vulnerabilitySeverity(v: OsvVulnerability): { severity: Severity; score?: number; vector?: string } {
  if (v.id.startsWith('MAL-')) return { severity: 'critical' };
  const vector = v.severity?.find((s) => s.type === 'CVSS_V3')?.score;
  const score = vector ? cvss3BaseScore(vector) : undefined;
  const label = String(v.database_specific?.severity ?? '').toUpperCase();
  const fromDb = GHSA_SEVERITY[label];
  if (fromDb) return { severity: fromDb, score, vector };
  if (score !== undefined) return { severity: scoreToSeverity(score), score, vector };
  const anyVector = v.severity?.[0]?.score;
  return { severity: 'medium', vector: anyVector };
}

function inRange(version: string, events: OsvEvent[]): { affected: boolean; fixed?: string } {
  // OSV events describe half-open intervals: [introduced, fixed) or [introduced, last_affected].
  const sorted = [...events].sort((a, b) => {
    const va = a.introduced ?? a.fixed ?? a.last_affected ?? a.limit ?? '0';
    const vb = b.introduced ?? b.fixed ?? b.last_affected ?? b.limit ?? '0';
    return compareSemver(va === '0' ? '0.0.0-0' : va, vb === '0' ? '0.0.0-0' : vb);
  });
  let start: string | undefined;
  for (const e of sorted) {
    if (e.introduced !== undefined) start = e.introduced === '0' ? '0.0.0-0' : e.introduced;
    else if (start !== undefined && (e.fixed || e.last_affected)) {
      const end = (e.fixed ?? e.last_affected)!;
      const afterStart = compareSemver(version, start) >= 0;
      const beforeEnd = e.fixed ? compareSemver(version, end) < 0 : compareSemver(version, end) <= 0;
      if (afterStart && beforeEnd) return { affected: true, fixed: e.fixed };
      start = undefined;
    }
  }
  if (start !== undefined && compareSemver(version, start) >= 0) return { affected: true };
  return { affected: false };
}

/** Finds the smallest version that fixes `vuln` for `dep`, if OSV records one. */
export function fixedVersionFor(dep: Dependency, vuln: OsvVulnerability): string | undefined {
  const candidates: string[] = [];
  const later: string[] = [];
  for (const a of vuln.affected ?? []) {
    if (a.package && (a.package.name !== dep.name || a.package.ecosystem.toLowerCase() !== 'npm')) continue;
    for (const r of a.ranges ?? []) {
      if (r.type !== 'SEMVER' && r.type !== 'ECOSYSTEM') continue;
      const hit = inRange(dep.version, r.events);
      if (hit.affected && hit.fixed) candidates.push(hit.fixed);
      for (const e of r.events) if (e.fixed && isSemver(e.fixed) && compareSemver(e.fixed, dep.version) > 0) later.push(e.fixed);
    }
  }
  const pick = candidates.length ? candidates : later;
  return pick.sort(compareSemver)[0];
}

function isIgnored(dep: Dependency, vuln: OsvVulnerability, rules: IgnoreRule[], now: Date): boolean {
  const ids = new Set([vuln.id, ...(vuln.aliases ?? [])]);
  return rules.some(
    (r) => ids.has(r.id) && (!r.package || r.package === dep.name) && (!r.expires || new Date(r.expires) > now),
  );
}

function primaryId(v: OsvVulnerability): string {
  if (v.id.startsWith('GHSA-') || v.id.startsWith('MAL-')) return v.id;
  return v.aliases?.find((a) => a.startsWith('GHSA-')) ?? v.id;
}

export function toFinding(dep: Dependency, vuln: OsvVulnerability, source?: string): VulnerabilityFinding {
  const { severity, score, vector } = vulnerabilitySeverity(vuln);
  const fixedIn = fixedVersionFor(dep, vuln);
  const id = primaryId(vuln);
  const malicious = vuln.id.startsWith('MAL-');
  const title = vuln.summary ?? vuln.details?.split('\n')[0]?.slice(0, 160) ?? 'Known vulnerability';
  const remediation = malicious
    ? `Remove ${dep.name} immediately, treat machines that installed it as compromised, and rotate credentials they could reach.`
    : fixedIn
      ? `Upgrade ${dep.name} to ${fixedIn} or later${dep.paths && dep.paths.some((p) => p.split('node_modules/').length > 2 || p.includes(' > ')) ? ' (it is a transitive dependency: update the parent, or use npm "overrides" / yarn "resolutions")' : ''}.`
      : `No fixed version is published. Consider replacing ${dep.name}, removing it, or mitigating the issue described in the advisory.`;
  return {
    fingerprint: fingerprint('depcheck', id, dep.name, dep.version),
    ruleId: id,
    severity,
    message: `${dep.name}@${dep.version}: ${title}`,
    location: source ? { file: source } : undefined,
    remediation,
    helpUrl: `https://osv.dev/vulnerability/${vuln.id}`,
    tags: [...new Set([vuln.id, ...(vuln.aliases ?? [])])],
    meta: {
      package: dep.name,
      version: dep.version,
      fixedIn,
      aliases: vuln.aliases ?? [],
      cvssScore: score,
      cvssVector: vector,
      dev: !!dep.dev,
      paths: dep.paths ?? [],
      published: vuln.published,
    },
  };
}

/** Looks up every dependency in OSV and returns one finding per (package version, advisory). */
export async function checkDependencies(deps: Dependency[], options: CheckOptions = {}): Promise<VulnerabilityFinding[]> {
  const wanted = options.production ? deps.filter((d) => !d.dev) : deps;
  if (!wanted.length) return [];
  const client = options.client ?? new OsvClient(options);
  const ids = await client.queryIds(wanted);
  const details = await client.getVulnerabilities(ids.flat());
  const now = options.now ?? new Date();
  const findings: VulnerabilityFinding[] = [];
  wanted.forEach((dep, i) => {
    const seen = new Set<string>();
    for (const id of ids[i]!) {
      const vuln = details.get(id);
      if (!vuln || vuln.withdrawn) continue;
      if (isIgnored(dep, vuln, options.ignore ?? [], now)) continue;
      const finding = toFinding(dep, vuln, options.source);
      if (seen.has(finding.ruleId)) continue; // same advisory under two OSV ids
      seen.add(finding.ruleId);
      findings.push(finding);
    }
  });
  return findings;
}

interface NpmAuditVia {
  source?: number;
  name?: string;
  title?: string;
  url?: string;
  severity?: string;
  range?: string;
}

/** Converts `npm audit --json` (npm 7+) output into findings, for teams already using npm audit. */
export function fromNpmAudit(json: string | unknown, source = 'package-lock.json'): Finding[] {
  const data = (typeof json === 'string' ? JSON.parse(json) : json) as {
    vulnerabilities?: Record<string, { name: string; via: Array<NpmAuditVia | string>; fixAvailable?: boolean | { name: string; version: string; isSemVerMajor?: boolean }; nodes?: string[] }>;
  };
  const findings: Finding[] = [];
  for (const v of Object.values(data.vulnerabilities ?? {})) {
    for (const via of v.via) {
      if (typeof via === 'string') continue; // inherited from another package; reported there
      const ghsa = /GHSA-[\w-]+/.exec(via.url ?? '')?.[0] ?? `npm-${via.source}`;
      const sev = (via.severity ?? 'medium').toLowerCase();
      const fix = v.fixAvailable;
      findings.push({
        fingerprint: fingerprint('depcheck', ghsa, v.name, via.range),
        ruleId: ghsa,
        severity: SEVERITIES.includes(sev as Severity) || sev === 'moderate' ? parseSeverity(sev) : 'medium',
        message: `${v.name} ${via.range ?? ''}: ${via.title ?? 'Known vulnerability'}`.replace(/\s+:/, ':'),
        location: { file: source },
        helpUrl: via.url,
        remediation:
          typeof fix === 'object'
            ? `Upgrade ${fix.name} to ${fix.version}${fix.isSemVerMajor ? ' (major version change: review breaking changes)' : ''}.`
            : fix
              ? 'Run `npm audit fix`.'
              : 'No fix available; consider replacing or removing the package.',
        meta: { package: v.name, range: via.range, nodes: v.nodes },
      });
    }
  }
  return findings;
}
