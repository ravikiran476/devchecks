import type { Finding } from './types.js';

export interface Baseline {
  version: 1;
  tool: string;
  createdAt: string;
  /** Fingerprints of accepted findings, with a little context so the file is reviewable. */
  entries: BaselineEntry[];
}

export interface BaselineEntry {
  fingerprint: string;
  ruleId: string;
  where?: string;
}

export interface BaselineDiff {
  /** Findings not present in the baseline — the ones to act on. */
  newFindings: Finding[];
  /** Findings already accepted in the baseline. */
  existing: Finding[];
  /** Baseline entries no longer reported (fixed, or code moved). */
  fixed: BaselineEntry[];
}

function where(f: Finding): string | undefined {
  const l = f.location;
  if (!l) return undefined;
  return [l.file ?? l.url, l.selector].filter(Boolean).join(' ') || undefined;
}

export function createBaseline(tool: string, findings: Finding[]): Baseline {
  const seen = new Set<string>();
  const entries: BaselineEntry[] = [];
  for (const f of findings) {
    if (seen.has(f.fingerprint)) continue;
    seen.add(f.fingerprint);
    entries.push({ fingerprint: f.fingerprint, ruleId: f.ruleId, where: where(f) });
  }
  entries.sort((a, b) => a.ruleId.localeCompare(b.ruleId) || a.fingerprint.localeCompare(b.fingerprint));
  return { version: 1, tool, createdAt: new Date().toISOString(), entries };
}

export function parseBaseline(json: string | unknown): Baseline {
  const data = typeof json === 'string' ? (JSON.parse(json) as unknown) : json;
  const b = data as Partial<Baseline>;
  if (!b || b.version !== 1 || !Array.isArray(b.entries)) {
    throw new Error('Invalid baseline file: expected { "version": 1, "entries": [...] }');
  }
  return b as Baseline;
}

export function diffBaseline(findings: Finding[], baseline: Baseline | undefined): BaselineDiff {
  if (!baseline) return { newFindings: findings, existing: [], fixed: [] };
  const known = new Set(baseline.entries.map((e) => e.fingerprint));
  const current = new Set(findings.map((f) => f.fingerprint));
  return {
    newFindings: findings.filter((f) => !known.has(f.fingerprint)),
    existing: findings.filter((f) => known.has(f.fingerprint)),
    fixed: baseline.entries.filter((e) => !current.has(e.fingerprint)),
  };
}
