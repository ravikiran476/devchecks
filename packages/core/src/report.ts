import type { BaselineDiff } from './baseline.js';
import { SEVERITIES, sortFindings, summarize } from './severity.js';
import type { Finding, Report, Severity } from './types.js';

export type OutputFormat = 'text' | 'json' | 'sarif' | 'markdown';

export const OUTPUT_FORMATS: readonly OutputFormat[] = ['text', 'json', 'sarif', 'markdown'];

export function createReport(
  tool: string,
  version: string,
  findings: Finding[],
  options: { notes?: string[]; baseline?: BaselineDiff } = {},
): Report {
  const report: Report = {
    schemaVersion: 1,
    tool,
    version,
    generatedAt: new Date().toISOString(),
    findings: sortFindings(findings.map((f) => (f.tool ? f : { tool, ...f }))),
    summary: summarize(findings),
  };
  if (options.notes?.length) report.notes = options.notes;
  if (options.baseline) {
    report.baseline = {
      new: options.baseline.newFindings.length,
      existing: options.baseline.existing.length,
      fixed: options.baseline.fixed.length,
    };
  }
  return report;
}

/** Rule id, prefixed with the tool when the report combines several tools. */
function ruleLabel(f: Finding, report: Report): string {
  return f.tool && f.tool !== report.tool ? `${f.tool}/${f.ruleId}` : f.ruleId;
}

function where(f: Finding): string {
  const l = f.location;
  if (!l) return '';
  const file = l.file ?? l.url ?? '';
  const pos = l.line ? `:${l.line}${l.column ? `:${l.column}` : ''}` : '';
  const sel = l.selector ? `${file ? ' ' : ''}${l.selector}` : '';
  return `${file}${pos}${sel}`;
}

const ANSI: Record<Severity, string> = {
  critical: '\x1b[35m',
  high: '\x1b[31m',
  medium: '\x1b[33m',
  low: '\x1b[36m',
  info: '\x1b[90m',
};

export function formatText(report: Report, options: { color?: boolean } = {}): string {
  const c = (s: Severity, text: string) => (options.color ? `${ANSI[s]}${text}\x1b[0m` : text);
  const dim = (text: string) => (options.color ? `\x1b[2m${text}\x1b[0m` : text);
  const lines: string[] = [];
  for (const f of report.findings) {
    lines.push(`${c(f.severity, f.severity.toUpperCase().padEnd(8))} ${ruleLabel(f, report)}  ${where(f)}`);
    lines.push(`         ${f.message}`);
    if (f.snippet) lines.push(dim(`         > ${f.snippet}`));
    if (f.remediation) lines.push(`         fix: ${f.remediation}`);
    lines.push('');
  }
  const counts = SEVERITIES.filter((s) => report.summary.bySeverity[s] > 0)
    .map((s) => `${report.summary.bySeverity[s]} ${s}`)
    .join(', ');
  lines.push(`${report.tool}: ${report.summary.total} finding(s)${counts ? ` (${counts})` : ''}`);
  if (report.baseline) {
    lines.push(
      `baseline: ${report.baseline.new} new, ${report.baseline.existing} accepted, ${report.baseline.fixed} fixed since baseline`,
    );
  }
  for (const n of report.notes ?? []) lines.push(dim(`note: ${n}`));
  return lines.join('\n');
}

export function formatJSON(report: Report): string {
  return JSON.stringify(report, null, 2);
}

function mdEscape(s: string): string {
  return s.replace(/\|/g, '\\|').replace(/\r?\n/g, ' ');
}

export function formatMarkdown(report: Report): string {
  const out: string[] = [`## ${report.tool} report`, ''];
  out.push(`Generated ${report.generatedAt} · ${report.summary.total} finding(s)`, '');
  if (report.baseline) {
    out.push(
      `Baseline: **${report.baseline.new} new**, ${report.baseline.existing} accepted, ${report.baseline.fixed} fixed`,
      '',
    );
  }
  if (report.findings.length) {
    out.push('| Severity | Rule | Location | Finding | Fix |', '|---|---|---|---|---|');
    for (const f of report.findings) {
      out.push(
        `| ${f.severity} | \`${ruleLabel(f, report)}\` | ${mdEscape(where(f))} | ${mdEscape(f.message)} | ${mdEscape(f.remediation ?? '')} |`,
      );
    }
    out.push('');
  }
  for (const n of report.notes ?? []) out.push(`> ${n}`, '');
  return out.join('\n');
}

const SARIF_LEVEL: Record<Severity, string> = {
  critical: 'error',
  high: 'error',
  medium: 'warning',
  low: 'note',
  info: 'note',
};

/** SARIF 2.1.0, consumable by GitHub code scanning and most CI dashboards. */
export function formatSARIF(report: Report, options: { informationUri?: string } = {}): string {
  const rules = new Map<string, Finding>();
  for (const f of report.findings) if (!rules.has(ruleLabel(f, report))) rules.set(ruleLabel(f, report), f);
  const sarif = {
    $schema: 'https://json.schemastore.org/sarif-2.1.0.json',
    version: '2.1.0',
    runs: [
      {
        tool: {
          driver: {
            name: report.tool,
            version: report.version,
            informationUri: options.informationUri,
            rules: [...rules.entries()].map(([id, f]) => ({
              id,
              shortDescription: { text: f.message.slice(0, 200) },
              helpUri: f.helpUrl,
              help: f.remediation ? { text: f.remediation } : undefined,
              defaultConfiguration: { level: SARIF_LEVEL[f.severity] },
            })),
          },
        },
        results: report.findings.map((f) => ({
          ruleId: ruleLabel(f, report),
          level: SARIF_LEVEL[f.severity],
          message: { text: f.remediation ? `${f.message} Fix: ${f.remediation}` : f.message },
          partialFingerprints: { devchecks: f.fingerprint },
          properties: { severity: f.severity, ...(f.location?.selector ? { selector: f.location.selector } : {}) },
          locations: f.location
            ? [
                {
                  physicalLocation: {
                    artifactLocation: { uri: f.location.file ?? f.location.url ?? '' },
                    ...(f.location.line
                      ? { region: { startLine: f.location.line, startColumn: f.location.column ?? 1 } }
                      : {}),
                  },
                },
              ]
            : [],
        })),
      },
    ],
  };
  return JSON.stringify(sarif, null, 2);
}

export function formatReport(report: Report, format: OutputFormat, options: { color?: boolean } = {}): string {
  switch (format) {
    case 'json':
      return formatJSON(report);
    case 'sarif':
      return formatSARIF(report);
    case 'markdown':
      return formatMarkdown(report);
    default:
      return formatText(report, options);
  }
}
