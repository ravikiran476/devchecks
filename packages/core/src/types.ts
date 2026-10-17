export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info';

export interface Location {
  /** Repository-relative file path (static analysis tools). */
  file?: string;
  line?: number;
  column?: number;
  /** CSS selector (browser tools). */
  selector?: string;
  /** Page or resource URL (browser tools). */
  url?: string;
}

export interface Finding {
  /** Tool that produced the finding (set by createReport). Lets merged reports keep their origin. */
  tool?: string;
  /** Stable identifier used for baselines. Independent of line numbers where possible. */
  fingerprint: string;
  /** Rule that produced the finding, e.g. "dom-unsafe-html" or "GHSA-xxxx". */
  ruleId: string;
  severity: Severity;
  message: string;
  location?: Location;
  /** How to fix it. */
  remediation?: string;
  /** Short, already-redacted excerpt that shows why the rule fired. */
  snippet?: string;
  /** Link to documentation for the rule. */
  helpUrl?: string;
  tags?: string[];
  /** Tool-specific data (package versions, WCAG criteria, PCI controls, ...). */
  meta?: Record<string, unknown>;
}

export interface ReportSummary {
  total: number;
  bySeverity: Record<Severity, number>;
}

export interface Report {
  /** Version of this report format. Consumers should check it before reading. */
  schemaVersion: 1;
  tool: string;
  version: string;
  generatedAt: string;
  findings: Finding[];
  summary: ReportSummary;
  /** Caveats every consumer of the report should see. */
  notes?: string[];
  /** Present when the report was compared with a baseline. */
  baseline?: { new: number; existing: number; fixed: number };
}
