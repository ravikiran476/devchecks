#!/usr/bin/env node
import { readFileSync } from 'node:fs';
import { parseArgs } from 'node:util';
import { createReport, diffBaseline, filterBySeverity, formatReport, meetsThreshold, OUTPUT_FORMATS, parseSeverity, type Finding, type OutputFormat } from '@devchecks/core';
import { loadBaselineFile, loadConfig, runCli, saveBaselineFile, useColor, writeOutput } from '@devchecks/core/node';
import { checkProject, fromNpmAudit, toReport, TOOL, VERSION, type IgnoreRule } from './node.js';

const HELP = `depcheck ${VERSION} - known vulnerabilities in your dependencies (via OSV.dev)

Usage:
  depcheck [project-dir]

Options:
  -l, --lockfile <file>      Lockfile to check (default: auto-detect package-lock, pnpm-lock, yarn.lock)
      --installed            Check the installed node_modules tree instead of the lockfile
      --production           Ignore packages only reachable through devDependencies
      --npm-audit <file>     Convert existing "npm audit --json" output instead of querying OSV
  -s, --min-severity <lvl>   Only report findings at or above this level (default low)
      --fail-on <lvl>        Exit 1 when a finding at or above this level exists (default high)
  -f, --format <fmt>         text | json | sarif | markdown (default text)
  -o, --output <file>        Write the report to a file
  -c, --config <file>        Config file (default .depcheckrc.json)
      --baseline <file>      Only fail on findings not in this baseline
      --update-baseline      Write current findings to --baseline and exit 0
  -h, --help                 Show help

Exit codes: 0 ok, 1 findings at or above --fail-on, 2 error.`;

interface DepCheckConfig {
  failOn?: string;
  minSeverity?: string;
  production?: boolean;
  ignore?: IgnoreRule[];
}

runCli(async () => {
  const { values, positionals } = parseArgs({
    allowPositionals: true,
    options: {
      lockfile: { type: 'string', short: 'l' },
      installed: { type: 'boolean', default: false },
      production: { type: 'boolean' },
      'npm-audit': { type: 'string' },
      'min-severity': { type: 'string', short: 's' },
      'fail-on': { type: 'string' },
      format: { type: 'string', short: 'f', default: 'text' },
      output: { type: 'string', short: 'o' },
      config: { type: 'string', short: 'c' },
      baseline: { type: 'string' },
      'update-baseline': { type: 'boolean', default: false },
      help: { type: 'boolean', short: 'h', default: false },
      version: { type: 'boolean', short: 'v', default: false },
    },
  });
  if (values.help) return (console.log(HELP), 0);
  if (values.version) return (console.log(VERSION), 0);

  const format = values.format as OutputFormat;
  if (!OUTPUT_FORMATS.includes(format)) throw new Error(`--format must be one of ${OUTPUT_FORMATS.join(', ')}`);
  const config = loadConfig<DepCheckConfig>(values.config, ['.depcheckrc.json', '.depcheckrc'])?.config ?? {};
  const failOn = parseSeverity(values['fail-on'] ?? config.failOn ?? 'high');
  const minSeverity = parseSeverity(values['min-severity'] ?? config.minSeverity ?? 'low');

  let findings: Finding[];
  if (values['npm-audit']) {
    findings = fromNpmAudit(readFileSync(values['npm-audit'], 'utf8'));
  } else {
    const result = await checkProject(positionals[0] ?? '.', {
      lockfile: values.lockfile,
      installed: values.installed,
      production: values.production ?? config.production,
      ignore: config.ignore,
    });
    findings = result.findings;
    console.error(`${TOOL}: checked ${result.dependencies.length} package versions from ${result.source}`);
  }
  findings = filterBySeverity(findings, minSeverity);

  if (values['update-baseline']) {
    if (!values.baseline) throw new Error('--update-baseline requires --baseline <file>');
    saveBaselineFile(values.baseline, TOOL, findings);
    console.error(`Wrote ${findings.length} finding(s) to ${values.baseline}`);
    return 0;
  }

  const diff = diffBaseline(findings, loadBaselineFile(values.baseline));
  const report = values['npm-audit']
    ? createReport(TOOL, VERSION, diff.newFindings, { baseline: values.baseline ? diff : undefined })
    : toReport(diff.newFindings as Parameters<typeof toReport>[0], values.baseline ? diff : undefined);
  writeOutput(formatReport(report, format, { color: useColor() && !values.output }), values.output);
  return diff.newFindings.some((f) => meetsThreshold(f.severity, failOn)) ? 1 : 0;
});
