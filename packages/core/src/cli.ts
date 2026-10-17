#!/usr/bin/env node
// `devchecks merge` — combine JSON reports from any devchecks tools into one report.
import { readFileSync } from 'node:fs';
import { parseArgs } from 'node:util';
import { mergeReports, parseReport } from './merge.js';
import { runCli, useColor, writeOutput } from './node.js';
import { formatReport, OUTPUT_FORMATS, type OutputFormat } from './report.js';
import { meetsThreshold, parseSeverity } from './severity.js';

const HELP = `devchecks ${__VERSION__} - combine reports from secretcheck, depcheck, archcheck, ...

Usage:
  devchecks merge <report.json...>

Options:
  -f, --format <fmt>      text | json | sarif | markdown (default text)
  -o, --output <file>     Write the merged report to a file
      --fail-on <level>   Exit 1 when any finding is at or above this severity
  -h, --help              Show help

Example:
  npx secretcheck -f json -o reports/secrets.json
  npx @devchecks/depcheck -f json -o reports/deps.json
  npx devchecks merge reports/*.json -f markdown -o report.md --fail-on high`;

runCli(async () => {
  const { values, positionals } = parseArgs({
    allowPositionals: true,
    options: {
      format: { type: 'string', short: 'f', default: 'text' },
      output: { type: 'string', short: 'o' },
      'fail-on': { type: 'string' },
      help: { type: 'boolean', short: 'h', default: false },
      version: { type: 'boolean', short: 'v', default: false },
    },
  });
  if (values.help) return (console.log(HELP), 0);
  if (values.version) return (console.log(__VERSION__), 0);
  const [command, ...files] = positionals;
  if (command !== 'merge' || !files.length) throw new Error('Usage: devchecks merge <report.json...>');
  const format = values.format as OutputFormat;
  if (!OUTPUT_FORMATS.includes(format)) throw new Error(`--format must be one of ${OUTPUT_FORMATS.join(', ')}`);

  const merged = mergeReports(files.map((f) => parseReport(readFileSync(f, 'utf8'), f)));
  writeOutput(formatReport(merged, format, { color: useColor() && !values.output }), values.output);
  if (!values['fail-on']) return 0;
  const threshold = parseSeverity(values['fail-on']);
  return merged.findings.some((f) => meetsThreshold(f.severity, threshold)) ? 1 : 0;
});
