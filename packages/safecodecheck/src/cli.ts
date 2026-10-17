#!/usr/bin/env node
import { existsSync } from 'node:fs';
import { parseArgs } from 'node:util';
import { diffBaseline, formatReport, meetsThreshold, OUTPUT_FORMATS, parseSeverity, type OutputFormat } from '@devchecks/core';
import { loadBaselineFile, loadConfig, runCli, saveBaselineFile, useColor, writeOutput } from '@devchecks/core/node';
import { RULES, scanPaths, toReport, TOOL, VERSION, type ProjectOptions } from './node.js';

const HELP = `safecodecheck ${VERSION} - find unsafe DOM, eval, randomness and URL patterns

Usage:
  safecodecheck [paths...]        (default: src if it exists, else .)
  safecodecheck rules             List rules

Options:
  -c, --config <file>       Config file (default .safecodecheckrc.json)
  -f, --format <fmt>        text | json | sarif | markdown (default text)
  -o, --output <file>       Write the report to a file
      --fail-on <level>     Exit 1 at or above this severity (default high)
      --include-tests       Also scan test files
      --baseline <file>     Only fail on findings not in this baseline
      --update-baseline     Write current findings to --baseline and exit 0
  -h, --help                Show help

Suppress a reviewed finding with: // safecodecheck-disable-next-line <rule-id> -- reason
Exit codes: 0 ok, 1 findings at or above --fail-on, 2 error.`;

runCli(async () => {
  const { values, positionals } = parseArgs({
    allowPositionals: true,
    options: {
      config: { type: 'string', short: 'c' },
      format: { type: 'string', short: 'f', default: 'text' },
      output: { type: 'string', short: 'o' },
      'fail-on': { type: 'string' },
      'include-tests': { type: 'boolean' },
      baseline: { type: 'string' },
      'update-baseline': { type: 'boolean', default: false },
      help: { type: 'boolean', short: 'h', default: false },
      version: { type: 'boolean', short: 'v', default: false },
    },
  });
  if (values.help) return (console.log(HELP), 0);
  if (values.version) return (console.log(VERSION), 0);
  if (positionals[0] === 'rules') {
    for (const r of Object.values(RULES)) console.log(`${r.id.padEnd(26)} ${r.cwe.padEnd(8)} ${r.title}`);
    return 0;
  }

  const format = values.format as OutputFormat;
  if (!OUTPUT_FORMATS.includes(format)) throw new Error(`--format must be one of ${OUTPUT_FORMATS.join(', ')}`);
  const config = loadConfig<ProjectOptions & { failOn?: string; paths?: string[] }>(values.config, ['.safecodecheckrc.json', '.safecodecheckrc'])?.config ?? {};
  const failOn = parseSeverity(values['fail-on'] ?? config.failOn ?? 'high');
  const targets = positionals.length ? positionals : config.paths ?? [existsSync('src') ? 'src' : '.'];

  const result = scanPaths(targets, { ...config, includeTests: values['include-tests'] ?? config.includeTests });
  for (const e of result.errors) console.error(`${TOOL}: could not fully parse ${e.file}: ${e.error}`);
  if (values['update-baseline']) {
    if (!values.baseline) throw new Error('--update-baseline requires --baseline <file>');
    saveBaselineFile(values.baseline, TOOL, result.findings);
    console.error(`Wrote ${result.findings.length} finding(s) to ${values.baseline}`);
    return 0;
  }
  const diff = diffBaseline(result.findings, loadBaselineFile(values.baseline));
  console.error(`${TOOL}: scanned ${result.files} files`);
  writeOutput(formatReport(toReport(diff.newFindings, values.baseline ? diff : undefined), format, { color: useColor() && !values.output }), values.output);
  return diff.newFindings.some((f) => meetsThreshold(f.severity, failOn)) ? 1 : 0;
});
