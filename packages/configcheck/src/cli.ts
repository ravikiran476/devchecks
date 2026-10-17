#!/usr/bin/env node
import { parseArgs } from 'node:util';
import { diffBaseline, formatReport, meetsThreshold, OUTPUT_FORMATS, parseSeverity, type Finding, type OutputFormat } from '@devchecks/core';
import { loadBaselineFile, loadConfig, runCli, saveBaselineFile, useColor, writeOutput } from '@devchecks/core/node';
import { checkRuntimeEnv, scanPaths, toReport, TOOL, VERSION, type ScanOptions } from './node.js';

const HELP = `configcheck ${VERSION} - catch broken and risky configuration

Usage:
  configcheck [paths...]      Check .env, JSON, YAML and .npmrc files (default: .)
  configcheck env             Validate the current process environment against the "env" schema

Options:
  -c, --config <file>       Config file (default configcheck.config.json)
      --production          Treat every file as production configuration
  -f, --format <fmt>        text | json | sarif | markdown (default text)
  -o, --output <file>       Write the report to a file
      --fail-on <level>     Exit 1 at or above this severity (default high)
      --baseline <file>     Only fail on findings not in this baseline
      --update-baseline     Write current findings to --baseline and exit 0
  -h, --help                Show help

configcheck.config.json example:
  { "env": { "required": ["DATABASE_URL"], "vars": { "PORT": { "type": "port" }, "API_URL": { "type": "url", "https": true } } },
    "exclude": ["test/fixtures/**"], "disableRules": ["insecure-url"] }

Setting values are never printed. Exit codes: 0 ok, 1 findings at or above --fail-on, 2 error.`;

runCli(async () => {
  const { values, positionals } = parseArgs({
    allowPositionals: true,
    options: {
      config: { type: 'string', short: 'c' },
      production: { type: 'boolean' },
      format: { type: 'string', short: 'f', default: 'text' },
      output: { type: 'string', short: 'o' },
      'fail-on': { type: 'string' },
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
  const config = loadConfig<ScanOptions & { failOn?: string; paths?: string[] }>(values.config, ['configcheck.config.json', '.configcheckrc.json'])?.config ?? {};
  const failOn = parseSeverity(values['fail-on'] ?? config.failOn ?? 'high');

  let findings: Finding[];
  if (positionals[0] === 'env') {
    if (!config.env) throw new Error('"configcheck env" needs an "env" schema in configcheck.config.json');
    findings = checkRuntimeEnv(config.env);
  } else {
    const result = scanPaths(positionals.length ? positionals : config.paths ?? ['.'], { ...config, production: values.production ?? config.production });
    findings = result.findings;
    console.error(`${TOOL}: checked ${result.files.length} config file(s)`);
  }
  if (values['update-baseline']) {
    if (!values.baseline) throw new Error('--update-baseline requires --baseline <file>');
    saveBaselineFile(values.baseline, TOOL, findings);
    console.error(`Wrote ${findings.length} finding(s) to ${values.baseline}`);
    return 0;
  }
  const diff = diffBaseline(findings, loadBaselineFile(values.baseline));
  writeOutput(formatReport(toReport(diff.newFindings, values.baseline ? diff : undefined), format, { color: useColor() && !values.output }), values.output);
  return diff.newFindings.some((f) => meetsThreshold(f.severity, failOn)) ? 1 : 0;
});
