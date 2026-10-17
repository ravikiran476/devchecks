#!/usr/bin/env node
import { parseArgs } from 'node:util';
import { diffBaseline, formatReport, meetsThreshold, OUTPUT_FORMATS, parseSeverity, type OutputFormat } from '@devchecks/core';
import { loadBaselineFile, loadConfig, runCli, saveBaselineFile, useColor, writeOutput } from '@devchecks/core/node';
import { analyzeProject, presets, toMermaid, toReport, TOOL, VERSION, type ProjectConfig } from './node.js';

const HELP = `archcheck ${VERSION} - enforce architecture rules on imports

Usage:
  archcheck [project-dir]
  archcheck init [react|vue|node]   Print a starter archcheck.config.json

Options:
  -c, --config <file>       Config file (default archcheck.config.json)
  -p, --preset <name>       Use a built-in preset: ${Object.keys(presets).join(', ')}
  -f, --format <fmt>        text | json | sarif | markdown | mermaid (default text)
  -o, --output <file>       Write the report to a file
      --fail-on <level>     Exit 1 at or above this severity (default medium)
      --baseline <file>     Only fail on violations not in this baseline
      --update-baseline     Write current findings to --baseline and exit 0
  -h, --help                Show help

Exit codes: 0 ok, 1 violations at or above --fail-on, 2 error.`;

runCli(async () => {
  const { values, positionals } = parseArgs({
    allowPositionals: true,
    options: {
      config: { type: 'string', short: 'c' },
      preset: { type: 'string', short: 'p' },
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

  if (positionals[0] === 'init') {
    const name = (positionals[1] ?? 'react') as keyof typeof presets;
    const preset = presets[name];
    if (!preset) throw new Error(`Unknown preset "${name}"`);
    console.log(JSON.stringify({ preset: name, layers: preset.layers, allowed: preset.allowed }, null, 2));
    return 0;
  }

  const format = values.format as OutputFormat | 'mermaid';
  if (format !== 'mermaid' && !OUTPUT_FORMATS.includes(format)) {
    throw new Error(`--format must be one of ${OUTPUT_FORMATS.join(', ')}, mermaid`);
  }
  const dir = positionals[0] ?? '.';
  const loaded = loadConfig<ProjectConfig & { failOn?: string }>(values.config, [`${dir}/archcheck.config.json`, `${dir}/.archcheckrc.json`]);
  const config: ProjectConfig & { failOn?: string } = { ...loaded?.config };
  if (values.preset) config.preset = values.preset as ProjectConfig['preset'];
  if (!loaded && !config.preset) {
    console.error(`${TOOL}: no archcheck.config.json found - checking circular imports only. Run "archcheck init" for layer rules.`);
  }
  const failOn = parseSeverity(values['fail-on'] ?? config.failOn ?? 'medium');

  const result = analyzeProject(dir, config);
  if (format === 'mermaid') {
    writeOutput(toMermaid(result), values.output);
    return 0;
  }
  if (values['update-baseline']) {
    if (!values.baseline) throw new Error('--update-baseline requires --baseline <file>');
    saveBaselineFile(values.baseline, TOOL, result.findings);
    console.error(`Wrote ${result.findings.length} finding(s) to ${values.baseline}`);
    return 0;
  }
  const diff = diffBaseline(result.findings, loadBaselineFile(values.baseline));
  const report = toReport(diff.newFindings, values.baseline ? diff : undefined);
  console.error(`${TOOL}: ${result.graph.files.length} files, ${result.graph.edges.length} imports`);
  writeOutput(formatReport(report, format, { color: useColor() && !values.output }), values.output);
  return diff.newFindings.some((f) => meetsThreshold(f.severity, failOn)) ? 1 : 0;
});
