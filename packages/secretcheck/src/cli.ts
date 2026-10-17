#!/usr/bin/env node
import { parseArgs } from 'node:util';
import { diffBaseline, formatReport, OUTPUT_FORMATS, type OutputFormat } from '@devchecks/core';
import { loadBaselineFile, loadConfig, runCli, saveBaselineFile, useColor, writeOutput } from '@devchecks/core/node';
import { installHook, scanPaths, scanStaged, toReport, TOOL, VERSION, isBlocking, type Confidence, type SecretCheckConfig, type SecretFinding } from './node.js';

const HELP = `secretcheck ${VERSION} - find credentials before they are committed

Usage:
  secretcheck [staged]            Scan content staged for the next commit (default)
  secretcheck scan <paths...>     Scan files or directories on disk
  secretcheck install-hook        Install a Git pre-commit hook

Options:
  -c, --config <file>       Config file (default .secretcheckrc.json)
  -f, --format <fmt>        text | json | sarif | markdown (default text)
  -o, --output <file>       Write the report to a file
      --fail-on <level>     high | medium | low confidence that fails (default high)
      --changed-lines       Only report lines added in the staged diff
      --baseline <file>     Ignore findings recorded in this baseline
      --update-baseline     Write current findings to --baseline and exit 0
      --force               Overwrite an existing pre-commit hook
  -h, --help                Show help

Exit codes: 0 no blocking secrets, 1 blocking secrets found, 2 error.
Secrets are always redacted in output.`;

runCli(async () => {
  const { values, positionals } = parseArgs({
    allowPositionals: true,
    options: {
      config: { type: 'string', short: 'c' },
      format: { type: 'string', short: 'f', default: 'text' },
      output: { type: 'string', short: 'o' },
      'fail-on': { type: 'string' },
      'changed-lines': { type: 'boolean', default: false },
      baseline: { type: 'string' },
      'update-baseline': { type: 'boolean', default: false },
      force: { type: 'boolean', default: false },
      help: { type: 'boolean', short: 'h', default: false },
      version: { type: 'boolean', short: 'v', default: false },
    },
  });
  if (values.help) return (console.log(HELP), 0);
  if (values.version) return (console.log(VERSION), 0);

  const [command = 'staged', ...targets] = positionals;
  if (command === 'install-hook') {
    console.log(`Installed pre-commit hook at ${installHook({ force: values.force })}`);
    return 0;
  }

  const format = values.format as OutputFormat;
  if (!OUTPUT_FORMATS.includes(format)) throw new Error(`--format must be one of ${OUTPUT_FORMATS.join(', ')}`);
  const config = loadConfig<SecretCheckConfig>(values.config, ['.secretcheckrc.json', '.secretcheckrc'])?.config ?? {};
  const failOn = (values['fail-on'] ?? config.failOn ?? 'high') as Confidence;
  if (!['high', 'medium', 'low'].includes(failOn)) throw new Error('--fail-on must be high, medium or low');

  let result;
  if (command === 'staged') result = scanStaged({ config, changedLinesOnly: values['changed-lines'] });
  else if (command === 'scan') result = scanPaths(targets.length ? targets : ['.'], { config });
  else throw new Error(`Unknown command "${command}". Run secretcheck --help.`);

  if (values['update-baseline']) {
    if (!values.baseline) throw new Error('--update-baseline requires --baseline <file>');
    saveBaselineFile(values.baseline, TOOL, result.findings);
    console.error(`Wrote ${result.findings.length} finding(s) to ${values.baseline}`);
    return 0;
  }

  const diff = diffBaseline(result.findings, loadBaselineFile(values.baseline));
  const findings = diff.newFindings as SecretFinding[];
  const report = toReport(findings, values.baseline ? diff : undefined);
  writeOutput(formatReport(report, format, { color: useColor() && !values.output }), values.output);

  const blocking = findings.filter((f) => isBlocking(f, failOn));
  if (blocking.length) {
    console.error(`\n${TOOL}: blocked - ${blocking.length} secret(s) at or above "${failOn}" confidence.`);
    console.error('Remove them from the commit, rotate the credentials, or allowlist reviewed false positives.');
    return 1;
  }
  return 0;
});
