#!/usr/bin/env node
import { parseArgs } from 'node:util';
import { diffBaseline, formatReport, meetsThreshold, OUTPUT_FORMATS, parseSeverity, type Finding, type OutputFormat } from '@devchecks/core';
import { loadBaselineFile, runCli, saveBaselineFile, useColor, writeOutput } from '@devchecks/core/node';
import { diffSpecs, loadSpecFile, probe, toReport, TOOL, validateHarFile, VERSION } from './node.js';

const HELP = `apicontractcheck ${VERSION} - keep APIs and their OpenAPI contract in sync

Usage:
  apicontractcheck validate --spec openapi.yaml --har traffic.har     Validate recorded traffic
  apicontractcheck probe --spec openapi.yaml --base-url http://localhost:3000
                                                                     Call GET endpoints and validate responses
  apicontractcheck diff old.yaml new.yaml                            Breaking changes between two versions

Options:
  -s, --spec <file>         OpenAPI 3.0/3.1 document (JSON or YAML)
      --har <file>          HAR file (DevTools "Save all as HAR", Playwright recordHar)
  -b, --base-url <url>      Server to probe
  -H, --header <k:v>        Extra request header for probe (repeatable), e.g. "authorization: Bearer ..."
      --requests            Also validate request parameters and bodies (validate)
      --ignore-unknown      Ignore traffic to paths not in the spec
  -f, --format <fmt>        text | json | sarif | markdown (default text)
  -o, --output <file>       Write the report to a file
      --fail-on <level>     Exit 1 at or above this severity (default high)
      --baseline <file>     Only fail on findings not in this baseline
      --update-baseline     Write current findings to --baseline and exit 0
  -h, --help                Show help

Exit codes: 0 ok, 1 findings at or above --fail-on, 2 error.`;

runCli(async () => {
  const { values, positionals } = parseArgs({
    allowPositionals: true,
    options: {
      spec: { type: 'string', short: 's' },
      har: { type: 'string' },
      'base-url': { type: 'string', short: 'b' },
      header: { type: 'string', short: 'H', multiple: true },
      requests: { type: 'boolean', default: false },
      'ignore-unknown': { type: 'boolean', default: false },
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
  const failOn = parseSeverity(values['fail-on'] ?? 'high');
  const [command, ...rest] = positionals;
  const opts = { requests: values.requests, ignoreUnknownPaths: values['ignore-unknown'] };

  let findings: Finding[];
  if (command === 'diff') {
    const [oldFile, newFile] = rest;
    if (!oldFile || !newFile) throw new Error('Usage: apicontractcheck diff <old-spec> <new-spec>');
    const result = diffSpecs(loadSpecFile(oldFile), loadSpecFile(newFile), { oldName: oldFile, newName: newFile });
    console.error(`${TOOL}: ${result.breaking.length} breaking, ${result.nonBreaking.length} non-breaking change(s)`);
    findings = [...result.breaking, ...result.nonBreaking];
  } else if (command === 'validate' || command === 'probe') {
    if (!values.spec) throw new Error('--spec <openapi file> is required');
    const spec = loadSpecFile(values.spec);
    if (command === 'validate') {
      if (!values.har) throw new Error('--har <file> is required for validate');
      const r = validateHarFile(spec, values.har, opts);
      console.error(`${TOOL}: validated ${r.exchanges} API exchange(s) from ${values.har}`);
      findings = r.findings;
    } else {
      if (!values['base-url']) throw new Error('--base-url is required for probe');
      const headers = Object.fromEntries((values.header ?? []).map((h) => [h.slice(0, h.indexOf(':')).trim(), h.slice(h.indexOf(':') + 1).trim()]));
      const r = await probe(spec, values['base-url'], { ...opts, headers, onSkip: (op, why) => console.error(`${TOOL}: skipped ${op} (${why})`) });
      console.error(`${TOOL}: probed ${r.exchanges.length} GET operation(s)`);
      findings = r.findings;
    }
  } else {
    throw new Error('Use "validate", "probe" or "diff". Run apicontractcheck --help.');
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
