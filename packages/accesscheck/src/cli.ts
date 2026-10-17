#!/usr/bin/env node
import { parseArgs } from 'node:util';
import { diffBaseline, formatReport, meetsThreshold, OUTPUT_FORMATS, parseSeverity, type OutputFormat } from '@devchecks/core';
import { loadBaselineFile, loadConfig, runCli, saveBaselineFile, useColor, writeOutput } from '@devchecks/core/node';
import { scanUrls, toReport, TOOL, VERSION, type NodeScanOptions, type PageTarget } from './node.js';

const HELP = `accesscheck ${VERSION} - automated accessibility checks (axe-core + Playwright)

Usage:
  accesscheck <url-or-path...>       e.g. accesscheck http://localhost:3000 /about /checkout

Options:
  -b, --base-url <url>      Base for relative paths (default from config, else http://localhost:3000)
  -c, --config <file>       Config file (default accesscheck.config.json)
      --tags <list>         Comma-separated axe tags (default wcag2a,wcag2aa,wcag21a,wcag21aa,wcag22aa)
      --browser <name>      chromium | firefox | webkit (default chromium)
      --include-incomplete  Report checks axe could not decide as "info" (needs manual review)
  -f, --format <fmt>        text | json | sarif | markdown (default text)
  -o, --output <file>       Write the report to a file
      --fail-on <level>     Exit 1 at or above this severity (default high = axe "serious")
      --baseline <file>     Only report issues not in this baseline
      --update-baseline     Write current findings to --baseline and exit 0
  -h, --help                Show help

Requires Playwright: npm i -D playwright && npx playwright install chromium
Exit codes: 0 ok, 1 issues at or above --fail-on, 2 error.`;

interface AccessCheckConfig extends Omit<NodeScanOptions, 'onPage'> {
  pages?: Array<string | Omit<PageTarget, 'setup'>>;
  failOn?: string;
}

runCli(async () => {
  const { values, positionals } = parseArgs({
    allowPositionals: true,
    options: {
      'base-url': { type: 'string', short: 'b' },
      config: { type: 'string', short: 'c' },
      tags: { type: 'string' },
      browser: { type: 'string' },
      'include-incomplete': { type: 'boolean' },
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
  const config = loadConfig<AccessCheckConfig>(values.config, ['accesscheck.config.json', '.accesscheckrc.json'])?.config ?? {};
  const failOn = parseSeverity(values['fail-on'] ?? config.failOn ?? 'high');
  const pages: Array<string | PageTarget> = positionals.length ? positionals : config.pages ?? [];
  if (!pages.length) throw new Error('Pass at least one URL or path, or list "pages" in accesscheck.config.json');

  const { pages: results, findings } = await scanUrls(pages, {
    ...config,
    baseUrl: values['base-url'] ?? config.baseUrl ?? 'http://localhost:3000',
    tags: values.tags ? values.tags.split(',').map((t) => t.trim()) : config.tags,
    browser: (values.browser as NodeScanOptions['browser']) ?? config.browser,
    includeIncomplete: values['include-incomplete'] ?? config.includeIncomplete,
    onPage: (url, f) => console.error(`${TOOL}: ${url} - ${f.length} issue(s)`),
  });
  const failed = results.filter((p) => p.error);
  for (const p of failed) console.error(`${TOOL}: could not scan ${p.url}: ${p.error}`);

  if (values['update-baseline']) {
    if (!values.baseline) throw new Error('--update-baseline requires --baseline <file>');
    saveBaselineFile(values.baseline, TOOL, findings);
    console.error(`Wrote ${findings.length} finding(s) to ${values.baseline}`);
    return failed.length ? 2 : 0;
  }
  const diff = diffBaseline(findings, loadBaselineFile(values.baseline));
  writeOutput(formatReport(toReport(diff.newFindings, values.baseline ? diff : undefined), format, { color: useColor() && !values.output }), values.output);
  if (failed.length === results.length) return 2;
  return diff.newFindings.some((f) => meetsThreshold(f.severity, failOn)) ? 1 : 0;
});
