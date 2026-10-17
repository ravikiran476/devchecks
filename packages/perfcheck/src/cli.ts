#!/usr/bin/env node
import { parseArgs } from 'node:util';
import { diffBaseline, formatReport, meetsThreshold, OUTPUT_FORMATS, parseSeverity, type Finding, type OutputFormat } from '@devchecks/core';
import { loadBaselineFile, loadConfig, runCli, saveBaselineFile, useColor, writeOutput } from '@devchecks/core/node';
import { checkBundles, checkUrls, formatBytes, toReport, TOOL, VERSION, type BundleBudget, type LabOptions, type PageBudgets } from './node.js';

const HELP = `perfcheck ${VERSION} - performance budgets for pages and bundles

Usage:
  perfcheck bundles [build-dir]     Check build output sizes (default dist)
  perfcheck <url...>                Measure pages in Chromium and check Web Vitals / weight budgets

Options:
  -c, --config <file>       Config file (default perfcheck.config.json)
  -b, --base-url <url>      Base for relative page paths
      --runs <n>            Page loads per URL; the median is used (default 3)
      --cpu <n>             CPU slowdown factor, e.g. 4 (default 1)
      --network <profile>   none | fast-4g | slow-4g | 3g (default none)
  -f, --format <fmt>        text | json | sarif | markdown (default text)
  -o, --output <file>       Write the report to a file
      --fail-on <level>     Exit 1 at or above this severity (default high)
      --baseline <file>     Only fail on findings not in this baseline
      --update-baseline     Write current findings to --baseline and exit 0
  -h, --help                Show help

perfcheck.config.json example:
  { "bundles": { "dir": "dist", "budgets": [{ "path": "assets/*.js", "maxGzip": "170kB" }, { "path": "total:js", "maxBrotli": "350kB" }] },
    "pages": ["/", "/products"], "baseUrl": "http://localhost:3000", "budgets": { "lcp": 2500, "cls": 0.1, "scriptBytes": "400kB" } }

Exit codes: 0 ok, 1 findings at or above --fail-on, 2 error.`;

interface PerfConfig extends LabOptions {
  bundles?: { dir?: string; budgets: BundleBudget[] };
  pages?: string[];
  baseUrl?: string;
  budgets?: PageBudgets;
  failOn?: string;
}

runCli(async () => {
  const { values, positionals } = parseArgs({
    allowPositionals: true,
    options: {
      config: { type: 'string', short: 'c' },
      'base-url': { type: 'string', short: 'b' },
      runs: { type: 'string' },
      cpu: { type: 'string' },
      network: { type: 'string' },
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
  const config = loadConfig<PerfConfig>(values.config, ['perfcheck.config.json', '.perfcheckrc.json'])?.config ?? {};
  const failOn = parseSeverity(values['fail-on'] ?? config.failOn ?? 'high');

  let findings: Finding[];
  if (positionals[0] === 'bundles') {
    const dir = positionals[1] ?? config.bundles?.dir ?? 'dist';
    const budgets = config.bundles?.budgets ?? [{ path: 'total:js', maxGzip: '300kB' }];
    if (!config.bundles) console.error(`${TOOL}: no "bundles" budgets in config; using total:js <= 300kB gzip`);
    const result = checkBundles(dir, budgets);
    for (const f of result.files.slice(0, 10)) console.error(`  ${formatBytes(f.gzip).padStart(10)} gzip  ${formatBytes(f.size).padStart(10)} raw  ${f.path}`);
    findings = result.findings;
  } else {
    const pages = positionals.length ? positionals : config.pages ?? [];
    if (!pages.length) throw new Error('Pass page URLs, "bundles", or list "pages" in perfcheck.config.json');
    const base = values['base-url'] ?? config.baseUrl;
    const urls = pages.map((p) => (/^https?:\/\//.test(p) ? p : new URL(p, base ?? 'http://localhost:3000').href));
    const { results, findings: f } = await checkUrls(urls, config.budgets, {
      ...config,
      runs: values.runs ? Number(values.runs) : config.runs,
      cpuThrottle: values.cpu ? Number(values.cpu) : config.cpuThrottle,
      network: (values.network as LabOptions['network']) ?? config.network,
    });
    for (const r of results) {
      const v = r.vitals;
      console.error(`${TOOL}: ${r.url}  LCP ${Math.round(v.lcp ?? 0)}ms  FCP ${Math.round(v.fcp ?? 0)}ms  CLS ${v.cls ?? 0}  TBT ${Math.round(v.tbt ?? 0)}ms  TTFB ${Math.round(v.ttfb ?? 0)}ms  ${formatBytes(r.resources.totalBytes)} / ${r.resources.requests} req`);
    }
    findings = f;
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
