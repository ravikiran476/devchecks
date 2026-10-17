#!/usr/bin/env node
import { parseArgs } from 'node:util';
import { diffBaseline, formatReport, meetsThreshold, OUTPUT_FORMATS, parseSeverity, type OutputFormat } from '@devchecks/core';
import { loadBaselineFile, loadConfig, runCli, saveBaselineFile, useColor, writeOutput } from '@devchecks/core/node';
import { attributionMarkdown, checkLicenses, inventoryProject, POLICIES, summarizeLicenses, toReport, TOOL, VERSION, type LicensePolicy, type ProjectOptions } from './node.js';

const HELP = `licensecheck ${VERSION} - dependency license inventory and policy

Usage:
  licensecheck [project-dir]                 Check licenses against the policy
  licensecheck inventory [project-dir]       List packages by license (-f json|csv|markdown)
  licensecheck attribution [project-dir]     Write a third-party notices file (-o THIRD-PARTY-NOTICES.md)

Options:
  -c, --config <file>       Config file (default .licensecheckrc.json): { "policy": {...} | "permissive" | "strict" | "copyleft-ok" }
  -p, --policy <name>       Built-in policy: ${Object.keys(POLICIES).join(', ')} (default permissive)
      --production          Ignore dev-only dependencies
      --from <source>       auto | node_modules | lockfile (default auto)
      --offline             Do not look up missing licenses in the npm registry
  -f, --format <fmt>        text | json | sarif | markdown (inventory also: csv)
  -o, --output <file>       Write output to a file
      --fail-on <level>     Exit 1 at or above this severity (default high)
      --baseline <file>     Only fail on findings not in this baseline
      --update-baseline     Write current findings to --baseline and exit 0
  -h, --help                Show help

Exit codes: 0 ok, 1 findings at or above --fail-on, 2 error.`;

interface LicenseConfig {
  policy?: LicensePolicy | keyof typeof POLICIES;
  production?: boolean;
  failOn?: string;
}

const csvCell = (s: string) => (/[",\n]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s);

runCli(async () => {
  const { values, positionals } = parseArgs({
    allowPositionals: true,
    options: {
      config: { type: 'string', short: 'c' },
      policy: { type: 'string', short: 'p' },
      production: { type: 'boolean' },
      from: { type: 'string' },
      offline: { type: 'boolean', default: false },
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

  const command = ['inventory', 'attribution'].includes(positionals[0] ?? '') ? positionals.shift()! : 'check';
  const dir = positionals[0] ?? '.';
  const config = loadConfig<LicenseConfig>(values.config, [`${dir}/.licensecheckrc.json`, `${dir}/.licensecheckrc`])?.config ?? {};
  const named = values.policy ?? (typeof config.policy === 'string' ? config.policy : undefined);
  if (named && !(named in POLICIES)) throw new Error(`Unknown policy "${named}". Use one of: ${Object.keys(POLICIES).join(', ')}`);
  const policy = named ? POLICIES[named as keyof typeof POLICIES] : typeof config.policy === 'object' ? config.policy : POLICIES.permissive;
  const options: ProjectOptions = {
    policy,
    production: values.production ?? config.production,
    from: values.from as ProjectOptions['from'],
    registry: !values.offline,
    texts: command === 'attribution',
  };
  const { packages, source } = await inventoryProject(dir, options);
  console.error(`${TOOL}: ${packages.length} packages from ${source}`);

  if (command === 'attribution') {
    writeOutput(attributionMarkdown(packages, { includeDev: !options.production }), values.output ?? 'THIRD-PARTY-NOTICES.md');
    if (!values.output) console.error(`${TOOL}: wrote THIRD-PARTY-NOTICES.md`);
    return 0;
  }
  if (command === 'inventory') {
    const list = options.production ? packages.filter((p) => !p.dev) : packages;
    let out: string;
    if (values.format === 'json') out = JSON.stringify({ packages: list.map(({ licenseText: _t, ...p }) => p), byLicense: summarizeLicenses(list) }, null, 2);
    else if (values.format === 'csv') out = ['name,version,license,declared,dev', ...list.map((p) => [p.name, p.version, p.license ?? '', p.declared ?? '', String(!!p.dev)].map(csvCell).join(','))].join('\n');
    else out = summarizeLicenses(list).map((s) => `${String(s.count).padStart(5)}  ${s.license}${s.categories.length ? `  (${s.categories.join(', ')})` : ''}`).join('\n');
    writeOutput(out, values.output);
    return 0;
  }

  const format = values.format as OutputFormat;
  if (!OUTPUT_FORMATS.includes(format)) throw new Error(`--format must be one of ${OUTPUT_FORMATS.join(', ')}`);
  const findings = checkLicenses(packages, { ...options, source });
  if (values['update-baseline']) {
    if (!values.baseline) throw new Error('--update-baseline requires --baseline <file>');
    saveBaselineFile(values.baseline, TOOL, findings);
    console.error(`Wrote ${findings.length} finding(s) to ${values.baseline}`);
    return 0;
  }
  const diff = diffBaseline(findings, loadBaselineFile(values.baseline));
  writeOutput(formatReport(toReport(diff.newFindings, values.baseline ? diff : undefined), format, { color: useColor() && !values.output }), values.output);
  const failOn = parseSeverity(values['fail-on'] ?? config.failOn ?? 'high');
  return diff.newFindings.some((f) => meetsThreshold(f.severity, failOn)) ? 1 : 0;
});
