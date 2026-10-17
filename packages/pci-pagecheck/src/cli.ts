#!/usr/bin/env node
import { readFileSync, existsSync } from 'node:fs';
import { parseArgs } from 'node:util';
import { formatReport, meetsThreshold, OUTPUT_FORMATS, parseSeverity, type OutputFormat } from '@devchecks/core';
import { loadConfig, runCli, useColor, writeOutput } from '@devchecks/core/node';
import { baselineFromInventory, buildEvidence, checkUrl, DISCLAIMER, evidenceToMarkdown, scanSourceDir, toReport, TOOL, VERSION, type ScriptBaseline } from './node.js';

const HELP = `pci-pagecheck ${VERSION} - payment page script inventory, CSP and card-data checks

Usage:
  pci-pagecheck <payment-page-url>                   Check against the approved script baseline
  pci-pagecheck approve <url> -b approved.json       Create/refresh the approved-script baseline

Options:
  -b, --baseline <file>     Approved script baseline (default pci-scripts.json if present)
      --source <dir>        Also scan checkout source code for card-data exposure
      --evidence <file>     Write an evidence report (.md or .json) mapped to PCI DSS requirements
      --first-party <list>  Extra first-party origins (comma-separated)
      --payment-origin <l>  Extra payment-provider origins allowed to receive card data
      --wait-for <selector> Wait for this element before capturing
  -f, --format <fmt>        text | json | sarif | markdown (default text)
  -o, --output <file>       Write the findings report to a file
      --fail-on <level>     Exit 1 at or above this severity (default high)
  -h, --help                Show help

Requires Playwright: npm i -D playwright && npx playwright install chromium
${DISCLAIMER}`;

interface PageCheckConfig {
  url?: string;
  baseline?: string;
  firstPartyOrigins?: string[];
  paymentOrigins?: string[];
  source?: string;
  waitFor?: string;
  failOn?: string;
}

runCli(async () => {
  const { values, positionals } = parseArgs({
    allowPositionals: true,
    options: {
      baseline: { type: 'string', short: 'b' },
      source: { type: 'string' },
      evidence: { type: 'string' },
      'first-party': { type: 'string' },
      'payment-origin': { type: 'string' },
      'wait-for': { type: 'string' },
      config: { type: 'string', short: 'c' },
      format: { type: 'string', short: 'f', default: 'text' },
      output: { type: 'string', short: 'o' },
      'fail-on': { type: 'string' },
      help: { type: 'boolean', short: 'h', default: false },
      version: { type: 'boolean', short: 'v', default: false },
    },
  });
  if (values.help) return (console.log(HELP), 0);
  if (values.version) return (console.log(VERSION), 0);

  const config = loadConfig<PageCheckConfig>(values.config, ['pci-pagecheck.config.json'])?.config ?? {};
  const approve = positionals[0] === 'approve';
  const url = (approve ? positionals[1] : positionals[0]) ?? config.url;
  if (!url) throw new Error('Pass the payment page URL. Run pci-pagecheck --help.');
  const format = values.format as OutputFormat;
  if (!OUTPUT_FORMATS.includes(format)) throw new Error(`--format must be one of ${OUTPUT_FORMATS.join(', ')}`);
  const baselinePath = values.baseline ?? config.baseline ?? 'pci-scripts.json';
  const baseline = existsSync(baselinePath) ? (JSON.parse(readFileSync(baselinePath, 'utf8')) as ScriptBaseline) : undefined;
  const list = (v?: string) => v?.split(',').map((s) => s.trim()).filter(Boolean);

  const result = await checkUrl(url, {
    baseline: approve ? undefined : baseline,
    firstPartyOrigins: list(values['first-party']) ?? config.firstPartyOrigins,
    paymentOrigins: list(values['payment-origin']) ?? config.paymentOrigins,
    waitFor: values['wait-for'] ?? config.waitFor,
  });

  if (approve) {
    const next = baselineFromInventory(result, baseline);
    writeOutput(JSON.stringify(next, null, 2), baselinePath);
    const missing = next.scripts.filter((s) => !s.justification).length;
    console.error(`${TOOL}: wrote ${next.scripts.length} script(s) to ${baselinePath}. ${missing} need a written justification and an approver.`);
    return 0;
  }

  const source = values.source ?? config.source;
  if (source) result.findings.push(...scanSourceDir(source));
  if (!baseline) console.error(`${TOOL}: no approved-script baseline at ${baselinePath}. Create one with: pci-pagecheck approve ${url} -b ${baselinePath}`);
  console.error(`${TOOL}: ${result.inventory.length} script(s), ${result.snapshot.cardFields.length} card field(s) in page DOM, ${result.snapshot.frames.length} frame(s)`);

  if (values.evidence) {
    const evidence = buildEvidence(result);
    writeOutput(values.evidence.endsWith('.json') ? JSON.stringify(evidence, null, 2) : evidenceToMarkdown(evidence), values.evidence);
    console.error(`${TOOL}: evidence written to ${values.evidence}`);
  }
  writeOutput(formatReport(toReport(result.findings), format, { color: useColor() && !values.output }), values.output);
  const failOn = parseSeverity(values['fail-on'] ?? config.failOn ?? 'high');
  return result.findings.some((f) => meetsThreshold(f.severity, failOn)) ? 1 : 0;
});
