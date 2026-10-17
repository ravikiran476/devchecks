// Browser-safe entry: validate config text (playgrounds, editors, CI, Node).
import { createReport, fingerprint, type BaselineDiff, type Finding, type Report } from '@devchecks/core';
import { compareEnv, validateEnv, type EnvSchema } from './env.js';
import { parseConfig, parseDotenv } from './parse.js';
import { checkEntries, isProductionFile } from './rules.js';

export { assertEnv, compareEnv, validateEnv, type EnvSchema, type EnvType, type EnvVarSpec } from './env.js';
export { formatFor, parseConfig, parseDotenv, type Entry, type ParsedConfig } from './parse.js';
export { checkEntries, isProductionFile, RULE_IDS, type FileContext } from './rules.js';
export { createBaseline, diffBaseline, formatReport, type Finding, type Report } from '@devchecks/core';

export const TOOL = 'configcheck';
export const VERSION = __VERSION__;

export interface ConfigCheckOptions {
  disableRules?: string[];
  /** Force production severities (otherwise inferred from the file name and NODE_ENV-style keys). */
  production?: boolean;
  /** Schema for .env files. */
  env?: EnvSchema;
}

/** Checks one config file's text: syntax, risky settings and (for .env files) the env schema. */
export function checkConfigText(text: string, file: string, options: ConfigCheckOptions = {}): Finding[] {
  const parsed = parseConfig(text, file);
  if (!parsed) return [];
  const findings: Finding[] = parsed.errors.map((e) => ({
    fingerprint: fingerprint(TOOL, 'config-syntax-error', file, e.message),
    ruleId: 'config-syntax-error',
    severity: 'high' as const,
    message: `${file} cannot be parsed: ${e.message}`,
    location: { file, line: e.line },
    remediation: 'Fix the syntax error; the application or tool reading this file will fail or silently use defaults.',
  }));
  const production = options.production ?? isProductionFile(file, parsed);
  findings.push(...checkEntries(parsed, { file, production }, new Set(options.disableRules)));
  if (parsed.format === 'env' && options.env && !/\.(example|sample|template|dist)$/i.test(file)) {
    findings.push(...validateEnv(parsed.entries, options.env, file));
  }
  return findings;
}

/** Compares .env text with .env.example text. */
export function checkEnvDrift(templateText: string, actualText: string, files = { template: '.env.example', actual: '.env' }): Finding[] {
  return compareEnv(parseDotenv(templateText).entries, parseDotenv(actualText).entries, files);
}

export function toReport(findings: Finding[], baseline?: BaselineDiff): Report {
  return createReport(TOOL, VERSION, findings, { baseline, notes: ['Setting values are never printed. Hard-coded secrets are SecretCheck’s job: run it alongside.'] });
}
