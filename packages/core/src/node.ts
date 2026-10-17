// Node-only helpers shared by the CLIs. Not part of the browser bundle.
import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { dirname } from 'node:path';
import { createBaseline, parseBaseline, type Baseline } from './baseline.js';
import type { Finding } from './types.js';

export function readJsonFile<T>(path: string): T {
  const text = readFileSync(path, 'utf8').replace(/^﻿/, '');
  try {
    return JSON.parse(text) as T;
  } catch (err) {
    throw new Error(`Could not parse ${path}: ${(err as Error).message}`);
  }
}

/** Loads the first config file that exists, or returns undefined. */
export function loadConfig<T>(explicit: string | undefined, candidates: string[]): { path: string; config: T } | undefined {
  if (explicit) return { path: explicit, config: readJsonFile<T>(explicit) };
  for (const c of candidates) if (existsSync(c)) return { path: c, config: readJsonFile<T>(c) };
  return undefined;
}

export function writeOutput(text: string, file?: string): void {
  if (file) {
    mkdirSync(dirname(file), { recursive: true });
    writeFileSync(file, text.endsWith('\n') ? text : `${text}\n`);
  } else {
    process.stdout.write(text.endsWith('\n') ? text : `${text}\n`);
  }
}

export function loadBaselineFile(path: string | undefined): Baseline | undefined {
  if (!path || !existsSync(path)) return undefined;
  return parseBaseline(readFileSync(path, 'utf8'));
}

export function saveBaselineFile(path: string, tool: string, findings: Finding[]): Baseline {
  const baseline = createBaseline(tool, findings);
  writeOutput(JSON.stringify(baseline, null, 2), path);
  return baseline;
}

export function useColor(): boolean {
  return !!process.stdout.isTTY && !process.env.NO_COLOR;
}

/** Runs a CLI main function, mapping thrown errors to exit code 2 (usage/runtime error). */
export function runCli(main: () => Promise<number>): void {
  main().then(
    (code) => {
      process.exitCode = code;
    },
    (err: unknown) => {
      process.stderr.write(`error: ${err instanceof Error ? err.message : String(err)}\n`);
      process.exitCode = 2;
    },
  );
}
