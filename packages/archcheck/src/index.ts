// Browser-safe entry: analyze an in-memory file map (a playground, a bundler plugin, CI).
import { createReport, type BaselineDiff, type Finding, type Report } from '@devchecks/core';

export {
  analyze,
  boundaryRoot,
  buildGraph,
  layerFor,
  toMermaid,
  type AnalysisResult,
  type ArchCheckConfig,
  type BoundaryConfig,
  type LayerConfig,
  type RestrictedRule,
} from './analyze.js';
export { findCycles, stronglyConnected, type Cycle, type DependencyGraph, type Edge } from './graph.js';
export { extractImports, importsForFile, scriptBlocks, type ImportKind, type ImportRecord } from './imports.js';
export { CODE_EXTENSIONS, Resolver, packageName, type Resolution, type ResolverOptions } from './resolve.js';
export { presets } from './presets.js';
export { createBaseline, diffBaseline, formatReport, type Finding, type Report } from '@devchecks/core';

export const TOOL = 'archcheck';
export const VERSION = __VERSION__;

export function toReport(findings: Finding[], baseline?: BaselineDiff): Report {
  return createReport(TOOL, VERSION, findings, { baseline });
}
