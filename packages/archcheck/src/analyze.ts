import { fingerprint, matchAny, matchGlob, normalizePath, type Finding, type Severity } from '@devchecks/core';
import { findCycles, type DependencyGraph, type Edge } from './graph.js';
import { importsForFile } from './imports.js';
import { Resolver, type ResolverOptions } from './resolve.js';

export interface LayerConfig {
  name: string;
  /** Globs of files that belong to the layer. The first matching layer wins. */
  include: string | string[];
}

export interface RestrictedRule {
  /** Files the rule applies to (default: all files). */
  from?: string | string[];
  /** Forbidden targets: package names ("axios", "lodash/*") or internal path globs ("src/data/**"). */
  to: string | string[];
  /** Exceptions among the importing files. */
  except?: string | string[];
  message?: string;
  severity?: Severity;
}

export interface BoundaryConfig {
  name: string;
  /** Glob matching each module root, e.g. "src/features/*". Every match is its own module. */
  pattern: string;
  /** Files other modules may import, relative to the module root. Default: index files. */
  publicApi?: string[];
  /** Set to false to forbid any import between two modules of this boundary. */
  allowCrossImports?: boolean;
}

export interface ArchCheckConfig extends ResolverOptions {
  /** Glob patterns of files to skip. */
  exclude?: string[];
  /** Circular import detection. Default on; type-only imports are ignored unless includeTypeImports. */
  cycles?: boolean | { includeTypeImports?: boolean; severity?: Severity };
  layers?: LayerConfig[];
  /** Which other layers each layer may import. Layers not listed here are unrestricted. */
  allowed?: Record<string, string[]>;
  restricted?: RestrictedRule[];
  boundaries?: BoundaryConfig[];
  /** Report relative/alias imports that do not resolve to a file. Default false. */
  reportUnresolved?: boolean;
}

export interface AnalysisResult {
  graph: DependencyGraph;
  findings: Finding[];
  /** Layer of every file that belongs to one. */
  layerOf: Map<string, string>;
}

const list = (v: string | string[] | undefined): string[] => (v === undefined ? [] : Array.isArray(v) ? v : [v]);

export function buildGraph(files: Record<string, string>, config: ArchCheckConfig = {}): DependencyGraph {
  const paths = Object.keys(files)
    .map(normalizePath)
    .filter((p) => !matchAny(config.exclude, p))
    .sort();
  const resolver = new Resolver(paths, config);
  const graph: DependencyGraph = { files: paths, edges: [], unresolved: [] };
  const sources = new Map(Object.entries(files).map(([k, v]) => [normalizePath(k), v]));
  for (const from of paths) {
    for (const imp of importsForFile(from, sources.get(from) ?? '')) {
      const r = resolver.resolve(imp.specifier, from);
      if (r.kind === 'asset') continue;
      if (r.kind === 'unresolved') {
        graph.unresolved.push({ from, specifier: imp.specifier, line: imp.line });
        continue;
      }
      graph.edges.push({
        from,
        to: r.kind === 'internal' ? r.path : r.name,
        specifier: imp.specifier,
        external: r.kind === 'external',
        typeOnly: imp.typeOnly,
        line: imp.line,
        kind: imp.kind,
      });
    }
  }
  return graph;
}

export function layerFor(path: string, layers: LayerConfig[] | undefined): string | undefined {
  return layers?.find((l) => matchAny(list(l.include), path))?.name;
}

/** Root of the boundary module that contains `path`, e.g. "src/features/cart". */
export function boundaryRoot(pattern: string, path: string): string | undefined {
  const depth = normalizePath(pattern).split('/').length;
  const segs = path.split('/');
  if (segs.length <= depth) return undefined;
  const root = segs.slice(0, depth).join('/');
  return matchGlob(pattern.includes('/') ? pattern : `/${pattern}`, root) ? root : undefined;
}

function finding(ruleId: string, severity: Severity, edge: Edge, message: string, remediation: string, meta: Record<string, unknown>): Finding {
  return {
    fingerprint: fingerprint('archcheck', ruleId, edge.from, edge.to),
    ruleId,
    severity,
    message,
    location: { file: edge.from, line: edge.line },
    snippet: `import '${edge.specifier}'`,
    remediation,
    meta,
  };
}

function matchesTarget(patterns: string[], edge: Edge): boolean {
  return patterns.some((p) => {
    if (edge.external) return p === edge.to || p === edge.specifier || (p.includes('*') && matchGlob(p.includes('/') ? p : `/${p}`, edge.specifier));
    return matchGlob(p, edge.to);
  });
}

export function analyze(files: Record<string, string>, config: ArchCheckConfig = {}): AnalysisResult {
  const graph = buildGraph(files, config);
  const findings: Finding[] = [];
  const layerOf = new Map<string, string>();
  for (const f of graph.files) {
    const l = layerFor(f, config.layers);
    if (l) layerOf.set(f, l);
  }

  // 1. Circular imports
  if (config.cycles !== false) {
    const opts = typeof config.cycles === 'object' ? config.cycles : {};
    for (const c of findCycles(graph, opts)) {
      const first = graph.edges.find((e) => e.from === c.path[0] && e.to === c.path[1] && !e.external);
      findings.push({
        fingerprint: fingerprint('archcheck', 'circular-import', ...c.members),
        ruleId: 'circular-import',
        severity: opts.severity ?? 'medium',
        message: `Circular import: ${c.path.join(' → ')}${c.members.length > c.path.length - 1 ? ` (${c.members.length} files are entangled)` : ''}`,
        location: { file: c.path[0], line: first?.line },
        remediation:
          'Move the shared code into a module both sides can import, depend on an interface and inject the implementation, or merge the modules if they are really one unit.',
        meta: { cycle: c.path, members: c.members },
      });
    }
  }

  for (const edge of graph.edges) {
    // 2. Layer rules (UI → service → data access)
    const fromLayer = layerOf.get(edge.from);
    const toLayer = edge.external ? undefined : layerOf.get(edge.to);
    if (fromLayer && toLayer && fromLayer !== toLayer) {
      const allowed = config.allowed?.[fromLayer];
      if (allowed && !allowed.includes(toLayer)) {
        findings.push(
          finding(
            'layer-violation',
            'high',
            edge,
            `Layer "${fromLayer}" must not import from layer "${toLayer}" (${edge.from} → ${edge.to}).`,
            allowed.length
              ? `"${fromLayer}" may only depend on: ${allowed.join(', ')}. Route this through an allowed layer instead.`
              : `"${fromLayer}" must not depend on other layers.`,
            { fromLayer, toLayer },
          ),
        );
      }
    }

    // 3. Restricted modules
    for (const rule of config.restricted ?? []) {
      const from = list(rule.from);
      if (from.length && !matchAny(from, edge.from)) continue;
      if (matchAny(list(rule.except), edge.from)) continue;
      if (!matchesTarget(list(rule.to), edge)) continue;
      findings.push(
        finding(
          'restricted-import',
          rule.severity ?? 'high',
          edge,
          rule.message ? `${rule.message} (${edge.from} imports ${edge.specifier})` : `${edge.from} must not import "${edge.specifier}".`,
          rule.message ?? 'Remove the import or move the code to a module that is allowed to depend on it.',
          { target: edge.to },
        ),
      );
    }

    // 4. Module boundaries (no deep imports into another feature's internals)
    if (!edge.external) {
      for (const b of config.boundaries ?? []) {
        const targetRoot = boundaryRoot(b.pattern, edge.to);
        if (!targetRoot) continue;
        const sourceRoot = boundaryRoot(b.pattern, edge.from);
        if (sourceRoot === targetRoot) continue;
        const inner = edge.to.slice(targetRoot.length + 1);
        const publicApi = b.publicApi ?? ['index.ts', 'index.tsx', 'index.js', 'index.jsx', 'index.mjs', 'index.vue'];
        if (sourceRoot && b.allowCrossImports === false) {
          findings.push(
            finding('boundary-violation', 'high', edge, `${b.name} "${sourceRoot}" must not depend on ${b.name} "${targetRoot}".`, `Move shared code to a common module, or communicate through events or an app-level composition root.`, { boundary: b.name, sourceRoot, targetRoot }),
          );
        } else if (!publicApi.some((p) => matchGlob(p.includes('/') ? p : `/${p}`, inner))) {
          findings.push(
            finding('boundary-violation', 'medium', edge, `Deep import into ${b.name} "${targetRoot}" internals (${inner}).`, `Import from the public API of ${targetRoot} (${publicApi[0]}) and export what you need from there.`, { boundary: b.name, sourceRoot, targetRoot, inner }),
          );
        }
      }
    }
  }

  if (config.reportUnresolved) {
    for (const u of graph.unresolved) {
      findings.push({
        fingerprint: fingerprint('archcheck', 'unresolved-import', u.from, u.specifier),
        ruleId: 'unresolved-import',
        severity: 'low',
        message: `Cannot resolve "${u.specifier}" from ${u.from}.`,
        location: { file: u.from, line: u.line },
        remediation: 'Fix the path, or add the alias to the archcheck "aliases" config.',
      });
    }
  }

  return { graph, findings, layerOf };
}

/** Mermaid diagram of the layer graph (or directory graph when no layers are configured). */
export function toMermaid(result: AnalysisResult, options: { depth?: number } = {}): string {
  const group = (file: string) =>
    result.layerOf.get(file) ?? file.split('/').slice(0, Math.max(1, options.depth ?? 2)).join('/');
  const edges = new Map<string, { count: number; violation: boolean }>();
  const violations = new Set(
    result.findings.filter((f) => f.ruleId === 'layer-violation').map((f) => `${f.meta?.fromLayer}->${f.meta?.toLayer}`),
  );
  for (const e of result.graph.edges) {
    if (e.external) continue;
    const a = group(e.from);
    const b = group(e.to);
    if (a === b) continue;
    const key = `${a}->${b}`;
    const cur = edges.get(key) ?? { count: 0, violation: violations.has(key) };
    cur.count++;
    edges.set(key, cur);
  }
  const id = (s: string) => s.replace(/[^\w]/g, '_');
  const lines = ['graph TD'];
  const nodes = new Set<string>();
  [...edges.keys()].forEach((k) => k.split('->').forEach((n) => nodes.add(n)));
  for (const n of [...nodes].sort()) lines.push(`  ${id(n)}["${n}"]`);
  let i = 0;
  const red: number[] = [];
  for (const [k, v] of [...edges.entries()].sort()) {
    const [a, b] = k.split('->') as [string, string];
    lines.push(`  ${id(a)} -->|${v.count}| ${id(b)}`);
    if (v.violation) red.push(i);
    i++;
  }
  if (red.length) lines.push(`  linkStyle ${red.join(',')} stroke:#d33,stroke-width:2px`);
  return lines.join('\n');
}
