import type { ImportRecord } from './imports.js';

export interface Edge {
  from: string;
  /** Internal file path, or the package name for external modules. */
  to: string;
  specifier: string;
  external: boolean;
  typeOnly: boolean;
  line: number;
  kind: ImportRecord['kind'];
}

export interface DependencyGraph {
  files: string[];
  edges: Edge[];
  unresolved: Array<{ from: string; specifier: string; line: number }>;
}

/** Strongly connected components (Tarjan), iterative to survive deep graphs. */
export function stronglyConnected(nodes: string[], adjacency: Map<string, string[]>): string[][] {
  let index = 0;
  const idx = new Map<string, number>();
  const low = new Map<string, number>();
  const onStack = new Set<string>();
  const stack: string[] = [];
  const result: string[][] = [];

  for (const root of nodes) {
    if (idx.has(root)) continue;
    const work: Array<{ node: string; i: number }> = [{ node: root, i: 0 }];
    idx.set(root, index);
    low.set(root, index++);
    stack.push(root);
    onStack.add(root);
    while (work.length) {
      const frame = work[work.length - 1]!;
      const next = adjacency.get(frame.node) ?? [];
      if (frame.i < next.length) {
        const w = next[frame.i++]!;
        if (!idx.has(w)) {
          idx.set(w, index);
          low.set(w, index++);
          stack.push(w);
          onStack.add(w);
          work.push({ node: w, i: 0 });
        } else if (onStack.has(w)) {
          low.set(frame.node, Math.min(low.get(frame.node)!, idx.get(w)!));
        }
        continue;
      }
      work.pop();
      const parent = work[work.length - 1];
      if (parent) low.set(parent.node, Math.min(low.get(parent.node)!, low.get(frame.node)!));
      if (low.get(frame.node) === idx.get(frame.node)) {
        const comp: string[] = [];
        let w: string;
        do {
          w = stack.pop()!;
          onStack.delete(w);
          comp.push(w);
        } while (w !== frame.node);
        result.push(comp);
      }
    }
  }
  return result;
}

/** Shortest cycle through `start` using only nodes in `members` (BFS). */
export function shortestCycle(start: string, members: Set<string>, adjacency: Map<string, string[]>): string[] {
  const prev = new Map<string, string>();
  const queue = [start];
  const seen = new Set([start]);
  while (queue.length) {
    const node = queue.shift()!;
    for (const w of adjacency.get(node) ?? []) {
      if (!members.has(w)) continue;
      if (w === start) {
        const path = [node];
        while (path[0] !== start) path.unshift(prev.get(path[0]!)!);
        return [...path, start];
      }
      if (!seen.has(w)) {
        seen.add(w);
        prev.set(w, node);
        queue.push(w);
      }
    }
  }
  return [start, start];
}

export interface Cycle {
  /** Files in the cycle; the first file is repeated at the end. */
  path: string[];
  /** All files in the strongly connected component (may be more than one cycle). */
  members: string[];
}

export function findCycles(graph: DependencyGraph, options: { includeTypeImports?: boolean } = {}): Cycle[] {
  const adjacency = new Map<string, string[]>();
  for (const e of graph.edges) {
    if (e.external || (e.typeOnly && !options.includeTypeImports)) continue;
    const list = adjacency.get(e.from) ?? [];
    if (!list.includes(e.to)) list.push(e.to);
    adjacency.set(e.from, list);
  }
  const cycles: Cycle[] = [];
  for (const comp of stronglyConnected(graph.files, adjacency)) {
    const selfLoop = comp.length === 1 && adjacency.get(comp[0]!)?.includes(comp[0]!);
    if (comp.length < 2 && !selfLoop) continue;
    const members = [...comp].sort();
    cycles.push({ path: shortestCycle(members[0]!, new Set(members), adjacency), members });
  }
  return cycles.sort((a, b) => a.members[0]!.localeCompare(b.members[0]!));
}
