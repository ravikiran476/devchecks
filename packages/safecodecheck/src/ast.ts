// Tiny ESTree helpers. Nodes are typed loosely so the rules work on ASTs from
// @babel/parser (estree plugin), espree (ESLint) and typescript-eslint alike.

export interface Node {
  type: string;
  start?: number;
  end?: number;
  range?: [number, number];
  loc?: { start: { line: number; column: number }; end: { line: number; column: number } };
  [key: string]: unknown;
}

const SKIP = new Set(['loc', 'range', 'start', 'end', 'extra', 'parent', 'leadingComments', 'trailingComments', 'innerComments', 'comments', 'tokens']);

export function isNode(v: unknown): v is Node {
  return typeof v === 'object' && v !== null && typeof (v as Node).type === 'string';
}

/** Depth-first walk that passes the ancestor chain (closest last). */
export function walk(root: Node, visit: (node: Node, ancestors: Node[]) => void): void {
  const ancestors: Node[] = [];
  const go = (node: Node) => {
    visit(node, ancestors);
    ancestors.push(node);
    for (const key of Object.keys(node)) {
      if (SKIP.has(key)) continue;
      const v = node[key];
      if (Array.isArray(v)) {
        for (const c of v) if (isNode(c)) go(c);
      } else if (isNode(v)) go(v);
    }
    ancestors.pop();
  };
  go(root);
}

/** Removes wrappers that do not change the value: TS casts, non-null, optional chains, parentheses. */
export function unwrap(n: Node | undefined): Node | undefined {
  let cur = n;
  while (
    cur &&
    ['TSAsExpression', 'TSNonNullExpression', 'TSTypeAssertion', 'TSSatisfiesExpression', 'ChainExpression', 'ParenthesizedExpression', 'AwaitExpression'].includes(cur.type)
  ) {
    cur = (cur.expression ?? cur.argument) as Node | undefined;
  }
  return cur;
}

export function propName(n: Node | undefined): string | undefined {
  if (!n) return undefined;
  if (n.type === 'Identifier' || n.type === 'PrivateIdentifier' || n.type === 'JSXIdentifier') return n.name as string;
  if (n.type === 'Literal' && typeof n.value === 'string') return n.value;
  return undefined;
}

/** "window.location.href" for member chains of identifiers; undefined otherwise. */
export function memberPath(n: Node | undefined): string | undefined {
  const node = unwrap(n);
  if (!node) return undefined;
  if (node.type === 'Identifier') return node.name as string;
  if (node.type === 'ThisExpression') return 'this';
  if (node.type === 'MemberExpression') {
    const obj = memberPath(node.object as Node);
    const prop = node.computed ? propName(node.property as Node) : propName(node.property as Node);
    if (obj === undefined || prop === undefined) return undefined;
    return `${obj}.${prop}`;
  }
  if (node.type === 'CallExpression') {
    const callee = memberPath(node.callee as Node);
    return callee === undefined ? undefined : `${callee}()`;
  }
  return undefined;
}

export function calleePath(call: Node): string | undefined {
  return memberPath(call.callee as Node);
}

export function lastProp(n: Node | undefined): string | undefined {
  const node = unwrap(n);
  if (node?.type === 'MemberExpression') return propName(node.property as Node);
  if (node?.type === 'Identifier') return node.name as string;
  return undefined;
}

export function args(call: Node): Node[] {
  return (call.arguments as Node[]) ?? [];
}

export function position(n: Node): { line: number; column: number } {
  return { line: n.loc?.start.line ?? 1, column: (n.loc?.start.column ?? 0) + 1 };
}

export function sourceOf(n: Node, src: string): string {
  const start = n.range?.[0] ?? n.start ?? 0;
  const end = n.range?.[1] ?? n.end ?? start;
  return src.slice(start, end);
}
