import { describe, expect, it } from 'vitest';
import { analyze, extractImports, presets, toMermaid, type ArchCheckConfig } from '../src/index.js';

describe('extractImports', () => {
  it('finds every import form and ignores comments, strings and regexes', () => {
    const src = `
import React, { useState } from 'react';
import type { User } from './types';
import './styles.css';
import * as api from "@/services/api";
export { helper } from './helper';
export * from './all';
export type { T } from './t';
const lazy = import('./Lazy');
const fs = require('node:fs');
// import fake from 'commented';
/* import fake2 from 'block'; */
const s = "import nope from 'string'";
const t = \`import x from 'template' \${value}\`;
const re = /import y from 'regex'/;
const meta = import.meta.url;
obj.require('not-a-require');
`;
    expect(extractImports(src).map((i) => [i.specifier, i.kind, i.typeOnly])).toEqual([
      ['react', 'import', false],
      ['./types', 'import', true],
      ['./styles.css', 'import', false],
      ['@/services/api', 'import', false],
      ['./helper', 'export', false],
      ['./all', 'export', false],
      ['./t', 'export', true],
      ['./Lazy', 'dynamic', false],
      ['node:fs', 'require', false],
    ]);
  });

  it('survives apostrophes in JSX text', () => {
    const src = `import a from './a';\nconst C = () => <p>Don't stop</p>;\nimport b from './b';`;
    expect(extractImports(src).map((i) => i.specifier)).toEqual(['./a', './b']);
  });

  it('reports line numbers', () => {
    expect(extractImports(`\n\nimport x from 'x'`)[0]?.line).toBe(3);
  });
});

const reactApp: Record<string, string> = {
  'src/components/UserCard.tsx': `
import { getUser } from '@/services/userService';
import { db } from '../data/db';
import axios from 'axios';
import { formatName } from '@/utils/format';
export const UserCard = () => null;`,
  'src/services/userService.ts': `import { db } from '../data/db';\nexport const getUser = () => db;`,
  'src/data/db.ts': `import { formatName } from '../utils/format';\nexport const db = {};`,
  'src/utils/format.ts': `import { getUser } from '../services/userService';\nexport const formatName = () => '';`,
  'src/features/cart/index.ts': `export * from './CartView';`,
  'src/features/cart/CartView.tsx': `import { secret } from '../checkout/internal/secret';\nexport const CartView = 1;`,
  'src/features/checkout/index.ts': `export const checkout = 1;`,
  'src/features/checkout/internal/secret.ts': `export const secret = 1;`,
};

describe('analyze', () => {
  const config: ArchCheckConfig = presets.react;
  const { findings, graph } = analyze(reactApp, config);
  const byRule = (rule: string) => findings.filter((f) => f.ruleId === rule);

  it('builds the graph with alias resolution', () => {
    const edges = graph.edges.filter((e) => e.from === 'src/components/UserCard.tsx').map((e) => e.to);
    expect(edges).toEqual(['src/services/userService.ts', 'src/data/db.ts', 'axios', 'src/utils/format.ts']);
  });

  it('detects circular imports with the shortest cycle path', () => {
    const [cycle] = byRule('circular-import');
    expect(cycle?.meta?.cycle).toEqual(['src/data/db.ts', 'src/utils/format.ts', 'src/services/userService.ts', 'src/data/db.ts']);
  });

  it('enforces UI → service → data layering', () => {
    const v = byRule('layer-violation').map((f) => `${f.meta?.fromLayer}->${f.meta?.toLayer}`);
    expect(v).toContain('ui->data');
    expect(v).toContain('shared->service');
    expect(v).not.toContain('ui->service');
  });

  it('blocks restricted modules', () => {
    expect(byRule('restricted-import').map((f) => f.location?.file)).toEqual(['src/components/UserCard.tsx']);
  });

  it('flags deep imports across feature boundaries', () => {
    const [b] = byRule('boundary-violation');
    expect(b?.location?.file).toBe('src/features/cart/CartView.tsx');
    expect(b?.meta?.inner).toBe('internal/secret.ts');
  });

  it('ignores type-only imports for cycles', () => {
    const r = analyze({ 'a.ts': `import type { B } from './b';`, 'b.ts': `import { a } from './a';` });
    expect(r.findings).toEqual([]);
  });

  it('can forbid cross-module imports entirely', () => {
    const r = analyze(
      { 'src/m/a/index.ts': `import { b } from '../b';`, 'src/m/b/index.ts': 'export const b = 1;' },
      { boundaries: [{ name: 'module', pattern: 'src/m/*', allowCrossImports: false }] },
    );
    expect(r.findings.map((f) => [f.ruleId, f.severity])).toEqual([['boundary-violation', 'high']]);
  });

  it('extracts Vue <script> blocks', () => {
    const r = analyze(
      {
        'src/components/A.vue': `<template><div>it's</div></template>\n<script setup lang="ts">\nimport axios from 'axios'\n</script>`,
      },
      presets.vue,
    );
    expect(r.findings.map((f) => [f.ruleId, f.location?.line])).toEqual([['restricted-import', 3]]);
  });

  it('renders a Mermaid layer diagram with violations highlighted', () => {
    const m = toMermaid(analyze(reactApp, config));
    expect(m).toContain('graph TD');
    expect(m).toContain('ui -->|');
    expect(m).toMatch(/linkStyle [\d,]+ stroke:#d33/);
  });
});
