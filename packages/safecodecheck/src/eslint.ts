// ESLint plugin: run the same rules inside ESLint (flat config), next to established
// plugins such as eslint-plugin-no-unsanitized and eslint-plugin-security.
//
//   import safecode from '@devchecks/safecodecheck/eslint';
//   export default [safecode.configs.recommended];
import type { Node } from './ast.js';
import { RULES, runRules, type RawFinding, type RuleId } from './rules.js';

interface RuleContext {
  sourceCode?: { text: string };
  getSourceCode?: () => { text: string };
  report(descriptor: { loc: { line: number; column: number }; message: string }): void;
}

const cache = new WeakMap<object, RawFinding[]>();

function findingsFor(program: Node, text: string): RawFinding[] {
  let cached = cache.get(program);
  if (!cached) {
    cached = runRules(program, text);
    cache.set(program, cached);
  }
  return cached;
}

function makeRule(id: RuleId) {
  const info = RULES[id];
  return {
    meta: {
      type: 'problem' as const,
      docs: { description: `${info.title} (${info.cwe})`, url: `https://cwe.mitre.org/data/definitions/${info.cwe.slice(4)}.html` },
      schema: [],
    },
    create(context: RuleContext) {
      return {
        'Program:exit'(program: Node) {
          const text = context.sourceCode?.text ?? context.getSourceCode?.().text ?? '';
          for (const f of findingsFor(program, text)) {
            if (f.rule !== id) continue;
            context.report({ loc: { line: f.line, column: f.column - 1 }, message: `${f.message} ${info.remediation}` });
          }
        },
      };
    },
  };
}

const rules = Object.fromEntries((Object.keys(RULES) as RuleId[]).map((id) => [id, makeRule(id)]));

const plugin = {
  meta: { name: '@devchecks/safecodecheck', version: __VERSION__ },
  rules,
  configs: {} as Record<string, unknown>,
};

plugin.configs.recommended = {
  plugins: { safecodecheck: plugin },
  rules: Object.fromEntries(Object.keys(RULES).map((id) => [`safecodecheck/${id}`, 'error'])),
};

export default plugin;
