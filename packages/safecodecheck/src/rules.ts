import type { Severity } from '@devchecks/core';
import { args, calleePath, lastProp, memberPath, position, propName, sourceOf, unwrap, walk, type Node } from './ast.js';

export type RuleId =
  | 'dom-unsafe-html'
  | 'react-dangerous-html'
  | 'framework-unsafe-html'
  | 'dynamic-code-execution'
  | 'command-injection'
  | 'insecure-randomness'
  | 'open-redirect'
  | 'javascript-url'
  | 'postmessage-wildcard'
  | 'message-origin-unchecked';

export interface RuleInfo {
  id: RuleId;
  title: string;
  cwe: string;
  remediation: string;
}

export const RULES: Record<RuleId, RuleInfo> = {
  'dom-unsafe-html': {
    id: 'dom-unsafe-html',
    title: 'Unsafe HTML insertion into the DOM',
    cwe: 'CWE-79',
    remediation:
      'Use textContent / innerText or build nodes with createElement. If you must insert HTML, sanitize it first (e.g. DOMPurify.sanitize) or use the Trusted Types / Sanitizer API.',
  },
  'react-dangerous-html': {
    id: 'react-dangerous-html',
    title: 'dangerouslySetInnerHTML with unsanitized content',
    cwe: 'CWE-79',
    remediation: 'Render the value as children so React escapes it, or pass it through DOMPurify.sanitize() before using dangerouslySetInnerHTML.',
  },
  'framework-unsafe-html': {
    id: 'framework-unsafe-html',
    title: 'Framework escape hatch renders raw HTML',
    cwe: 'CWE-79',
    remediation: 'Prefer text interpolation ({{ }} / { }). If raw HTML is required, sanitize it with DOMPurify, and never bypass Angular sanitization for user-controlled values.',
  },
  'dynamic-code-execution': {
    id: 'dynamic-code-execution',
    title: 'Dynamic code execution',
    cwe: 'CWE-95',
    remediation: 'Avoid eval, new Function and string-based timers. Pass a function to setTimeout/setInterval, parse data with JSON.parse, and use lookup tables instead of generated code.',
  },
  'command-injection': {
    id: 'command-injection',
    title: 'Shell command built from dynamic input',
    cwe: 'CWE-78',
    remediation: 'Use execFile/spawn with an argument array (no shell) and validate inputs against an allowlist.',
  },
  'insecure-randomness': {
    id: 'insecure-randomness',
    title: 'Math.random() used for a security-sensitive value',
    cwe: 'CWE-338',
    remediation: 'Use crypto.getRandomValues(), crypto.randomUUID() (browser and Node) or crypto.randomBytes() (Node) for tokens, IDs, nonces and secrets.',
  },
  'open-redirect': {
    id: 'open-redirect',
    title: 'Navigation to a dynamic URL',
    cwe: 'CWE-601',
    remediation: 'Validate the destination: parse it with new URL(), allow only http(s) and an allowlist of origins or relative paths, and reject "javascript:" URLs.',
  },
  'javascript-url': {
    id: 'javascript-url',
    title: 'javascript: URL',
    cwe: 'CWE-79',
    remediation: 'Use an event handler (onClick) instead of a javascript: URL.',
  },
  'postmessage-wildcard': {
    id: 'postmessage-wildcard',
    title: 'postMessage with "*" target origin',
    cwe: 'CWE-345',
    remediation: 'Pass the exact origin of the receiving window as the second argument to postMessage.',
  },
  'message-origin-unchecked': {
    id: 'message-origin-unchecked',
    title: 'message event handler does not check event.origin',
    cwe: 'CWE-346',
    remediation: 'Compare event.origin against an allowlist before using event.data.',
  },
};

export type Taint = 'safe' | 'tainted' | 'unknown';

export interface RawFinding {
  rule: RuleId;
  severity: Severity;
  message: string;
  line: number;
  column: number;
}

// Values an attacker commonly controls.
const SOURCES = [
  /(^|\.)location\.(search|hash|href|pathname)$/,
  /^document\.(URL|documentURI|baseURI|referrer|cookie)$/,
  /^(window|self|top|parent)\.name$/,
  /\.searchParams\.get\(\)$/,
  /(^|\.)(searchParams|params|query)\.get\(\)$/,
  /^(req|request|ctx\.request)\.(query|params|body|headers|cookies)(\.|$)/,
  /^(req|request)\.(query|params|body)\./,
  /^(router|route|\$route)\.(query|params)(\.|$)/,
  /^(e|evt|event|ev|msg|message)\.data(\.|$)/,
  /(^|\.)(useSearchParams|useParams)\(\)/,
];

const SANITIZER = /(sanitize|purify|escape|encode|dompurify|xss|clean)/i;

function isSourcePath(path: string | undefined): boolean {
  return !!path && SOURCES.some((r) => r.test(path));
}

/** Rough provenance of an expression: constant, attacker-controlled, or unknown. */
export function classify(expr: Node | undefined): Taint {
  const n = unwrap(expr);
  if (!n) return 'safe';
  switch (n.type) {
    case 'Literal':
      return 'safe';
    case 'TemplateLiteral': {
      const parts = (n.expressions as Node[]).map(classify);
      return parts.includes('tainted') ? 'tainted' : parts.includes('unknown') ? 'unknown' : 'safe';
    }
    case 'BinaryExpression':
    case 'LogicalExpression': {
      const parts = [classify(n.left as Node), classify(n.right as Node)];
      return parts.includes('tainted') ? 'tainted' : parts.includes('unknown') ? 'unknown' : 'safe';
    }
    case 'ConditionalExpression': {
      const parts = [classify(n.consequent as Node), classify(n.alternate as Node)];
      return parts.includes('tainted') ? 'tainted' : parts.includes('unknown') ? 'unknown' : 'safe';
    }
    case 'CallExpression': {
      const callee = calleePath(n) ?? '';
      if (SANITIZER.test(callee)) return 'safe';
      if (/^(String|Number|parseInt|parseFloat|Boolean)$/.test(callee)) return callee === 'String' ? classify(args(n)[0]) : 'safe';
      if (/\.(toFixed|toString)$/.test(callee) && classify((n.callee as Node).object as Node) === 'safe') return 'safe';
      if (isSourcePath(`${callee}()`)) return 'tainted';
      // Methods on a tainted value (e.g. location.hash.slice(1)) stay tainted.
      const obj = (unwrap(n.callee as Node) as Node | undefined)?.object as Node | undefined;
      if (obj && classify(obj) === 'tainted') return 'tainted';
      return 'unknown';
    }
    case 'MemberExpression':
    case 'Identifier': {
      const path = memberPath(n);
      if (isSourcePath(path)) return 'tainted';
      if (n.type === 'MemberExpression' && classify(n.object as Node) === 'tainted') return 'tainted';
      if (n.type === 'Identifier' && n.name === 'undefined') return 'safe';
      return 'unknown';
    }
    case 'NewExpression':
      // new URL(location.href), new URLSearchParams(location.search) carry their input's taint.
      return args(n).some((a) => classify(a) === 'tainted') ? 'tainted' : 'unknown';
    case 'ArrayExpression':
    case 'ObjectExpression':
    case 'ArrowFunctionExpression':
    case 'FunctionExpression':
      return 'safe';
    default:
      return 'unknown';
  }
}

const SENSITIVE_WORDS = new Set([
  'token', 'secret', 'password', 'passwd', 'pwd', 'nonce', 'salt', 'otp', 'csrf', 'xsrf', 'session', 'sessionid',
  'apikey', 'auth', 'uuid', 'guid', 'verifier', 'challenge', 'iv', 'pin', 'passcode', 'credential', 'credentials',
]);

function words(name: string): string[] {
  return name
    .replace(/([a-z0-9])([A-Z])/g, '$1 $2')
    .split(/[^A-Za-z0-9]+/)
    .map((w) => w.toLowerCase())
    .filter(Boolean);
}

function sensitiveName(name: string | undefined): boolean {
  if (!name) return false;
  const w = words(name);
  return w.some((x) => SENSITIVE_WORDS.has(x)) || /api_?key|secret_?key|private_?key|reset_?code|invite_?code/i.test(name);
}

/** Names that describe what a Math.random() result is used for. */
function contextNames(ancestors: Node[]): string[] {
  const names: string[] = [];
  for (let i = ancestors.length - 1; i >= 0 && names.length < 6; i--) {
    const a = ancestors[i]!;
    if (a.type === 'VariableDeclarator') names.push(propName(a.id as Node) ?? '');
    else if (a.type === 'AssignmentExpression') names.push(lastProp(a.left as Node) ?? '');
    else if (a.type === 'Property' || a.type === 'PropertyDefinition' || a.type === 'MethodDefinition') names.push(propName(a.key as Node) ?? '');
    else if (a.type === 'FunctionDeclaration' || a.type === 'FunctionExpression') names.push(propName(a.id as Node) ?? '');
    else if (a.type === 'CallExpression') names.push(lastProp(a.callee as Node) ?? '');
    else if (a.type === 'JSXAttribute') return []; // e.g. key={Math.random()} is a React smell, not a security issue
  }
  return names.filter(Boolean);
}

const HTML_PROPS = new Set(['innerHTML', 'outerHTML', 'srcdoc']);
const LOCATION_TARGETS = /^(window\.|document\.|self\.|top\.|parent\.)?location(\.href)?$/;

function severityFor(t: Taint, tainted: Severity, unknown: Severity | undefined): Severity | undefined {
  return t === 'tainted' ? tainted : t === 'unknown' ? unknown : undefined;
}

export function runRules(ast: Node, source: string): RawFinding[] {
  const out: RawFinding[] = [];
  const report = (node: Node, rule: RuleId, severity: Severity | undefined, message: string) => {
    if (!severity) return;
    out.push({ rule, severity, message, ...position(node) });
  };
  const taintNote = (t: Taint) => (t === 'tainted' ? ' The value comes from a user-controllable source.' : '');

  walk(ast, (node, ancestors) => {
    // Assignments: el.innerHTML = x, location.href = x
    if (node.type === 'AssignmentExpression') {
      const left = unwrap(node.left as Node)!;
      const right = node.right as Node;
      const prop = lastProp(left);
      const t = classify(right);
      if (left.type === 'MemberExpression' && prop && HTML_PROPS.has(prop)) {
        report(node, 'dom-unsafe-html', severityFor(t, 'critical', 'high'), `Assigning a dynamic value to ${prop}.${taintNote(t)}`);
      }
      const target = memberPath(left);
      if (target && LOCATION_TARGETS.test(target)) {
        report(node, 'open-redirect', severityFor(t, 'high', 'medium'), `Navigating via ${target} to a dynamic URL.${taintNote(t)}`);
        checkJavascriptUrl(right, node);
      } else if (left.type === 'MemberExpression' && prop && ['src', 'href', 'action', 'formAction'].includes(prop)) {
        report(node, 'open-redirect', severityFor(t, 'high', undefined), `Setting ${prop} from a user-controllable value.`);
        checkJavascriptUrl(right, node);
      }
      if (prop === 'onmessage' && isFunction(right) && !mentionsOrigin(right)) {
        report(node, 'message-origin-unchecked', 'medium', 'onmessage handler uses event data without checking event.origin.');
      }
    }

    if (node.type === 'CallExpression' || node.type === 'NewExpression') {
      const callee = calleePath(node) ?? '';
      const method = lastProp(node.callee as Node) ?? '';
      const a = args(node);

      // DOM HTML sinks
      if (method === 'insertAdjacentHTML' && a[1]) {
        const t = classify(a[1]);
        report(node, 'dom-unsafe-html', severityFor(t, 'critical', 'high'), `insertAdjacentHTML with dynamic HTML.${taintNote(t)}`);
      } else if (/^(window\.)?document\.(write|writeln)$/.test(callee) && a.length) {
        const t = a.map(classify).includes('tainted') ? 'tainted' : a.map(classify).includes('unknown') ? 'unknown' : 'safe';
        report(node, 'dom-unsafe-html', severityFor(t, 'critical', 'high'), `${callee}() with dynamic content.${taintNote(t)}`);
      } else if ((method === 'createContextualFragment' || method === 'setHTMLUnsafe' || method === 'parseHTMLUnsafe') && a[0]) {
        const t = classify(a[0]);
        report(node, 'dom-unsafe-html', severityFor(t, 'critical', 'high'), `${method}() with dynamic HTML.${taintNote(t)}`);
      } else if (method === 'html' && a[0] && /^(\$|jQuery)/.test(callee)) {
        const t = classify(a[0]);
        report(node, 'dom-unsafe-html', severityFor(t, 'critical', 'medium'), `jQuery .html() with dynamic content.${taintNote(t)}`);
      }

      // Angular sanitizer bypass
      if (/^bypassSecurityTrust(Html|Script|Style|Url|ResourceUrl)$/.test(method) && a[0]) {
        const t = classify(a[0]);
        report(node, 'framework-unsafe-html', severityFor(t, 'critical', 'high'), `${method}() disables Angular sanitization for a dynamic value.${taintNote(t)}`);
      }

      // Dynamic code
      if (callee === 'eval' || callee === 'window.eval' || callee === 'globalThis.eval') {
        const t = classify(a[0]);
        report(node, 'dynamic-code-execution', t === 'safe' ? 'low' : t === 'tainted' ? 'critical' : 'high', `eval() executes ${t === 'safe' ? 'a constant string; replace it with real code' : 'dynamic code'}.${taintNote(t)}`);
      } else if (callee === 'Function' || callee === 'window.Function' || callee === 'globalThis.Function') {
        const t = a.some((x) => classify(x) === 'tainted') ? 'tainted' : a.every((x) => classify(x) === 'safe') ? 'safe' : 'unknown';
        report(node, 'dynamic-code-execution', t === 'safe' ? 'low' : t === 'tainted' ? 'critical' : 'high', `${node.type === 'NewExpression' ? 'new ' : ''}Function() compiles code from strings.${taintNote(t)}`);
      } else if (/^(window\.|globalThis\.)?(setTimeout|setInterval|setImmediate|execScript)$/.test(callee) && a[0] && isStringLike(a[0])) {
        const t = classify(a[0]);
        report(node, 'dynamic-code-execution', t === 'tainted' ? 'critical' : 'medium', `${callee}() with a string argument evaluates it as code.${taintNote(t)}`);
      } else if (/(^|\.)(runInThisContext|runInNewContext|runInContext|compileFunction)$/.test(callee) || (node.type === 'NewExpression' && /(^|\.)Script$/.test(callee) && /vm/.test(callee))) {
        const t = classify(a[0]);
        report(node, 'dynamic-code-execution', severityFor(t, 'critical', 'high'), `${callee}() executes dynamic code.${taintNote(t)}`);
      }

      // Shell commands
      if (/(^|\.)(exec|execSync)$/.test(callee) && /^(exec|execSync|child_process\.|cp\.|childProcess\.)/.test(callee) && a[0]) {
        const t = classify(a[0]);
        report(node, 'command-injection', severityFor(t, 'critical', 'high'), `${callee}() runs a shell command built from dynamic input.${taintNote(t)}`);
      }

      // Insecure randomness
      if (callee === 'Math.random') {
        const names = contextNames(ancestors);
        const hit = names.find(sensitiveName);
        if (hit) report(node, 'insecure-randomness', 'high', `Math.random() is not cryptographically secure but is used for "${hit}".`);
      }

      // Navigation
      if (/^(window\.|document\.)?location\.(assign|replace)$/.test(callee) && a[0]) {
        const t = classify(a[0]);
        report(node, 'open-redirect', severityFor(t, 'high', 'medium'), `${callee}() navigates to a dynamic URL.${taintNote(t)}`);
        checkJavascriptUrl(a[0], node);
      } else if (/^(window\.)?open$/.test(callee) && a[0]) {
        const t = classify(a[0]);
        report(node, 'open-redirect', severityFor(t, 'high', 'low'), `window.open() with a dynamic URL.${taintNote(t)}`);
      }

      // postMessage
      if (method === 'postMessage' && a[1]?.type === 'Literal' && a[1].value === '*') {
        report(node, 'postmessage-wildcard', 'medium', 'postMessage(..., "*") can deliver data to any origin.');
      }
      if (method === 'addEventListener' && a[0]?.type === 'Literal' && a[0].value === 'message' && a[1] && isFunction(a[1]) && !mentionsOrigin(a[1])) {
        report(node, 'message-origin-unchecked', 'medium', 'message listener uses event data without checking event.origin.');
      }
    }

    // React
    if (node.type === 'JSXAttribute') {
      const name = propName(node.name as Node);
      const value = node.value as Node | null;
      const expr = value?.type === 'JSXExpressionContainer' ? (value.expression as Node) : value ?? undefined;
      if (name === 'dangerouslySetInnerHTML' && expr) {
        const obj = unwrap(expr);
        const html =
          obj?.type === 'ObjectExpression'
            ? ((obj.properties as Node[]).find((p) => p.type === 'Property' && propName(p.key as Node) === '__html')?.value as Node | undefined)
            : obj;
        const t = classify(html);
        report(node, 'react-dangerous-html', severityFor(t, 'critical', 'high'), `dangerouslySetInnerHTML renders unsanitized HTML.${taintNote(t)}`);
      }
      if (name && ['href', 'src', 'action', 'formAction'].includes(name) && expr) {
        const t = classify(expr);
        if (t === 'tainted') report(node, 'open-redirect', 'high', `JSX ${name} is set from a user-controllable value; "javascript:" URLs would execute.`);
        checkJavascriptUrl(expr, node);
      }
    }
  });

  function checkJavascriptUrl(expr: Node, at: Node) {
    const n = unwrap(expr);
    const text = n?.type === 'Literal' ? String(n.value) : n?.type === 'TemplateLiteral' ? sourceOf(n, source).slice(1) : '';
    if (/^\s*javascript:/i.test(text) && text.trim().toLowerCase() !== 'javascript:void(0)' && text.trim().toLowerCase() !== 'javascript:;') {
      report(at, 'javascript-url', 'medium', 'javascript: URL executes code when followed.');
    }
  }

  function mentionsOrigin(fn: Node): boolean {
    return /\.origin\b|\borigin\s*[!=]==?|\{\s*[^}]*\borigin\b/.test(sourceOf(fn, source)) || ((fn.params as Node[] | undefined)?.length ?? 1) === 0;
  }

  return out;
}

function isFunction(n: Node): boolean {
  return n.type === 'ArrowFunctionExpression' || n.type === 'FunctionExpression';
}

function isStringLike(n: Node): boolean {
  const u = unwrap(n)!;
  if (u.type === 'Literal') return typeof u.value === 'string';
  if (u.type === 'TemplateLiteral') return true;
  if (u.type === 'BinaryExpression' && u.operator === '+') return isStringLike(u.left as Node) || isStringLike(u.right as Node);
  return false;
}
