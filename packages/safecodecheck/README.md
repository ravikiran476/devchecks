# @devchecks/safecodecheck

AST-based security checks for JavaScript, TypeScript, JSX, Vue, Svelte and Angular templates. Code is parsed with `@babel/parser` (ESTree mode), so the rules see real syntax, not text. A sink is reported only when its input is dynamic, and the severity rises to `critical` when the value comes from a user-controllable source (`location.*`, `URLSearchParams.get`, `req.query`, `event.data`, ...).

| Rule | Finds | CWE |
|---|---|---|
| `dom-unsafe-html` | `innerHTML`/`outerHTML`/`srcdoc` =, `insertAdjacentHTML`, `document.write`, `createContextualFragment`, `setHTMLUnsafe`, jQuery `.html()` | 79 |
| `react-dangerous-html` | `dangerouslySetInnerHTML` without sanitization | 79 |
| `framework-unsafe-html` | Vue `v-html`, Svelte `{@html}`, Angular `[innerHTML]`, `bypassSecurityTrust*` | 79 |
| `dynamic-code-execution` | `eval`, `new Function`, string `setTimeout`/`setInterval`, `vm.run*` | 95 |
| `command-injection` | `child_process.exec` with built-up commands | 78 |
| `insecure-randomness` | `Math.random()` used for tokens, passwords, nonces, session ids... (by naming context) | 338 |
| `open-redirect` | `location = x`, `location.assign/replace`, `window.open`, tainted `href`/`src` | 601 |
| `javascript-url` | `javascript:` URLs (except `javascript:void(0)`) | 79 |
| `postmessage-wildcard` | `postMessage(data, '*')` | 345 |
| `message-origin-unchecked` | `message` handlers that never check `event.origin` | 346 |

Values passed through `DOMPurify.sanitize`, or any call whose name contains `sanitize`, `escape` or `encode`, count as safe. Constant strings are not reported.

## CLI

```bash
npx @devchecks/safecodecheck            # scans src/ (or .), skipping tests, build output and node_modules
npx @devchecks/safecodecheck rules      # list rules
npx @devchecks/safecodecheck src --fail-on high -f sarif -o safecode.sarif
```

Suppress a reviewed finding: `// safecodecheck-disable-next-line dom-unsafe-html -- sanitized on the server`

Config `.safecodecheckrc.json`: `{ "disable": ["javascript-url"], "severity": { "open-redirect": "high" }, "exclude": ["legacy/**"], "includeTests": false }`

## ESLint plugin

Run the same rules alongside established plugins such as `eslint-plugin-no-unsanitized` and `eslint-plugin-security`:

```js
// eslint.config.js
import safecode from '@devchecks/safecodecheck/eslint';
export default [safecode.configs.recommended];
```

## API / CDN

```js
import { analyzeSource } from '@devchecks/safecodecheck';
const { findings } = analyzeSource(code, 'src/App.tsx');
```

`https://cdn.jsdelivr.net/gh/ravikiran476/devchecks@v0.1.0/cdn/safecodecheck.min.js` → `SafeCodeCheck.analyzeSource(code, 'a.tsx')` (about 87 kB gzip, including the parser).

Static analysis finds likely issues, not proof of exploitability. Data flow is tracked within an expression, not across functions.
