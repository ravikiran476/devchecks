# @devchecks/archcheck

Keeps an architecture honest by checking imports. It works for React, Vue (`<script>` blocks in `.vue` files), Svelte and Node projects, in JS or TS:

- **circular imports**, reported as the shortest cycle path; type-only imports are ignored because they are erased at compile time
- **layer rules**, e.g. UI → service → data access
- **restricted modules**, e.g. no `axios` in components, no DB driver in route handlers
- **module boundaries**: no deep imports into another feature's internals; only its `index.ts` public API

## CLI

```bash
npx @devchecks/archcheck --preset react      # or vue, node
npx @devchecks/archcheck init react > archcheck.config.json
npx @devchecks/archcheck -f mermaid -o architecture.mmd   # layer diagram, violations in red
```

`tsconfig.json` / `jsconfig.json` `paths` and `baseUrl` are picked up automatically.

## Configuration: `archcheck.config.json`

```json
{
  "preset": "react",
  "layers": [
    { "name": "ui", "include": ["src/components/**", "src/pages/**"] },
    { "name": "service", "include": ["src/services/**"] },
    { "name": "data", "include": ["src/data/**"] },
    { "name": "shared", "include": ["src/utils/**"] }
  ],
  "allowed": { "ui": ["service", "shared"], "service": ["data", "shared"], "data": ["shared"], "shared": [] },
  "restricted": [
    { "from": "src/components/**", "to": ["axios", "src/data/**"], "message": "Components must go through a service" }
  ],
  "boundaries": [{ "name": "feature", "pattern": "src/features/*", "publicApi": ["index.ts"] }],
  "cycles": { "includeTypeImports": false },
  "aliases": { "@/*": ["src/*"] },
  "exclude": ["**/*.stories.tsx"]
}
```

- `allowed[layer]` lists the *other* layers that layer may import. Imports within a layer are always allowed. Layers without an entry are unrestricted.
- `restricted[].to` takes package names (`"axios"`, `"lodash/*"`) or path globs (`"src/data/**"`).
- `boundaries[].allowCrossImports: false` forbids imports between two modules entirely.

| Rule | Default severity |
|---|---|
| `layer-violation`, `restricted-import` | high |
| `circular-import`, `boundary-violation` (deep import) | medium |
| `boundary-violation` (cross-module import when `allowCrossImports: false`) | high |

## API

```js
import { analyze, presets, toMermaid } from '@devchecks/archcheck';   // pure: give it { path: source }
import { analyzeProject } from '@devchecks/archcheck/node';

const result = analyze({ 'src/a.ts': "import { b } from './b'", 'src/b.ts': "import { a } from './a'" });
result.findings;  // circular-import a.ts → b.ts → a.ts
```

The import scanner is a small tokenizer that understands comments, strings, template literals, regex literals and JSX text. It finds `import`, `export … from`, `import()` and `require()` without a full parser, which keeps the CDN build at about 8 kB gzip.
