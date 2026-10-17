# devchecks

Ten small, independent checkers for web projects. Every library is a **single file on a public CDN** that anyone can drop into a page. No install, account or build step is needed:

```html
<script src="https://cdn.jsdelivr.net/gh/ravikiran476/devchecks@v0.1.0/cdn/accesscheck.min.js"></script>
<script>AccessCheck.scan().then((r) => console.table(r.findings));</script>
```

| Library | `<script>` global | ES module |
|---|---|---|
| AccessCheck | [`accesscheck.min.js`](https://cdn.jsdelivr.net/gh/ravikiran476/devchecks@v0.1.0/cdn/accesscheck.min.js) → `AccessCheck` | [`accesscheck.esm.js`](https://cdn.jsdelivr.net/gh/ravikiran476/devchecks@v0.1.0/cdn/accesscheck.esm.js) |
| SecretCheck | [`secretcheck.min.js`](https://cdn.jsdelivr.net/gh/ravikiran476/devchecks@v0.1.0/cdn/secretcheck.min.js) → `SecretCheck` | [`secretcheck.esm.js`](https://cdn.jsdelivr.net/gh/ravikiran476/devchecks@v0.1.0/cdn/secretcheck.esm.js) |
| DepCheck | [`depcheck.min.js`](https://cdn.jsdelivr.net/gh/ravikiran476/devchecks@v0.1.0/cdn/depcheck.min.js) → `DepCheck` | [`depcheck.esm.js`](https://cdn.jsdelivr.net/gh/ravikiran476/devchecks@v0.1.0/cdn/depcheck.esm.js) |
| PCI PageCheck | [`pci-pagecheck.min.js`](https://cdn.jsdelivr.net/gh/ravikiran476/devchecks@v0.1.0/cdn/pci-pagecheck.min.js) → `PCIPageCheck` | [`pci-pagecheck.esm.js`](https://cdn.jsdelivr.net/gh/ravikiran476/devchecks@v0.1.0/cdn/pci-pagecheck.esm.js) |
| ArchCheck | [`archcheck.min.js`](https://cdn.jsdelivr.net/gh/ravikiran476/devchecks@v0.1.0/cdn/archcheck.min.js) → `ArchCheck` | [`archcheck.esm.js`](https://cdn.jsdelivr.net/gh/ravikiran476/devchecks@v0.1.0/cdn/archcheck.esm.js) |
| SafeCodeCheck | [`safecodecheck.min.js`](https://cdn.jsdelivr.net/gh/ravikiran476/devchecks@v0.1.0/cdn/safecodecheck.min.js) → `SafeCodeCheck` | [`safecodecheck.esm.js`](https://cdn.jsdelivr.net/gh/ravikiran476/devchecks@v0.1.0/cdn/safecodecheck.esm.js) |
| ConfigCheck | [`configcheck.min.js`](https://cdn.jsdelivr.net/gh/ravikiran476/devchecks@v0.1.0/cdn/configcheck.min.js) → `ConfigCheck` | [`configcheck.esm.js`](https://cdn.jsdelivr.net/gh/ravikiran476/devchecks@v0.1.0/cdn/configcheck.esm.js) |
| PerfCheck | [`perfcheck.min.js`](https://cdn.jsdelivr.net/gh/ravikiran476/devchecks@v0.1.0/cdn/perfcheck.min.js) → `PerfCheck` | [`perfcheck.esm.js`](https://cdn.jsdelivr.net/gh/ravikiran476/devchecks@v0.1.0/cdn/perfcheck.esm.js) |
| APIContractCheck | [`apicontractcheck.min.js`](https://cdn.jsdelivr.net/gh/ravikiran476/devchecks@v0.1.0/cdn/apicontractcheck.min.js) → `APIContractCheck` | [`apicontractcheck.esm.js`](https://cdn.jsdelivr.net/gh/ravikiran476/devchecks@v0.1.0/cdn/apicontractcheck.esm.js) |
| LicenseCheck | [`licensecheck.min.js`](https://cdn.jsdelivr.net/gh/ravikiran476/devchecks@v0.1.0/cdn/licensecheck.min.js) → `LicenseCheck` | [`licensecheck.esm.js`](https://cdn.jsdelivr.net/gh/ravikiran476/devchecks@v0.1.0/cdn/licensecheck.esm.js) |

Use a tag (`@v0.1.0`) in production: tagged files never change. `@main` always serves the latest build. `cdn/index.json` lists every library, and `cdn/report.schema.json` is the shared report schema.

Each library is also an npm package with a **CLI** and a Node API for the jobs a browser can't do, such as reading staged Git content or driving Playwright. See [Publishing](#publishing) for the npm side.

| Package | Checks | Browser (CDN) | Node / CLI |
|---|---|---|---|
| [`@devchecks/accesscheck`](packages/accesscheck) | WCAG issues via axe-core, with selectors, fixes and baselines | scans the current page | Playwright against local dev URLs |
| [`@devchecks/secretcheck`](packages/secretcheck) | credentials and high-entropy strings | scans text | **staged Git content**, pre-commit hook |
| [`@devchecks/depcheck`](packages/depcheck) | known vulnerabilities (OSV.dev) with fixed versions | lockfile text → OSV | lockfiles or installed `node_modules` |
| [`@devchecks/pci-pagecheck`](packages/pci-pagecheck) | payment-page script inventory, CSP, card-data exposure, PCI DSS evidence | snapshots the current page | Playwright, network-level script capture |
| [`@devchecks/archcheck`](packages/archcheck) | circular imports, layers, restricted modules, boundaries | analyzes a file map | walks the project, reads tsconfig paths |
| [`@devchecks/safecodecheck`](packages/safecodecheck) | unsafe DOM, eval, weak randomness, risky URLs (AST-based) | analyzes source text | scans the project; ESLint plugin |
| [`@devchecks/configcheck`](packages/configcheck) | `.env` drift, typed env schemas, risky settings in JSON/YAML/.npmrc | checks config text | scans the project; `assertEnv()` at startup |
| [`@devchecks/perfcheck`](packages/perfcheck) | Core Web Vitals, page weight and bundle size budgets | measures the current page (RUM too) | bundle budgets, Playwright lab runs |
| [`@devchecks/apicontractcheck`](packages/apicontractcheck) | responses vs OpenAPI 3.0/3.1, breaking-change diff | wraps `fetch` to validate live traffic | HAR validation, probing, spec diff |
| [`@devchecks/licensecheck`](packages/licensecheck) | SPDX license policy, copyleft/unknown licenses, attribution | `package-lock.json` text + npm registry | `node_modules` or lockfile, NOTICE file |

## Independent, but sharing an output format

None of the tools imports another. They share only [`@devchecks/core`](packages/core), which defines the **report format** (`schemaVersion: 1`, [JSON Schema](packages/core/report.schema.json)), severities, baselines and the reporters. The browser bundles include it, so each CDN file stands alone.

Every CLI accepts the same flags and returns the same exit codes:

| Flag | Meaning |
|---|---|
| `-f, --format` | `text` (default), `json`, `sarif` (GitHub code scanning), `markdown` |
| `-o, --output <file>` | write the report to a file |
| `--fail-on <severity>` | exit 1 when a finding is at or above `critical`, `high`, `medium`, `low` or `info` |
| `--baseline <file>` / `--update-baseline` | accept the current findings and fail only on new ones |
| `-c, --config <file>` | tool config (each tool also finds its own default file) |

Exit codes: `0` ok, `1` findings at or above `--fail-on`, `2` usage or runtime error.

```bash
npx @devchecks/secretcheck                       # staged changes
npx @devchecks/depcheck
npx @devchecks/archcheck --preset react
npx @devchecks/safecodecheck
```

The `npx` commands work once the packages are published to npm (see [Publishing](#publishing)). Until then, run a CLI from a clone: `npm ci && npm run build && node packages/depcheck/dist/cli.js`.

Once a tool is installed as a dev dependency (`npm i -D @devchecks/depcheck`), the short bin name works: `npx depcheck`. **Note:** `secretcheck`, `depcheck`, `archcheck`, `perfcheck` and `licensecheck` are also names of unrelated packages on npm. A bare `npx depcheck` *without* a local install downloads that other package, so use the scoped name for one-off runs.

### Combining reports

Tools communicate only through report files. `devchecks merge` (from `@devchecks/core`) combines any number of them and keeps the tool that produced each finding:

```bash
npx @devchecks/secretcheck   -f json -o reports/secrets.json
npx @devchecks/depcheck      -f json -o reports/deps.json
npx @devchecks/archcheck     -f json -o reports/arch.json
npx @devchecks/safecodecheck -f json -o reports/code.json
npx @devchecks/core merge reports/*.json -f markdown -o report.md --fail-on high
```

See [examples/github-actions.yml](examples/github-actions.yml) for a CI job that uploads SARIF to GitHub code scanning.

### From a CDN

```html
<!-- Global build -->
<script src="https://cdn.jsdelivr.net/gh/ravikiran476/devchecks@v0.1.0/cdn/accesscheck.min.js"></script>
<script>
  AccessCheck.scan().then((r) => console.table(r.findings));
</script>

<!-- ES module build -->
<script type="module">
  import { analyzeSource } from 'https://cdn.jsdelivr.net/gh/ravikiran476/devchecks@v0.1.0/cdn/safecodecheck.esm.js';
  console.log(analyzeSource('el.innerHTML = location.hash', 'a.js').findings);
</script>
```

The files are served by jsDelivr straight from the `cdn/` folder of this GitHub repository. [examples/cdn.html](examples/cdn.html) loads every bundle on one page.

| Global | File | Size (gzip) |
|---|---|---|
| `AccessCheck` | `accesscheck.min.js` | ~198 kB (includes axe-core) |
| `SafeCodeCheck` | `safecodecheck.min.js` | ~87 kB (includes @babel/parser) |
| `APIContractCheck` | `apicontractcheck.min.js` | ~40 kB (includes yaml) |
| `ConfigCheck` | `configcheck.min.js` | ~38 kB (includes yaml) |
| `PCIPageCheck` | `pci-pagecheck.min.js` | ~12 kB |
| `ArchCheck`, `DepCheck`, `SecretCheck`, `LicenseCheck`, `PerfCheck` | `<tool>.min.js` | 5–8 kB each |

## Package layout

Every package follows the same structure:

```
src/index.ts   browser-safe API (the CDN and npm entry)
src/node.ts    Node-only API (file system, Git, Playwright); re-exports index
src/cli.ts     the CLI
test/          vitest tests
```

`npm run build` produces, per package:

```
dist/index.js          ESM for bundlers and Node (dependencies external)
dist/node.js, cli.js   Node entry and CLI
dist/<tool>.esm.js     self-contained browser ES module (CDN)
dist/<tool>.min.js     self-contained IIFE exposing a global (CDN, unpkg/jsdelivr default)
dist/types/            TypeScript declarations
```

Import paths: `@devchecks/<tool>` (browser-safe API), `@devchecks/<tool>/node` (Node API), `@devchecks/<tool>/cdn` (IIFE file), `@devchecks/<tool>/cdn/esm`. AccessCheck, PCI PageCheck and PerfCheck use Playwright as an **optional** peer dependency, needed only for their Node URL scanners.

## Development

```bash
npm install
npm test            # vitest, all packages
npm run typecheck
npm run build       # every package: npm, Node, CDN and type outputs
npx playwright install chromium   # only for the Playwright-based CLIs
```

## Publishing

**CDN release** (what most users need):

1. Bump versions, then `npm run cdn` (builds every package and refreshes `cdn/`). CI fails if `cdn/` is out of date.
2. Commit, then tag and push: `git tag v0.2.0 && git push origin main v0.2.0`.
3. The new files are live at `https://cdn.jsdelivr.net/gh/ravikiran476/devchecks@v0.2.0/cdn/<tool>.min.js`.

**npm** (optional, for the CLIs and `import` from a bundler):

1. Create the `@devchecks` organization on npm (the scope was unclaimed when this was written), or rename the scope in `scripts/manifests.mjs` and run `node scripts/manifests.mjs`.
2. `npm run check` (typecheck, tests, build).
3. Publish core first: `npm publish -w @devchecks/core --access public`, then each tool: `npm publish -w @devchecks/<tool> --access public`.

Once a package is on npm, jsDelivr and unpkg also serve it at `https://cdn.jsdelivr.net/npm/@devchecks/<tool>@<version>/dist/<tool>.min.js`.

## Limits

These are developer aids, not certifications:

- **AccessCheck**: automated checks catch only part of WCAG. Keyboard, focus and screen-reader testing are still required.
- **PCI PageCheck**: a readiness aid for selected PCI DSS v4.0.1 requirements (6.4.3, 11.6.1, 4.2.1, 3.3.1, 3.5.1, 6.2.4). It is not an assessment and does not establish compliance.
- **LicenseCheck**: engineering guidance, not legal advice.
- **SafeCodeCheck**: finds likely issues with a simple taint heuristic, not proof of exploitability.

## License

MIT
