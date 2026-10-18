// One-off generator for package manifests, kept so the packages stay consistent.
import { writeFileSync } from 'node:fs';

const pkgs = [
  { dir: 'accesscheck', name: 'accesscheck', global: 'AccessCheck', desc: 'Accessibility checks powered by axe-core: scan pages in the browser or local dev URLs with Playwright, with selectors, suggested fixes and baselines.', deps: { 'axe-core': '^4.10.0' }, peer: { playwright: '>=1.40.0' }, kw: ['accessibility', 'a11y', 'wcag', 'axe-core', 'playwright'] },
  { dir: 'secretcheck', name: 'secretcheck', global: 'SecretCheck', desc: 'Detect credentials and high-entropy secrets in staged Git content before they are committed. Secrets are never printed in full.', kw: ['secrets', 'git', 'pre-commit', 'credentials', 'security'] },
  { dir: 'depcheck', name: 'depcheck', global: 'DepCheck', desc: 'Check npm, Yarn and pnpm lockfiles or installed trees against the OSV vulnerability database, with fixed-version guidance and severity thresholds.', kw: ['vulnerabilities', 'osv', 'sca', 'lockfile', 'npm', 'security'] },
  { dir: 'pci-pagecheck', name: 'pci-pagecheck', cdn: 'pci-pagecheck', global: 'PCIPageCheck', desc: 'PCI DSS readiness aid for payment pages: script inventory against an approved baseline, CSP review, card-data exposure checks and control-mapped evidence.', peer: { playwright: '>=1.40.0' }, kw: ['pci', 'pci-dss', 'csp', 'payment', 'script-inventory', 'security'] },
  { dir: 'archcheck', name: 'archcheck', global: 'ArchCheck', desc: 'Enforce architecture in JS/TS, React, Vue and Node projects: circular imports, layer rules, restricted modules and module boundaries.', kw: ['architecture', 'imports', 'circular-dependencies', 'layers', 'boundaries', 'lint'] },
  { dir: 'safecodecheck', name: 'safecodecheck', global: 'SafeCodeCheck', desc: 'AST-based detection of unsafe DOM insertion, dynamic code execution, insecure randomness and risky URL handling, with remediation guidance.', deps: { '@babel/parser': '^7.26.0' }, kw: ['security', 'xss', 'sast', 'ast', 'eslint', 'static-analysis'], extra: { './eslint': 'eslint' } },
  { dir: 'configcheck', name: 'configcheck', global: 'ConfigCheck', desc: 'Validate configuration: .env drift against .env.example, required and typed variables, JSON/YAML syntax, and risky settings such as debug mode, CORS wildcards and disabled TLS verification.', deps: { yaml: '^2.6.0' }, kw: ['config', 'dotenv', 'env', 'yaml', 'validation', 'security'] },
  { dir: 'perfcheck', name: 'perfcheck', global: 'PerfCheck', desc: 'Performance budgets: Core Web Vitals and resource weight in the browser, bundle size budgets (gzip/brotli) and Playwright lab runs in CI.', peer: { playwright: '>=1.40.0' }, kw: ['performance', 'web-vitals', 'lcp', 'cls', 'inp', 'bundle-size', 'budget'] },
  { dir: 'apicontractcheck', name: 'apicontractcheck', global: 'APIContractCheck', desc: 'Check APIs against their OpenAPI contract: validate real responses (live, HAR files or a fetch wrapper) and detect breaking changes between spec versions.', deps: { yaml: '^2.6.0' }, kw: ['openapi', 'swagger', 'contract-testing', 'api', 'breaking-changes', 'har'] },
  { dir: 'licensecheck', name: 'licensecheck', global: 'LicenseCheck', desc: 'Dependency license inventory and policy checks with SPDX expressions: deny/allow lists, copyleft and unknown licenses, and third-party attribution files.', kw: ['license', 'spdx', 'compliance', 'oss', 'attribution', 'notice'] },
];

for (const p of pkgs) {
  const node = { types: './dist/types/node.d.ts', default: './dist/node.js' };
  const manifest = {
    name: `@devchecks/${p.name}`,
    version: '0.1.0',
    description: p.desc,
    keywords: p.kw,
    type: 'module',
    license: 'MIT',
    repository: { type: 'git', url: 'git+https://github.com/ravikiran476/devchecks.git', directory: `packages/${p.dir}` },
    homepage: `https://github.com/ravikiran476/devchecks/tree/main/packages/${p.dir}#readme`,
    bugs: { url: 'https://github.com/ravikiran476/devchecks/issues' },
    publishConfig: { access: 'public' },
    sideEffects: false,
    main: './dist/index.js',
    module: './dist/index.js',
    types: './dist/types/index.d.ts',
    unpkg: `./dist/${p.cdn ?? p.name}.min.js`,
    jsdelivr: `./dist/${p.cdn ?? p.name}.min.js`,
    exports: {
      '.': { types: './dist/types/index.d.ts', default: './dist/index.js' },
      './node': node,
      './cdn': `./dist/${p.cdn ?? p.name}.min.js`,
      './cdn/esm': `./dist/${p.cdn ?? p.name}.esm.js`,
      ...Object.fromEntries(Object.entries(p.extra ?? {}).map(([k, f]) => [k, { types: `./dist/types/${f}.d.ts`, default: `./dist/${f}.js` }])),
      './package.json': './package.json',
    },
    bin: { [p.name]: 'dist/cli.js' },
    files: ['dist', 'README.md'],
    engines: { node: '>=20' },
    scripts: { build: 'node ../../scripts/build.mjs' },
    devchecks: { global: p.global, cdn: p.cdn ?? p.name, node: ['src/node.ts', 'src/cli.ts', ...Object.values(p.extra ?? {}).map((f) => `src/${f}.ts`)] },
    dependencies: { '@devchecks/core': '^0.1.0', ...(p.deps ?? {}) },
    ...(p.peer ? { peerDependencies: p.peer, peerDependenciesMeta: Object.fromEntries(Object.keys(p.peer).map((k) => [k, { optional: true }])) } : {}),
  };
  writeFileSync(`packages/${p.dir}/package.json`, JSON.stringify(manifest, null, 2) + '\n');
}
