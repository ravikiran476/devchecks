#!/usr/bin/env node
// Shared build for every package. Run from a package directory (npm run build -w <pkg>).
//
// Each package declares its build in package.json under "devchecks":
//   { "global": "SecretCheck", "cdn": "secretcheck", "node": ["src/node.ts", "src/cli.ts"] }
//
// Outputs:
//   dist/index.js              ESM for bundlers / Node (dependencies stay external)
//   dist/<node entries>.js     Node-only APIs and the CLI (dependencies stay external)
//   dist/<cdn>.esm.js          Self-contained browser ESM for <script type="module"> via a CDN
//   dist/<cdn>.min.js          Self-contained IIFE exposing window.<global> via a CDN
//   dist/types/                TypeScript declarations
import { execFileSync } from 'node:child_process';
import { readFileSync, rmSync } from 'node:fs';
import { createRequire } from 'node:module';
import { join } from 'node:path';
import { build } from 'esbuild';

const cwd = process.cwd();
const pkg = JSON.parse(readFileSync(join(cwd, 'package.json'), 'utf8'));
const cfg = pkg.devchecks ?? {};
const external = [
  ...Object.keys(pkg.dependencies ?? {}),
  ...Object.keys(pkg.peerDependencies ?? {}),
];
const banner = `/*! ${pkg.name} v${pkg.version} | ${pkg.license} */`;
const define = { __VERSION__: JSON.stringify(pkg.version) };

rmSync(join(cwd, 'dist'), { recursive: true, force: true });

await build({
  entryPoints: ['src/index.ts'],
  outfile: 'dist/index.js',
  bundle: true,
  format: 'esm',
  platform: 'neutral',
  mainFields: ['module', 'main'],
  target: 'es2020',
  external,
  define,
  sourcemap: true,
  banner: { js: banner },
});

if (cfg.node?.length) {
  await build({
    entryPoints: cfg.node,
    outdir: 'dist',
    bundle: true,
    format: 'esm',
    platform: 'node',
    target: 'node20',
    external,
    define,
    sourcemap: true,
    banner: {
      js: `${banner}\nimport { createRequire as __cr } from 'node:module'; const require = __cr(import.meta.url);`,
    },
  });
}

if (cfg.cdn) {
  const browser = {
    entryPoints: ['src/index.ts'],
    bundle: true,
    platform: 'browser',
    target: 'es2020',
    minify: true,
    define,
    sourcemap: true,
    legalComments: 'eof',
    banner: { js: banner },
  };
  await build({ ...browser, format: 'esm', outfile: `dist/${cfg.cdn}.esm.js` });
  await build({ ...browser, format: 'iife', globalName: cfg.global, outfile: `dist/${cfg.cdn}.min.js` });
}

const require = createRequire(import.meta.url);
const tsc = join(require.resolve('typescript/package.json'), '..', 'bin', 'tsc');
execFileSync(process.execPath, [tsc, '-p', 'tsconfig.build.json'], { stdio: 'inherit', cwd });

console.log(`built ${pkg.name}@${pkg.version}`);
