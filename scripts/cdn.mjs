#!/usr/bin/env node
// Copies each package's browser bundles into cdn/ so they can be served straight from
// GitHub through jsDelivr, without publishing to npm:
//   https://cdn.jsdelivr.net/gh/ravikiran476/devchecks@<tag>/cdn/<tool>.min.js
// Run after `npm run build`. CI fails if cdn/ is out of date.
import { copyFileSync, existsSync, mkdirSync, readdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';

const root = new URL('..', import.meta.url).pathname.replace(/^\/([A-Za-z]:)/, '$1');
const out = join(root, 'cdn');
rmSync(out, { recursive: true, force: true });
mkdirSync(out);

const index = [];
for (const dir of readdirSync(join(root, 'packages'))) {
  const pkg = JSON.parse(readFileSync(join(root, 'packages', dir, 'package.json'), 'utf8'));
  const cfg = pkg.devchecks;
  if (!cfg?.cdn) continue;
  for (const file of [`${cfg.cdn}.min.js`, `${cfg.cdn}.esm.js`]) {
    const src = join(root, 'packages', dir, 'dist', file);
    if (!existsSync(src)) throw new Error(`${src} is missing; run "npm run build" first`);
    // Source maps stay in the npm package; drop the reference so the CDN copy causes no 404s.
    writeFileSync(join(out, file), readFileSync(src, 'utf8').replace(/\n\/\/# sourceMappingURL=\S+\s*$/, '\n'));
  }
  index.push({ name: pkg.name, version: pkg.version, global: cfg.global, script: `${cfg.cdn}.min.js`, module: `${cfg.cdn}.esm.js`, description: pkg.description });
}
copyFileSync(join(root, 'packages', 'core', 'report.schema.json'), join(out, 'report.schema.json'));
writeFileSync(join(out, 'index.json'), `${JSON.stringify(index, null, 2)}\n`);
console.log(`cdn/: ${index.length} libraries`);
