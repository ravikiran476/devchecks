#!/usr/bin/env node
// Copies each package's browser bundles into cdn/ so they can be served straight from
// GitHub through jsDelivr, without publishing to npm:
//   https://cdn.jsdelivr.net/gh/ravikiran476/devchecks@<tag>/cdn/<tool>.min.js
// It also records a Subresource Integrity hash for every file in cdn/index.json, and writes
// it into each versioned <script> tag in the docs. Run after `npm run build`. CI fails if
// cdn/ or the docs are out of date.
import { createHash } from 'node:crypto';
import { copyFileSync, existsSync, mkdirSync, readdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';

const root = new URL('..', import.meta.url).pathname.replace(/^\/([A-Za-z]:)/, '$1');
const out = join(root, 'cdn');
rmSync(out, { recursive: true, force: true });
mkdirSync(out);

const sri = (text) => `sha384-${createHash('sha384').update(text).digest('base64')}`;
const integrity = new Map();
const index = [];
for (const dir of readdirSync(join(root, 'packages'))) {
  const pkg = JSON.parse(readFileSync(join(root, 'packages', dir, 'package.json'), 'utf8'));
  const cfg = pkg.devchecks;
  if (!cfg?.cdn) continue;
  for (const file of [`${cfg.cdn}.min.js`, `${cfg.cdn}.esm.js`]) {
    const src = join(root, 'packages', dir, 'dist', file);
    if (!existsSync(src)) throw new Error(`${src} is missing; run "npm run build" first`);
    // Source maps stay in the npm package; drop the reference so the CDN copy causes no 404s.
    const text = readFileSync(src, 'utf8').replace(/\n\/\/# sourceMappingURL=\S+\s*$/, '\n');
    writeFileSync(join(out, file), text);
    integrity.set(file, sri(text));
  }
  index.push({
    name: pkg.name,
    version: pkg.version,
    global: cfg.global,
    script: `${cfg.cdn}.min.js`,
    scriptIntegrity: integrity.get(`${cfg.cdn}.min.js`),
    module: `${cfg.cdn}.esm.js`,
    moduleIntegrity: integrity.get(`${cfg.cdn}.esm.js`),
    description: pkg.description,
  });
}
copyFileSync(join(root, 'packages', 'core', 'report.schema.json'), join(out, 'report.schema.json'));
writeFileSync(join(out, 'index.json'), `${JSON.stringify(index, null, 2)}\n`);

// Pin each <script> tag that points at this version's files to the exact bytes being released.
const { version } = JSON.parse(readFileSync(join(root, 'package.json'), 'utf8'));
const docs = ['README.md', ...readdirSync(join(root, 'examples')).map((f) => join('examples', f))];
for (const dir of readdirSync(join(root, 'packages'))) {
  if (existsSync(join(root, 'packages', dir, 'README.md'))) docs.push(join('packages', dir, 'README.md'));
}
const TAG = /<script src="(https:\/\/cdn\.jsdelivr\.net\/gh\/ravikiran476\/devchecks@v([^/"]+)\/cdn\/([\w.-]+))"(?: integrity="[^"]*")?(?: crossorigin="[^"]*")?><\/script>/g;
let pinned = 0;
for (const file of docs) {
  const path = join(root, file);
  const text = readFileSync(path, 'utf8');
  const updated = text.replace(TAG, (tag, url, tagVersion, name) => {
    if (tagVersion !== version || !integrity.has(name)) return tag;
    pinned++;
    return `<script src="${url}" integrity="${integrity.get(name)}" crossorigin="anonymous"></script>`;
  });
  if (updated !== text) writeFileSync(path, updated);
}
console.log(`cdn/: ${index.length} libraries; ${pinned} <script> tag(s) in the docs pinned with integrity hashes`);
