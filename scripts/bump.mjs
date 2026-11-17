#!/usr/bin/env node
// Sets one version on the root, every package and the CDN links in the docs:
//
//   npm run bump -- 0.2.0
//
// Then run `npm run cdn`, commit, and tag (see "Publishing" in the README).
import { execFileSync } from 'node:child_process';
import { existsSync, readdirSync, readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';

const next = process.argv[2];
if (!/^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?$/.test(next ?? '')) {
  console.error('Usage: npm run bump -- <version>   (e.g. 0.2.0)');
  process.exit(2);
}

const readJson = (file) => JSON.parse(readFileSync(file, 'utf8'));
const writeJson = (file, data) => writeFileSync(file, `${JSON.stringify(data, null, 2)}\n`);

const root = readJson('package.json');
const prev = root.version;
root.version = next;
writeJson('package.json', root);

const core = readJson('packages/core/package.json');
core.version = next;
writeJson('packages/core/package.json', core);

// The tool manifests take their version (and their @devchecks/core range) from the root.
execFileSync(process.execPath, ['scripts/manifests.mjs'], { stdio: 'inherit' });

// Versioned CDN links in the docs and source comments.
const docs = ['README.md', ...readdirSync('examples').map((f) => join('examples', f))];
for (const dir of readdirSync('packages')) {
  for (const file of ['README.md', 'src/index.ts']) {
    const path = join('packages', dir, file);
    if (existsSync(path)) docs.push(path);
  }
}
let changed = 0;
for (const file of docs) {
  const text = readFileSync(file, 'utf8');
  const updated = text.replaceAll(`devchecks@v${prev}`, `devchecks@v${next}`).replaceAll(`(\`@v${prev}\`)`, `(\`@v${next}\`)`);
  if (updated !== text) {
    writeFileSync(file, updated);
    changed++;
  }
}

// Workspace versions are recorded in the lockfile, and `npm ci` refuses a stale one.
const npm = process.platform === 'win32' ? 'npm.cmd' : 'npm';
execFileSync(npm, ['install', '--package-lock-only', '--ignore-scripts', '--no-audit', '--no-fund'], { stdio: 'inherit', shell: process.platform === 'win32' });

console.log(`\n${prev} -> ${next}: package manifests, lockfile and ${changed} doc file(s) updated.`);
console.log(`Next: npm run check && npm run cdn, commit, then: git tag v${next} && git push origin main v${next}`);
