#!/usr/bin/env node
// Publishes every package to npm: core first, then the tools. Versions already on npm are
// skipped, so it is safe to re-run after a failure. Run it in your own terminal so npm can
// ask for two-factor authentication (choose "don't ask again for 5 minutes" in the browser).
//
//   npm run release            # or: npm run release -- --otp=123456
import { execFileSync, spawnSync } from 'node:child_process';
import { readFileSync } from 'node:fs';

const order = ['core', 'accesscheck', 'secretcheck', 'depcheck', 'pci-pagecheck', 'archcheck', 'safecodecheck', 'configcheck', 'perfcheck', 'apicontractcheck', 'licensecheck'];
const extra = process.argv.slice(2);
const npm = process.platform === 'win32' ? 'npm.cmd' : 'npm';

for (const dir of order) {
  const { name, version } = JSON.parse(readFileSync(`packages/${dir}/package.json`, 'utf8'));
  let published = false;
  try {
    published = execFileSync(npm, ['view', `${name}@${version}`, 'version'], { encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'], shell: process.platform === 'win32' }).trim() === version;
  } catch {
    // not published yet
  }
  if (published) {
    console.log(`skip     ${name}@${version} (already on npm)`);
    continue;
  }
  console.log(`publish  ${name}@${version}`);
  const r = spawnSync(npm, ['publish', '-w', name, '--access', 'public', ...extra], { stdio: 'inherit', shell: process.platform === 'win32' });
  if (r.status !== 0) {
    console.error(`\nStopped at ${name}. Fix the error above and run "npm run release" again; finished packages are skipped.`);
    process.exit(r.status ?? 1);
  }
}
console.log('\nAll packages are on npm. jsDelivr search picks them up within a few hours.');
