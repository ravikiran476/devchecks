# @devchecks/depcheck

Reports known vulnerabilities in your dependencies, with the version that fixes each one. It uses [OSV.dev](https://osv.dev), which aggregates the GitHub Advisory Database, OpenSSF malicious-package reports and other sources, so there is no vulnerability database of its own to go stale.

## CLI

```bash
npx @devchecks/depcheck                      # auto-detects package-lock.json, pnpm-lock.yaml or yarn.lock
npx @devchecks/depcheck --installed          # check what is actually in node_modules
npx @devchecks/depcheck --production --fail-on critical -f sarif -o depcheck.sarif
npx @devchecks/depcheck --npm-audit audit.json   # convert existing `npm audit --json` output instead
```

| Option | |
|---|---|
| `-l, --lockfile <file>` | lockfile to check |
| `--installed` | walk `node_modules` (npm, Yarn classic and pnpm layouts) |
| `--production` | skip packages only reachable through devDependencies |
| `-s, --min-severity <lvl>` | hide findings below this level |
| `--fail-on <lvl>` | exit 1 at or above this level (default `high`) |

Supported inputs: `package-lock.json` / `npm-shrinkwrap.json` (v1–v3), `yarn.lock` (classic and Berry), `pnpm-lock.yaml` (v5, v6, v9), and `npm ls --all --json` output.

Each finding includes the advisory id (GHSA, or MAL for malicious packages), severity (from the advisory, else computed from the CVSS v3 vector), **fixed version**, aliases (CVE ids), and a hint for transitive dependencies (`overrides` / `resolutions`). Malicious packages are always `critical`.

## Configuration: `.depcheckrc.json`

```json
{
  "failOn": "high",
  "production": true,
  "ignore": [
    { "id": "CVE-2024-12345", "package": "some-lib", "reason": "not reachable: server-only code path", "expires": "2026-12-31" }
  ]
}
```

Ignores **expire**, so accepted risk is reviewed again.

## API

```js
import { checkLockfile, parseLockfile, checkDependencies } from '@devchecks/depcheck';
import { checkProject } from '@devchecks/depcheck/node';

const findings = await checkLockfile(lockfileText, { filename: 'package-lock.json', production: true });
```

The OSV API allows CORS, so the CDN build works from a page:

```html
<script src="https://cdn.jsdelivr.net/gh/ravikiran476/devchecks@v0.1.0/cdn/depcheck.min.js"></script>
<script>DepCheck.checkLockfile(text).then(console.table)</script>
```

Package names, versions and nothing else are sent to `api.osv.dev`.
