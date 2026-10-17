# @devchecks/licensecheck

Dependency license inventory and policy checks, built on SPDX expressions.

- reads licenses from `node_modules` (npm, Yarn classic and pnpm layouts, including license texts) or straight from `package-lock.json` v2/v3, which records each package's license; missing ones are looked up in the npm registry
- normalizes messy values (`"Apache 2.0"`, `{ "type": "MIT" }`, legacy `licenses` arrays, deprecated `GPL-2.0+`, `UNLICENSED`, `SEE LICENSE IN …`)
- evaluates full expressions: `OR` picks the most acceptable option, `AND` requires every part, and `WITH` linking exceptions (e.g. `GPL-2.0-only WITH Classpath-exception-2.0`) count as weak copyleft
- classifies licenses as permissive, weak copyleft, strong copyleft, network copyleft (AGPL, SSPL), source-available (BUSL, Elastic), non-commercial, proprietary or unknown
- writes a **third-party notices** file grouped by license, with license texts

## CLI

```bash
npx @devchecks/licensecheck --production             # policy check (default policy: permissive)
npx @devchecks/licensecheck --policy strict
npx @devchecks/licensecheck inventory -f csv -o licenses.csv
npx @devchecks/licensecheck attribution -o THIRD-PARTY-NOTICES.md --production
```

Built-in policies:

| Policy | Denied | Needs review |
|---|---|---|
| `permissive` (default) | strong and network copyleft, non-commercial, proprietary | weak copyleft, source-available, unknown |
| `strict` | as above, plus source-available and unknown | weak copyleft |
| `copyleft-ok` | non-commercial, proprietary | network copyleft, source-available, unknown |

A denied license is `high` (`medium` for dev-only packages, which are usually not distributed). Review items are `medium`, and a missing license is `medium`.

`.licensecheckrc.json`:

```json
{
  "policy": {
    "denyCategories": ["strong-copyleft", "network-copyleft", "non-commercial", "proprietary"],
    "reviewCategories": ["weak-copyleft", "unknown"],
    "allow": ["MPL-2.0"],
    "deny": ["WTFPL"],
    "exceptions": [{ "package": "some-gpl-cli", "reason": "build tool, never distributed" }]
  },
  "production": true
}
```

## API / CDN

```js
import { checkPackageLock, evaluate, normalizeLicense } from '@devchecks/licensecheck';
evaluate('GPL-3.0-only OR MIT');   // { verdict: 'allowed', license: 'MIT', category: 'permissive' }
```

The npm registry allows CORS, so `LicenseCheck.checkPackageLock(lockfileText)` works from the CDN build.

License classification is engineering guidance, not legal advice.
