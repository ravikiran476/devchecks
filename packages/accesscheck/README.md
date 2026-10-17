# @devchecks/accesscheck

Automated accessibility checks powered by [axe-core](https://github.com/dequelabs/axe-core). Every finding includes the **selector** of the failing element, a **severity**, the WCAG success criteria it maps to, and a **concrete fix**. Baselines let a team fail only on newly introduced issues.

## CLI: local development pages via Playwright

```bash
npm i -D @devchecks/accesscheck playwright && npx playwright install chromium
npx accesscheck http://localhost:3000 /checkout /account --fail-on high
npx accesscheck --update-baseline --baseline a11y-baseline.json   # accept today's issues
npx accesscheck --baseline a11y-baseline.json                     # fail only on new ones
```

`accesscheck.config.json`:

```json
{
  "baseUrl": "http://localhost:3000",
  "pages": ["/", { "url": "/checkout", "waitFor": "form#payment" }],
  "tags": ["wcag2a", "wcag2aa", "wcag21aa", "wcag22aa"],
  "exclude": ["#third-party-chat"],
  "storageState": "auth.json",
  "failOn": "high"
}
```

Severity follows axe impact: critical → `critical`, serious → `high`, moderate → `medium`, minor → `low`. `--include-incomplete` adds checks that axe could not decide, as `info` "needs review" items. Baseline fingerprints use the page path plus the selector, so the same baseline works on localhost and staging.

## Browser / CDN

```html
<script src="https://cdn.jsdelivr.net/gh/ravikiran476/devchecks@v0.1.0/cdn/accesscheck.min.js"></script>
<script>
  AccessCheck.scan(document, { exclude: ['#ads'] }).then(({ findings }) => console.table(findings));
  // or AccessCheck.audit() to print a table
</script>
```

From npm in tests (jsdom, Vitest, Storybook): `import { scan } from '@devchecks/accesscheck'`.

## Limitation

Automated scans cannot verify every WCAG requirement. Keyboard operation, focus order, meaningful text alternatives, and screen-reader announcements still need manual testing with a keyboard and a screen reader (NVDA, VoiceOver).
