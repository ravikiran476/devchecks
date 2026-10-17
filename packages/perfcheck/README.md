# @devchecks/perfcheck

Performance budgets for pages and bundles.

- **In the browser** (CDN): Core Web Vitals (LCP and its element, CLS with session windows, INP, FCP, TTFB, TBT) and resource weight by type, including third-party bytes. Use it in development, or for real-user monitoring with `onPageHidden`.
- **Bundles**: raw, gzip and brotli sizes of build output, checked against per-file or total budgets.
- **Lab runs**: Playwright/Chromium runs with optional CPU and network throttling. Each run starts with a cold cache, and the median of several runs is used.

Without explicit budgets, metrics are checked against Google's Core Web Vitals thresholds: "needs improvement" → `medium`, "poor" → `high`.

## CLI

```bash
npx @devchecks/perfcheck bundles dist
npm i -D @devchecks/perfcheck playwright && npx playwright install chromium
npx perfcheck http://localhost:4173/ /products --runs 5 --cpu 4 --network slow-4g
```

`perfcheck.config.json`:

```json
{
  "bundles": {
    "dir": "dist",
    "budgets": [
      { "path": "assets/index-*.js", "maxGzip": "170kB" },
      { "path": "total:js", "maxBrotli": "350kB" },
      { "path": "total:css", "maxGzip": "50kB" }
    ]
  },
  "baseUrl": "http://localhost:4173",
  "pages": ["/", "/products"],
  "budgets": { "lcp": 2500, "cls": 0.1, "tbt": 200, "scriptBytes": "400kB", "thirdPartyBytes": "150kB", "requests": 60 }
}
```

Sizes accept `B`, `kB`/`MB` (1000) and `KiB`/`MiB` (1024). Hashes in file names are ignored in fingerprints, so baselines survive rebuilds.

## Browser / CDN

Load it early in `<head>` so it sees every layout shift and interaction:

```html
<script src="https://cdn.jsdelivr.net/gh/ravikiran476/devchecks@v0.1.0/cdn/perfcheck.min.js"></script>
<script>
  PerfCheck.measure({ budgets: { lcp: 2500 } }).then((r) => console.table(r.vitals));
  PerfCheck.onPageHidden((vitals) => navigator.sendBeacon('/rum', JSON.stringify(vitals)));
</script>
```

INP needs real interactions, so lab runs report TBT as the responsiveness proxy. Lab numbers vary between machines; use several runs and field data for decisions.
