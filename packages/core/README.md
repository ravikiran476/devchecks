# @devchecks/core

The shared contract of the devchecks tools: the finding and report format, severities, baselines, glob matching and reporters. The tools depend on this package and never on each other. Their CDN bundles include it, so it is never loaded separately in the browser.

## Report format (v1)

Every tool's `--format json` output follows [`report.schema.json`](report.schema.json) (`https://cdn.jsdelivr.net/gh/ravikiran476/devchecks@main/cdn/report.schema.json`):

```json
{
  "schemaVersion": 1,
  "tool": "depcheck",
  "version": "0.1.0",
  "generatedAt": "2026-10-17T12:00:00.000Z",
  "summary": { "total": 1, "bySeverity": { "critical": 0, "high": 1, "medium": 0, "low": 0, "info": 0 } },
  "findings": [
    {
      "tool": "depcheck",
      "fingerprint": "5c1e0f6e2a9b7d34",
      "ruleId": "GHSA-35jh-r3h4-6jhm",
      "severity": "high",
      "message": "lodash@4.17.20: Command Injection in lodash",
      "location": { "file": "package-lock.json" },
      "remediation": "Upgrade lodash to 4.17.21 or later.",
      "helpUrl": "https://osv.dev/vulnerability/GHSA-35jh-r3h4-6jhm",
      "meta": { "package": "lodash", "version": "4.17.20", "fixedIn": "4.17.21" }
    }
  ],
  "notes": ["..."],
  "baseline": { "new": 1, "existing": 4, "fixed": 0 }
}
```

- `severity` is always one of `critical | high | medium | low | info`.
- `fingerprint` is stable across runs and, where possible, independent of line numbers. Baselines store only fingerprints.
- `location` has `file`/`line`/`column` for static tools, and `url`/`selector` for browser tools.
- `meta` holds tool-specific data and is documented in each tool's README.

## Merging reports

```bash
npx @devchecks/core merge reports/*.json -f markdown -o report.md --fail-on high
```

Text, Markdown and SARIF output label each merged finding as `tool/ruleId`.

## API

```js
import { createReport, formatReport, mergeReports, parseReport, createBaseline, diffBaseline, matchGlob, meetsThreshold } from '@devchecks/core';
```

To build another compatible tool, produce findings in this shape and call `createReport(tool, version, findings)`.
