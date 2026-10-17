# @devchecks/secretcheck

Stops credentials before they are committed. It scans **the content staged in the Git index**, which is exactly what the commit will contain, even if the working tree differs. It also scans files on disk or plain text (including in a browser).

Secrets are **never printed in full**. Output shows at most a 4-character prefix and a fixed-width mask (`ghp_********`), and baseline fingerprints are computed from the redacted line.

## CLI

```bash
npx @devchecks/secretcheck                 # scan staged changes (default command: staged)
npx @devchecks/secretcheck scan src config # scan files or directories on disk
npx @devchecks/secretcheck install-hook    # add a .git/hooks/pre-commit that runs `secretcheck staged`
```

| Option | |
|---|---|
| `--fail-on high\|medium\|low` | lowest **confidence** that fails (default `high`) |
| `--changed-lines` | only report lines added by this commit (handy when adopting in an old repo) |
| `--baseline f` / `--update-baseline` | accept existing findings |
| `-f text\|json\|sarif\|markdown`, `-o file`, `-c file` | shared devchecks options |

Exit code 1 means a blocking secret was found and the commit should stop. With husky or lefthook, run `secretcheck staged` from your pre-commit configuration instead of `install-hook`.

## What it detects

- **High confidence** (blocks by default): private key blocks, AWS access keys, GitHub/GitLab/npm/Slack/Stripe live/SendGrid/Google/Anthropic/OpenAI keys, Slack webhooks, and passwords inside connection strings (`postgres://user:pass@host`).
- **Medium**: JWTs, Twilio keys, and hard-coded values assigned to sensitive names (`password = "..."`, `apiKey: '...'`).
- **Low**: high-entropy quoted strings (Shannon entropy). They are reported but do not block.

Placeholders (`changeme`, `<your-key>`, `${VAR}`, `process.env.X`, AWS `...EXAMPLE` keys) are ignored.

Skipped by default: `node_modules`, `dist`, `build`, `coverage`, `vendor`, `*.min.js`, source maps, snapshots, lockfiles, binary files, and files marked `@generated`.

## Configuration: `.secretcheckrc.json`

```json
{
  "failOn": "high",
  "exclude": ["docs/**"],
  "disableRules": ["jwt"],
  "customRules": [{ "id": "acme-key", "pattern": "(?<secret>acme_live_[a-z0-9]{24})", "confidence": "high" }],
  "entropy": { "minLength": 24 },
  "allowlist": {
    "paths": ["test/fixtures/**"],
    "patterns": ["^pk_test_"],
    "fingerprints": ["9f3c1a2b4d5e6f70"]
  }
}
```

Inline suppression: add `// secretcheck:allow` on the line, or put `// secretcheck:allow-next-line` on the line above.

## API

```js
import { scanText, scanFiles } from '@devchecks/secretcheck';        // browser-safe
import { scanStaged, scanPaths, installHook } from '@devchecks/secretcheck/node';

const result = scanStaged({ changedLinesOnly: true });
if (result.blocking.length) process.exit(1);
```

CDN: `https://cdn.jsdelivr.net/gh/ravikiran476/devchecks@v0.1.0/cdn/secretcheck.min.js` → `SecretCheck.scanText(text, 'file.js')`.

A detected secret must be treated as leaked: **rotate it**. Deleting it from the commit is not enough.
