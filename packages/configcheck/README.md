# @devchecks/configcheck

Catches broken and risky configuration before it ships:

- **syntax errors** in JSON (comments allowed for tsconfig/jsconfig/.eslintrc), YAML (including multi-document Kubernetes manifests) and `.env`, reported with line numbers; duplicate YAML keys too
- **`.env` drift** against `.env.example` / `.env.sample` / `.env.template`: missing, undocumented and duplicate keys
- **typed environment schemas**: required variables, `number`, `integer`, `port`, `boolean`, `url` (optionally https only), `email`, `json`, `duration`, enums and patterns
- **risky settings**: TLS verification disabled, debug mode, CORS `*` (worse with credentials), insecure cookies, default credentials, short signing secrets, plain-HTTP endpoints, privileged containers, verbose production logging

Files whose name contains `prod`/`production`/`live`, or that set `NODE_ENV=production`, get stricter severities. **Values are never printed**, only setting names. Hard-coded secrets are [SecretCheck](../secretcheck)'s job.

## CLI

```bash
npx @devchecks/configcheck                 # every .env*, JSON, YAML, .npmrc under .
npx @devchecks/configcheck env             # validate process.env against the schema (CI, container entrypoint)
```

`configcheck.config.json`:

```json
{
  "env": {
    "required": ["DATABASE_URL", "SESSION_SECRET"],
    "vars": {
      "PORT": { "type": "port" },
      "API_URL": { "type": "url", "https": true },
      "LOG_LEVEL": { "enum": ["debug", "info", "warn", "error"] },
      "SESSION_SECRET": { "minLength": 32 }
    }
  },
  "exclude": ["test/fixtures/**"],
  "disableRules": ["insecure-url"]
}
```

## API

```js
import { assertEnv } from '@devchecks/configcheck';

// Fail fast at startup with a readable list of problems (no values printed).
assertEnv({ required: ['DATABASE_URL'], vars: { PORT: { type: 'port' } } });
```

Also: `checkConfigText(text, file)`, `checkEnvDrift(exampleText, envText)`, `validateEnv(vars, schema)`, and `scanPaths()` from `@devchecks/configcheck/node`. CDN global: `ConfigCheck`.
