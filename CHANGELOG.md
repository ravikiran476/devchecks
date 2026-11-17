# Changelog

All packages share one version. Tags (`vX.Y.Z`) are what jsDelivr serves from `cdn/`.

## 0.2.0

### secretcheck

- **Fixed:** `--changed-lines` scanned nothing when Git was configured with `diff.mnemonicPrefix` (the diff paths did not match the staged paths, so every file looked clean). The diff prefixes are now set explicitly, quoted paths are decoded, and a diff that still cannot be matched stops the scan with an error instead of passing it.
- **New rule `config-secret-assignment`:** unquoted secrets in `.env`, YAML, TOML, INI and `.properties` files (`DB_PASSWORD=...`, `password: ...`), which no rule caught before. Medium confidence (`high` severity). References such as `${VAR}`, names, URLs, sizes and durations are ignored.
- **Changed (stricter):** `--fail-on` and the `failOn` config key now take a **severity**, like every other devchecks tool, instead of a confidence level. The default, `critical`, blocks the same findings as before (high-confidence matches). An existing `"failOn": "high"` now also blocks medium-confidence findings such as hard-coded passwords; use `"critical"` to keep the old behaviour. `isBlocking(finding, failOn)` changed the same way.
- The CLI now says how many findings were below the threshold instead of exiting silently.
- Custom rules accept `files` (globs) to limit where they apply.

### pci-pagecheck

- **Fixed:** when a line held several card numbers, each `pan-literal` finding masked only its own number and printed the others in full. Every Luhn-valid number in a snippet is now masked, in every rule. `maskPans()` is exported.

### accesscheck

- **Fixed:** the CLI exited 0 when some (but not all) pages failed to load. Any unscanned page now exits 2 and is listed in the report notes.
- **Fixed:** pages with a Content-Security-Policy that blocks inline scripts could not be scanned, because axe-core was injected as a `<script>` tag. It is now evaluated through the browser's DevTools protocol, which CSP does not apply to.

### apicontractcheck

- **Fixed:** `createValidatingFetch` waited for the whole response body before returning, which stalled streaming responses and delayed every call. The response is returned as soon as its headers arrive, and validation runs on a copy in the background. Event streams, NDJSON and bodies over 5 MB are not buffered. The wrapper has a `flush()` method that waits for pending validations.

### depcheck

- **Fixed:** `--production` silently checked every package when the lockfile does not record development dependencies (`yarn.lock`, `pnpm-lock.yaml` v9, `--installed`). It still checks everything (the safe choice) but now says so on stderr and in the report notes.
- **Fixed:** Yarn aliases (`my-lodash@npm:lodash@4.17.20`) were looked up under the alias name, so their advisories were missed.
- OSV requests time out after 30 s and are retried twice on network errors, 429 and 5xx responses (`timeoutMs`, `retries`, `retryDelayMs`).

### Docs and release

- Every `<script>` example now carries a Subresource Integrity hash, and `cdn/index.json` lists `scriptIntegrity` and `moduleIntegrity` for each library. `npm run cdn` keeps them in sync.
- Examples and CLI help use the scoped package names (`npx @devchecks/accesscheck`). Several unscoped names belong to unrelated npm packages.
- `npm run bump -- <version>` sets one version everywhere; regenerating the manifests no longer resets them to 0.1.0.

## 0.1.0

First release: ten checkers, a shared report format, CLIs and CDN builds.
