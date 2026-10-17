# @devchecks/apicontractcheck

Keeps an API and its OpenAPI 3.0/3.1 contract in sync.

- **Validate real traffic**: from HAR files (DevTools "Save all as HAR", Playwright `recordHar`), by probing GET endpoints, or live in the browser through a `fetch` wrapper.
- **Breaking-change diff** between two spec versions, for code review or CI.

It has its own dependency-free validator for the OpenAPI schema dialects: 3.0 `nullable` and boolean `exclusiveMinimum`, 3.1 type arrays and `const`, `readOnly`/`writeOnly` by direction, discriminators, `allOf`/`anyOf`/`oneOf`, formats, and local `$ref`s. Errors carry JSON pointers (`/items/0/price must be >= 0`).

## CLI

```bash
npx @devchecks/apicontractcheck validate --spec openapi.yaml --har session.har --requests
npx @devchecks/apicontractcheck probe --spec openapi.yaml --base-url http://localhost:3000 -H "authorization: Bearer $TOKEN"
npx @devchecks/apicontractcheck diff main/openapi.yaml openapi.yaml --fail-on high
```

`probe` only sends **GET** requests, filling path and query parameters from `example`/`default`/`enum` values. It skips operations whose required parameters have no example.

| Finding | Severity |
|---|---|
| `response-schema-violation` | high |
| `undocumented-status` (5xx high), `undocumented-path`, `undocumented-method`, `undocumented-content-type` | medium |
| `request-schema-violation`, `request-parameter-missing`, `request-body-missing` (with `--requests`) | medium |
| `missing-response-header`, `undocumented-response-body` | low |

Diff rules: `endpoint-removed`, `required-parameter-added`, `request-body-required`, `required-property-added`, `property-removed`, `type-changed`, `enum-narrowed` (requests) → high; `enum-widened`, `property-optional`, `response-nullable` (responses), `constraint-tightened`, `response-removed` → medium. Additions are reported as info. Renaming a path parameter is not treated as a breaking change.

## Browser / CDN

```html
<script src="https://cdn.jsdelivr.net/gh/ravikiran476/devchecks@v0.1.0/cdn/apicontractcheck.min.js"></script>
<script>
  fetch('/openapi.json').then((r) => r.json()).then((spec) => {
    window.fetch = APIContractCheck.createValidatingFetch(spec, { onFinding: (f) => console.warn(f.message) });
  });
</script>
```

The wrapper never changes the response your app receives; it only reports. Also: `validateExchange(spec, exchange)`, `fromHar(har)`, `diffSpecs(old, next)`, `validateSchema(schema, value, ctx)`.

Swagger 2.0 must be converted first (e.g. with `swagger2openapi`). External `$ref`s must be bundled into one file (e.g. with `redocly bundle`).
