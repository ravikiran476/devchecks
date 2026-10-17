# @devchecks/pci-pagecheck

A readiness aid for payment pages. It:

- **inventories every script** the browser actually runs, including ones injected later by tag managers, with SHA-256 hashes, and compares them with an **approved baseline** that records a business justification for each script
- identifies **third-party scripts**, categorized (payment provider, tag manager, analytics, session replay, advertising...), and flags missing Subresource Integrity
- reviews the **Content-Security-Policy** and security headers: `unsafe-inline`, `unsafe-eval`, wildcards, JSONP-bypassable hosts, `object-src`, `base-uri`, `form-action`, `frame-ancestors`, `connect-src`, reporting, report-only mode, HSTS
- flags **card-data exposure**: card fields in the merchant DOM (instead of a provider iframe), card forms posting over HTTP or to unknown origins, GET forms, and first-party code that logs, stores or sends card data to analytics; also hard-coded card numbers (Luhn-checked, with test cards ignored)
- generates **evidence** mapped to PCI DSS v4.0.1 requirements **6.4.3, 11.6.1, 4.2.1, 3.3.1, 3.5.1 and 6.2.4**, saying what was collected automatically and what still needs manual evidence

> This is a PCI readiness aid, not a PCI DSS assessment or compliance certification. It does not replace a QSA or your acquirer's requirements.

## CLI

```bash
npm i -D @devchecks/pci-pagecheck playwright && npx playwright install chromium

# 1. Record the current scripts as the approved baseline, then add justifications and approvers
npx pci-pagecheck approve https://staging.shop.example/checkout -b pci-scripts.json

# 2. Check (in CI, or on a schedule for 11.6.1 change detection)
npx pci-pagecheck https://staging.shop.example/checkout -b pci-scripts.json \
  --source src/checkout --evidence pci-evidence.md --fail-on high
```

`pci-scripts.json` entry: `{ "id": "https://js.stripe.com/v3/", "hash": "sha256-…", "justification": "Stripe Elements card fields", "approvedBy": "security@", "approvedAt": "2026-10-01" }`. Leave `hash` out for scripts whose content legitimately changes (vendor SDKs), and rely on the vendor's integrity controls for those.

Options: `--first-party <origins>`, `--payment-origin <origins>` (allowed card form targets), `--wait-for <selector>`. A config file (`pci-pagecheck.config.json`) takes the same keys.

A changed hash on an approved script is reported as **critical** (`script-integrity-changed`). Treat it as possible skimming until someone explains it.

## Browser / CDN

Run it on a staging copy of the page:

```html
<script src="https://cdn.jsdelivr.net/gh/ravikiran476/devchecks@v0.1.0/cdn/pci-pagecheck.min.js"></script>
<script>
  PCIPageCheck.check({ baseline }).then((r) => {
    console.table(r.inventory);
    console.log(PCIPageCheck.evidenceToMarkdown(PCIPageCheck.buildEvidence(r)));
  });
</script>
```

In the browser, cross-origin scripts can only be hashed when they are served with CORS. The Node/Playwright scanner captures every script body from the network.
