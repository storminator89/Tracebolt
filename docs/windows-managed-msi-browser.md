# Central MSI browser supplement (source fixture only)

The additive `tests/e2e-review/windows-managed-msi-runner.mjs` uses the compiled
`web/dist` and the existing hosted Playwright Chromium installation. It leaves
the existing 40 Windows action/prepared-MSI captures and their 120-second budget
unchanged. This separate runner has its own 120-second bound.

The four required stages are **uploaded, delivery not approved**, **protected
import, review not approved**, **fresh readiness, installation unchecked**, and
**saved 3010 outcome, independent registration unknown**. Each is captured in
English and German at desktop (1440×1000) and mobile (390×844), for 16 images.
The flow also checks the initial upload inputs, three raw chunks of at most
32 KiB, explicit upload completion, distinct delivery and review acknowledgements,
exact package/native-evidence readback, duplicate-click fencing and saved outcome
after reload. Package evidence waits for deterministic selected-data readiness
and opens only its semantic disclosure, never the separate setup/limits details.

Every document, asset and API request is fulfilled or rejected by the fixture.
The invented HTTPS origin has no network fallback. The source fixture uses
inert compound-header bytes, not a valid or selected MSI. All receipts, grants,
TLS/session and native outcomes are simulated in memory. No real upload,
installation, agreement acceptance, host action or credential setup occurs.

Inert source validation (does not launch a browser):

```sh
node --check tests/e2e-review/windows-managed-msi-browser.mjs
node --check tests/e2e-review/windows-managed-msi-runner.mjs
node --test tests/e2e-review/windows-managed-msi-fixtures.test.mjs
```

On the separately authorized hosted runner, after the ordinary locked UI build
and existing browser setup:

```sh
TRACEBOLT_SOURCE_SHA=<exact-40-character-source-sha> node tests/e2e-review/windows-managed-msi-runner.mjs
```

Outputs are `artifacts/review/windows-managed-msi-results.json`,
`windows-managed-msi-manifest.json`, and `synthetic-windows-managed-msi-*.png`.
The completion gate requires all exact screenshot/source/language/viewport
records, every behavioral fact, zero unexpected/second-target writes, no secret
or package evidence in browser storage, and no runtime errors. Diagnostics retain
only bounded phase/failure information, not raw browser state.

Only source syntax and inert fixture checks have been run for this supplement.
No local browser was launched. Hosted screenshots, visual acceptance and the
separate real Windows/package acceptance gate remain pending.
