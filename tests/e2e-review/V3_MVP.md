# Focused managed-v3 MVP browser acceptance

This additive target checks the usable dashboard path for complete supported dpkg
package generations, system-service sections and local socket/connection sections.
It uses built React and the real authenticated operator handler on **loopback
HTTP-test**, with a new temporary store and wholly invented observations. It does
not run an installer, collector, sender, package command, VM, service or real-host
inventory. The rendered public installation command is checked and never executed.

## Run

Build `web/dist`, put Go on `PATH` (or set `GO_BIN`), and install the repository's
pinned Playwright Chromium. From the repository root:

```sh
TRACEBOLT_SOURCE_SHA=<exact-commit> node tests/e2e-review/v3-mvp-browser.mjs
```

The default fixture address is `127.0.0.1:19894`; `V3_REVIEW_PORT` can choose another
loopback port. `CHROMIUM_PATH` is optional; otherwise Playwright uses its installed
pinned browser. No certificate-warning bypass, insecure-browser flag, tunnel or
public listener is used. Each of the eight cases gets a new disposable fixture.
The browser and fixture start together from this one process tree.

A separate API/store smoke can run without a browser:

```sh
node tests/e2e-review/v3-mvp-browser.mjs --api-smoke
```

That smoke checks actual package/system status and query handlers, sparse-search
continuation, filters, retained pending/failed state, and the exact public bootstrap
checksum. Its report explicitly states that no browser ran.

## Eight required cases

1. Fresh v3 metadata consent gates invitation creation. The public dashboard
   command contains `--pending-service`, the real manager origin and exact public
   bootstrap checksum, while the invitation stays in its masked input. Dismissal
   clears the input; no invitation value is captured or exported.
2. Only the selected inventory source mounts and requests data. Real package rows
   preserve distinct binary/source versions and installed/incomplete states;
   package/service/socket views are separate from the older bounded preview.
3. Package pagination advances beyond the first 100 rows. A target after row 2,048
   first yields an empty nonexhausted scan window, then a match after explicit
   continuation. Search remains in a CSRF-protected POST body, never in the URL.
4. Service views distinguish runtime state from enablement and uncollected MainPID.
   Real server filters and sparse-search continuation preserve the whole-section
   count without claiming filtered totals or healthy-device status.
5. Socket pages preserve TCP listener/connection versus UDP bound semantics and
   explicit unknown ownership. Local observations do not imply reachability.
6. A failed system attempt retains the prior complete section's original generation
   and age. Successful zero rows and an activated but unsampled device are distinct.
7. Pending and failed package transfers preserve the prior completed generation.
   The fixture explicitly aborts an unfinished transfer before submitting the next
   failed attempt, as required by the actual store protocol. Zero is a separate
   completed observation, not a substitute for unavailable data.
8. Mobile source tabs and wide tables remain keyboard-scrollable within the
   viewport. German navigation stays usable and switching sources clears the old
   source panel.

All eight names must be unique and PASS, with zero setup/runtime failures, before
claiming this target passed. The exact tested commit comes from
`TRACEBOLT_SOURCE_SHA`, supplied by the hosted workflow's `github.sha`. A local
API smoke or component build is not hosted browser or pixel acceptance.

## Fixture boundary

`v3fixture` reuses the ordinary generated claim/approval/issuance/activation proof
sequence with fresh Ed25519 material and a dedicated temporary authority. It binds
`managed-operations-v3` and the explicit complete-system privacy declaration.
`fullinventory.Build` creates 2,052 invented package rows, committed through real
`InventoryBegin`, `InventoryAppend` and `InventoryFinalize`. Real systemwire frames
admit 2,052 invented services and 30 invented sockets through
`SaveSystemObservation`. This direct store integration is not telemetry-transport
or native-collection acceptance. Smaller empty and awaiting fixtures establish
honest zero/unknown presentation; no host data is read.

Mutations of invented source state use a private stdin control pipe, never an HTTP
test backdoor. The fixture's service clock is injected for deterministic newer
attempts; the operator session clock stays real. The fixture display names make
its invented nature explicit while exercising the real nonsynthetic LAN DTO shape.
The root key is ephemeral, identities and databases are disposable, and the known
fixture password is not a real user credential.

The public command is only for independently prepared local binaries/source and
uses the native client's hidden invitation prompt. This browser target does not
establish binary provenance, installation, approval by a real operator, persistent
service behavior, restart or reboot acceptance. The API smoke checks public
bootstrap bytes without publishing its invitation or credential state.

## Evidence allowlist

Only these new paths may be uploaded from the hosted target:

- `artifacts/review/v3-mvp-browser-results.json`
- `artifacts/review/v3-mvp-browser-manifest.json`
- `artifacts/review/synthetic-v3-services-desktop-en.png`
- `artifacts/review/synthetic-v3-sockets-mobile-en.png`

The two PNGs are original inventory-only viewport captures (1440×1000 and390×844),
not an automatic gallery addition. Actual pixels require independent inspection.
No command/invitation dialog is captured. Reports contain fixed stage labels and
pass/fail metadata only, with no raw exception text, request bodies, command text,
invitation, key, cookie, database, logs or real telemetry. Do not upload the local
API-smoke report, native fixture state, HTML, videos or browser traces.

The inherited 84 required cases, three explicit enrollment quarantines and five
review-recovery cycles remain byte-for-byte unchanged. The existing coverage429
manual-refresh gap remains backlog; this target does not expand that repair.
