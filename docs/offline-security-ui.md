# Offline security UI slice

This slice is limited to `web/src/security-coverage.tsx`, its local CSS, its strict
DTO module and synthetic component tests. It does not contact advisory providers,
run package matching, launch commands, export to models, install software or
provide update/remediation actions.

## Public component seams

- `SecurityCoveragePanel({ deviceId, sessionKey? })` lazily reads
  `/api/devices/{id}/security` when mounted.
- `OfflineCatalogPanel({ sessionKey? })` reads `/api/security/catalog` when mounted.

Both require the existing operator context to confirm authenticated LAN access.
The catalog view must additionally pass strict validation and explicitly enable
imports. No operator context, development mode, a disabled profile, invalid data,
an access error or an expired configuration lease authorizes a mutation.
The integrating drawer must mount security coverage only in its selected Security
view for LAN Linux/unknown devices; settings may mount the catalog card. Do not
preload device evidence on other tabs. A changed device or `sessionKey` remounts
the isolated component and discards its previous state. Main UI integration is a
separate owner; these files do not modify the drawer, settings, enrollment or
shared translations.

English is the default inherited locale; German is supplied through the existing
`useLocale` context with a component-local dictionary. Locally served icons and
existing theme variables are used. Native disclosure controls expose format
metadata and inventory provenance without conflating the three coverage areas.

## Security meanings

The three cards keep client-reported binary inventory, offered updates and CVE
coverage separate. Only exact complete enumeration can display a full installed
count. Partial and stale are independent labels and can appear together.
Update offers, affected CVEs and review candidates remain explicitly unknown;
zero file rules or zero inventory records never imply zero CVEs. Source-package
mapping, exact release and installed-origin gaps remain visible even with a
catalog loaded. Retained observations keep their original time and generation.

A supplied catalog's rule/source/byte counts are format facts. Its declared
provider/release, hash and import time do not establish authenticated vendor
origin or publication freshness. There is no green security/verification badge.
The card explicitly states memory-only storage and reset on manager restart.

## Request and lifecycle boundaries

Responses are read through the approved `request`/`mutateRaw` helpers with a
32 KiB response bound. DTO validators require all exact keys, fixed discriminants,
finite bounded counts, UTC timestamps, opaque ID/digest formats and conservative
cross-field relationships. Expanded or internally inconsistent data is discarded.

A single controller is current per panel. Refresh first invalidates the existing
view and synchronously aborts any mutation, clears file state and revokes the
old form's authority. A late response cannot reinstall it. This applies before
both successful and failed/invalid configuration reads, avoiding the historical
stale-form failure mode reviewed in enrollment.

Reads time out after 10 seconds; mutations after 15 seconds. Configurations have
a conservative 60-second monotonic lease, after which manual refresh is required.
Coverage freshness is independently derived from the server UTC anchor plus
monotonic elapsed time, the collection/receipt timestamps and the server's fixed
120-second maximum age. Overall collection freshness ages independently of a
retained or unknown software section. Retained or explicitly stale data never
becomes fresh. A wall/monotonic discontinuity of either sign above 1.5 seconds
revokes the view/request, including sleep on platforms with a paused monotonic
clock. This wall-clock check can only revoke authority, never establish or extend
it. It is checked on async completion, before mutation and once a second while
a view is displayed.

Authentication loss, unmount/device/session changes, pagehide, hidden documents
and BFCache restoration discard authority and selected file state. Coverage also
rechecks on window blur/focus. The catalog deliberately ignores window-only picker
blur/focus: native dialog focus changes neither refresh nor extend the lease.
Actual lifecycle suspension still clears it; focus then resumes a fresh read.
Hash navigation clears state without stranding a still-mounted card's Refresh
action. No interrupted
write is automatically replayed. Canceled, transport-failed, timed-out or invalid
mutation results remain explicitly uncertain until the operator reads current
state. CAS conflict, busy, too-large, unavailable and normalized-format rejection
use fixed local messages, never server-supplied/raw file errors.

## Files and writes

The native picker accepts a local JSON file. Size is checked before reading (at
most 2 MiB), then `FileReader.readAsArrayBuffer` and fatal UTF-8 decoding reject
invalid bytes. `ignoreBOM: true` deliberately preserves a BOM for the server's
parser, as are whitespace and duplicate JSON keys. No browser
`JSON.parse`/`JSON.stringify` canonicalization masks duplicate-key rejection.

The input value is immediately cleared and the filename is neither retained in
React state nor rendered/sent. Content stays only in transient memory. No
filename/content appears in URLs, browser storage, logs, downloads, clipboard or
external links. Cancel, refresh, suspension, lease expiry, authentication loss
and every submitted mutation clear selection. This is reference/state cleanup,
not a secure-memory zeroization guarantee for browser-managed buffers.

Import sends the original decoded JSON body through `mutateRaw`, including exactly
`X-Tracebolt-Catalog-Revision` with the current validated revision. The helper owns
same-origin credentials and CSRF; the UI does not create another credential path.
Clear requires a deliberate confirmation and sends exactly the JSON
`expectedRevision` field without a catalog revision header. Both successful write
responses must contain a new revision and the expected loaded/empty state.

## Verification scope

Tests use only synthetic mocked API responses and local synthetic File objects.
They cover strict DTO failures; partial/stale/unknown distinctions; auth/profile
gates; English/German; raw JSON/BOM preservation; file size and UTF-8 rejection;
CAS/busy/format errors; explicit clear; old-device/session/read/write races;
invalid refresh; cancellation; logout/401; BFCache; monotonic lease and timeouts;
both native-picker focus event orders; genuinely deferred FileReader callbacks;
selected-file expiry; route recovery; and paused-clock sleep.
No actual feed, provider, model or browser request is part of these checks.

Run from `web/`:

```
npm test -- --run src/security-coverage.test.tsx
npm run typecheck
npm test
```

Main UI/browser acceptance and end-to-end real-handler validation remain separate
gates. A passing mocked component suite is not evidence of vendor trust, real
CVE matching, native update support or deployed behavior.
