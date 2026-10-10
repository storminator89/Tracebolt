# Selected Windows event messages in Logs

Source candidate only. The published preview and existing five-scope Setup are
unchanged. This interface requires the separately activated local event-content
grant and a compatible endpoint/manager. It cannot create or enable a grant and
does not establish native Windows acceptance.

## Operator flow

The production Device → Logs panel keeps the existing bounded header sample,
local filters and pagination. An administrator can select 1–16 displayed
Application/System rows across those pages. Named read users cannot enqueue
content. An inline review shows all six original fields, including full decimal
record IDs and original UTC timestamps at 100 ns precision. Changing the exact
selection invalidates the acknowledgement.

The operator separately acknowledges sensitive message content and, in HTTP-test,
plaintext transmission. Only the explicit “Request messages once” control creates
a request. Header filters, sample refreshes, content status checks and opening the
review never create one. Header/five-scope consent never substitutes for content
consent. HTTP warnings explain that signatures provide no encryption or manager
response authentication.

A pending request is polled with GET. Once its exact receipt becomes available,
the real production hook reads the bounded result with a CSRF-protected POST.
An ambiguous create is reconciled through GET and is never resubmitted. Cancel
remains available while create/result/status work is in flight. If a create has
committed but its identity was lost, cancellation first reconciles the exact
selection. If that identity cannot yet be established, the UI says cancellation
is unverified; it never claims that clearing the browser canceled the endpoint.

## Privacy and lifetime

- Message content and searches remain in process memory. No URL parameters,
  browser storage, export, AI calls or automatic links contain them.
- React renders message text literally, with whitespace preserved and long lines
  wrapped. Markup and URLs are inert text. Successfully empty messages, missing
  records, identity mismatch, publisher unavailable/denied, partial, unavailable,
  truncated and lost results are distinct.
- Strict DTO validation preserves uint64 record IDs as strings. It checks exact
  ordered six-field identities, fixed budgets/source/warning, per-row and aggregate
  outcome consistency, request state/receipt and immutable expiry.
- The result response is independently capped at 512 KiB encoded, 16 rows,
  16 KiB UTF-8 per message and 64 KiB aggregate text. This accommodates worst-case
  JSON escaping without relaxing other API response bounds.
- The original 15-minute request, 24-hour header capture and session deadlines are
  never renewed by status refresh. A returned result may have a strictly earlier
  certificate/session/header cutoff; the browser validates and clamps to that
  cutoff without changing the original request/receipt expiry. A separately refreshed, matching capability
  report can extend only its five-minute freshness lease. Disabled/replaced grants,
  expired leases, clock changes or identity conflicts discard content.
- Device/session/navigation/visibility/page-loss/unmount/expiry clears content,
  review, selection and search and aborts in-flight reads. Operation epochs reject
  late creates/results. Best-effort server cancellation uses existing session,
  origin and CSRF controls; local disclosure ends regardless of its outcome.
- Identical background header/status refreshes preserve filters, pages, focused
  controls and an unmodified review. A new header generation invalidates only an
  unsubmitted selection/review. Once created, the immutable original selection,
  result and search survive newer ordinary header telemetry. A replaced grant
  still clears them.
  Terminal header loss hides private results in the same render as the loss.

## API contract

All paths are under `/api/devices/{deviceId}/windows-event-content`:

- GET: versioned status, server time, opaque session binding, session expiry,
  configured/local/content status, optional endpoint status, capability and eligible
  header binding, plus a nullable browser-safe request record.
- POST `/create`: expected sequence floor, displayed header generation/digest,
  selected `{channel, recordId}` pairs and content/plaintext acknowledgements.
- POST `/query` and `/cancel`: exact `{identity:{id,sequence,queryDigest}}`.
- Query result: `{identity,receipt,report,expiresAt}` with browser-safe event DTOs.

Every operation rechecks the authenticated administrative session. Query/cancel/
create retain existing CSRF and same-origin protections. Only the query route
receives the larger bounded JSON response allowance.

## Verification and remaining gates

Portable frontend tests use the real hook, session checks, CSRF preflight and fetch
adapter. They exercise explicit consent, cross-page selection limits, literal
rendering, captured-only search, escaped byte limits, lost-versus-empty truth,
ambiguous creation, cancellation during reads/creation, late-response isolation,
clock/header/grant/session/request expiry and same-sample interaction preservation.
A fixture generated through Go New → Claim → Accept and browser DTO conversion
checks interoperable >2^53 IDs and 100 ns timestamps.

`tests/e2e-review/windows-event-content-browser.mjs` is invoked inside the existing
Windows browser case for English/German and 1440/390 px layouts. It uses invented
responses for only the exact content routes while preserving real loopback login,
session and CSRF reads. It covers deliberate HTTP acknowledgement, keyboard
creation, pending polling, partial real-renderer results, literal markup, local
search, wrapping and cancellation. Its source fixture tests are statically imported
by the existing Windows fixture entry and explicitly classified in the inert suite
manifest; discovery does not authorize test execution.

Source/unit checks and synthetic browser checks do not prove installed LocalService
permissions, publisher resource availability, native cancellation, real event
reads, or native Windows acceptance. Those remain separately authorized exact-
source disposable-host gates. No native source read, grant, permission change,
release, merge or deployment is performed by this UI work.
