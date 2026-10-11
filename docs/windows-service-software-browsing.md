# Windows service and software browsing

The original preview browsing path below remains bounded. A separate default-off
[complete caller-visible Win32 service generation](windows-full-services-contract.md)
source slice now adds resumed SCM enumeration, frozen durable chunks and protected
manager-side search/pages after new explicit local consent. It does not widen old
grants or selected-service alarm sources. Drivers and ACL-invisible services remain outside that slice. A separate
[complete machine software registration extension](windows-full-software-contract.md)
now has its own default-off HKLM 32/64 consent, native reader, frozen generation
and protected manager search/pages. Per-user, MSIX/Store and portable discovery
remain excluded. Source tests are not native acceptance.

## Original bounded-preview browsing

Services and Software now have literal, case-insensitive search, ascending and
descending sorting, and 25-row local pages. Services sort by name, numeric PID or
translated status. Software sorts by name, literal version text or publisher;
version order is not update order. Missing source values sort last in either
direction. Equal values use the complete source row and original row ordinal for
stable ordering; equal names and duplicate uninstall registrations are retained.
Search covers the reported fields, including raw and translated service status
and registry view. It does not query a host, join process details or treat labels
as markup, regular expressions, commands or destinations.

Pages cover only the already accepted snapshot, at most 128 rows per section and
potentially fewer under its 48 KiB shared encoding limit. Captured, matching,
visible and observed counts remain distinct. A lower-bound count stays a lower
bound, and truncated, denied, unavailable and healthy-empty sections keep their
original meaning. The original capture/receipt times are never changed by pages,
search or sorting. No UI action collects more rows or authorizes new data.
The separately consented [service-startup source slice](windows-service-startup.md)
adds configured mode to this same table, with exact original-row binding and
independent per-field quality. Existing five-scope grants do not enable it.

Controls remain during a same-generation refresh, but all private rows and
controls are hidden while its request is pending. A changed device, original
capture, generation, tab, session or nonloading absent snapshot clears controls.
Visibility loss, authentication loss, untrusted time and original 24-hour expiry
continue to clear data through the existing protected resource. No new cache,
persistent browser state, request, endpoint, schema, frame or grant is added.

Both languages have native keyboard controls outside the mobile-hidden table
header, bounded live counts, disabled end-page buttons, column sort metadata and
mobile cell labels. Hosted fixtures cover English/German at 1440 and 390 pixels
inside the existing restricted loopback runner. Source/DOM checks do not establish
that a browser or Windows endpoint passed; those results must be reported
separately. No local browser, native collector, service or permission change is
part of that original preview-only UI slice.

## Remaining wider-coverage work

Complete caller-visible services and machine software registrations now have
separate source contracts linked above. Their new local consent, native readers,
exact protected generations, independent durable floors, bounded transport,
manager search/pages and operator UI do not widen the old preview receipts.
Current runtime and native-acceptance limits are documented in those contracts.

Complete process enumeration remains a separate follow-on. Per-user software,
MSIX/Store registrations and portable/unregistered application discovery also
need an explicit source and user-context design. LocalService HKCU is not the
interactive user's registry. Scanning user profiles or arbitrary executable paths
is not authorized by machine-registration consent.

Any future source must preserve scoped complete-versus-unavailable truth,
duplicate and stable source identities, exact retries and original expiry,
consume-once state, current identity/grant authority and bounded complete-generation
search. A successful scoped enumeration is not proof of every program on a host.
Native acceptance, broader local grants and release approval remain separate.
