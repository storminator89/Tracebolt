# Fleet machine-software lookup

The fleet's **Find machine software** panel searches already accepted complete
[HKLM 32/64 machine registration generations](windows-full-software-contract.md).
Enter an application-name fragment and, optionally, a reported-version fragment.
Both filters are literal Unicode case-insensitive substrings and combine with
AND. A version-only query is also supported. Versions are text, not upgrade order.
This manager/UI source feature adds no collection, consent or endpoint change.

## Reading results

Each page shows up to five currently authorized Windows devices, including devices
with unavailable, disabled or unconfigured software data. Up to three matching
registrations are shown per device. Counts apply to each device's complete retained
generation; the page position shows which devices remain to be searched.
**View all matching registrations** opens a read-only, exact-device view with up to twenty matching
registrations per page. Duplicate names stay separate registration IDs.

The original capture time, complete caller-visible enumeration, HKLM registry
view and freshness remain visible. A capture becomes stale after 120 seconds;
the original 24-hour source retention is never renewed by a lookup. A newer failed
or pending attempt is distinct from a retained earlier complete capture.
Unavailable queried fields are counted separately. No reported match is not proof
that an application is absent: selected-user HKCU/MSIX, Store, portable and
unregistered applications are outside this lookup, and optional name/version
fields can be unavailable even in a complete enumeration.

## Private read contract

POST `/api/fleet/windows-software/query` accepts only
`{"name":"Example","version":"1.2","cursor":""}` in its protected JSON body.
At least one filter must be nonempty; each has a 256-byte UTF-8 ceiling.
No private query or cursor is accepted in a URL. Shared operators and named read
accounts use the existing fleet/per-device read visibility, current session,
Origin and CSRF guards. There is no new device visibility or action capability.

The response is `tracebolt.windows-fleet-software-page.v1`, bounded at 256 KiB.
The existing Windows enrollment roster remains capped at 25 records. One
inventory admission and transaction read the original enrollment identities and
software authority metadata; there is no client-side per-device request fanout
or independent ID-only label join. Only the selected page's complete generations
are searched, using existing generation/ordinal indexes and full-generation
integrity checks. Each generation stays capped at 32,768 rows / 8 MiB; the existing
global 200,000-row ceiling also remains unchanged. A request has a ten-second
deadline. No tables or persistent keys are added or initialized by lookup.

Fleet and detail cursors use the existing software key with a separate signature
purpose. They bind the exact filters, mode, position, operator session, original
enrollment binding/invitation/issued certificate, current leaf and authority
deadline, grants, accepted generations and latest-attempt metadata across the
bounded roster. A changed roster, identity, leaf, grant or generation requires a
new search; pages cannot splice replacement devices or captures. Their original
deadline is the earliest of five minutes, session/certificate/source expiry and
pending-attempt transition. An expired source remains unavailable.

Guards resample the trusted clock after transaction admission and before commit,
then recheck current authority after response bytes are prepared. Denial or
uncertainty returns no result rows. Exact detail stays inside the read-only
lookup; it never passes search results to operational approvals or actions.

The browser retains only its current page and bounded navigation cursors in
memory. Close, navigation, blur/hidden state, access/session loss, untrusted clocks
and original expiry clear private results, controls and cursors. A new read is
deliberate; late requests cannot restore cleared data. The lookup has no AI,
notification, CSV/export, software-action or selected-user inventory integration.

## Verification boundary

Focused inert store/API-route and UI tests cover complete and unavailable
coverage, missing fields, name/version matching, paging, exact source binding,
session/grant/generation changes, revocation, corrupt rows and expiry after a
connection wait. The protected shared/named HTTP integration fixture and hosted
EN/DE desktop/mobile capture gate are separate runtime checks. Source checks and
capture fixtures establish neither browser pixels nor a native host read, grant,
installation, deployment or release.
