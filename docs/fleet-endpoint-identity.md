# Reported hostname and IP addresses in the fleet

The fleet table uses the existing explicitly opted-in endpoint-identity metadata.
It shows the locally reported hostname first, with interface-scoped address text,
original observation age, and the stable agent ID separately. Neither a hostname
nor an address is treated as a unique, verified, resolvable or reachable identity.
No server peer, manager address or NAT address is substituted for an endpoint IP.

`GET /api/fleet/endpoint-identities` is a read-only operator endpoint under the
existing transport, origin and session guards. It accepts no query parameters.
Its `tracebolt.fleet-endpoint-identity.v1` response has `serverNow` and `items`;
every item retains the exact existing `tracebolt.endpoint-identity-view.v1`
contract. A certificate expiring between authorization and output uses the
existing value-free expired form with null receipt fields in this batch; the
original durable receipt is unchanged. The read uses one shared bounded admission and one store transaction,
not per-row HTTP calls or repeated full-store transactions. The existing complete
managed-profile store already enforces at most 25 enrollment records. Every
approved record is returned in stable device-ID order, including value-free
revoked/expired/uncollected states. No records are silently truncated: an invalid
oversized store fails closed. Unsupported/manual profiles return an empty
collection; their rows explicitly show unavailable metadata. The complete
response, including its trailing newline, is strictly below 256 KiB, within the existing protected browser reader
limit. No database schema or collection/grant changes are required.

The UI validates the entire batch and keeps it in ephemeral display/search state,
separate from `model.Device`, general CSV exports, AI packets, connection targets
and routing. Device details still open by stable agent ID. Name sorting and local
search use only currently displayable hostname/address observations. All reported
addresses remain searchable, including ones behind the compact extra-address
count. Two addresses are shown with their interface; remaining addresses are
available in the existing device identity details. Display order prefers up,
nonloopback interfaces but does not identify a primary IP. Link-local association
retains interface name and index. Address-family and hostname collection failures
remain independent; permission denied, failed collection, successful emptiness,
not-collected, stale, expired and revoked are not relabeled as healthy/current.

Original 120-second freshness and 24-hour retention remain unchanged. Refresh
cannot extend them. Post-transaction and final-output trusted clock/session checks
are retained. The response is encoded once, then its authority/freshness and
session are checked again before those exact bytes are written. Crossing a
certificate, retention or freshness boundary during encoding fails closed and
requires a fresh read. The browser ages observations while open, clears expired values,
clears on read failure or access loss, aborts obsolete requests, and suspends on
hidden/blurred navigation. Resuming requires a fresh read. A single exact
`storage_busy` retry stays inside the original ten-second request budget.

## Verification

- Go store/API fixtures check shared admission, cancellation, original retained
  bytes/receipts, expiry, revocation, final output authority/session checks and
  unauthenticated/cross-origin/method/query rejection.
- Web tests check strict bounded batches, no per-device request fanout, inert text,
  local search/sort, scoped multiple addresses, missing/failure states, original
  age, stale/expired clearing and interruption/access-loss handling.
- `node tests/e2e-review/fleet-identity-browser.mjs` builds the existing isolated
  endpoint fixture, serves the compiled React application, and exercises the real
  authenticated operator/store route using invented hostname/address data. It
  checks desktop and German mobile layout, search, stable routing, original age,
  revocation, read failure, visibility recovery and logout.

Build `web/` first. The browser script accepts `GO_BIN`, `CHROMIUM_PATH`,
`FLEET_IDENTITY_REVIEW_PORT` and `TRACEBOLT_SOURCE_SHA`; its JSON and screenshots
are under `artifacts/review/`. These fixtures do not execute a native collector,
change consent, deploy binaries or establish an installed-host acceptance result.
