# Endpoint identity operator UI candidate

Status: isolated, held source overlay on the sealed wide-device-page candidate
originally based on `fbfb8aefdc8707ee28d77f694037da927365ffff` plus its sealed
wide-page changes, now committed locally as
`a9a9d4e08233ed8b0e968e074da1fa7cf7916121`. The modified-file base hashes
remain identical. This extension is separate from that candidate's publication
gate. This document does not establish deployment,
actual endpoint collection, installed-service behavior or browser acceptance.

## Fixed consumer contract

- One read-only `GET /api/devices/{id}/inventory/endpoint-identity`; no query,
  request body, hostname, address or search value is put in its URL.
- Authenticated LAN operator and eligible real Linux/unknown-platform device
  gate. No fetch in development, synthetic, unauthenticated or non-Linux views.
- Exact `tracebolt.endpoint-identity-view.v1` shape and
  `tracebolt.endpoint-identity.v1` snapshot; unsupported fields fail closed.
- Response streaming is bounded to 16 KiB with the released same-origin helper;
  canonical snapshot accounting is additionally bounded to 8 KiB. Interface,
  family, count, byte, numeric-address, scope and ordering limits match the
  separately held backend DTO.
- Fresh/stale describe the original attempt age (120 seconds), never healthy
  connectivity or successful coverage. Values are hidden at 24 hours and in
  revoked/expired/unknown/not-collected states. Original timestamps remain
  unchanged by manual refresh or a normal report without this extension.
- `unknown`, `revoked` and `not_collected` carry null sequence/receipt/expiry.
  Identity-expired views may also carry all-null metadata; retention-expired
  views may retain the original sequence/receipt/expiry without a snapshot.

## Display and isolation

The header uses a successfully reported hostname while it remains visible, with
an explicit local-source/age label and separate stable cryptographic device ID.
The overview shows per-interface IPv4 and IPv6 independently, including denied,
unsupported, failed, partial and successfully empty results. Names and addresses
are React text; there are no network links, lookup buttons or inferred primary
IP. The previous singular IP field is omitted for real LAN source pages.

Observed interface flags do not imply connectivity. Hardware kind remains
unknown, and names such as eth0, tun0 or docker0 do not establish physical or
virtual hardware. Numeric address scopes do not establish public reachability;
IPv4-mapped IPv6 remains in the IPv6 section.

The source/permission disclosure describes default-off local-administrator
consent without claiming that the manager remotely verifies a current disabled
state. It contains no new opt-in CLI command. No values are copied into Device,
AI, general export, persistent browser storage, connection targets or trust
inputs.

Authentication loss, visibility loss, pagehide, blur, hash navigation, device or
session replacement, timeout and unmount clear or abort the resource. The hook
rejects stale asynchronous completions, rollback of manager time and divergence
of monotonic and wall time. Manual refresh clears existing values before the
new read. No background API polling is added.

## Synthetic verification

All observations used by tests are fixed fixtures, never local host reads.

- Focused endpoint decoder/component/released-API tests: 101 passed.
- Full web suite: 40 files, 823 tests passed.
- Existing e2e source preflight: 9 tests passed.
- The unchanged Go-marshaled synthetic fixture (SHA-256
  `12b1b6e6bfd120acfd7268b3ecbdbf4fd86ba7c4b65dc65777a891d18884abdd`)
  passes the TypeScript decoder with decimal sequence, HTML-escaped hostname
  and nine-digit fractional UTC times.
- TypeScript check and Vite production build passed. Vite reports its existing
  large-bundle warning (JavaScript bundle exceeds 500 kB); no dependency or
  build-limit change was made.
- Neither a Chromium launch nor hosted browser QA was performed by this UI
  implementation task. Responsive/dark/light visual acceptance, actual endpoint
  integration and local-source/service acceptance remain separate gates.

## Browser gate checklist

Use a hosted synthetic preview of the integrated held candidate. Do not use live
hostnames, user addresses or telemetry for screenshots. Exercise English and
German at desktop and narrow viewport widths in both themes. Check full and
partial families, failed hostname, all-null states, long inert hostname text,
link-local and mapped IPv6, and original timestamps. Check header fallback,
manual retry, session expiry, hidden/resumed page, Back/Forward, repeated focus,
superseded navigation and late/timeout responses. Verify that no unintended
request, hyperlink, remote action or primary-IP classification is introduced.
