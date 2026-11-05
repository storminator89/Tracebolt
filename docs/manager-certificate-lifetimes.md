# Manager certificate lifetime report

The authenticated operator API now includes a read-only certificate lifetime
report in `GET /api/manager/readiness`. Shared administrator sessions and named
read-only accounts use the same existing private route. There is no dashboard
panel in this increment. No new login, permission, notification, renewal,
credential issuance or host change is introduced.

## Read the loaded dates

An admitted runtime snapshot adds `certificateLifetimes` to the existing
`tracebolt.manager-readiness.v1` response. Its three fixed roles are:

- `server_chain`: the entire already-loaded presented server chain, including
  the leaf. `validFrom` is the latest original `NotBefore`, and `validUntil` is
  the earliest original `NotAfter`. A longer-lived leaf cannot hide an expiring
  presented intermediate.
- `enrollment_issuer`: the already-loaded dedicated enrollment issuer's exact
  original validity dates.
- `enrollment_root`: the already-loaded public enrollment root's exact original
  validity dates, reported independently of the issuer.

Dates are UTC RFC 3339 instants. Compare them with the response's `serverNow`,
not the time of download. Refreshing the route never extends a certificate or
changes its original dates. The report does not reload certificate files, read a
private key or contact an endpoint, issuer, provider or trust service.

Every row has `role` and `state`. Dates are included only for a complete,
parsable, nonempty validity window. States are:

- `valid`: the current time is within the window, with more than 30 days left.
- `within_30_days`: more than seven and at most 30 days remain.
- `within_7_days`: more than zero and at most seven days remain.
- `expired`: the current time is at or after the original expiry instant.
- `not_yet_valid`: the current time precedes the original window start.
- `not_configured`: that role is disabled. The explicit HTTP-test profile does
  not invent a TLS server certificate; absent guided enrollment does not invent
  an issuer or root.
- `unavailable`: enabled material, the time reference or the complete chain
  window is missing, malformed, disjoint or beyond the report's bounds. There
  are no partial dates or successful fallback rows.

The server chain is bounded to 64 certificates and 64 KiB of aggregate DER. The
real loader already bounds its certificate PEM input to 64 KiB. Unsupported
in-memory material remains unavailable rather than silently dropping a chain
member. Missing readiness wiring, a busy probe or an early unavailable fallback
can omit the entire optional report. An absent report is unknown, not an empty
successful certificate assessment.

## Dates do not establish trust or renewal

Lifetime warnings do not change the existing `status` or HTTP status: a currently
valid certificate nearing expiry may still accompany HTTP 200, while a store or
worker failure can return HTTP 503 with useful lifetime evidence. Existing
server-chain validity and issuer/root fingerprint, role and trust validation
remain separate readiness components. A parsable certificate's dates cannot
override a failed authority check. `valid` describes only remaining lifetime,
not a verified TLS handshake, current on-disk configuration or safe deployment.

The report exposes fixed role/state labels and validity dates only. It includes
no subject, SAN/hostname, serial number, fingerprint, certificate/key bytes,
configuration path or raw parser error. It is still private operator metadata;
the existing TLS/explicit HTTP-test, Host/Origin, session lifetime/revocation,
canonical path and no-store boundaries remain in force. A session ending during
the read cannot receive the resulting dates. POST/HEAD and query parameters do
not become certificate controls.

For a near-expiry, expired or future certificate, have the authorized custodian
review the exact running artifacts, approved public/private material, trust
bindings and existing replacement/restart procedure. This report never changes
trust, replaces an issuer, renews a certificate, restarts a manager, re-enrolls a
device or grants such an action. A file replacement alone does not update the
already-loaded runtime report. Endpoint certificate expiry is not assessed.

## Verification boundary

Pure source fixtures cover exact seven/30-day and validity boundaries, the
whole presented-chain window, independent issuer/root deadlines, malformed and
disjoint chains, invalid clocks, bounded input and redaction. Runtime fixtures
cover actual loaded material, original-date retention, defensive copying,
HTTP-test absence, independent authority validation and unchanged private state.
API fixtures cover named read accounts, no-store responses, session loss and
read-only methods. These checks are not deployment, browser, native endpoint,
certificate replacement/renewal or release acceptance.
