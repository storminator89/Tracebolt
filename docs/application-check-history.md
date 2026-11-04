# Recent application-check observations

The existing LAN Overview Application checks panel now offers **Recent check
observations**. Expand it to read saved outcomes of the already authorized
manager-side HTTP/HTTPS, DNS and TCP checks. Opening or reloading history never
starts a probe, resolves a name, changes a target or enables checks.

## Scope and bounds

- At most 32 completed outcomes per target, across the existing maximum of eight
  targets, remain in memory for at most 24 hours. At a one-minute cadence this
  usually covers only about 32 minutes, not a complete day.
- Each row retains its original check-start time, completion-recorded time,
  fixed result/reason and HTTP status where applicable. Completion is timestamped
  under the monitor publication lock after the bounded check returns.
- There are no URLs, IP addresses, ports, response bodies, certificate details,
  credentials, configuration audit records or AI inputs in this representation.
- Historical failures followed by sampled success are observations, not a
  confirmed incident recovery or an uptime percentage. Gaps are explicitly
  marked; earlier omitted rows and missing samples do not prove success.
- Cancelled, unfinished and never-run checks do not create history rows. Retention
  and count limits do not change probe timing or latest-status freshness.

Disabling, blocking or replacing configuration removes access to the old monitor's
history. Replacement never adopts earlier rows even when a target ID is reused.
Restart begins with no history. There is no durable archive, export, notification
or incident creation.

## Snapshot and clock behavior

The UI labels the server time of the read and displays the configuration active
at that read. A previously returned snapshot can remain visible for up to one
minute; reload after configuration changes. Closing, navigation, hidden/unfocused
windows, session loss or an unreliable local clock clear it. The view also clears
before any displayed row's original 24-hour retention deadline. Repeated or frozen
server times cannot renew that deadline. There is no background history polling.

A regressed/frozen clock cannot append a new chronological outcome. A server
clock rollback discards retained history rather than extending retention or
resurrecting previously removed rows. Subsequent observations show missing prior
coverage. Latest-status observations keep their existing independent contract.

## Private HTTP representation

The unchanged authenticated `GET /api/application-checks/status` route returns
its original strict v1/v2 current-status JSON by default. Explicit
`Accept: application/vnd.tracebolt.application-check-history.v1+json` selects the
separate `tracebolt.application-check-history.v1` history representation. Its
response has that media type, `Vary: Accept`, and the operator's `no-store` policy.
The complete response is capped at 128 KiB.

Existing same-origin/session/named-read and final active-session checks apply.
There is no query parameter, request body, target selector or write operation.
A changing configuration returns a temporary busy response rather than queueing
history readers. Managed configuration is leased through bounded encoding and
publication; a two-second per-response write deadline bounds a slow reader's hold
on configuration replacement. The shorter deadline remains in effect for that
response, including the server's final flush.

## Verification and remaining gates

Focused Go race and API tests cover bounds, exact default-status compatibility,
inert reads, per-kind redaction, source replacement, cancellation, copied values,
retention, clock rollback and queued-reader timing. DOM tests cover strict parsing,
explicit reads, EN/DE copy, expiry, interruption and late-response rejection.
These checks use invented observations. They do not establish real-target
reachability, production deployment, browser acceptance or native host support.
