# Application availability observations (source candidate)

This opt-in LAN-manager feature makes HTTP or HTTPS observations **from the
management server**. It does not inspect endpoint health or establish that an
application works correctly. HTTP 2xx means only that the selected resource
returned that status. Failures can reflect the manager's DNS, network, firewall
or trust store rather than an application failure.

The feature is disabled when `--application-checks-config` is omitted. Loading
configuration, constructing the monitor and polling status perform no DNS lookup
or check. This source change supplies no real targets and changes no host,
network, certificate, permission or service configuration.

An optional [v2 DNS/TCP extension](application-network-checks.md) adds bounded
manager-side resolution and connect-only observations. V1 HTTP configuration and
wire status remain unchanged; v2 keeps each protocol's result fields distinct.

## Explicit target authority

A local operator may separately provision a private, manager-owned configuration
file and pass its absolute path with `--application-checks-config PATH`. Existing
LAN protected-file rules apply: regular file, one hard link, no symlinks, no
other-user access, and protected path ancestors. Invalid supplied configuration
fails startup closed. Non-Linux protected-file loading is unsupported.

A minimal disabled file is:

```json
{"schemaVersion":"tracebolt.application-checks-config.v1","enabled":false}
```

Enabled files require all these fields:

- `schemaVersion`: `tracebolt.application-checks-config.v1`
- `enabled`: `true`
- `managerInstanceId`: exact enrolled manager ID, or `""` in manual mode
- `operatorOrigin` and `profile`: exact current LAN-manager origin and profile
- `checksFromManagerAcknowledged`: `true`
- `intervalSeconds`: integer between 60 and 3600
- `targets`: one to eight objects, each containing:
  - `id`: distinct, nonsecret 1–48-character lowercase identifier using letters,
    digits, underscores or hyphens. This identifier is shown to operators.
  - `url`: one fixed HTTP/HTTPS resource, at most 1024 ASCII characters
  - `allowedAddresses`: one to sixteen distinct canonical numeric IP addresses
  - `allowPrivateLAN`: explicit boolean; `true` admits RFC1918 or ULA destinations
  - `plaintextHTTPAcknowledged`: `true` for HTTP; `false` for HTTPS

Choose a **side-effect-free, credential-free health resource**. Every check sends
GET. Do not select an action URL or include secrets in the path or ID. User
information, queries, fragments, percent escapes, custom headers, arbitrary
methods, credentials and request bodies are unsupported. Noncanonical paths and
ports are rejected. Unknown, duplicate, case-aliased and null fields fail closed.

The plaintext acknowledgement concerns requests to that application. It is
separate from Tracebolt's operator/agent transport profile: an HTTPS manager may
intentionally check HTTP, and an HTTP-test manager still verifies HTTPS target
certificates normally. HTTP rows visibly identify `targetScheme: "http"` and
`tls.state: "not_applicable"`.

Configuration is an immutable startup snapshot. Changing, removing or disabling
the file takes effect on the next separately authorized manager restart; there
is no API to enable, edit, trigger or pause checks. Restart discards old results.
Stop the manager to stop checks immediately. Configuration binds origin/profile
and, where present, the existing enrolled manager ID; no identity is created.

## Destination and transport policy

Every hostname is resolved for every check using the manager's existing system
DNS/search rules, including single-label LAN names. The original configured name
remains the HTTP Host and TLS verification name. **All** answers must pass address
policy and belong to that target's exact numeric allowlist. No answers or more
than sixteen answers fail closed. DNS changes outside the allowlist produce an
unknown/destination-blocked result without a connection. Numeric URLs must belong
to the allowlist. One deterministically selected numeric address is pinned for
TCP; the original hostname remains HTTP Host and TLS verification name. There is
no second resolution or fallback connection.

Private-LAN permission never admits loopback, link-local, multicast, unspecified,
translation or other conservatively excluded special-purpose ranges, nor the
explicit AWS/GCP/Azure metadata addresses. IPv4-mapped DNS answers use IPv4 rules.
Configured mapped addresses and scoped IPv6 addresses are rejected. This is a
conservative safety policy, not general service discovery.

HTTPS uses normal hostname and chain verification with existing system trust
roots, TLS 1.2 or later, and HTTP/1.1. Private-CA services cannot pass unless their
trust already exists on the manager. This feature never installs a CA and has no
insecure-verification or custom-CA option. No proxy environment, redirect
following, cookie jar, compression, connection reuse or retry is used. Redirect
status is a failed HTTP observation; its destination is never followed.

Each attempt has a five-second deadline covering DNS, connection, TLS, response
headers and bounded body discard. Response headers are capped at 16 KiB; at most
4 KiB of body content is read and discarded. Content, error text, URLs, resolved
addresses and certificate subjects are never stored, logged or returned. Only
HTTP status and verified leaf expiry are interpreted. A body error does not undo
a received status: this is a status/header observation, not a content test.

Checks run sequentially, at most one connection per target per sweep. The next
sweep waits the configured interval after the preceding sweep finishes. There
are no catch-up bursts or overlapping runs. Cancellation joins the worker before
manager stores close. No SQLite transaction or store connection participates.

## Read-only status

`GET /api/application-checks/status` is available only through the authenticated
LAN operator surface, with existing origin, authority, session and named-read
boundaries. It is absent from the development manager and agent ingress. The
LAN Overview presents a compact read-only panel with the application ID, explicit
HTTP/HTTPS transport, HTTP result, separate leaf-certificate expiry and original
observation age. Reload fetches retained status; it never triggers a check.
Polling pauses when hidden, aborts on unmount/access changes and cannot overlap.
Read errors and locally stale evidence cannot remain successful. Disabled mode
is shown concisely; no browser control enables targets or changes configuration.

The response has schema `tracebolt.application-checks.v1`, `vantage:
"management_server"`, server time, enabled/cadence/freshness fields, and at most
eight latest rows. Polling never performs a check.

Each row identifies its nonsecret ID, target scheme and original observation
start time. States are:

- `ok`: received HTTP 2xx
- `http_error`: received non-2xx; 3xx has reason `redirect_blocked`
- `network_error`: DNS, connection, timeout or HTTP protocol/read failure
- `tls_error`: TLS handshake or certificate verification failed
- `unknown`: not checked, cancelled, blocked destination or stale observation

TLS is separate: `valid`, `expiring` (within 30 days), `expired`, `unknown` or
`not_applicable`. `expiresAt` is the **verified leaf certificate** expiry only,
not the full chain's future lifetime. Certificates that are expired, untrusted or wrong-host at handshake
cannot yield trusted expiry. HTTP may succeed while a certificate is expiring;
HTTP failure can accompany a currently valid certificate. For a still-fresh
observation, the known leaf expiry is reclassified against current server time
without a new check. An earlier HTTP success can therefore coexist with an
expired leaf. These labels describe the certificate verified at the last
observation, not a new handshake or continued chain validity.

Freshness allows the configured interval plus the complete bounded sequential
round and one in-progress check. Older or future-dated observations become
unknown; current HTTP status and verified TLS expiry are cleared, preserving the
original timestamp. HTTP TLS stays not-applicable. Cancelled work never replaces
a prior observation with a synthetic failure.

## Scope and remaining gates

Results exist only in memory. There is no history, alert delivery, incident
creation, endpoint association, DB/backup check, content matching,
credential support or target-configuration UI. Existing device pages, health incidents and
external alarm behavior are unchanged.

Tests use invented configuration, injected transports and local/in-memory TLS
fixtures. They do not establish real application reachability, production trust,
installed-service acceptance or deployment. Native target selection, authorized
provisioning, publication/CI and hosted browser acceptance remain separate work.
Local browser rendering could not be verified in the editing environment; no
local screenshot or responsive-browser acceptance is claimed.
