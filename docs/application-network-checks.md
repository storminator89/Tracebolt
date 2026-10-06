# DNS resolution and TCP connection observations (source candidate)

The optional application-check worker can also observe one configured hostname
resolution or one configured TCP connection **from the management server**.
Neither result establishes full application or endpoint health. Existing v1
HTTP/HTTPS configuration and status remain unchanged, including normal HTTPS
certificate verification and the separate plaintext-HTTP acknowledgement.

No real targets, credentials, trust, resolver, network, service or permission
configuration is provided or changed by this source candidate.

## Versioned explicit configuration

Use the same protected `--application-checks-config PATH` file and existing
manager binding/acknowledgement rules documented in [application checks](application-checks.md).
For DNS/TCP, select `schemaVersion: "tracebolt.application-checks-config.v2"`.
The root fields otherwise stay identical. Version 1 never accepts new kinds.
A minimal disabled v2 file is:

```json
{"schemaVersion":"tracebolt.application-checks-config.v2","enabled":false}
```

Each v2 target requires `kind`, `id`, `allowedAddresses` and `allowPrivateLAN`.
The shared ID, exact-address list and private-LAN policy are unchanged. Each kind
has an exact additional key set:

- `http`: `url` and `plaintextHTTPAcknowledged`, exactly as v1
- `dns`: `host`, one canonical hostname; numeric IP literals are rejected
- `tcp`: `host`, one canonical hostname or numeric IP, and `port`, one integer
  from 1 through 65535

No cross-kind fields, wildcard names, address/port ranges, arbitrary DNS query
text or record types, custom resolver, banner options, protocol payloads,
credentials, TLS switches or extra fields are accepted. IPv6 host literals use
canonical unbracketed address syntax; they may not contain an interface zone.
A configured literal TCP address must be in the exact numeric allowlist.

The existing eight-target total is shared by all kinds. Targets are startup
snapshots, remain off without explicit configuration, and have no browser
configuration or trigger controls. Altering the file requires the same separately
authorized manager restart. Disabled v2 preserves its v2 status schema without
starting an outbound worker.

## What the observations establish

### DNS resolution

The manager uses its existing system A/AAAA resolution path. This may consult
hosts files, caches and DNS search rules, including for single-label LAN names.
It is not a direct test of a selected nameserver, authoritative DNS, DNSSEC,
record TTLs, or propagation.

“Resolved” means a nonempty result of at most sixteen addresses, **all** permitted
by that target's exact address allowlist and destination policy. An allowed
subset is sufficient; the result does not prove every expected record is present.
An extra/unapproved/special-purpose address blocks the observation. No connection
is opened to any returned address. Hostnames, answers and resolver details are
not included in status.

### TCP connection

For a hostname, resolve and validate every answer under the identical policy.
Choose one deterministic numeric address and attempt exactly one TCP connection
to the configured port. A literal host skips name resolution but not address
policy. The socket is closed immediately, including late/error returns carrying
a connection.

“Connected” means only that the selected numeric socket connection was established
within the attempt deadline. It does not prove other returned addresses work,
that an application can answer a request, or that any TLS/certificate check ran.
No application read, write, banner, command, login, TLS handshake, retry or port
scan occurs. A TCP connection can still appear in the target's access logs.

## Shared bounds and status

Both kinds retain the five-second whole-attempt deadline, private-LAN opt-in,
permanent special/metadata exclusions, all-answer checking, sequential execution,
completion-based 60–3600-second cadence, cancellation and memory-only retention.
A successful dependency returning after the deadline cannot create success.
Cancelled work never replaces an earlier observation. No SQLite transaction,
health incident or alert delivery is involved.

The existing authenticated read-only status route returns v1 for v1 configuration
and `tracebolt.application-checks.v2` for v2, including disabled v2. The envelope,
manager-side vantage, maximum eight rows and freshness formula are unchanged.
V2 rows are strictly tagged:

- Every row: `kind`, `id`, `state`, `reason`, `observedAt`
- HTTP only: the existing `targetScheme`, `httpStatus` and `tls` members
- DNS/TCP: no HTTP, TLS, host, port, address or resolver members

DNS success is `ok/dns_resolved`; TCP success is `ok/tcp_connected`. Failed
resolution, deadlines and connection errors use bounded `network_error` reasons.
Denied destinations, unperformed checks and stale/future observations remain
unknown. Stale projection preserves the kind and original age without inventing
HTTP or certificate data.

The existing compact Overview panel supports both versions, shows DNS/TCP labels,
“Resolved”/“Connected” results and a neutral certificate dash for these kinds.
The dash means a certificate is outside this check; it does not imply TLS is
absent on the target. Refresh remains an authenticated read of retained results.

## Verification boundary

Injected resolver/connection fixtures verify policy, zero DNS-target connections,
zero TCP application reads/writes, single dialing, cleanup, deadline/cancellation
and per-kind schemas. Existing HTTP/TLS regressions remain required. Local browser
acceptance is unavailable in the editing environment. Publication/CI, hosted
browser checks and separately authorized real-target/native acceptance remain
pending. Database, backup and authenticated application checks are separate work.
