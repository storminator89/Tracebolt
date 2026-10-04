# Explicit endpoint display-metadata extension

Status: isolated, unpublished integrated source candidate. The strict endpoint
DTO and Linux source have completed static source-boundary review; actual OS
provider execution and installed-service acceptance remain held. This candidate
adds explicit local consent administration, a versioned authenticated system
frame, bounded optional retention and a dedicated operator-only read endpoint.
No live hostname/interface/address source was executed during these tests, and
no existing service, credential, identity, manager or deployment was changed.

## Compatibility and consent decision

The extension retains the existing activated Linux
`managed-operations-v3` principal and all existing metrics, package and system
sequence ledgers. It does **not** grant operational or package collection to a
basic/v2 identity, relabel an old profile, recreate missing state or require a
fresh manager/database. The existing mandatory fresh-identity rule for expanding
basic/v2 operational/package scope remains unchanged.

A separate, explicit, protected local-administrator acknowledgement enables only
`tracebolt.endpoint-identity.v1` and its exact scope
`agent-visible-linux-hostname-and-interface-addresses`. It must bind the current
agent ID, current leaf fingerprint, exact manager origin, transport profile and
collection profile. Absence means disabled, including every existing v3 agent.
A manager config change alone cannot enable endpoint collection. Consent is
agent-declared local consent; it is not verified administrator/OS attestation.
A separate manager grant and re-enrollment are not required for this narrowly
bounded opt-in. No activation/enrollment default is widened.

The integration uses a distinct recognized system wire variant, keeping
the current strict v1 schema unchanged. The exact extension scope/version and
metadata are inside the original signed/authenticated request body. The existing
system sequence, stable device ID, state binding, latest-body digest, original
receipt, certificate authorization, revocation and replay checks remain intact.
Display hostname is never substituted for stable cryptographic device identity.

Manager storage retains one optional endpoint snapshot in the existing system
authority JSON. The entire record must still fit its current 16 KiB ceiling;
endpoint snapshots are separately limited to 8 KiB. Absent optional fields must
encode identically for old records. This integration changes no SQL table and does
not migrate, reset or discard any existing ledger. Focused tests compare default frame bytes and old authority-record bytes against
their original representations. No manager SQL schema version or table changes.

Local disable must be checked before source construction and before any send,
including a retained extension frame. The consent command requires a stopped sender and changes only the protected
sidecar. On the next sender attempt, pending extension bytes are explicitly
discarded before collection/network using the existing operation that retains
the consumed sequence floor.
Already delivered values expire at their original 24-hour retention deadline,
without refreshing their age on ordinary v1 reports. The server does not infer
an explicit remote-disabled acknowledgement from a local command.
Disabling locally does not remotely erase previously delivered bytes. Re-enabling
must not resurrect a discarded request or reuse a consumed sequence. A stopped
service or inaccessible manager is not evidence of server-side deletion.

Endpoint data stays inert operator-only metadata. It must not enter AI inputs,
raw logs, general exports, URLs, DNS, connection destinations, routing, access
control or other SSRF-sensitive decisions. Rendering must use escaped text.

## Implemented typed observation

All JSON members are required. The snapshot is:

- `schemaVersion`: `tracebolt.endpoint-identity.v1`
- `generationId`: `sample_` plus 32 lowercase hex digits, supplied by the existing
  system sequence domain at a future authenticated integration boundary
- `collectedAt`: nonzero UTC time in years 1970–9999
- `durationMs`: nonnegative integer up to 2^53−1
- `scope`: `agent-visible-linux-hostname-and-interface-addresses`
- `reportedHostname`: `{coverage,reason,value}`
- `interfaces`: `{meta,items}`

Hostname is the locally reported display value, not necessarily an FQDN, unique,
resolvable, trusted or remotely reachable. Successful hostname observations have
`complete/none` and a nonnull value of 1–253 UTF-8 bytes. Failed observations have
`failed/<fixed reason>` and null. Invalid UTF-8, control/format/replacement
characters and leading/trailing whitespace are rejected. A hostname failure does
not suppress a valid interface observation, or vice versa.

An interface row is `{index,name,up,loopback,hardwareKind,addresses}`. Index is
1–2147483647 in the observing network namespace; interface rows are uniquely
sorted by index and names are unique. Name is 1–15 valid UTF-8 bytes with no
control/format/replacement/space/slash/backslash/colon characters. `up` and
`loopback` are observed interface flags; they do not mean connectivity is healthy.
`hardwareKind` is always `unknown` in v1. A name such as `eth0`, `veth0`, `tun0`
or `docker0` cannot establish physical/virtual/VPN/bridge classification. All
visible interfaces, including loopback, down and virtual interfaces, are within
scope; no class is omitted because of its name or address range.

Each interface's `addresses` has independent `ipv4` and `ipv6` sections, each
`{meta,items}`. An address row is exactly `{family,address,scope}`. Family is `ipv4|ipv6`; address uses canonical
numeric `netip` spelling without a zone string. The enclosing interface index
supplies link-local association. Assigned host bits are retained, not replaced with masked network prefixes.
Prefix lengths are deliberately outside this requested v1 scope. IPv4-mapped IPv6 remains
IPv6. Rows are uniquely sorted by numeric address within their family section.
Scope is derived solely from the numeric address: `unspecified`, `loopback`,
`link-local`, `multicast`, `private` (RFC1918/IPv6 ULA), or `other`. `other` is not
labeled public/reachable. No primary address, external IP, route, gateway,
connection, socket peer, DNS resolution, MAC or physical identity is inferred.

Both section metas contain `{coverage,reason,observedCount,countExact}`.
Successful empty arrays have `complete/none`, an exact count of zero and
`countExact=true`. A failed enumeration has no rows, a null count and
`countExact=false`. Per-interface, per-family address failures preserve that interface and the
other successful family with explicit coverage. The aggregate interface section is then
`partial/address_unavailable`, with an exact count of the successfully enumerated
interface rows; it does not claim all assigned addresses were read. The specific
failure reason remains on each affected interface. There is no partial-success
prefix for a failed enumeration and no `truncated=true` shortcut.

Fixed reasons are `source_missing`, `permission_denied`, `not_supported`,
`timeout`, `invalid_source`, `read_failed`, `item_limit`, `byte_limit`,
`collector_busy`, `not_collected`; `address_unavailable` is only the aggregate
partial-interface reason. Raw operating-system error text is never exported.

## Rejection limits and source ownership

- 32 interface rows per attempt
- 32 assigned addresses per interface across both families
- 128 assigned addresses across all interfaces
- 8 KiB encoded complete endpoint snapshot
- 5-second cooperative collection context
- One synchronous collection in flight, including canceled blocked providers
- No background collection, goroutine-per-read or abandoned goroutine on timeout

The held OS provider caps raw reads/allocations before returning data;
a typed result-size check is not a raw-source memory bound. Caller-invalid,
canceled-before-admission and busy calls do not invoke the injected provider.
An interface-list limit fails the whole interface section. A per-family address limit fails that family and marks aggregate coverage
partial. Exceeding the combined per-interface address cap fails both families.
A total-address or encoded-byte limit drops the entire interface section with
its explicit reason, retaining only the independently bounded hostname result.
This avoids presenting a prefix as complete.

These are sequential observations in the agent's visible namespaces. A complete
attempt is not an atomic machine-wide census, proof of all network namespaces,
proof of external reachability or attestation of identity. Interface rename,
address change and namespace limitations need explicit source handling rather
than a fabricated complete result. Non-Linux runtime collection is unsupported;
no cross-platform OS implementation is supplied by this candidate.

## Source review and remaining integration gates

The held Linux provider uses the following fixed local sources; final source
acceptance remains required before runtime wiring or actual host reads.

- `uname` nodename only, not the domainname or other uname fields
- Pinned, procfs-verified `/proc` descriptors, bounded `net -> self/net` and
  canonical numeric `self` resolution, then the pinned self `net` directory
- Fixed `dev` and `if_inet6` files, no-follow regular procfs entries, at most
  64 KiB each and 4 KiB per line; packet counters/prefix/flags are not exported
- An unconnected `AF_INET`, `SOCK_DGRAM|SOCK_CLOEXEC` control descriptor
- Exactly read-only `SIOCGIFCONF`, `SIOCGIFINDEX`, `SIOCGIFFLAGS`; no other ioctl
- One preallocated IPv4 buffer of 129 architecture-sized ifreq records; a
  response with no whole spare record is rejected, never labeled complete
- A single cached enumeration per address family, plus index/name/flag checks
  detecting observed interface races; IPv4 aliases and secondary addresses
  resolve through kernel-reported labels and read-only index lookup

The provider refuses effective UID 0. This is only a privilege guard; UID/account
data is not retained or exported. It does not bind, connect, send network traffic,
query a hardware address, open AF_NETLINK, alter a namespace or use a subprocess.
The existing systemd `RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6` and empty
capability sets are unchanged. Test fixtures do not establish installed-service
compatibility or actual source success. Missing IPv6 is an explicit family
failure and cannot become a successful empty address list.

References used for source semantics: [Linux netdevice documentation](https://man7.org/linux/man-pages/man7/netdevice.7.html),
[Linux IPv4 address enumeration](https://github.com/torvalds/linux/blob/master/net/ipv4/devinet.c),
[Linux read-only interface ioctl handling](https://github.com/torvalds/linux/blob/master/net/core/dev_ioctl.c).
These describe the source contract, not tested host behavior. Inert providers used by tests contain only fixed synthetic observations.
No scan, DNS query, remote connection, subprocess, namespace entry, service
mutation, privilege addition, MAC/UID/account, environment or command-line
collection is part of this extension.

## Local opt-in administration (held candidate interface)

Existing v3 agents remain default-off. The sidecar is the fixed
`<StateDirectory>/endpoint-identity-consent.json`; it is separate from unchanged
`agent.json`/`ready.json` hashes and all three sender ledgers. It contains exactly
`schemaVersion`, `extensionVersion`, `scope`, `senderBinding`, `acknowledged`.
The binding is the existing validated v3 sender binding. No hostname or address
appears in the consent file, preview/result output or safe errors.

After upgrading both manager and native binaries to the same reviewed revision,
an authorized human administrator stops only the existing endpoint service,
then runs the selected local command as the existing dedicated state UID/GID
(with no additional groups), and restarts the same service after success:

```
lan-agent --config ABSOLUTE_EXISTING_AGENT_JSON --service-identity UID:GID \
  --endpoint-identity-consent preview

lan-agent --config ABSOLUTE_EXISTING_AGENT_JSON --service-identity UID:GID \
  --endpoint-identity-consent enable --ack-endpoint-identity

lan-agent --config ABSOLUTE_EXISTING_AGENT_JSON --service-identity UID:GID \
  --endpoint-identity-consent disable
```

These modes are mutually exclusive with foreground/one-shot reporting,
validation-only and pending-enrollment modes. The numeric service identity is
checked before private reads. They perform no collection or network request,
validate the existing ready/config/certificate binding and all required ledgers,
and acquire an opaque inspection lease in the existing metrics-owner lock
domain. An active sender or missing/incompatible state refuses the operation.
No ledger or crash temporary is initialized, reset or cleaned. An inventory
uncertainty marker still refuses the handoff; consent administration never
bypasses that refusal or removes the marker. The enable action
requires its explicit scope acknowledgement. It writes only the bounded 0600
sidecar via an exclusive 0600 temporary, file fsync, atomic rename and directory
fsync under the protected existing 0700 state directory. Symlinks, hardlinks,
unsafe ownership/modes and leftover consent temporaries fail closed. Failed or
uncertain writes must be inspected, not blindly retried or repaired by changing
permissions. The sidecar is the only file removed by disable.

Removal is local. Pending endpoint bytes may remain privately on disk until the
next sender start, which discards them before source/network while retaining the
consumed floor. Previously delivered server values remain subject to their
original expiry. No immediate remote-erasure or disabled-state acknowledgement
is claimed. Malformed, unreadable or foreign consent disables only this extension
at runtime; normal v3 metrics/package/system work is preserved.

## Operator view and retained original age

`GET /api/devices/{agent_id}/inventory/endpoint-identity` accepts no query and is
under the existing operator transport, Host, Origin and session guards. The
session is checked again after the store read. Its response is capped at 16 KiB:

- `schemaVersion`: `tracebolt.endpoint-identity-view.v1`
- `deviceId`: existing cryptographic device ID
- `status`: `not_collected|fresh|stale|expired|revoked|unknown`
- `serverNow`: trusted manager time; `maxAgeSeconds`: 120
- `sequence`: original endpoint system sequence string, or null
- `receivedAt`: original endpoint receipt time, or null
- `expiresAt`: original collection time plus 24 hours, or null
- `latest`: the typed endpoint snapshot, or null

`fresh` permits an original collection age up to 120 seconds; `stale` is older
than 120 seconds but younger than 24 hours. Both require original sequence,
receipt/expiry times and a snapshot. `expired` hides payload and may retain these
three metadata fields, or all may be null for expired enrollment authority.
`not_collected`, `revoked` and `unknown` expose no endpoint snapshot or sequence/
receipt/expiry fields. Invalid/backward authority clocks fail closed. Neither
ordinary v1 reports nor exact v2 retries refresh endpoint timestamps. A later
failed endpoint attempt replaces the latest endpoint snapshot with explicit
failure; no hidden last-good hostname/address fallback is added.

The new strict `tracebolt.agent-system-inventory.v2` frame carries the existing
system snapshot plus `endpointIdentity` and exact `consentScope`. The old v1
three-member frame remains unchanged and rejects extension fields. Both share
the existing sequence, request path, signed/TLS authorization, request byte cap,
exact-body digest and receipt. If the combined frame exceeds the existing cap,
the entire endpoint interface/hostname snapshot becomes a typed `byte_limit`
failure rather than truncating rows or increasing limits. Only the opted-in
sender can construct the v2 variant. Older managers do not recognize it; update
binaries without replacing existing manager state. A downgrade after retaining
new typed metadata may fail closed and is not an automatic rollback procedure.

## Candidate verification and remaining gates

Focused package tests and race tests passed for strict DTO/local consent,
read-only source fixtures, 32/40-byte ifreq ABI, bounded raw parsing, aliases,
secondary IPv4, independent family denial, safe names and local source races.
The isolated mTLS and signed-HTTP transport tests use only generated identities,
loopback test listeners and inert endpoint observations. They verify activation,
exact-body retry, mutation conflict and revocation. Store tests cover original
age after ordinary v1 reports, retention/cleanup, restart, old serialized bytes
and independent metrics/package floors. Native injected-source tests cover
quiescent consent administration, unchanged ledger/temp bytes, active-owner
refusal, missing-state refusal, unsafe/malformed consent, exact retry without
recapture, and disable before pending delivery or during collection. Operator
handler fixtures cover authentication, route/method/query/origin/cross-site
rejection and session invalidation after the read.

The foundation's source tests, race tests and vet passed; Linux arm64/386,
Darwin arm64 and Windows amd64 foundation test binaries cross-built without
execution. Its overall 70.0% statement coverage intentionally excludes actual OS
calls. Integrated vet passed for all changed Go packages. Integrated test binaries
cross-built for Linux arm64/386, Darwin arm64 and Windows amd64 without execution.
All tests passed in endpointidentity, systemwire, enrollmentstore,
enrollmenttransport, enrollmentservice, lanclientstate, systemstate, api and
cmd/lan-agent. In lanclient, the endpoint/system/complete-state inert-source
regression selection passed; unrelated actual-host sender tests were not run.
The endpoint/inspection tests also passed under the race detector across the
eight directly affected packages. No broader full-repository test claim is made. No actual host collection, installed-service,
reboot, browser UI, upgrade or publication acceptance follows from these tests.
Remaining gates are final runtime/retention/CLI security review, operator UI
verification, and separately authorized real Linux/service acceptance. No
installer, background grant, persistent credential, source widening or service
permission change is part of this slice.
