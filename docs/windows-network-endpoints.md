# Windows TCP and UDP endpoint metadata

This source candidate adds a separate default-off `windows-network-endpoints-v1`
local capability to an activated `windows-inventory-v1` identity. Base inventory,
event headers, volume metadata and process CPU/RAM grants do not authorize it.
Existing identities, profiles, protected enrollment/sender manifests and sequence
floors stay unchanged. Portable fixtures and Windows cross-builds establish source
behavior only; they are not native installation or host-read acceptance.

## Explicit local approval

An owned, stopped inventory service can inspect its local grant with
`windows-service --network-preview`. Enable is
`windows-service --network-enable --apply --network-endpoints`; disable is
`windows-service --network-disable --apply`. The enable operation prints the
network-specific privacy disclosure before making any change. Deliberate
HTTP-test use additionally requires `--insecure-http-test`, matching the existing
identity exactly, and prints the network-specific plaintext-risk disclosure.
HTTPS remains the default. These command descriptions do not authorize host
changes, service installation or a native network read.

All three operations verify the existing owned service is stopped before reading
or writing its grant. The separate protected sibling uses a create-only manifest
and binds consent to the existing sender. Missing records in a used store,
foreign bindings, unsafe paths, access denial and incomplete writes fail closed.
The existing exclusive sender lock is held throughout configuration. Preview
never creates state. Disabling preserves the grant record; re-enabling creates a
new grant ID. No operation resets identity/counters, repairs protection, adopts a
foreign service, restarts the service or erases retained manager metadata.

The reusable upfront `WindowsCapabilityConsent` contract has a fresh v3 supporting
base inventory plus any explicitly selected combination of event headers, volumes,
process CPU/RAM and network endpoints. The acknowledgement covers every selected
scope and, for HTTP-test, its plaintext disclosure. V1 and v2 keep their original
scope sets and reject network endpoints. V3 neither grants unselected scopes nor
promotes earlier approvals. Activation and owned/stopped-service verification
remain required. No installer automatically invokes this contract. Extension
writes are sequential: partial results identify completed scopes and the possibly
indeterminate failed scope. Recovery must preserve state rather than roll back,
re-enroll or enable scopes the user did not select.

## What the scope exposes

Snapshots contain bounded caller-visible IPv4/IPv6 TCP and UDP endpoint metadata:
local numeric IP addresses and ports, TCP remote numeric IP addresses and ports,
TCP state, and the owning PID reported by the Windows table API at capture time.
UDP and TCP listeners have no remote peer. Listener remote fields are withheld
because the API says they have no meaning. UDP PID zero means ownership is
unavailable; it is never presented as attribution to a process zero. Wildcard addresses and genuine port zero retain their
API meaning; unavailable or denied data is not an empty successful snapshot.

An owning PID is an API-snapshot attribution. It is not a stable process identity,
and it does not identify a process name. PIDs can disappear or be reused between
independent captures. Do not join these rows to an older process list or claim a
stable executable association. This scope does not collect traffic payloads,
packet contents, byte counters, DNS names, process names/paths/owners, or process
memory, and it provides no connection termination or network-control action.
There is no DNS resolution, shell command, process join or privilege elevation.

Each snapshot retains at most 64 sorted rows and 12 KiB. Native collection
examines at most 4,096 rows per table, 16,384 across the four protocol/family
tables, with at most four calls and a 1 MiB buffer per table. A five-second
cooperative budget is checked between calls/rows; an in-flight native call cannot
be forcibly canceled. Collection uses the ordinary service token. Exact counts
are reported only for fully observed coverage; partial coverage has lower-bound
counts. Truncation means the observed count exceeds retained rows. Denial,
unavailability, unsupported families and capture freshness are represented
honestly, including successful zero-row tables. It does not install a driver, request debug privileges,
change firewall rules or grant new host permissions. The standard reporting
interval is reused; retry sends the original pending bytes and capture time.

## Shared transport and private views

A strict v5 Windows frame carries the separately consented network snapshot with
any independently selected event, volume and process-metric extensions. Earlier
v1-v4 frames keep their original version and shape whenever network is absent.
The existing 72 KiB whole-frame budget, signed sender, authenticated ingress,
durable store and operator read path remain authoritative. Complete volume and
process-metric rows may be trimmed first to reserve the network envelope, then
network rows are trimmed to fit without changing original counts or capture. Snapshot ordering and trimming
are deterministic; pending retries never re-collect or refresh retained capture
or manager receipt times.

A replaced/revoked network grant prevents affected pending bytes from being sent
without resetting sequence. Consent is checked before capture, after capture and
immediately before transmission. Network capture/generation floors
preserve replay protection. After a network snapshot, the next base inventory
capture must advance beyond it even if network scope is omitted, preserving the
floor without resetting state. Network rows stay in the authenticated private
operator view with their own freshness/expiry checks and explicit
stale/unavailable states. The existing base-inventory 24-hour privacy envelope
still hides all siblings when it expires. They
never enter basic observations, external AI/provider exports or process-metric
attribution. Disabling collection does not retroactively refresh retained rows.

## Remaining native acceptance

Separately authorized Windows acceptance must verify ordinary LocalService token
visibility and denial, protected sibling ACLs, IPv4/IPv6 TCP and UDP table layout,
PID reuse and transient sockets, bounded buffers/calls, stopped-service guards,
disable/re-enable, exact retry, and actual Windows → Linux manager → shared browser
behavior. Synthetic fixture tests, API mocks and cross-compilation do not grant
host reads, install services, change security settings, approve a browser session,
publish a release, dispatch a workflow or authorize external AI disclosure.
