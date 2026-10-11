# Windows routes and raw interface counters

Source-only, separately consented local metadata for the private Network tab.
`windows-network-context-v1` is default off. Existing adapter and endpoint grants
never authorize it, and the ordinary v14 observation, disclosure entries and
16 KiB observation / 72 KiB frame budgets remain unchanged. Native acceptance
and publication remain separate; this source work grants no host access.

## Exact fields and source meaning

One fixed local `GetIpForwardTable2(AF_UNSPEC)` call returns caller-visible IPv4
and IPv6 routes: numeric destination prefix, destination scope ID, next-hop IP
(including a numeric IPv6 scope when present), capture-time interface index,
route metric offset, numeric protocol and numeric origin. An unspecified next
hop is retained as such. The metric is only the route component; the interface
metric is not read and no best-route or reachability claim is made. Its uint32
maximum is the documented unused sentinel, not a very expensive route.

One fixed local `GetIfTable2Ex(MibIfTableRaw)` call returns interface index,
interface alias and exact unsigned 64-bit `InOctets`, `OutOctets`, `InErrors`,
`OutErrors`, `InDiscards` and `OutDiscards`. Decimal strings preserve all bits
through JSON and JavaScript. Octets are successfully received/transmitted data;
errors and discards are packet counts with their distinct native meanings.
These are raw interface-level counters, not top-of-filter-stack statistics,
rates or guaranteed since-boot totals. They may reset; logical, physical and
filter interfaces can overlap and must not be summed into a host total.

The calls are sequential and not atomic. Their indices are temporary labels
within each source table. Route rows are never joined to the separate counter
table, existing adapters, sockets, process rows or retained observations. Alias
unavailability stays on its original interface row. There is no DNS lookup,
probe, packet capture, shell, remote query, privilege adjustment or change to
network settings. MAC addresses, LUIDs, GUIDs, descriptions and other excluded
fields in the aggregate native allocations are not decoded into model rows.

Primary API contracts:
- [GetIpForwardTable2](https://learn.microsoft.com/en-us/windows/win32/api/netioapi/nf-netioapi-getipforwardtable2)
- [Route fields and metric](https://learn.microsoft.com/en-us/windows/win32/api/netioapi/ns-netioapi-mib_ipforward_row2)
- [Raw versus normal interface tables](https://learn.microsoft.com/en-us/windows/win32/api/netioapi/nf-netioapi-getiftable2ex)
- [Interface fields and counter meanings](https://learn.microsoft.com/en-us/windows/win32/api/netioapi/ns-netioapi-mib_if_row2)

## Bounded complete context

At most 4,096 route rows and 256 interface rows are retained, with 2 MiB canonical
row JSON and a five-second cooperative deadline covering both calls. Windows
owns and sizes the native table allocations; the caller cannot promise a hard
OS allocation ceiling. In-flight synchronous native calls cannot be forcibly
canceled. Counts are checked before creating bounded slices, each selected row
is checked between reads, and native tables are freed synchronously on return.
There is no allocation-retry loop or abandoned worker goroutine.

Only complete results from both tables publish a new generation. A known empty
route table, including documented `ERROR_NOT_FOUND`, is different from failure.
A cutoff, malformed source, denial, cancellation or deadline discards the whole
attempt's prefix. The latest finite failure is displayed separately from any
previous completed generation, which keeps its original age and expiry. This is
complete coverage of the returned caller-visible tables, not every network
compartment or an assertion that the network is healthy.

An independent generation follows the primary attempt. It uses at most 64
immutable chunks, each 128 rows / 64 KiB, a 3 MiB protected pack and a 64-operation
/ 20-second burst. Capture is at least one minute apart; exact pending bytes
resume without recapture. This does not increase generic timeouts or crowd out
ordinary observation fields. Each completed context expires 24 hours after its
original capture start. Manager reservations are bounded to 12 MiB per device
and share the unchanged 128 MiB global byte ceiling with services, software,
processes and existing metadata. Existing database/WAL limits remain enforced.

## Consent and authority

Fresh Read admin explicitly includes this seventeenth scope under consent v10,
outer receipt 8 and the V6 `fresh-seventeen-read-admin-scopes-v1` capability
contract. All previous consent, receipt, capability and pending-frame bytes
remain valid only for their original scopes. HTTP-test requires the additional
plaintext route/alias/counter disclosure; production remains HTTPS. No provider
read is performed to turn Setup requirements into a claimed access result.

The retained source-development CLI requires an existing activated identity and
the exact owned stopped service:
- `windows-service --network-context-preview`
- `windows-service --network-context-enable --apply --routes-interface-counters`
- `windows-service --network-context-disable --apply`

These examples authorize no execution. Enable creates the protected independent
`-network-context` sibling only after writing the irreversible primary v5 used
marker. Earlier primary records and used flags retain their meaning, and exact
ordinary pending bytes survive. Missing used sidecars/sender/pack state fails
closed; no counter/floor reset or recreation is a recovery path. Disable retains
state; reenable uses a new grant and revision. Local changes can only be reported
when the endpoint next runs. Grant, protected identity and original expiry are
rechecked before native capture and send, and manager authority is rechecked
through serialized waits and immediately before disclosure.

## Private browsing

Protected read-only POST `/api/devices/{id}/windows-network-context/query` accepts
`kind` (`route`, `interface`, `all`), literal `search`, `sort`, `limit`, `cursor`.
Sorts are `source-asc`, `source-desc`, `interface-asc`, `interface-desc`; capture
row order is a deterministic tie-breaker, never a routing preference. Search
covers source kind, index, route destination/next hop/metric/protocol/origin and
interface alias. All matching counts derive from the verified complete context.
Pages are at most 100 rows / 256 KiB. Session-bound signed cursors bind source
kind, query, sort, size, device, grant/revision, exact generation and original
expiry. Changed authority/generation requires restarting, never mixed pages.

The existing Network tab offers compact adapter/endpoint, route and raw-counter
views. Current failure, count and original age remain visible; detailed caveats
are available on demand. Device/tab/source/session changes, focus/visibility
loss, untrusted time and original expiry clear private rows and cursors. Rows do
not enter basic observations, AI/provider export, health policies or actions.

## Verification boundary

Inert source fixtures cover complete/empty/failing tables, exact uint64 values,
Unicode aliases, scoped numeric IPs, finite count/deadline bounds, independent
retry/used floors, private count/search/paging, session/authority/expiry fences,
TLS and signed HTTP purpose separation, and compact UI lifecycle. Windows
cross-builds establish compilation only. Hosted browser evidence uses synthetic
fixtures; no native source or host grant is executed by those tests.

Separately approved fresh Windows acceptance must prove actual LocalService
visibility, native allocation/return behavior, protected files, unchanged host
privileges, explicit Setup disclosure and the real endpoint-to-manager-to-browser
path. It must not change routes, interface state, ACLs or traffic to manufacture
passing data. Native acceptance remains deferred until the missing Admin-data
slices are ready. Migration and existing-binary upgrade are not delivery gates.
