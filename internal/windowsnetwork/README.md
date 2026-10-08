# Windows network endpoint source candidate

Separate default-off `windows-network-endpoints-v1` scope, snapshot
`tracebolt.windows-network-endpoints.v1`, and identity-bound
`tracebolt.windows-network-consent.v1`. Inventory, event, volume and process
metric grants never authorize endpoint tables. `Collect` requires its caller to
validate a currently enabled local grant before collection and again before
transport. This package does not activate consent or change permissions.

## Read scope and API truth

The synchronous collector reads four caller-visible IP Helper OWNER_PID tables:
`GetExtendedTcpTable` for IPv4/IPv6 with `TCP_TABLE_OWNER_PID_ALL`, and
`GetExtendedUdpTable` for IPv4/IPv6 with `UDP_TABLE_OWNER_PID`. It opens no socket,
process or handle, performs no DNS/process-name lookup, and uses no shell,
packet capture, elevation or API owner-module lookup. A PID is only the API's
snapshot value, not a stable process identity or a verified process-name join.
Zero PID remains the API value and can mean ownership is unavailable.

Local numeric addresses/ports are reported for all rows. TCP non-listener rows
also carry the API's numeric remote address/port and finite state. A TCP LISTEN
row carries its state but null remote address/port because Microsoft defines the
remote fields as meaningless for a listener. UDP remote address, remote port and
state are null: a bound UDP endpoint does not prove it is receiving datagrams.
All four tables are captured sequentially, not as an atomic whole-machine view.

DWORD count, state and PID use native little-endian representation. Address
bytes, the significant first two port bytes, and IPv6 scope IDs use network byte
order. The unused upper two port bytes are ignored. A nonzero IPv6 scope is a
canonical numeric `%scope`, never an interface name; IPv4-mapped IPv6 remains
IPv6. The supported Windows 386/amd64/arm64 ABI uses DWORD alignment for these
pointer-free structures: header 4 bytes; TCP4/TCP6/UDP4/UDP6 rows 24/56/12/28.
Malformed headers, invalid state values and size overflows fail safely instead
of being relabeled as empty success. The API reports estimated/allocation size;
a table may shrink between calls. Count must fit the available bounded buffer,
and only those counted rows are parsed. Unused tail bytes are ignored, never
interpreted as endpoints or exported.

## Work, count and retention bounds

- At most four synchronous API calls per table including the nil size probe.
  Each provided table buffer is at most 1 MiB. Non-growing resize requests and
  repeated resize churn fail without an unbounded retry.
- At most 4,096 validated rows per table and 16,384 observed rows total.
- Five-second cooperative budget checked before/after calls and between parsed
  rows. An in-flight Windows API cannot be preempted; no goroutine is abandoned.
- At most 64 retained complete rows and 12 KiB canonical serialized snapshot.
  Exact duplicate API tuples are retained and counted, not deduplicated.
- Deterministic nondecreasing order: protocol, family, numeric local address,
  numeric local scope, local port, numeric remote address/scope/port, state, PID.
  A listener's absent remote sorts before any remote address.

`observedCount` counts validated rows before retention trimming. `countExact`
is true only when all four tables were completely parsed; otherwise it is a
lower bound, including zero when nothing could be read. `quality=observed`
means exact table coverage (even if retention was trimmed); `partial` means some
table data was available but coverage is incomplete. `denied` means all four
tables denied access; `unavailable` means no table data was available for other
or mixed errors. `truncated` is exactly observedCount > retained row count, not
an implicit substitute for incomplete collection. A partial result may retain
zero rows; unavailable/denied results have zero observed count and an empty row
array, never invented endpoint observations.

Caller-supplied original UTC capture, generation, grant, quality and count truth
are preserved by `FitBudget`. Budget reduction removes highest-sorted complete
rows; retry must reuse the same bytes/capture and must not recollect.
`Decode` rejects unknown/duplicate/missing/noncanonical fields, invalid scalar
bounds, ambiguous/non-numeric addresses, nonnumeric scopes, contradictory
null/state/count fields, unsorted rows and excess size.

## Source-only checks

`CollectWithReader` takes a synthetic table reader and exercises the same
production size-probe, bounded retry, parser and aggregation paths. Linux tests
use only fabricated documentation-range addresses and byte arrays. Windows
native tests inject readiness and syscall functions: they do not invoke DLL
procedures, enumerate host endpoints or open processes. The pure Windows source
runner requires these mocks; the separate native-read gate is unchanged.

Cross-compilation and injected source tests do not establish native acceptance.
A separately authorized native gate must verify real Windows API return-size
behavior (including empty/changing tables), scope byte order on scoped IPv6,
caller-token visibility/denial, listener semantics and the existing signed
sender → Linux manager → authenticated UI path. No running-host observation,
service operation, grant, installer, publication or workflow dispatch is implied.

Primary references:
- [GetExtendedTcpTable](https://learn.microsoft.com/en-us/windows/win32/api/iphlpapi/nf-iphlpapi-getextendedtcptable)
- [GetExtendedUdpTable](https://learn.microsoft.com/en-us/windows/win32/api/iphlpapi/nf-iphlpapi-getextendedudptable)
- [TCP6 OWNER_PID layout and byte order](https://learn.microsoft.com/en-us/windows/win32/api/tcpmib/ns-tcpmib-mib_tcp6row_owner_pid)
- [UDP6 OWNER_PID layout and byte order](https://learn.microsoft.com/en-us/windows/win32/api/udpmib/ns-udpmib-mib_udp6row_owner_pid)
