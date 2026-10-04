# Held Linux service and local-socket inventory contract

Status: isolated, unpublished source foundation. This package does not grant
consent, enroll identities, enable collection, transport observations, expose API
routes, retain telemetry, call AI, or update software. Runtime wiring requires
its separately reviewed fresh `managed-operations-v3` identity/consent. No actual
host provider, `/proc` collector, or `systemctl` subprocess was executed during
this implementation's tests. The Linux source is defined for boundary review.

## Exact typed model

`internal/systeminventory` exports `Snapshot`, `ServiceSection = Section[Service]`,
`SocketSection = Section[Socket]`, `Validate`, `Encode`, `DecodeStrict` (`Decode`
alias), and standalone `ValidateService`, `ValidateSocket`, `ValidateSectionMeta`.

A snapshot contains exactly:

- `schemaVersion`: `tracebolt.linux-system-inventory.v1`
- `generationId`: `sample_` followed by 32 lowercase hex digits
- `collectedAt`: nonzero UTC RFC3339 time, years 1970–9999
- `durationMs`: integer 0–9007199254740991
- `scope`: `agent-visible-linux-system`
- `services`: `{meta,items}`
- `sockets`: `{meta,items}`

Both sections' `meta` contains exactly `generationId`, `observedAt`, `coverage`,
`reason`, `observedCount`, `countExact`. Fresh snapshots require section identity
and time to equal the snapshot identity/time. Independently retained last-good
sections must retain their original metadata and must not be synthesized into a
new fresh snapshot with new labels. The standalone metadata validator accepts a
section's own original identity/time; its row-count argument is the total number
of section rows, not the number on one manager page.

`coverage=complete` requires `reason=none`, exact nonnull count equal to all
returned rows, and `countExact=true`. `coverage=failed` requires a non-success
reason, `observedCount=null`, `countExact=false`, and `items=[]`. Empty successful
enumerations remain distinguishable from unavailable observations. One section
may succeed while the other fails. No successful prefix or `truncated=true`
semantics exist in this protocol.

Service row: `{name,runtime,enablement,mainPid}`. `runtime` is either null or
`{loadState,activeState,subState}`. `enablement` is a nullable state token. These
are separate observations, not equivalent health flags. `mainPid` is required
and **always null in v1: not collected**. Services are sorted uniquely by name.
Service names are canonical systemd `.service` identifiers, 9–255 ASCII bytes,
allowing normal name characters and literal lowercase `\\xHH` escapes. States
are 1–64 lowercase alphanumeric/hyphen tokens starting with a letter; systemd
explicitly permits its state vocabulary to evolve. There are no descriptions,
unit paths, journal entries, user/account properties or process command lines.

Socket row: `{protocol,family,kind,local,remote,state,owners,attribution}`.
`protocol` is `tcp|udp`; `family` is `ipv4|ipv6`; each endpoint is
`{address,port}`, with canonical numeric `netip` spelling and port 0–65535.
IPv4-mapped IPv6 remains IPv6, with its actual mapped address. Addresses never
contain DNS names or zone/UNIX paths. Zero/wildcard endpoints are retained.

`kind` is `listener|connection|bound|unclassified`. TCP states are `established`,
`syn-sent`, `syn-recv`, `fin-wait-1`, `fin-wait-2`, `time-wait`, `closed`,
`close-wait`, `last-ack`, `listen`, `closing`, `new-syn-recv`, `bound-inactive`.
`listen` maps to listener, `closed` to unclassified, `bound-inactive` to bound,
and remaining TCP states to connection. UDP kernel state 1 maps to `connected`
and connection; kernel state 7 maps to `bound`/bound unless both ports are zero,
which is `unbound`/unclassified. UDP is never described as TCP-listening. A local
observation does not establish firewall policy or remote/external reachability.
Socket rows are validated in nondecreasing order by protocol, family, local address/port, remote
address/port, then state. Duplicate endpoint tuples are retained (for example,
multiple SO_REUSEPORT sockets), rather than discarded. Inodes are transient
correlation keys, absent from the wire model.

Owner: `{pid,processName,nameReason}`. PID is 1–2147483647 in the pinned
procfs mount's visible PID namespace. A present process name
is 1–64 bytes of valid UTF-8 without control/format/replacement characters or
slashes/backslashes and requires `nameReason=none`. Missing/invalid/denied names
stay null with a fixed reason. Owners are sorted uniquely by PID. Attribution is
`{coverage,reason}`, where coverage is `observed|partial|unavailable`.
`observed/none` requires at least one named owner; it means a best-effort scan of
accessible processes finished without a detected access/work error, **not** that
all global owners are known. An empty match is `unavailable/no_match`, not proof
of no process. Partial scans, denied PIDs, races and owner/work limits are marked
explicitly. A failed attribution never converts observed sockets to absence.

Section failure reasons are `source_missing`, `permission_denied`,
`not_supported`, `timeout`, `invalid_source`, `read_failed`, `item_limit`,
`byte_limit`, `collector_busy`, `not_collected`. Attribution additionally uses
`no_match`, `process_gone`, `work_limit`, `owner_limit`; its allowed subset is
validated independently. Raw source error strings never cross this boundary.

Every declared JSON member is required. `DecodeStrict` rejects unknown or duplicate
keys at every depth, case aliases, invalid UTF-8, omitted nullable fields, null
nonnullable fields/arrays, noninteger/exponent/negative numeric spellings,
noncanonical addresses, overflow, contradictory coverage/counts and oversized
raw or encoded JSON. Export arrays are never null. There is no polymorphic map
payload into which arbitrary metadata can be added.

## Rejection ceilings and bounded work

These are rejection ceilings, not capacity claims; encoded byte size normally
binds before maximum row counts on rows with larger names or many owners.

- 8,192 joined service rows
- 16,384 observed socket rows across all four proc sources
- 512 KiB encoded bytes per entire section, including metadata and **all owners**
- 1 MiB encoded entire snapshot including envelope
- 8 MiB raw bytes per service command or proc-net source; 64 KiB maximum line
- 64 KiB service stderr, counted and immediately discarded; any stderr or command
  failure conservatively fails services rather than certifying completeness
- 15-second cooperative overall collection deadline
- 4-second subprocess deadline per fixed service command; 1-second `WaitDelay`
- 5-second cooperative attribution deadline within the overall deadline
- 32,768 numeric process directories and 65,536 total root directory entries
- 4,096 fd directory entries per process; 262,144 fd entries total
- 16 owners per socket, with explicit `partial/owner_limit` if exceeded
- Directory batches of 128; one PID/fd scan in flight; no per-PID subprocesses

Service and socket enumeration caps reject the **entire affected section**; they
do not retain a successful prefix. If combined valid sections still exceed the
snapshot envelope cap, both sections fail explicitly with `byte_limit`.
Attribution work caps retain every socket observation and mark its attribution
partial. If accumulated owner metadata makes the encoded socket section exceed
512 KiB, that section fails `byte_limit`, never publishes a prefix or silently
drops owners to invent completeness.

The process scan is separate from network-namespace enumeration. `/proc`
visibility, hidepid/ACL/ptrace restrictions, PID/net namespaces, concurrent exit,
exec, fd changes, inode reuse and sequential reads prevent global/atomic owner
claims even when no read fails. Successful socket enumeration means all supported
rows returned by the four fixed sources within this attempt. It is not an atomic
host-wide census. Missing/denied IPv6 or any one required source fails the socket
section rather than implying zero IPv6 rows.

## Fixed source boundary (held; never exercised in tests)

`Collect` constructs the real provider only after admission; there are no
initialization side effects. It **refuses effective UID 0** and never adds
capabilities, changes identity/namespaces/firewalls, opens remote connections,
scans ports or resolves names. Non-Linux construction returns `not_supported`.
The code itself cannot verify consent: runtime must gate the call separately.

The provider pins and verifies procfs descriptors (`PROC_SUPER_MAGIC`). It accepts
only `/proc/net`'s documented `self/net` symlink and reaches that network view
through the exact canonical numeric PID returned by reading `self` relative to
the pinned procfs descriptor, then its pinned `net` directory. That PID belongs
to the proc mount's PID namespace, which can differ from the caller's PID
namespace; `os.Getpid()` is never substituted. Both links are bounded to 64 bytes
with full-buffer/truncation rejection; only literal `self/net` and a canonical
positive PID are accepted. Only fixed `tcp`,
`tcp6`, `udp`, `udp6` files are opened; final files are regular procfs entries
opened `O_NOFOLLOW|O_NONBLOCK|O_CLOEXEC`. FD-owner association only reads numeric
`/proc/<PID>/fd/<FD>` link text; it never opens the link target. It retains only
`socket:[<decimal inode>]` matches and reads that matched process's fixed `comm`
file. Other link text is discarded immediately. No cmdline, environ, status,
UID, username, executable path, payload, raw log or UNIX-socket path is exported.

Services execute only the pinned root-owned, non-group/world-writable ELF inode
for `/usr/bin/systemctl` (no setuid/setgid bits or file capabilities), beneath pinned protected `/`, `/usr`, `/usr/bin`
directories. The descriptor is passed as child fd 3 and executed directly via
`/proc/self/fd/3`; no PATH search or shell occurs. Working directory is `/`.
Exact argv (two invocations):

```
--system --no-pager --no-ask-password --all --type=service --full --plain --no-legend list-units
--system --no-pager --no-ask-password --all --type=service --full --plain --no-legend list-unit-files
```

Exact environment, with no inherited variables:

```
LC_ALL=C
LANG=C
TZ=UTC
SYSTEMD_COLORS=0
SYSTEMD_URLIFY=0
SYSTEMD_PAGERSECURE=1
```

The runtime parser takes only the first four columns (unit/load/active/sub);
optional pending-job and description columns are discarded. The unit-file parser
takes unit and enablement; optional preset is discarded. No JSON-output support
is assumed for `systemctl list-*`. Unsupported formats, missing tools, warnings,
permission failures and excess output are explicit failures, never a fallback
to a broader query. Runtime and unit-file lists are joined by unit name; a unit
present in only one list keeps null for the other source. Uninstantiated template
unit files can therefore appear without fabricated runtime state. No per-unit
`status`, `show`, MainPID lookup, journal query, service mutation, reload or start
is performed.

`Provider` supplies synchronous `OpenServices`, `OpenSockets`, `Attribute`,
`Close` methods. `CollectWithProvider` is an explicit inert/test injection seam,
not a mutable global hook. Provider ownership transfers only once admission
succeeds; rejected/canceled-before-admission calls do not consume a supplied
provider. A single atomic admission slot is held until all synchronous work and
closing return. There is no goroutine-per-read or abandoned goroutine on deadline.
Filesystem operations are cooperative and may outlast a deadline while blocked
inside a kernel call; the slot deliberately remains occupied until they return.
The subprocess implementation synchronously waits for cancellation/pipe shutdown.

## Source references

Primary reference points used for parsing and scope, checked 2026-10-04:

- [Linux kernel proc TCP documentation](https://docs.kernel.org/networking/proc_net_tcp.html)
- [Linux IPv4 UDP source](https://github.com/torvalds/linux/blob/master/net/ipv4/udp.c)
- [Linux IPv6 UDP source](https://github.com/torvalds/linux/blob/master/net/ipv6/udp.c)
- [Linux TCP state definitions](https://github.com/torvalds/linux/blob/master/include/net/tcp_states.h)
- [proc_pid_net(5)](https://man7.org/linux/man-pages/man5/proc_pid_net.5.html)
- [pid_namespaces(7), proc mount PID semantics](https://man7.org/linux/man-pages/man7/pid_namespaces.7.html)
- [proc_pid_fd(5)](https://man7.org/linux/man-pages/man5/proc_pid_fd.5.html)
- [systemctl(1), systemd project's manual mirrored by man-pages](https://www.man7.org/linux/man-pages/man1/systemctl.1.html)
- [systemd list-units implementation](https://github.com/systemd/systemd/blob/main/src/systemctl/systemctl-list-units.c)
- [systemd list-unit-files implementation](https://github.com/systemd/systemd/blob/main/src/systemctl/systemctl-list-unit-files.c)

Kernel hex addresses consist of native-endian 32-bit words; parsers use
`binary.NativeEndian` and retain IPv4/IPv6 family. Proc TCP is a deprecated
interface in favor of tcp_diag; choosing the fixed read-only proc boundary here
does not claim it is the preferred general-purpose Linux monitoring API.

## Validation evidence and remaining gates

Implemented tests use only injected literal providers/readers and pure manifests.
They cover exact JSON/nullable/duplicate/overflow rules, failed-versus-empty counts,
service/runtime enablement joins, privacy-field dropping, all supported TCP
states, UDP bound/connected/unbound semantics, IPv4/mapped IPv6 decoding,
duplicate endpoints and rejected reversed socket ordering, injected differing
caller/proc-mount PID resolution and unsafe-link rejection, row/raw/encoded
limits, independent section failure,
missing/malformed/denied attribution, owner limits and held single-flight
admission across cooperative cancellation.

Passed: focused Go tests, race tests, `go vet`, a 5-second strict-decoder fuzz run
(42,753 executions), and non-executed Darwin arm64 and
Windows amd64 and Linux arm64 test-binary cross-builds. The focused coverage result is 54.5% of
all package statements; actual Linux host-provider paths intentionally remain
unexecuted. No full-host, service, privileged, integration, deployment, publication
or reboot acceptance is implied. Manager/runtime/transport/retention/privacy
integration and explicit Linux source-boundary review remain separate gates.
