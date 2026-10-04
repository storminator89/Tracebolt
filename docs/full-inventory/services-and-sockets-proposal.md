# Service and socket inventory: next scoped design

Status: design only, separate from the frozen release and complete-dpkg packages.
The user requires useful administrative visibility of installed software, running
services and open ports. Dpkg completeness does not cover other software managers,
and local socket visibility does not establish external reachability.

## Service view

Keep system-service runtime state and startup configuration separate. Proposed
fields are unit name, load/active/sub state, unit-file enablement state, main PID
when observed, original collection window and per-field availability. A service
can be active but disabled for startup, or inactive but enabled. Static, generated,
alias, transient and template units are not simply enabled/disabled booleans.
Unknown/new systemd states remain explicitly unknown instead of healthy defaults.

The current bounded128-row runtime list is not complete installed-unit coverage.
The source adapter should reconcile the full supported system-service runtime and
installed-unit sets, then transfer them using bounded complete generations and
searchable pages. Systemd documents that list-units represents loaded units and
that list-unit-files is needed for installed templates; their scopes must not be
conflated. Use only reviewed fixed introspection commands or a fixed read-only
D-Bus interface, with no shell, descriptions, ExecStart, environment, user/account
fields or journal message text. Do not use human-oriented status output, which
also includes recent logs. [systemd v255 systemctl documentation](https://raw.githubusercontent.com/systemd/systemd/v255/man/systemctl.xml)

Per-user service managers are separate unsupported coverage unless independently
implemented and acknowledged. Systemd unavailable/denied is not a zero-service
result. Parse and resource failures must not publish a complete prefix. Runtime
state changes during a sample window are expected; this is an observation window,
not a transaction freezing every service in the OS.

## Network socket view

Proposed IPv4/IPv6 TCP/UDP row fields:

- protocol, address family and fixed socket-state classification
- numeric local address and port
- numeric remote address/port where meaningful; otherwise explicit null
- TCP listening versus connection rows; UDP bound/connected semantics remain UDP,
  not a fabricated TCP-style listening guarantee
- zero or more observed owning PID/process-name associations, with independent
  attribution coverage/reason
- sample generation and start/end timestamps, source namespace scope and freshness

Process names and local/remote addresses can reveal user activity or sensitive
network topology. They require an explicit new consent/version boundary and must
remain out of AI packets and public artifacts. Exclude usernames/UIDs, command
lines, environment, payloads, DNS lookups, UNIX-socket paths, credentials and
arbitrary interface/process/filesystem targets. No remote connection is opened
and no port scan, packet capture, firewall edit or reachability probe occurs.

Label results **locally observed TCP listeners / UDP-bound sockets / connections**.
A wildcard bind, loopback bind and specific address are distinct; none proves that
a firewall, NAT or remote route admits traffic. IPv6 dual-stack behavior must not
be inferred solely from an IPv6 wildcard row. External reachability remains
unknown without a separate explicitly authorized test.

## Sources, permissions and completeness

Select one fixed kernel source contract after fixture review. Kernel documentation
prefers socket diagnostics over the older TCP proc interface. The current service
sandbox excludes AF_NETLINK, so adopting a diagnostic socket would need an
explicit reviewed unit/permission change rather than silently weakening it.
A fixed proc-based first adapter can avoid that change, but must parse only the
selected fields and acknowledge the interface's limitations. [Linux TCP proc interface](https://docs.kernel.org/networking/proc_net_tcp.html)

The network view belongs to the agent's network namespace, not every container or
host namespace. `/proc/net` is the process-relative namespace view; do not enter
other namespaces or claim host-wide coverage. Socket-to-process joins may be
missing because a process exits, descriptors change, or permission is denied.
Linux restricts process descriptor inspection; do not add capabilities, change
proc mounts or run the agent as root to manufacture complete ownership data.
[Linux proc network scope](https://man7.org/linux/man-pages/man5/proc_pid_net.5.html),
[Linux process-descriptor permissions](https://man7.org/linux/man-pages/man5/proc_pid_fd.5.html)

A successful enumeration means the selected source was consumed within its
sample window. Highly dynamic sockets cannot provide an atomic simultaneous host
snapshot. Socket enumeration and PID attribution have separate completion flags;
an attribution work cap can leave process owners unknown without dropping the
socket rows. Source-byte, FD-scan, time, per-generation spool and manager-storage
budgets need explicit measured ceilings. Exceeding the socket enumeration budget
fails the new generation; it must not silently report the firstN sockets as all.
Retain a previous complete generation only with its original age and clear label.

## Implementation and acceptance order

1. Finish complete-dpkg generation/store/pagination and source tests first.
2. Add separately typed service and socket contracts, privacy/coverage fields and
   strict pure parser fixtures. Do not generalize package rows into untyped blobs.
3. Add bounded inert-provider adapters and PID attribution race/denial fixtures.
4. Review the explicit consent/profile, transport, retention and service sandbox
   integration; no new privilege grant is implied by this design.
5. Test real loopback listeners and established connections created only by a
   disposable authorized fixture, then explicit native service acceptance. No
   network scan or production endpoint collection is part of the pure-test gate.

UI search/pagination must traverse complete committed supported datasets, retain
original collection times and expose coverage limits. No missing service, process,
connection, update or CVE may be inferred absent from a failed/partial view.
