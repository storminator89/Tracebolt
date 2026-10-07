# Windows agent foundation: explicit read-only preview

This additive source candidate introduces `cmd/windows-agent`, a real native
Windows inventory collector with a local JSON output. It is a first useful slice,
not an installed or enrolled Windows fleet agent. The existing Linux sender,
release pin and default `cmd/agent` contract are unchanged.

## What is implemented

| Section | Fixed local source | Bounded scope |
| --- | --- | --- |
| OS and uptime | Existing `RtlGetVersion` and `GetTickCount64` adapter | Numeric NT build and elapsed system-start time |
| CPU | Two `GetSystemTimes` reads, 250 ms apart | Percent busy for systems with one processor group; multi-group data stays unknown |
| RAM | `GlobalMemoryStatusEx` | Physical memory unavailable as a percentage of total |
| Disk | `GetDiskFreeSpaceExW` on the fixed system-directory drive | Caller-quota-aware system-volume capacity, not every volume |
| Hostname | `GetComputerNameExW` via Go `os.Hostname` | Local physical DNS hostname, no domain/user/serial inventory |
| Interfaces | One fixed 1 MiB `GetAdaptersAddresses` query | At most 128 interfaces and 512 up, non-loopback local unicast IP/prefix rows; does not emit MAC, routes, DNS or socket ownership |
| Processes | Toolhelp process snapshot | Up to 2,048 caller-visible PID, parent PID, executable basename and thread-count rows; no command line, full path, owner or process memory |
| Services | `EnumServicesStatusExW` with enumeration-only SCM rights | Up to 2,048 visible Win32 service name, display name, state and PID rows; one 256 KiB API buffer; no driver inventory or service control |
| Software | Fixed HKLM uninstall-registry location, separate 64/32-bit views | Up to 2,048 name/version/publisher registrations; no `Win32_Product`, MSI consistency/repair, uninstall commands or arbitrary registry paths |
| Optional event headers | `EvtQuery`, `EvtNext`, fixed-property `EvtRender` | Newest 25 Application and 25 System event headers; provider, event ID, level, timestamp, channel and record ID only |

Software registrations are not a complete installed-software catalog: per-user,
Store, portable and unregistered applications are outside this slice. Service
entries without query-status rights may be silently omitted by Windows.
`complete` is always relative to the stated, caller-visible section scope, never
proof that every object on the host was visible. Limits, malformed rows and
permission failures cannot become an empty healthy complete inventory.

The network query skips anycast, multicast and DNS-server lists and does not request gateways. The native adapter structure can include additional OS fields, such as a MAC address or DNS suffix, but the code never reads or emits them. An oversized network response remains unavailable/truncated; there is no unbounded allocation or retry.

The full output is capped at 4 MiB. Strings are bounded and control characters
are rejected. Raw Windows errors never enter the JSON or diagnostics. Values
remain local on stdout; the command has no network sender, credential store,
background loop, shell, PowerShell or remote execution endpoint. It requests no
elevation or token privileges and changes no registry values, services, logs,
firewall settings, ACLs or group memberships.

## Run deliberately on an authorized Windows test machine

There is no released or signed Windows download yet. Build the reviewed source
with the revision's pinned Go toolchain. These are developer preview commands,
not the Linux dashboard installation command:

```powershell
go build -buildvcs=false -trimpath -o .\bin\windows-agent.exe ./cmd/windows-agent
.\bin\windows-agent.exe --help
.\bin\windows-agent.exe --collect-read-only
```

The explicit flag acknowledges the inventory listed above. With no flag, help or
invalid arguments, no host observation is collected. Review the output privately;
it contains identifying host, network and software information. Do not paste it
into public issues or CI logs. The command never writes a report file itself.

For the separately acknowledged event-header scope:

```powershell
.\bin\windows-agent.exe --collect-read-only --event-metadata
```

There is no caller-supplied channel, XPath, exported-log file or remote host.
Security logs, rendered messages, XML/EventData, usernames and SIDs are excluded.
A denied channel is reported as unavailable/partial without broadening access.
Event collection has a cooperative five-second budget; an in-flight synchronous
Windows call cannot be preempted. The overall command has a cooperative 30-second
budget and finite per-source work/row limits. External CI timeout is independent.

## Why this is not yet a Windows LAN installation

At the base revision `7b20a93e481feb1f7433ee0ef6c912a35f68ce6d`:

- `cmd/enroll-agent` and `cmd/lan-agent` explicitly reject non-Linux execution.
- `cmd/enroll-agent/terminal_other.go` does not implement hidden invitation input.
- `internal/enrollmentclient/protocol.go` validates a Linux platform response.
- `internal/enrollmentservice/service.go` admits Linux enrollment only, although
  the lower-level state model recognizes the Windows token.
- `internal/lanclientstate` and `internal/lanconfig` depend on Linux-owned,
  no-follow filesystem handles and Unix protection/lifecycle guarantees.
- Manager inventory, overview, system and health views bind the complete profile
  to activated Linux identities. This standalone report is deliberately not
  submitted as Linux inventory or accepted by those manager endpoints.

Removing the platform checks would not implement the missing Windows ACL,
identity, durable-state or manager-admission boundaries. Existing Linux grants
must not be reused as Windows authorization.

## Next coherent slice: Windows enrollment and service architecture

These are implementation requirements, not shipped commands or host grants:

1. Introduce a distinct, immutable Windows read-only collection profile and
   schema admission. Bind its exact scope to the local identity and manager
   approval. Keep the Linux v3 profile, ledgers, clients and views intact.
2. Add a hidden local console invitation prompt using Windows console mode,
   restoring mode on all exits. Never accept invitation secrets via arguments,
   environment, redirected stdin, URLs, log files or chat.
3. Implement Windows durable identity/replay state using handles, reparse-point
   rejection, create-only initialization, exclusive locking, atomic replacement
   and verified protected DACLs. Check owners and actual rights; Unix mode bits
   such as `0600` are not Windows ACL validation. Preserve existing state after
   interruption and fail closed on identity, counter or grant disagreement.
4. Implement a Windows SCM service host using a low-privilege service account
   and service SID scoped to its state. Keep installation/elevation separate
   from normal runtime. Do not default the collector to LocalSystem or grant
   SeDebugPrivilege. No arbitrary service-control, command or PowerShell API.
5. Make installation a deliberate, one-time elevated local ceremony. Present
   the read scope, service/account identity, persistence and protected-state
   changes together; obtain the required action-time authorization before
   applying them. Optional log-content/Security access needs a distinct grant.
   This preview does not grant Event Log Readers membership or alter log ACLs.
6. Reuse the reviewed manager trust/fingerprint comparison and explicit operator
   approval flow after Windows-specific protocol/state validation. The service
   stays pending and does not transmit expanded inventory before activation.
   Use the production HTTPS path; no implicit downgrade to HTTP.
7. Add a simple Windows choice in the existing install UI only when verified
   signed artifacts and compatible manager admission exist. Show one public
   command, one local scope confirmation, hidden invitation input and the same
   dashboard identity comparison. Do not display a working installer now.
8. Test a disposable Windows VM under the intended service identity: standard
   user denial boundaries, install/start/stop, interrupted approval, persistence
   after actual OS reboot, replay rejection, identical retry bytes, same-identity
   upgrade, revocation and uninstall. Persistent identity/service creation is a
   separate action-time-approved test gate, not implied by source/CI checks.

Windows Update inventory and Windows-specific CVE matching come after this
identity/service slice. Linux APT data or CVE labels must not be reused for
Windows. Process CPU/memory, all-volume usage, sockets, drivers, per-user/Store
software and event message content are also outside the initial collector.

## Verification and acceptance boundaries

Portable fixture/race tests exercise CPU delta arithmetic, row/string limits,
malformed data, permission failures, cancellation, consent, output caps and
sanitized diagnostics. The Event Log adapter additionally tests its fixed native
value layout and native metadata parser. Windows amd64/arm64 builds establish
compilation only.

`.github/workflows/windows-readonly.yml` runs the actual collector and Event Log
adapter on `windows-2025` amd64. Its Python gate captures all runtime data in
memory, requires both named native tests to pass without skips, verifies the
CLI consent boundary and performs an ARM64 cross-build. It uploads no telemetry,
logs or binaries and installs no service. A passed hosted gate demonstrates that
runner/token combination only; it does not prove standard-user, Windows 10/11,
ARM64 native, reboot or installed-service acceptance. Inspect the exact commit's
workflow result before claiming even hosted Windows runtime passed.

## API references

- [GetSystemTimes](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-getsystemtimes)
- [Toolhelp process snapshots](https://learn.microsoft.com/en-us/windows/win32/toolhelp/taking-a-snapshot-and-viewing-processes)
- [EnumServicesStatusExW](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-enumservicesstatusexw)
- [Service access rights](https://learn.microsoft.com/en-us/windows/win32/services/service-security-and-access-rights)
- [Uninstall registry properties](https://learn.microsoft.com/en-us/windows/win32/msi/uninstall-registry-key)
- [Event metadata API references and adapter notes](../internal/windowsevents/README.md)
- [Windows ACLs](https://learn.microsoft.com/en-us/windows/win32/secauthz/access-control-lists)
- [Service user accounts](https://learn.microsoft.com/en-us/windows/win32/services/service-user-accounts)
