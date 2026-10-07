# Windows basic TLS service: guarded source candidate

This is the next source increment after the native read-only Windows collector.
It implements protected Windows state and a fixed SCM service path toward the
existing manager dashboard. It is not a released Windows installer, privileged
installation acceptance, reboot proof or Linux-v3 feature parity.

The preceding standalone Windows read-only collector passed native amd64 CI on
[2df4f5b](https://github.com/storminator89/Tracebolt/actions/runs/37590142289).
That result does not establish the state, enrollment or service changes here.

## Implemented path

1. Read-only planning resolves fixed Program Files/ProgramData locations through
   Windows KnownFolder APIs and verifies the already provisioned executable.
2. Explicit installation creates an administrator-only write-ahead intent before
   attempting SCM creation. The fixed service uses LocalService, its individual
   service SID and a restricted required-privileges list. Existing services,
   even apparently matching ones, are never adopted or overwritten.
3. Completed SCM configuration produces a bound receipt. Partial creation and
   incomplete receipts remain for inspection; there is no rollback deletion or
   automatic retry which could adopt a foreign installation.
4. The installer creates a separate protected runtime root and prepared empty
   enrollment store, bound to the individual service SID. It copies only the
   validated public bootstrap into that root.
5. The hidden local console prompt collects the invitation after showing exact
   TLS trust, public key fingerprint and comparison value. The existing guided
   protocol durably commits a pending claim. The manager operator still has to
   compare and approve that specific identity.
6. The SCM service resumes only that committed operation, retaining its original
   pending deadline. Recoverable per-attempt timeouts and transport failures retry
   in process with bounded cancellation-aware backoff and reinspection of the
   same retained identity and original expiry. A 15-minute session limit never
   shortens or renews the original approval window. On activation, the existing sender obtains a durable replay
   ledger and transmits bounded basic observations over the existing TLS ingress.
   SCM Running means its locally validated lifecycle is running; it does not
   mean the manager approved the device or accepted a report.

Only Windows + production TLS + `basic-readonly-v1` are admitted. The existing
basic scope provides numeric OS version, uptime, physical RAM and system-volume
utilization. It does not transmit the standalone collector's expanded hostname,
IP, process, service, software or event inventory. CPU remains unavailable in
this basic sender contract. Expanded Windows transmission requires a separately
reviewed Windows wire/profile increment. Windows Update/CVE remains later work.

Linux retains its existing profiles, transports, storage implementation and CLI.
A manager configured for Linux `managed-operations-v3` still rejects Windows
invitations. The lower-level enrollment state model already recognized Windows;
this change adds only the precise basic TLS admission and local-platform checks.
The dashboard's generic approved-device/basic-metrics path is reused. No new
Windows installer button, Windows release download or expanded dashboard view is
claimed by this source candidate.

## Protected state and authority

`internal/windowsstate` uses a fixed schema with pinned native directory handles,
relative `NtCreateFile` operations, explicit protected DACLs, owner checks,
exclusive locking, file IDs, hashes and bounded reads. It rejects reparse points,
additional hard links, alternate data streams, unexpected files, changed owners,
changed ACLs, replaced files and missing previously initialized objects.

Runtime DACLs permit the exact service SID, SYSTEM and Administrators. Installer
state has a separate SYSTEM/Administrators-only schema. Generic LocalService
ownership is rejected. The unrestricted service SID is checked as enabled and
owner-capable, so the runtime can create service-SID-owned files without turning
on ownership/restore/debug privileges. The agent is not LocalSystem.

A durable pending manifest precedes file replacement or child-store creation.
The temporary file is flushed before handle-relative replacement and the final
manifest is committed after identities are recorded. An interrupted operation
fails closed on reopen; automatic recovery, state reset and re-enrollment are
not implemented. Filesystem flushes do not establish every storage stack's
physical-power-loss ordering. Trusted-administrator compromise and whole-volume
rollback are outside this local boundary.

The initial store implementation deliberately supports fixed local NTFS volumes
and canonical ASCII drive-absolute paths, with existing parent directories.
UNC/device/relative paths, DOS aliases, alternate streams, non-ASCII paths and
other filesystems fail closed. These restrictions must be visible in a future
installer's preflight rather than bypassed silently.

## Fixed service lifecycle

- Service: `TraceboltWindowsAgent`
- Account: `NT AUTHORITY\LocalService`
- Binary: machine Program Files + `\Tracebolt\tracebolt-windows-service.exe`
- Runtime root: machine ProgramData + `\Tracebolt\windows-agent`
- Administrator-only installer root: runtime-root path + `-installer`
- SCM command: quoted fixed binary with only `--run-service`

There is no arbitrary command, shell, PowerShell script, service name, service
account or remote target option. Start/stop results report a requested transition
and the observed state; they are not fabricated completion. Uninstall requires a
stopped, receipt-bound service and retains all private state. SCM deletion can
remain pending until Windows releases outstanding handles.

Failures expose only [finite phase/reason service codes](windows-service-diagnostics.md),
including expired approval, rejected state, denied runtime read access and sender
failure. Unknown errors never expose arbitrary native text or paths.

The service worker cancels on Stop/Shutdown and is not reported stopped until it
actually returns. Pending initialization, manager approval and runtime failure
remain separate states. A normal console cannot enter SCM runtime, and the
runtime validates LocalService plus the expected owner-capable service SID and
its privilege boundary before opening enrollment state.

## Source command surface, not a request to execute

Build the source executable with the repository's pinned toolchain. Before any
native installation, explicitly approve the exact disposable Windows VM,
privileged service creation, persistence, protected SID/DACL changes and endpoint
identity creation. Source tests do not give that approval.

The future manually approved VM gate can exercise these existing commands after
its separate provisioning prerequisites have been satisfied:

```text
tracebolt-windows-service.exe --plan
tracebolt-windows-service.exe --inspect
tracebolt-windows-service.exe --install --apply --basic-readonly --bootstrap-file ABSOLUTE_PROTECTED_PUBLIC_BOOTSTRAP
tracebolt-windows-service.exe --enroll --apply --basic-readonly
tracebolt-windows-service.exe --start --apply
tracebolt-windows-service.exe --stop --apply
tracebolt-windows-service.exe --uninstall --apply
```

Installation combines the explicitly acknowledged basic/persistent scope with
hidden invitation entry and then requests pending-service start. If enrollment
is interrupted, the existing stopped installation can use the separate enroll
operation; it never replaces the bootstrap, identity or original deadline.
Manager approval remains a separate deliberate fingerprint/comparison step.

The binary and its parent directories must already be provisioned with trusted
owners, non-replaceable permissions and the explicit LocalService rights in the
[runtime-read preflight](windows-runtime-read-preflight.md). The public bootstrap input must be in a
protected administrator-only location. This candidate neither downloads/copies
binaries nor repairs ACLs, adds groups or substitutes weaker input handling when
those prerequisites fail. A one-command released installer is a later milestone.
Never put invitation bytes in arguments, environment, files, redirected stdin or
logs. Hidden input uses the real local console and restores/validates its original
mode on success, failure, cancellation and panic.

## Checks and remaining gates

Portable fixtures cover profile admission, a synthetic Windows basic enrollment
lifecycle, real manager-store ingress/dashboard-model projection with invented
RAM/disk values, wrong-platform/profile rejection and replay preservation,
state/DACL policy, write ordering and crash poisoning, SCM receipt
binding, lifecycle cancellation, input parsing and CLI consent boundaries.
Windows-only automated tests in this increment are in-memory descriptor/ABI/
constant checks. They do not create directories or endpoint keys, modify ACLs,
install/control a service, or interact with a real console.

Required separately authorized native acceptance remains:

- Exact protected state create/read/replace/reopen under the real service token
- Denial to an unrelated LocalService process and an ordinary user
- Hidden console entry/restoration, including cancellation and redirected input
- Installation, pending approval, fingerprint approval and first dashboard report
- Genuine stop/shutdown, interrupted write behavior and actual OS reboot
- Replay rejection, same-byte retry, certificate expiry/revocation and uninstall
- Windows desktop versions and native ARM64 beyond the hosted source-test runner

Until those gates pass, describe this as an implemented, fixture-tested service
candidate. The existing Linux release remains the shipped installation path.

## Implementation references

- [Protected state API and limits](../internal/windowsstate/README.md)
- [SCM lifecycle API and Microsoft references](../internal/windowsservice/README.md)
- [Hidden console input and Microsoft references](../internal/windowsconsole/README.md)
- [First Windows read-only collector increment](windows-agent-foundation.md)
