# Fixed Windows SCM service source candidate

This package is an implementation and fixture-tested foundation, not evidence of
an installed agent, native lifecycle acceptance, successful enrollment/reporting,
or boot persistence. No test installs a service, changes a host ACL, creates a
credential, or invokes the live SCM runtime.

## Boundaries

- One service: `TraceboltWindowsAgent`; one account:
  `NT AUTHORITY\LocalService`; own-process, automatic startup, no dependencies,
  triggers, recovery commands, shell invocation or configurable command arguments.
- The binary is `ProgramFiles\Tracebolt\tracebolt-windows-service.exe` and the only
  SCM argument is `--run-service`. Both are explicitly quoted. ProgramFiles and
  ProgramData come from Windows KnownFolder APIs, never environment variables.
- State layout is `ProgramData\Tracebolt\windows-agent`, with enrollment and
  telemetry children. This package does not create, open, grant access to, erase,
  reset, recover or adopt identity/counter state.
- `SERVICE_SID_TYPE_UNRESTRICTED` adds the service-specific SID to the limited
  account token; it does not switch to LocalSystem or grant administrator rights.
  SCM required privileges are limited to `SeChangeNotifyPrivilege`. Runtime
  requires LocalService user SID, the expected enabled/non-deny-only service SID
  with `SE_GROUP_OWNER`, no enabled Administrators SID, and no additional token
  privileges (even disabled privileges). No `SeDebugPrivilege` grant is made.
- Install and runtime are separate APIs. `Run` connects to SCM and cannot install,
  grant ACLs, or fall back to an administrator foreground worker. The privileged
  coordinator may perform only the separately approved, hidden-input `ClaimOnly`
  operation and write SID-protected pending identity. Approval resumption,
  activation and telemetry transmission run only in the limited service token.

## APIs and coordinator contract

`ResolveLayout`, `LookupServiceSID`, `ValidateRuntimeIdentity`, `Inspect`, and
`Plan` and `InspectOwned` are read-only. `InspectOwned(ctx, receipt)` requires the
exact completed protected receipt, current SCM binding and trusted executable
hash; an enrollment coordinator must additionally require `Stopped`. `Plan` requires the selected executable to be provisioned
already. It checks every component for reparse points, rejects non-fixed drives,
checks trusted owners and replacement-capable DACL access, holds the path chain
against deletion while hashing, denies executable write sharing, and rejects
hard-linked executables. Trusted executable owners/writers are SYSTEM,
Administrators and TrustedInstaller. It grants or repairs nothing. Unexpected
ACL forms fail closed; native acceptance must validate target-specific defaults.

The same held-descriptor check also requires LocalService-specific effective
allow ACEs for executable read/execute and for descriptor/attribute read and
traverse on every ancestor, including the volume root. SYSTEM/Administrators-only
permissions now fail before installation or an owned enrollment preflight.
Required-access denies fail conservatively regardless of trustee or ACE order.
`ErrRuntimeReadAccess` identifies a missing/denied runtime grant. This is a
sufficient-DACL source policy, not a simulated token or proof that the future SCM
token can load the image. See the [runtime-read policy and native acceptance
limits](../../docs/windows-runtime-read-preflight.md).

The parent coordinator owns explicit authorization, independently selected byte
verification, artifact placement and protected durable installation records. It
must persist a create intent before `ApplyInstall(ctx, plan)`. The plan's random
installation ID and executable SHA-256 are stored as public metadata in the
SCM description and returned in the receipt.
Every subsequent operation requires the protected completed receipt and exact
current configuration, SID, installation marker and resolved layout. Starting
also rechecks the trusted executable hash.

`ApplyInstall` is create-only. Even a matching existing service is rejected; a
missing receipt never licenses adoption. Creation starts disabled and changes to
automatic startup only after SID/privilege configuration succeeds. On partial
failure, an incomplete receipt is returned with the error. No rollback deletes
that object. Keep the intent and partial record for a separately authorized
manual diagnosis; do not retry by inventing a receipt or deleting state.

`ApplyStart` and `ApplyStop` return both the requested action and an observed
status; pending does not mean completed. Repeating a request while a transition
is pending is rejected. `ApplyUninstall` requires a stopped, matching service and
marks only the SCM object for deletion; other open handles can delay deletion.
It does not stop the service implicitly or delete binaries/private state. The
caller must observe absence separately before claiming deletion completed.

`Run(ctx, worker)` uses `golang.org/x/sys/windows/svc.Run` and validates the runtime
token before calling the worker. It also checks the actual executable path,
trusted path/ACLs, SCM's recorded executable digest and exact fixed configuration.
The administrator receipt is not read by the service. SCM's process ID is checked
only for a running snapshot because Windows does not guarantee a valid PID in
`START_PENDING`; fixed SCM dispatch and the service-SID token establish startup
identity. The worker calls `ready()` after local
initialization, then stays alive and obeys context cancellation. `Running` means
the initialized loop accepts controls; it says nothing about manager approval or
report receipt. Stop, shutdown, closed control transport and parent cancellation
produce `StopPending`, cancel the worker, and wait for its exit. No timer invents
checkpoint progress. A stuck worker stays pending; final `Stopped` is sent by
`svc.Run` only after the callback exits. Unexpected worker exit is a failure.

## Verification and remaining gates

Default tests use injected service handles and workers on every platform. Windows
native-only tests parse allocated privilege buffers, check structure layouts,
and validate in-memory SDDL descriptors. They perform no SCM or filesystem
mutation. Cross-compiling those tests does not execute their Windows ABI cases.

A separately approved disposable native Windows VM gate must still establish
artifact/parent ACL acceptance, actual create and SID lookup, LocalService token
restrictions, service-SID-owned state access, callback initialization, stop and
shutdown cancellation, retained-state uninstall, and a genuine guest reboot.
Native credential enrollment, manager trust approval and reporting also need
independent authorization and evidence. Ordinary Windows CI must not turn these
fixtures into an installation/credential test.

## Primary contracts

- [LocalService account](https://learn.microsoft.com/en-us/windows/win32/services/localservice-account)
- [Service SID configuration](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/ns-winsvc-service_sid_info)
- [Required service privileges](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/ns-winsvc-service_required_privileges_infow)
- [Service state transitions](https://learn.microsoft.com/en-us/windows/win32/services/service-status-transitions)
- [Service status](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/ns-winsvc-service_status)
- [CreateServiceW quoting and account parameters](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-createservicew)
- [DeleteService deferred deletion](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-deleteservice)

- [SCM process ID validity](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-queryservicestatusex)
