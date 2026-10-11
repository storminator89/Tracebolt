# Local own-agent restart source candidate

This candidate adds exactly one explicit local command to a newly built
`tracebolt-windows-service.exe`:

```text
tracebolt-windows-service.exe --restart --apply
```

Use it only with explicit authority to interrupt this installed agent. It is
not in the published Windows preview, and source fixtures/cross-builds do not
establish native acceptance of these changed bytes. No installer, service or
native host gate was run to implement this candidate.

## Scope and admission

The only target is the existing `TraceboltWindowsAgent` SCM object, under the
existing limited `NT AUTHORITY\LocalService` account and service SID. The command
accepts no service name, executable path, arguments, deadline override or remote
request. It requires the existing protected, prepared, completed installation
receipt. The receipt is ownership evidence, not a new authorization token.
Missing, foreign, incomplete or staged receipts are rejected without adoption.

The initial SCM state must be Running. Initially Stopped, StartPending,
StopPending, paused and unknown states are rejected with no control request.
Use the separate explicitly approved `--start --apply` operation when startup
is actually intended. Restart never silently converts into start, enrollment,
repair, upgrade, reconciliation, collection enablement or uninstall.

Restart can interrupt reporting and discard memory-only in-flight event-message
results. Identity, grants, durable consumed-work floors and original expiry
remain in force; no request is reset, replayed or recaptured using old authority.
The draining sender may legitimately advance its existing durable counters.
This operation does not promise byte-for-byte unchanged live sender state.

## Exact effect sequence

1. Open the existing administrator-only installer store and keep its exclusive
   native lock held while reading and decoding the exact protected receipt.
2. Validate the fixed resolved layout and receipt digest. Open one local SCM
   service handle with only QUERY_CONFIG, QUERY_STATUS, STOP and START rights;
   SCM itself needs only CONNECT. Retain that handle for the whole restart.
3. Verify every supported configuration field, installation marker, service SID,
   trusted executable/hash and protected lease. Reobserve Running, with a
   nonzero SCM process ID, before attempting STOP once.
4. Observe Stopped using the same handle. Pending or the most recently reported
   pre-stop state may be polled within the fixed observation budget. Unexpected
   states, lost ownership and observation errors stop the sequence.
5. Reverify the lease and executable/hash, and reobserve the same exact owned
   configuration/SID in Stopped. Attempt START once with no arguments.
6. Observe Running, then reverify the executable/lease and reobserve Running.
   Close the service handle, verify the installer store and release its lock.

One held SCM handle prevents closing/reopening by name from targeting a replaced
service. The lock coordinates this version's own CLI/Setup paths, not arbitrary
external administrator tools, SCM automatic startup, shutdown or a hostile
administrator. SCM has no atomic compare-and-control operation against external
privileged changes; no broader SCM database lock or security setting is added.

The total cooperative restart budget is 45 seconds with at most 184 observations
and 250 ms between polls. Native SCM, trust and filesystem calls are synchronous:
Windows can keep a call blocked beyond that budget. The code checks cancellation
and time before/after calls and rejects late results. It does not abandon a
background goroutine, release the lease during an outstanding effect, terminate
a process or claim a hard wall-clock cancellation guarantee. The public deadline starts before receipt/lease acquisition and is rechecked
after final verification and closure. Those calls also have no interruptible
native-call guarantee.

## Results and interruption

The command emits bounded JSON with finite `outcome` and `phase`, individual
`stopAttempted`/`stopRequested` and `startAttempted`/`startRequested` flags,
`stoppedObserved`, `runningObserved`, historical `lastObservedState`, observation
count and `stateRetained`. It emits this partial result on an error as well as
on success; the exit status remains nonzero on failure. Raw native error text,
paths or command output are not added to diagnostics.

- `not-requested`: no control was attempted; admission or initial state failed.
- `intervention-required`: a control may have taken effect, or final verification
  or release failed. Earlier observations remain historical evidence, not a
  claim that the current state is known.
- `running-observed`: both controls returned success, Stopped and subsequent
  Running were observed, and final checks/closure succeeded.

`Attempted` is set before the native call. `Requested` only means that call
returned success; it does not prove the asynchronous transition finished.
A control error can occur before or after a side effect. There is no retry,
compensating restart/stop, dependent-service stop, service deletion, process kill,
start-type change, ACL repair, privilege expansion or persistent-state reset.
After an uncertain result, retain the receipt/state, use read-only `--inspect`
for diagnosis, and obtain a deliberate decision before another lifecycle action.
Do not automatically rerun this command to force completion.

SCM status is its most recently reported state. A nonzero Running PID is required
but is not compared across restart because PIDs can be reused. Pending/Stopped
PIDs are never used as process proof. Running does not establish activated
manager trust, current telemetry, application health, successful delivery,
shutdown persistence or an operating-system reboot. The existing runtime can
report Running before enrollment/telemetry readiness.

## Shared exclusion and setup compatibility

The existing installer-store manifest, lock file, file identities, ACLs and
schema are unchanged. All receipt-dependent CLI paths, including existing
start/stop/uninstall, enrollment and stopped-service consent, hold the same store
until their operation returns. GUI removal holds it through stop, deletion and
absence observation; its completion message waits until release succeeds.
Concurrent access fails closed rather than waiting on or recreating a lock.

Fresh/basic setup now retains its original create-only journal through final
startup. Durable protected verification replaces the former early Close before
enrollment. The fresh five-scope coordinator writes its existing progress
receipts through that same open store, avoiding nested/reentrant acquisition.
Every receipt remains durably written and verified before the subsequent effect.
The scope contract, receipt bytes, incomplete-state fencing and first-start
semantics are unchanged. A final close failure can now follow an attempted
startup; it returns an error with retained effect evidence, never a claim that
nothing happened. Earlier errors and close errors are both preserved.

The legacy `ApplyStart`, `ApplyStop` and `ApplyUninstall` result schemas and
asynchronous semantics are unchanged. The lifecycle library remains a low-level
API whose caller owns the protected installer lease; it does not acquire a
second store or grant rights. The new restart API also requires that lease for
revalidation.

## Remaining parity and acceptance work

This is own-agent lifecycle parity only. It does not implement manager-driven
control of another Windows service. That still needs a separate reviewed broker,
exact target-service ACL/authority design, selected-action protocol, local
approval, durable consume-once dispatch and intervention results. None of those
permissions follows from this command, service health, existing read scopes or
Linux action authority. Same-identity repair/upgrade is also separate work.

A separately authorized disposable Windows gate must exercise exact candidate
bytes, real lock contention, existing SID/config/hash checks, stop/start and
cancellation/late outcomes, and retained sender/enrollment behavior. Cross-builds
for amd64/arm64, portable injected tests, race/vet and source guards are source
evidence only. They neither grant host access nor inherit the old preview's
native acceptance.

## Primary contracts

- [QueryServiceStatusEx and PID/state validity](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-queryservicestatusex)
- [Starting a service requires subsequent status observation](https://learn.microsoft.com/en-us/windows/win32/services/starting-a-service)
- [ControlService synchronous control behavior](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-controlservice)
