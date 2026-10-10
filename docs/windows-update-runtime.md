# Opt-in cached Windows Update runtime candidate

**Source candidate, 10 October 2026. No native Windows or installed-service
acceptance, released binary, local grant or installation is established.**
This slice connects [cached WUA inspection](windows-update-inspection.md) to the
existing Windows sender, signed manager admission, private operator view and UI.
It does not provide CVE coverage, online detection or update installation.

## Explicit local scope

The independent scope is `windows-cached-update-inspection-v1`. An owned existing
Windows inventory service must be stopped before any of these source commands:

```text
windows-service --updates-preview
windows-service --updates-enable --apply --cached-windows-updates
windows-service --updates-disable --apply
```

These examples describe the source interface, not permission to execute it.
Preview displays the full disclosure and reads existing protected state without
creating a grant. Enable requires the explicit scope acknowledgement and complete
disclosure output before dispatch. For an already configured HTTP-test identity,
add `--insecure-http-test`; the separate update plaintext warning must complete
before enabling. TLS remains default. Disable retains the grant receipt and
sender state. A subsequent explicit re-enable creates a new independent grant ID.

The grant is a protected create-only sibling of the runtime root, ending in
`-updates`. It has its own immutable manifest, lock and temporary-file names.
Missing consent in an already existing store, partial writes, foreign identity,
unsafe paths, close failures and denied access fail closed. No existing state is
adopted or repaired. The five-scope installer/coordinator, receipt, enrollment,
identity, ACLs and sequence ledger are unchanged. The combined capability APIs do
not select this scope. A manager/schema/agent upgrade grants nothing.

## Synchronous WUA isolation and authority

WUA's synchronous COM calls cannot be forcibly interrupted in an ordinary Go
collector. The installed sender therefore uses `internal/windowsupdateworker`:

- Only the current executable and one fixed internal worker switch are launched.
  There is no shell, executable selector, query selector, config path or credential
  argument. The setup/wizard entry point still rejects command-line operation.
- At most 1 KiB of canonical metadata travels through private inherited stdin:
  exact sender binding, grant ID, base generation and original capture time.
  At most 24 KiB of canonical snapshot data returns through stdout. Stderr goes
  to the null device. No secrets are inherited through environment variables;
  Windows receives only `SystemRoot` derived from the OS, not ambient input.
- Before private state or WUA access, the child verifies the inherited restricted
  LocalService identity, exact enabled owning service SID and privilege set.
  Generic LocalService membership is insufficient. It obtains its actual creator
  PID from the current process, opens only that parent for limited read/query and
  synchronization, requires a live parent created before the child, and matches
  it to the exact running SCM service. The fixed protected executable path/hash,
  service configuration, service SID, parent PID and parent creation time must
  remain identical when checked after capture. PID reuse, an exited creator, a
  replaced parent and a standalone invocation fail closed.
- The child derives the fixed enrollment path from the verified runtime layout,
  reloads the activated identity and exact protected update grant, and repeats
  these checks after capture. It never reads the administrator-only installer
  receipt or acquires the sender ledger held by the parent. IPC cannot authorize
  a grant. There is no native WUA call when a grant is missing or invalid.
- Before COM initialization or activation, the locked native thread must have no
  impersonation token and the process must report a valid High or System mandatory
  integrity label. Query failure or any other level denies collection. This is a
  read-only guard for documented machine-only COM registration behavior; it does
  not elevate the child, change registry policy or establish general isolation
  between LocalService processes. See the [activation boundary](windows-update-inspection.md).
- The parent applies a 15-second owned-process budget, kills on timeout or caller
  cancellation, and synchronously waits/reaps before returning. A 100 ms
  `WaitDelay` also bounds inherited pipe waits and joins pipe-copy goroutines.
  Output overflow immediately cancels the child. No Go goroutine is left running
  a blocked native WUA call in the service.
- A fixed 20-second child-only watchdog covers parent crashes. It targets only
  the current isolated process with `TerminateProcess`, avoiding DLL-detach
  deadlock possible with `ExitProcess`; it is stopped on clean completion.
  Parent cancellation still uses the shorter authoritative budget and reap.

The budget bounds the owned child/process and pipe lifetime subject to OS process
termination/scheduling. It does not prove a bound on WUA's internal service work,
COM server memory or Windows bookkeeping. Native measurements remain required.
The fixed native search retains `Online=false` and
`CanAutomaticallyUpgradeService=false`, with mandatory readback, and never scans
online, downloads, installs, accepts terms, changes policy/services or reboots.

Internal timeout is an `unavailable` snapshot with
`windows_updates_budget_exhausted`, bound to the original generation/capture;
ordinary inventory reporting can continue. Other worker failures use finite
unavailable reasons, never raw subprocess, COM or operating-system prose. Caller
cancellation returns cancellation with no new snapshot.

## Frame and retry contract

`tracebolt.agent-telemetry.windows.v7` requires `windowsUpdates` using the existing
`tracebolt.windows-update-inspection.v1` snapshot contract. All preceding optional
siblings remain independently selectable. Without an update grant, v1-v6 field
shape/encoding and existing persisted retry bytes are unchanged.

Updates bind exactly to the final inventory generation and `collectedAt`. Their
capture is not advanced to the worker completion, manager receipt or retry time.
Bundle generation time may follow capture. The separate grant ID cannot equal a
visible sibling grant. The complete frame remains at most 72 KiB. Only complete
optional extension rows may be trimmed to reserve a minimal update envelope;
base row ordering, startup digest, protected self metrics, original captures,
counts and grants are preserved. Update row fitting preserves unknown cache
freshness and observed/truncated/count-exact truth.

The sender checks update consent before native capture, after capture and
immediately before send. Protected identity is reread at the same production
checks. Disable or grant replacement discards affected pending bytes without
resetting sequence, while an eligible retry/restart reuses exact protected bytes
without recollection or refitting. The existing sender's monotonic durable
sequence and two-minute capture-age checks remain authoritative. The manager
binds updates to the existing strictly advancing durable inventory capture floor,
including transitions where the next generation omits updates. There is no second sender generation ledger
and no migration of the existing Windows sender manifest.

## Operator data and limitations

The authenticated Windows inventory view exposes the bounded update snapshot.
Original capture and receipt, unknown cache freshness, partial/unavailable states,
counts, truncation and already-downloaded flags remain visible. Identity
revocation and the existing private 24-hour expiry hide it. Update data does not
enter public/basic observations, AI/provider packets, event-content grants or
action permissions. Zero retained rows never means current, fully patched or
compliant. Titles and vendor severity are cached labels, not CVE assessments.

## Verification and separate native gate

Portable fixtures cover protected create-only consent, stopped/owned lifecycle
checks, disclosure short-write failures, no-grant source exclusion, all 64
independent scope combinations through TLS-verification and signed HTTP-test
admission seams, lost-response exact retry/restart, replacement/revocation races,
old retry bytes, maximal frame fitting, invalid captures and cancellation.
Worker tests use inert fixture subprocesses to prove kill/reap, bounded output,
sanitary environment and inherited-pipe cleanup. Native process identity and
watchdog tests use injected values/functions; no fixture calls WUA or terminates
a Windows host process. Windows cross-builds are compilation evidence only.

Before an installed-service/native gate, approve one disposable VM, exact reviewed
binary, cached-WUA read scope and any lifecycle/grant actions separately. Verify
actual inherited token/SCM-parent access, High/System integrity, absence of thread
impersonation, provider module provenance, creation-time and identity checks,
watchdog/stop responsiveness, worker reaping, offline traffic behavior, resource
use, disabled/unavailable WUA, stale/empty/partial cache, enable/disable/re-enable,
and exact retry into the real manager/operator UI. Source tests do not authorize
these actions or establish Windows Update CVE/installation parity with Linux.
