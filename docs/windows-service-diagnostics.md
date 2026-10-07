# Windows service finite diagnostics and pending retry

The Windows basic-service candidate returns stable, bounded phase/reason codes
instead of a generic service-specific code 1. This is source functionality, not
native SCM/service-installation acceptance.

## Pending approval lifecycle

`ResumeService` has a bounded 15-minute session while the original locally bound
manager approval window may be 30 minutes. Exhausting one session is not proof
that the original approval expired. The Windows coordinator now:

1. Revalidates the runtime identity and opens the same retained pending identity.
2. Checks the original deadline and exact fixed TLS handoff path.
3. Resumes only that saved operation; it never enters an invitation or creates a
   new key, identity, claim, state directory or deadline.
4. On a recoverable session timeout or transport error, re-inspects before a
   five-second cancellation-aware wait and again after that wait before retry.
5. Stops on actual original expiry, terminal enrollment, state loss or identity
   rejection. Expiry records only the existing monotonic local stop marker.
6. Re-inspects activation and durably marks the exact handoff before constructing
   the sender. A successful resume return alone is not treated as readiness.

Running still means the validated local service loop accepts controls; it does
not mean approval or reporting succeeded. Normal Stop/Shutdown cancels a pending
attempt or backoff and retains its cancellation category, so orderly shutdown
returns zero. A real state, expiry, terminal, handoff or sender failure observed
concurrently with Stop remains a failure. Mixed error chains containing both an
authority failure and cancellation are never normalized to success. Only
exclusively cooperative cancellation chains receive that treatment. This is not
an SCM automatic-restart policy, enrollment reset or
extension of the approval window.

Deterministic fixtures model approval at minute 16 after a first 15-minute timeout,
original expiry at minute 30, expiry during backoff, cancellation, state/identity
loss, non-retryable terminal failures and handoff validation. They do not wait
30 real minutes or contact a real manager.

## Safe failure projection

CLI failures emit a single finite line such as:

```text
TRACEBOLT_WINDOWS phase=pending_approval reason=approval_expired serviceSpecificExitCode=1805
```

The SCM callback returns the same finite code as its service-specific exit code.
The existing read-only `--inspect` response includes `serviceSpecificExitCode`.
No event provider is registered, no event-source registry key is created, and no
new diagnostic file, telemetry upload or persistent log is introduced here.

Only enumerated phase/reason labels and an integer are emitted. Raw native errors,
wrapped error prefixes, arbitrary labels, paths, hostnames, invitations, keys,
certificate material and inventory bytes are never part of this projection.
Unknown labels collapse to `unknown/unknown` (1000). Error-chain inspection is
bounded and does not call arbitrary error-formatting methods. `Mark` preserves
`errors.Is` cancellation identity while formatting and JSON remain sanitized.

Useful codes:

| Code | Phase | Reason |
| --- | --- | --- |
| 0 | success | Orderly shutdown or no error |
| 1000 | unknown | Unclassified failure |
| 1313 | runtime_dispatch | Invalid SCM invocation |
| 1314 | runtime_dispatch | Dispatcher unavailable |
| 1402 | runtime_identity | Limited token/service SID rejected |
| 1501 | runtime_installation | Fixed installation/configuration mismatch |
| 1503 | runtime_installation | Required LocalService read/execute rights absent or denied |
| 1515 | runtime_installation | Unsafe executable path/owner/writer policy |
| 1601 | bootstrap | Invalid configuration/profile |
| 1704 | retained_state | State or deadline-marker update rejected |
| 1805 | pending_approval | Original approval deadline expired |
| 1806 | pending_approval | Enrollment terminal |
| 1807 | pending_approval | Non-retryable enrollment failure |
| 2008 | handoff | Exact activated handoff invalid |
| 2109 | sender | Reporting loop failed |

The compatibility formula is `1000 + 100 * phaseID + reasonID`; IDs are explicit
in `internal/windowsservice/diagnostics.go`, not inferred from declaration order.
The source tests pin the finite mapping and reject malformed diagnostic labels.
A raw code is a local failure category, not authority to repair ACLs, reset an
identity, extend expiry, retry terminal enrollment or start a new service.

## Runtime-read preflight remains separate

The executable and each ancestor must satisfy the documented explicit
[LocalService sufficient-DACL policy](windows-runtime-read-preflight.md). Both
initial installation and resumed enrollment recheck the receipt-bound stopped
service and executable immediately before `ClaimOnly`. A denied check prevents
invitation use, key creation and service start. It never modifies an ACL.

This source policy can conservatively reject group-only or unusually ordered
ACLs that Windows might permit. It is not proof of the future effective SCM token,
image loading, encrypted-file access, target policy or native runtime startup.
The separately approved disposable Windows acceptance gate remains necessary.
