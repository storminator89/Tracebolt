# Rust agent health/status/support metadata (TB-09 source candidate)

This is a bounded **source candidate**, not a published Rust package or native
Windows Event Log delivery/service/Windows/Linux/browser acceptance. Use the
matching [Rust candidate](integrated-test-candidate.md) and
[compatibility contract](rust-manager-compatibility.md) separately. SCM `Running`
never establishes enrollment, usable credentials, successful collection or a
fresh accepted report. This implementation does not inspect SCM state.

## Read-only commands

With the reviewed binary and an existing approved absolute configuration directory:

```powershell
.\tracebolt-windows-agent.exe status --directory 'C:\ProgramData\TraceboltRustAgent' --json
.\tracebolt-windows-agent.exe status --directory 'C:\ProgramData\TraceboltRustAgent'
.\tracebolt-windows-agent.exe support-bundle --directory 'C:\ProgramData\TraceboltRustAgent'
```

`status --json` emits `tracebolt.rust-agent-health.v1`; the text form emits a fixed
state code and its safe next action. `support-bundle` emits a single bounded JSON
object with schema `tracebolt.rust-agent-support.v1` to stdout. It is deliberately
not a recursive filesystem archive or automatic upload. Successful command exit
means the diagnostic representation was produced, **not that the endpoint is
healthy or online**. Unknown/unavailable states remain explicit in the JSON.

These commands read only the bounded selected configuration, optional public
server CA and the derived health sidecar. They never call `Runtime::open`, open a
sender/enrollment DB, acquire/create an enrollment/sender lock, send a request,
collect metrics, initialize state, repair a journal, inspect SCM or change a host.
A missing sidecar is `not-observed`, never fresh receipt evidence. A malformed,
unknown-version, oversized, mismatched or linked sidecar is `health-unavailable`.
It is not deleted, replaced, adopted or repaired by a read command. Ordinary file
reads can update filesystem access-time metadata; no content/mode/mtime change is
performed by status or bundle export.

## Evidence and time sources

An enabled runtime writes one bounded derived `state/health-v1.json`, at most
8192 bytes, and holds the separate optional `health-v1.lock` single-writer lock.
Read-only commands never open/create that lock. Failure to acquire the diagnostic
lock disables diagnostics only; failure to acquire an authoritative sender or
enrollment lock never overwrites an active runtime's status. There is no growing
application-managed event or telemetry log file. The original configuration
binding is checked internally and omitted from public status/bundle output.

- `lastAttemptAt` is the **local UTC** start of a runtime cycle or a failed local
  runtime open. It can describe startup, enrollment, collection or delivery, not
  necessarily an HTTP request. A successful local open alone never refreshes it.
- `lastAttemptResult` is a finite code. An attempt marker without a recorded
  completion remains `attempt-in-progress`; a crash is not success.
- `lastAcceptedReceipt` is recorded only after the existing strict receipt
  identity/sequence/original-collection-time contract succeeds **and** the existing
  local sender sequence advance is durably confirmed. Invalid receipts, redirects,
  rejected responses, successful collection alone and SCM state never create it.
- The receipt's `receivedAt` is **manager UTC**; `collectedAt` is the original
  sample UTC and remains unchanged on exact-byte retry. `receiptObservedAt` is
  **local UTC** after validation and local commit. Duplicate receipts retain their
  duplicate marker. No agent identity or raw receipt body is exported.
- `receiptFreshness` uses the original local receipt-observation time, with a
  bounded expected interval. Later failed attempts, rereads, support export and
  restart do not refresh that time. A stale accepted receipt produces
  `receipt-stale`, not a healthy/live claim. If either the last local attempt or
  local receipt-observation time is over 30 seconds ahead of diagnostic UTC,
  status is `clock-invalid`, including pending/failed attempts with no receipt.
  Any retained receipt then has `clock-unknown` freshness; its original times and
  last attempt result are preserved, not refreshed or repaired. A scheduled
  `nextAttemptAt` is not an observation and does not trigger this clock check.
- Recorded certificate expiry makes otherwise accepted status `certificate-expired`; expiry within 24
  hours is `expiring` and, when otherwise accepted, `certificate-expiring`.
  This is a public-certificate lifetime check, not renewal authority or a guarantee
  that the manager has not revoked the credential. A retained expired certificate
  does not hide the latest failure or replace its next action: revocation, corrupt
  state, DNS/TLS and other failures retain their code while `certificateStatus`
  independently reports the recorded expiry. Clock uncertainty still takes precedence.

A locally validated TLS receipt is bounded evidence of the selected peer's
acknowledgement. It is not independent proof of production-manager database
contents, current reachability or end-to-end installation acceptance. The sidecar
is derived diagnostics, **never** identity, enrollment, revocation, replay,
consume-once or sequence authority. Same-account/root tampering and rollback of a
previous valid full backup are not detected by this diagnostic format.

## Failure classes and next action

All public codes and messages come from fixed allowlists; raw error strings,
paths, URLs, certificate/key material and remote bodies are never interpolated.
Typed errors are classified, not guessed from words such as “TLS” or “revoked” in
an exception message. Transport classification uses the existing request result
only: no extra DNS lookup, handshake, network probe or retry is introduced. The
system resolver is the same `hyper-util` getaddrinfo adapter used by reqwest, with
a static typed failure marker attached at that resolver boundary. It retains no
OS error text, DNS name or returned address. A resolver failure is not a claim of
NXDOMAIN, offline status, manager unavailability or revocation. TLS
and typed network causes are inspected through bounded source/held-I/O-error
traversal; missing or unfamiliar types stay unclassified. Existing explicit
operation classes and request timeouts keep their precedence. The public next
action remains fixed text, never a formatted source error.

The additional transport codes are derived diagnostic vocabulary only;
identity, grants, wire telemetry and authoritative state are unchanged. Older
binaries may reject a sidecar containing a new code as `health-unavailable` rather
than interpret it or repair it. Preserve that optional sidecar on rollback.

| State | Interpretation |
| --- | --- |
| `registration-pending`, `pending-approval` | Separate initial registration from waiting for deliberate manager fingerprint/comparison approval. No new identity or approval is created by diagnostics. |
| `transport-dns-failed` | The actual system resolver failed during this request. Resolver timeouts keep `transport-timeout` precedence. No additional lookup, DNS-status guess, error prose or offline claim is used. |
| `transport-tls-failed` | A typed rustls failure was retained by the request error chain. Review selected trust, peer identity, certificate lifetime and TLS policy. This is not confirmed enrollment revocation or permission to weaken TLS. |
| `transport-connection-refused` | A typed OS I/O cause reported connection refusal during this attempt. Review approved listeners/ports/policy; refusal does not prove an offline endpoint. |
| `transport-unreachable` | A typed OS I/O cause reported network/host unreachability during this attempt. Review approved routing/connectivity; no definitive offline claim. |
| `transport-timeout`, `transport-unclassified` | Timeout or an ambiguous transport failure. `Other`, `NotFound`, error prose and platform-specific numeric codes are not guessed into DNS/TLS/offline states. |
| `authentication-rejected` | HTTP authorization rejection; it does not itself establish revocation. |
| `protocol-unavailable`, `manager-rejected`, `receipt-invalid` | Endpoint/protocol status unavailable, other rejection or invalid receipt. No successful acceptance is inferred. |
| `enrollment-revoked`, `enrollment-expired`, `enrollment-terminated` | A validated, original-binding manager snapshot/retained terminal ledger stopped enrollment. Confirmed specific terminal reason can be retained across restart; no automatic replacement/rearm follows. |
| `state-corrupt`, `state-unavailable` | Explicit SQLite corruption/not-a-database code, or unavailable/invalid state. Preserve all authoritative bytes and use a separately approved recovery procedure. |
| `certificate-not-yet-valid`, `certificate-expired`, `clock-invalid` | Review original credential lifetime and UTC time. No time rewriting, renewal, sequence reset or re-enrollment is performed. |
| `collection-failed`, `unclassified-failure`, `health-unavailable` | Source error, safely unclassified failure or missing/invalid derived diagnostics. Unknown is never a zero metric or healthy state. |

Read-only status does not inspect authoritative ledgers or a live service. Runtime
startup records a failed local open when valid configuration-bound diagnostics
are available, distinguishing typed SQLite corruption, unavailable/invalid state
and invalid local credential configuration. The original failure is returned even
if this optional write fails. It preserves the last accepted receipt and its
observation time, and clears scheduling hints: a stopped startup has no scheduled
service retry. A successful open alone leaves existing diagnostic bytes unchanged.
Malformed/mismatched diagnostics and uncertain temporary files are never repaired.
Invalid configuration is reported read-only without adopting a previous binding.
Missing/unwritable diagnostic storage can still leave startup evidence unavailable;
neither that absence nor an older receipt is success or a recovery instruction.

## Bounded retry and diagnostic opt-out

After a cycle failure, the service uses exponential backoff based on the selected
interval, with at most 30 seconds of bounded jitter and an overall one-hour cap.
There is no immediate retry loop. Onboarding without an error keeps its existing
30-second phase cadence; successful reporting keeps its configured interval.
`retryDelaySeconds` and local `nextAttemptAt` expose the recorded scheduling hint,
not an immutable wall-clock promise or authority to retry a host operation.
Service waiting uses a duration and remains stop-aware. Restart can begin a fresh
bounded wait episode; it cannot reset identity, pending bytes, sample age or
sequence floors. Stale sample consumption retains the existing sender contract.

The Windows service no longer silently discards `cycle` errors. It emits fixed
code/action text only on diagnostic-state transitions, and persists bounded
metadata when available. A best-effort Event Log worker uses the fixed
`TraceboltRustAgent` source, event 1001 for startup failure and event 1002 for
diagnostic transitions (including pending and recovery). Its three insertion
strings are fixed stage, finite code and fixed next action; there is no raw binary
payload, supplied user SID, identity, error or telemetry. Windows adds its own
normal event envelope (such as event time and source computer); this is not an
anonymous support export. No source registry key or message DLL is
installed. Windows can use Application fallback; Event Viewer may lack a formatted
description, so inspect the insertion strings/EventData. This is not provider
registration or proof of native delivery. Event envelope timestamps describe
delivery, not original attempt, collection or receipt time; a queued event can
arrive late. Use the sidecar's separately named time sources, never delivery time
as freshness evidence.
The Windows API contracts are
[RegisterEventSourceW](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-registereventsourcew)
and [ReportEventW](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-reporteventw);
their availability is not a native acceptance result for this binary/account.

The service never waits on Event Log RPC: at most one event is in flight and one
is queued. A full queue drops that transition rather than building a backlog;
duplicate states are suppressed even after delivery failure. A failed sink is
disabled without retries and emits at most one fixed local notice (failure to
start the worker disables it silently). Shutdown/process
exit does not flush or wait for the worker; especially a startup-failure event can
be lost when the process exits. The bounded sidecar, when writable, remains the
retained diagnostic evidence. Native LocalService delivery/rendering and failure
behavior require their own acceptance below, not a source-test success claim.

`once` and `service` accept `--no-health-diagnostics` as an explicit process-level
opt-out. It suppresses derived sidecar reads/writes and the service Event Log sink
without changing the immutable
Config shape, enrollment or sender ledger bindings, credentials or collection
scope. No service settings are rewritten by this flag; changing an installed
service's invocation remains a separately authorized host action. A diagnostic
write/schema failure similarly disables only diagnostic persistence for that
runtime. Original telemetry/receipt handling continues; failure is not repaired
by deleting or resetting authoritative state. Uncertain temporary sidecar bytes
are retained for local inspection.

## Support allowlist and verification boundary

Bundle fields are product/version, actual binary execution-platform/architecture,
and the typed public diagnostic view: finite codes, fixed next actions, bounded
retry metadata, public certificate expiry and receipt/attempt timestamps. They
exclude identities and configuration bindings, hostnames/IPs, account/path labels,
keys, CSRs, certificates, invitation/token/password/cookie values, raw errors,
remote prose, database content, raw telemetry, metrics and logs. Nothing is
uploaded automatically. Review even this minimized metadata before sharing.

Portable Rust tests cover read-only CLI noncreation, strict schemas/size limits,
secret/telemetry/path injection rejection, linked/shared file refusal, uncertain
temporary preservation, stale/clock/expiry states, typed error classes and retry
bounds, startup corruption/unavailable/configuration classification, unchanged
retained authority/receipt bytes, disabled/unavailable diagnostics, and bounded
event transition/payload/queue behavior. The disposable loopback mutual-TLS fixture additionally checks that bad
receipts/redirects do not become acceptance; exact pending bytes survive retry
and restart; valid duplicate receipts retain original times; and diagnostic
corruption/opt-out do not reset sequence state or stop reporting.

These are source/protocol-fixture checks, **not native Windows acceptance**.
The typed-cause regressions include injected failures through the real reqwest
wrapper and disposable loopback wrong-trust/wrong-name TLS rejections. Injected
network errors are not native DNS/routing acceptance. The resolver fixture rejects
an injected invalid name locally at getaddrinfo and checks its typed cause through
the real request wrapper; a second fixture resolves localhost to a selected
loopback port. Neither uses an external DNS service. Source tests never establish
a live endpoint's offline status.

## Remaining issue-closure gates

| Gate | Required evidence before closing #136 |
| --- | --- |
| Supported offline evidence | A separately reviewed source/contract that can actually establish offline, or an explicit product decision to represent it as unknown. DNS/TLS/refusal/timeout/stale receipts alone cannot truthfully distinguish offline from routing, trust, manager failure or a stopped service. No additional host collection is authorized here. |
| Native Windows diagnostics | Exact unchanged EXE/ZIP hash, OS/version/architecture/profile, LocalService startup/cycle/pending/acceptance/revocation/expiry/corruption fixtures, actual EventData delivery and documented drop/failure behavior; verify bounded stop with an unavailable Event Log sink. |
| Protected sidecar persistence | Native installed-service ACL and atomic replacement checks across failure/restart/diagnostic opt-out; original identity, sequence/pending bytes and receipt times remain unchanged. Portable file tests are not Windows ACL acceptance. |
| Matching joint release and true E2E | Meet #128 with the reviewed manager/frontend/agent bytes and immutable manifest/hashes, then actual Windows↔Linux↔browser acceptance. A local receipt fixture or SCM Running does not satisfy this. |

Record passed, failed and not-run classes separately. Keep #136 open until these
gates and its complete acceptance criteria are actually met; do not turn this
source completion into a native or release acceptance claim.
