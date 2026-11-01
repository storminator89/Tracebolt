# Rust agent health/status/support metadata (TB-09 source candidate)

This is a bounded **source candidate**, not a published Rust package, native
Windows Event Log integration or new Windows/Linux/browser acceptance. Use the
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
8192 bytes. There is no growing event or telemetry log. The original configuration
binding is checked internally and omitted from public status/bundle output.

- `lastAttemptAt` is the **local UTC** start of a runtime cycle. It can describe
  enrollment, collection or delivery, not necessarily an HTTP request.
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
- Recorded certificate expiry becomes `certificate-expired`; expiry within 24
  hours is `expiring` and, when otherwise accepted, `certificate-expiring`.
  This is a public-certificate lifetime check, not renewal authority or a guarantee
  that the manager has not revoked the credential.

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
only: no extra DNS lookup, handshake, network probe or retry is introduced. TLS
and typed network causes are inspected through bounded source/held-I/O-error
traversal; missing or unfamiliar types stay unclassified. Existing explicit
operation classes and request timeouts keep their precedence. The public next
action remains fixed text, never a formatted source error.

The three additional transport codes are derived diagnostic vocabulary only;
identity, grants, wire telemetry and authoritative state are unchanged. Older
binaries may reject a sidecar containing a new code as `health-unavailable` rather
than interpret it or repair it. Preserve that optional sidecar on rollback.

| State | Interpretation |
| --- | --- |
| `registration-pending`, `pending-approval` | Separate initial registration from waiting for deliberate manager fingerprint/comparison approval. No new identity or approval is created by diagnostics. |
| `transport-tls-failed` | A typed rustls failure was retained by the request error chain. Review selected trust, peer identity, certificate lifetime and TLS policy. This is not confirmed enrollment revocation or permission to weaken TLS. |
| `transport-connection-refused` | A typed OS I/O cause reported connection refusal during this attempt. Review approved listeners/ports/policy; refusal does not prove an offline endpoint. |
| `transport-unreachable` | A typed OS I/O cause reported network/host unreachability during this attempt. Review approved routing/connectivity; no definitive offline claim. |
| `transport-timeout`, `transport-unclassified` | Timeout or an ambiguous transport failure. The default resolver exposes no portable typed DNS discriminator; `Other`, `NotFound`, error prose and platform-specific numeric codes are not guessed into DNS/TLS/offline states. |
| `authentication-rejected` | HTTP authorization rejection; it does not itself establish revocation. |
| `protocol-unavailable`, `manager-rejected`, `receipt-invalid` | Endpoint/protocol status unavailable, other rejection or invalid receipt. No successful acceptance is inferred. |
| `enrollment-revoked`, `enrollment-expired`, `enrollment-terminated` | A validated, original-binding manager snapshot/retained terminal ledger stopped enrollment. Confirmed specific terminal reason can be retained across restart; no automatic replacement/rearm follows. |
| `state-corrupt`, `state-unavailable` | Explicit SQLite corruption/not-a-database code, or unavailable/invalid state. Preserve all authoritative bytes and use a separately approved recovery procedure. |
| `certificate-not-yet-valid`, `certificate-expired`, `clock-invalid` | Review original credential lifetime and UTC time. No time rewriting, renewal, sequence reset or re-enrollment is performed. |
| `collection-failed`, `unclassified-failure`, `health-unavailable` | Source error, safely unclassified failure or missing/invalid derived diagnostics. Unknown is never a zero metric or healthy state. |

Read-only status does not inspect authoritative ledgers or a live service. In
particular, startup errors **before a recorded cycle** can remain unknown or an
older retained diagnostic result. Startup emits only a safe static class/action,
not an automatically repairable DB or a fresh attempt receipt. Complete startup
state discrimination remains an acceptance gate.

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
metadata when available. This is **not** a Windows Event Log provider: native
Event Log delivery/registration is not implemented or claimed by source tests.

`once` and `service` accept `--no-health-diagnostics` as an explicit process-level
opt-out. It suppresses derived sidecar reads/writes without changing the immutable
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
bounds. The disposable loopback mutual-TLS fixture additionally checks that bad
receipts/redirects do not become acceptance; exact pending bytes survive retry
and restart; valid duplicate receipts retain original times; and diagnostic
corruption/opt-out do not reset sequence state or stop reporting.

These are source/protocol-fixture checks, **not native Windows acceptance**.
The typed-cause regressions include injected failures through the real reqwest
wrapper and disposable loopback wrong-trust/wrong-name TLS rejections. Injected
network errors are not native DNS/routing acceptance. Source tests never establish
a live endpoint's offline status.

Outstanding TB-09 gates include portable DNS-failure discrimination and any
separately supported offline-evidence contract,
full startup-state diagnosis, native Windows Event Log integration, Windows ACL/
service acceptance for atomic sidecar replacement and real Windows↔Linux↔browser
acceptance using unchanged, jointly reviewed release bytes. Keep #136 open until
its complete acceptance criteria and the #128 compatibility dependency are met.
