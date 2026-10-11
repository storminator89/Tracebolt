# Selected Windows event message runtime candidate

**Source candidate, 10 October 2026. Source fixtures and cross-builds are not
native Windows, installed-service or release acceptance.** The separate runtime
connects the bounded reader and request foundation to explicit local consent,
a serialized sender stage and an isolated worker. Neither the five-scope Setup
nor the existing event-header grant enables it.

## Independent local approval

Only a stopped, owned, activated Windows inventory service may use these source
commands. They describe an interface, not authorization to operate a host:

```text
windows-service --event-content-preview
windows-service --event-content-enable --apply --selected-application-system-event-messages
windows-service --event-content-disable --apply
```

Preview is nonmutating. Enable requires the complete content warning to be
successfully written before dispatch. An existing HTTP-test identity additionally
requires `--insecure-http-test` and the separate plaintext-content warning. Event
messages may contain credentials, personal information and other secrets. HTTP
signatures authenticate endpoint requests only; they neither encrypt content nor
authenticate manager responses. Production uses mutually authenticated HTTPS.
No service restart, account/ACL change, privilege increase or enrollment occurs.

The create-only protected sibling `-event-content` has its own immutable manifest,
consent file and independently locked `reports` and `consumption` child stores.
Initialization completes both ledgers before writing enabled consent. Missing
used records, partial initialization, ambiguous writes, identity changes or failed
close checks fail closed without adoption, repair or reset. Disable retains the
grant receipt and both monotonic floors. Explicit re-enable generates a new grant
ID and preserves existing sender, capability, claim-attempt and consume state.

## Claim once, consume before read

The existing one-shot and foreground sender own the serialized event-content
stage. Capability metadata has an independent durable sequence and exact pending
bytes. Retries preserve original capture; stale reports are replaced only with a
higher sequence. Disabled consent is reported as disabled. Content never enters
telemetry or the ordinary sender ledger. The one-shot report adds a bounded stage
status; the existing foreground observation/diagnostic schema is unchanged.

The parent commits an exact non-content claim-attempt marker before requesting a
manager claim. An ambiguous response or restart cannot retry that request as new
work. After the exact grant is returned, the child independently rereads installed
identity, local consent and the parent marker. It opens its exclusive consumption
store, commits the exact request sequence, ID, query digest, policy digest, grant
and original expiry, then closes successfully before calling the native reader.
Replaying the same worker cannot cause another read. These markers contain
neither selected event headers nor messages. Parent metadata handles are closed
before worker launch; the child never acquires the parent-held sender ledger.

## Owned child lifetime and authority

Only the current executable with one fixed private worker argument is launched.
No shell, executable/path selector, credential, arbitrary query or ambient
configuration crosses IPC. Windows receives only OS-derived `SystemRoot`. The
private request is bounded to 32 KiB, response to 512 KiB, and stderr goes to the
null device. The parent applies a ten-second process deadline, shortened by
original request expiry or caller cancellation, then kills and synchronously
reaps. A 100 ms pipe wait bounds inherited-handle cleanup. Overflow cancels
immediately. A fifteen-second child watchdog terminates only its own process if
the parent dies.

Before consumption and after capture, the existing observation-worker guard
verifies the actual creator PID and creation time against the exact running
own-process SCM service, restricted LocalService token, enabled service SID,
fixed protected executable/hash and configuration. Creator exit, substitution or
PID reuse rejects output. Activated identity and exact content consent are reread
around the operation. Existing SCM ACLs and privileges are unchanged.

The source retains its five-second cooperative budget. Synchronous Windows calls
can exceed that budget; isolation bounds the owned child rather than claiming to
cancel an in-flight API. Valid partial or unavailable reports survive the reader's
accompanying fixed error. Missing/invalid output never becomes a successful empty
result, and raw native/process errors are not released.

## Memory-only result delivery

At most one exact canonical result is retained in process memory, with an expiry
timer tied to the immutable fifteen-minute request expiry. Every retry rereads
identity and consent and rechecks time. Disable, replacement, backward time,
expiry, terminal manager rejection and sender close discard the slot. Clearing
is best effort, not a promise about garbage-collected or transport copies. Lost
claims, lost in-memory results and restart never authorize recapture. An accepted
receipt must match exact identity, policy, native report digest and original
expiry. Metadata retry never refreshes source age or expiry.

## Verification and remaining native gate

Portable fixtures cover independent consent and disclosure failure, missing/used
state, exact metadata retry, durable attempt/consume ordering, replay, exclusive
concurrent consumers, ambiguous writes, lost claim/result replies, restart,
revocation/replacement, expiry, partial reports and creator identity changes.
Inert subprocess fixtures cover kill/reap, cancellation, output overflow,
sanitized environment and inherited-pipe cleanup. None reads Windows event logs.

A separately approved disposable Windows gate must still verify actual SCM
creator/token access, protected-store behavior under LocalService, synthetic
Application/System selection and publisher rendering, missing/denied records,
stop/crash/watchdog behavior, durable replay prevention and exact retry through
the real manager/operator view on supported architectures. Approval must name
the reviewed binaries and any lifecycle or local-grant operations.
