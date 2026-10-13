# macOS inventory protected sender integration (inactive source)

`internal/macosinventorysender` connects the reviewed collector, wire and sender
state through a protected checkpoint adapter and a single-owner coordinator.
It is **not selected by any CLI, enrollment flow, service or renewal scheduler**.
There is no production `Authority` implementation. Existing basic macOS commands
still grant and report only their original scope. Linux and Windows scopes,
72 KiB ordinary telemetry budgets and release pins are unchanged.

This slice executes no native collector, creates no host identity or grant,
installs no service and makes no native acceptance claim. All executed tests use
synthetic providers, in-memory storage or fake filesystem operations. Darwin
storage test binaries are compiled only.

## Protected checkpoint custody

`OpenFreshStorage(path, originalEnable)` and
`OpenExistingStorage(path, originalEnable)` are separate operations. The first
accepts only a dedicated empty protected directory, creates an exclusive lock,
and returns a `Storage` implementing the pure state's `DurableCommitter`. It does
not authenticate consent or establish that an enrollment identity is fresh.
The fresh enrollment owner must establish that separately before opening storage.

`State.InitializeFresh(storage, originalEnable, now)` publishes an immutable used
marker first, then the checkpoint, then a ready marker. Both markers bind the
exact original enable bytes. `OpenExistingStorage` requires the original markers
and canonical checkpoint. It never creates missing state, adopts another grant,
changes original enable bytes, or falls back to initialization. Interrupted
initialization, orphan files, missing used/ready markers, missing checkpoint,
unknown files and leftover write temporaries fail closed. No repair/delete/reset
path is supplied. A replaced lock cannot create a second live owner.

The Darwin backend uses descriptor-anchored traversal from `/`, no-follow opens,
strict runtime ownership/private modes, conservative native ACL validation,
regular single-link files and bounded stable reads. First publications use
`RENAME_EXCL`; replacement verifies the expected file identity and exact bytes.
Regular files are synchronized/full-flushed before publication, the directory is
synchronized, and a same-volume regular descriptor is full-flushed afterward.
Exclusive `flock` ownership lasts until `Close`. Unsupported platforms fail
closed rather than substituting an unprotected filesystem implementation.

Protocol and backend failures, including callbacks that panic, poison a live
storage owner. An after-write error is uncertain, never permission to retry with
old bytes. The pure state additionally poisons itself before each commit callback.
Only a later existing-state open under exclusive custody may inspect the actual
committed bytes. A complete rollback of all protected state by the runtime UID or
root is outside this local storage model; an old backup is not a supported reset.

## Source and send order

`NewNative(state, originalEnable, authority, release)` takes ownership of an
already initialized/restored state and its storage release function only on
success. A rejected constructor leaves cleanup with the caller. It accepts
Darwin only and fixes collection to the reviewed `macosinventory.CollectNative`.
There is no exported custom-source constructor. Construction itself performs no
source read or network operation. Internal tests inject inert sources and a clock.

One `Cycle(context)` at a time performs:

1. Advance original-expiry retention even when the current credential is invalid.
2. Acquire the mandatory authenticated authority lease and validate its current
   evidence against the exact original enable and fresh local consent.
3. Deliver a pending original control and durably accept its exact canonical
   receipt before any source may run.
4. Retry any already committed pending report byte-for-byte, without collection.
5. Otherwise durably reserve one sequence, generation and original capture time.
6. Recheck current authority, invoke the fixed collector with that exact lease
   and local consent, then recheck authority and encode without repairing fields.
7. Durably stage the report, recheck authority immediately before exchange, recheck the report’s original 24-hour lifetime after that
   authority check, and acknowledge only after the same current credential passes the final check.

The bound report is a separate maximum-520-KiB canonical JSON body. Fixed paths
are `/v1/macos/inventory/control` and `/v1/macos/inventory/report`. Responses are
bounded to 2 KiB canonical receipts. A receipt is acknowledged only against the
exact request and original timestamp. Transport failure keeps original pending
bytes. Invalid/failed/cancelled collection consumes its reservation; failed and
lost captures participate in the one-minute floor. No collection retry uses an
old sequence. Source/provider/transport prose never enters errors or telemetry.

## What authentic authority still requires

`Authority.WithCurrent` and its `ActiveAuthority` are trusted implementation
interfaces, **not evidence of authentication by themselves**. An arbitrary
callback returning syntactically correct data does not satisfy this gate. No
production callback is supplied, and no runtime caller constructs the sender.

The next fresh-enrollment integration must provide a concrete protected reader
that independently establishes all of the following, before calling the action:

- The original activated guided enrollment ledger, immutable issuer and identity
  anchor belong to `darwin`, TLS and `macos-read-inventory-v1`.
- A create-only local acknowledgement of the complete scope produced the exact
  protected collector consent and immutable original enable. The independent
  128-bit grant ID was created once from secure randomness at that approved
  initialization, never taken from a remote control or reused basic identity.
- A primary enrollment-owned initialization-started/used fence was durably
  committed before creating the independent inventory store. Losing that whole
  store must block the original enrollment owner from creating it again.
- The original issuance description and approved issuer were authenticated using
  enrollment's existing verification, not by trusting this package's certificates.
- The current manifest identifies an activated leaf for that same identity/key,
  with unchanged profile and original authority horizon. Current leaf validity,
  live local approval and final manager revocation checks remain authoritative.
- Every actual TLS exchange uses exactly the credential checked by the admission
  lease and the approved original manager origin. The adapter holds admission
  across collection and send, rereads authority at each `Check`, prevents cutover
  while admitted work runs, and joins all owned transport activity on cancellation.

The coordinator validates evidence again: exact protected original enable,
strict enabled consent, matching grant and original binding, direct original and
current issuer signatures, the same public key, exclusive client-auth role,
current leaf/issuer times, historical original validity bounds and an unchanged
current-leaf digest throughout one cycle. These checks are defense in depth;
they do not prove where a caller obtained its consent or approved issuer.

The exact required `Evidence` fields are `ManagerOrigin`, `OriginalEnable`,
`Consent`, `AnchorDER`, `CurrentDER`, `IssuerDER` and `CredentialGeneration`.
No secret key or row data belongs in evidence. `ActiveAuthority.Check(now)` must
return independently validated current evidence. `Exchange(ctx, path, body)`
must select only the two fixed paths, exact Content-Length and application/json,
verify TLS with that same leaf, reject redirects/HTTP/compression, cap response
reads before allocation and perform no automatic request retry or row logging.

Original sender binding is lowercase SHA-256 of this exact UTF-8 sequence:

```go
"tracebolt.sender-binding.macos-inventory.v1\n" +
"macos-read-inventory-v1\n" +
"tls\n" + approvedAgentOrigin + "\n" +
originalLeafSHA256LowerHex + "\n" + originalDeviceID
```

There is one newline after each of the first five fields and none after the
original device ID. The manager recomputes this independently. A renewed leaf
never substitutes for the original leaf in this digest.

No new endpoint configuration schema is accepted by this slice. The later
reviewed configuration must explicitly select the fresh inventory profile and
its independent state directory, original consent/enable paths and renewal
manifest when approved. Existing basic schema/profile, pending enrollment and
Linux/Windows settings must reject that selection rather than be promoted.

## Stop, terminal disable and renewal handoff

`Disable()` closes new operation admission, cancels the active context and waits
for its source or transport to return before committing terminal control revision
2 with the final durable floor. An already issued network request cannot be
recalled, so its join precedes the local decision. Once committed, state forbids
all further reports and captures. A later `Cycle` may deliver only the unchanged
disable control. A failed disable keeps local admission stopped; only an explicit disable retry
or close may proceed until terminal commit succeeds. Disable needs no valid
credential or network merely to stop local reporting; calling it requires the local owner's explicit authority.

`Close()` is the stopped-owner/renewal barrier. It closes admission, cancels and
joins active work, closes the pure state, then releases its protected lock.
It does not disable the scope, activate a candidate, rewrite a certificate,
rebind pending bytes or create new storage. An interrupted capture is recorded
as lost; an interrupted send retains its exact pending bytes.

The future renewal scheduler must include this sender in its existing join set
before activation. After successful close and before credential cutover, validate
existing inventory markers/checkpoint against the original enable without fresh
initialization. Publish the existing atomic current-credential manifest only
after that validation. Reopen `OpenExistingStorage`, then
`State.Restore(storage, originalEnable, raw, now)`, and construct the sender using
the same original enable plus the newly authenticated current leaf. Both a lost
activation reply and an expired old leaf must retain all original report/control
bytes, receipts, floor and capture ages. Failure to prove this continuity blocks
cutover; deleting state or reconsenting an old identity is not recovery.

`Maintain(context)` performs retention maintenance without collection, network or
valid current credentials, including after terminal disable. A future runtime
must drive it regularly while stopped for authority reasons; no scheduler or
wall-clock disk erasure is implemented here. Original 24-hour expiry remains the
only pending/source lifetime. Bounded control/receipt/floor tombstones survive.

## Verification and remaining gates

Synthetic tests exercise enable-before-collection, exact lease mapping, failed
and lost capture pacing, malformed result rejection, after-write poisoning,
expired-authority retention, current-leaf change during capture, original anchor
preservation across renewal after the original certificate expires while the
report remains within its original 24-hour lifetime, expiry crossing during final
authority checks, malformed-time reservation settlement, and cancellation/join of sources and transports
before disable or lock release. Storage protocol tests inject each publication
failure boundary and marker/expected-byte mismatch. These are source contracts.

Still required: concrete authenticated fresh enrollment/local-consent adapter,
primary enrollment used fence, protected current transport, strict fresh endpoint
config and CLI, scheduler joining/retention ownership, composed authenticated
manager end-to-end tests, independent final review, and separately approved
native macOS/APFS syscall/ACL/flush/crash/lock/provider tests. Native account,
service, TCC/permission, installer and release acceptance remain unperformed.
