# macOS inventory wire foundation (inactive source)

`internal/macosinventorywire` defines pure report, control and receipt contracts
for the fresh `darwin` / `macos-read-inventory-v1` identity. It imports the reviewed
inactive [collector contract](macos-read-inventory-source.md), without changing its
12 files. Nothing registers a profile, configuration, route, sender, manager,
store, CLI, service or UI. Basic macOS, Linux and Windows identities and existing
72 KiB telemetry budgets remain unchanged. This is separate work from the basic
macOS source candidate and is not a release or native-acceptance claim.

## Canonical contracts and bounds

All JSON has one exact typed `encoding/json` representation, including key order,
UTC RFC3339Nano timestamps, numeric spelling and explicit empty/null values.
Decoders reject duplicate keys (including identical duplicates), unknown fields
at every depth, wrong-case aliases, malformed UTF-8, alternate spellings, trailing
bytes/documents and bounds violations. Errors use fixed safe codes, never source
text, identifiers, addresses or parser diagnostics.

- Report: `tracebolt.macos-read-inventory-report.v1`, at most 520 KiB total.
- Snapshot: at most 512 KiB, embedded as its canonical JSON object, never base64,
  an unchecked raw JSON fragment, truncation or a legacy telemetry extension.
- Control: `tracebolt.macos-read-inventory-control.v1`, at most 2 KiB.
- Receipt: `tracebolt.macos-read-inventory-receipt.v1`, at most 2 KiB.

Each request binds the original device ID and sender-binding digest, explicit
platform/profile, independent fresh grant ID and grant/control revisions. Reports
also bind a positive capture sequence, deterministic domain-separated generation
ID, original capture time, exact 24-hour original-capture expiry and domain-separated
canonical snapshot digest. Sequences are bounded to 2^53-1; wraparound, zero and
unsafe integers are rejected. Neither generation derivation nor hashing establishes
authenticity. Fresh unpredictable grant creation and original sender-binding
provenance are obligations of the future authenticated initializer, not this package.

Receipts bind the exact canonical request digest and all relevant binding/revision,
generation, source-digest and original capture metadata. Report receipts say
`recorded`; control receipts say `enabled` or `disabled`. `ReceiptFor` only computes
content: it does not make these states true. Publish a receipt only after the
future authenticated durable admission transaction commits. Exact retries reuse
stored original receipt bytes and `receivedAt`, rather than calling the builder
again with a later time. A receipt for a different same-sequence request is invalid.

## First-grant terminal disable

The v1 contract deliberately has only these two control states:

1. Fresh enable: grant revision 1, control revision 1, enabled true, initial
   capture floor zero. The control remains immutable as live capture floors advance.
2. Terminal disable: the same original identity and grant ID/revision, control
   revision 2, enabled false. It records the exact last locally durable reserved
   capture sequence, including pending, failed and lost attempts; zero means no
   capture has ever been reserved. Its change time cannot precede enable.

There is no reenable, grant replacement, revision increment beyond these states,
identity adoption or missing-state reset in v1. A future new-profile/new-identity
workflow would need separately reviewed authority, not a higher number here.
`Disable` copies a supplied final local reservation floor; it cannot verify that
storage is truthful. `ValidateControlTransition` compares already-known canonical
controls and a supplied durable floor. A receiver that has observed fewer captures
may accept a higher terminal sender floor, but cannot accept a lower one than its
known floor. Exact disable retries are valid only with identical bytes and a
consistent floor; all later non-identical controls are rejected. Zero/missing
previous control is not a fresh initialization fallback.

Once terminal disable is committed, every report is inadmissible, including exact
retries captured before disable and sequences above or below its floor. The future
integration must serialize report admission and receipt commit atomically with
disable, prevent further reservations, cancel and join in-flight collectors/senders,
and preserve the irreversible used marker, original controls, receipts and floors.
A disable acknowledgement is not an immediate erasure guarantee for already
retained metadata. This package performs no storage, cancellation or erasure.

## Capture order, source quality and age

The source policy is one capture at least one minute apart, with latest-generation
retention for at most 24 hours from original capture, pending native performance
checks. Sequence reservations must be durable before capture. A failed/lost attempt
still consumes its sequence; a later successful capture may skip numbers.
`ValidateReportTransition` rejects rollback, faster advancing captures and altered
same-sequence bytes. It compares only the two supplied reports: independently
retained floors must also cover reservations/failed attempts after the earlier
report, and capture pacing must include failed attempts. Missing used state is a
blocker, not evidence that collection has never run. Do not recapture a lost pending
result under its old sequence or rewrite its timestamp for retry/renewal.

Snapshot fields and five independent source statuses remain exactly as captured.
The derived `sourceQuality` is:

- `full`: all five selected sources and emitted process names were observed.
- `partial`: at least one source was observed, but a source or process label is
  unavailable/denied. Successful siblings stay useful.
- `unknown`: no source was observed. Empty failed-source rows do not mean zero
  installed software, processes or interfaces.

`full` is selected-source coverage only. Installer receipts do not prove software
is still installed; process accounting labels can be truncated; IPv4 and IPv6 are
independent observations, not atomic whole-machine inventories. Underlying denied,
unsupported, malformed, bounds and budget reasons remain explicit.

`Assess` takes an explicit caller time without changing report bytes. It returns
source coverage separately from `fresh`, `stale` or `expired`: stale starts at the
next one-minute sampling boundary; expiry begins exactly 24 hours after original
capture. Stale evidence remains distinguishable from unknown/partial source
coverage, and original age is never refreshed. Future clocks must be trusted and
rollback-guarded; a supplied time here is not proof of trusted time. Expired reports
cannot obtain a newly computed report receipt. This slice implements no retention
store, history, data erasure or freshness UI.

## Authority and verification boundary

Collector `Consent` and `Snapshot`, wire `Control`, matching digests and successful
validation are not authenticated authority. Before any future capture or admission,
the integrator must establish an explicitly acknowledged protected fresh identity
and scope; hold its original sender binding across same-key renewal; verify TLS,
current-leaf validity and final revocation/profile/grant state; enforce durable
used/revision/capture floors, exact pending bytes and transaction-time clock guards.
Renewal cannot relabel a basic identity, expand scope or refresh retained evidence.
See [automatic renewal](automatic-certificate-renewal.md).

Any future private operator read needs current identity, grant, session and expiry
guards and explicit frame/paging/resource budgets. No AI/provider export, network
listener, HTTP-test transport, credentials, host read, package action, TCC/privilege
change, native setup, launchd operation or runtime activation is introduced here.

Pure synthetic tests cover strict canonical bytes, nested duplicates/unknown fields,
maximum embedded snapshot size, integer/date overflow, original bindings/ages,
quality states, terminal revision/floor rules, exact retry conflicts, receipt binding
and unchanged old telemetry limits. Windows full-process wire, sender-used-state
and ledger patterns informed the separate-domain/exact-retry/floor design; their
runtime and persistent-storage implementations are not copied into this package.
Native macOS utility coverage, resource/performance behavior, durable platform state
and end-to-end authenticated acceptance remain separately authorized future gates.
