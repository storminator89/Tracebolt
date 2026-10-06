# Controlled-action contract and consumption foundation

Status: permit/consumption foundation used by the wired, default-off
[controlled-action helper](controlled-action-helper.md) and narrow
[manager/agent/UI service workflow](service-action-workflow.md). The contract
below remains valid for legacy v1 admissions; the helper document owns the v2
fresh-only durable attempt/result lifecycle and concrete runtime checks.
Original foundation base: `4def163cf9d879f3b91360de41754d8aa299b639`.

The original `internal/actionpermit` and legacy `Admit` API remain inert and have
no execution callback. The integrated helper adds a fresh-only Attempt, fixed
systemd adapter and existing-only inherited-socket runtime. The workflow adds
separate named-operator approval, command signing and first-claim-only delivery.
It is default-off; host provisioning and native acceptance remain separate gates.
No real service restart or package installation is claimed.

## Implemented contract

`actionpermit` accepts exactly `tracebolt.execution-permit.v1`. Its Ed25519
signature covers the UTF-8 domain `Tracebolt controlled action execution permit
v1`, a NUL byte, and the exact canonical JSON permit bytes. The envelope contains
the permit followed by an unpadded standard-base64 signature. JSON is deliberately
the Go encoder's single native representation, not a general-purpose JSON
canonicalization standard. Other languages must produce these exact bytes.

The signed fields are:

- Version, manager instance ID and command-key ID (SHA-256 of the raw public key)
- Endpoint ID and immutable enrollment-incarnation digest
- Unique action job/execution ID and an independent monotonic action sequence
- Exact typed plan and SHA-256 of its canonical bytes
- Stable named operator ID and immutable server-side approval-record digest
- Root-local policy digest
- Original issued-at, not-before and exclusive start-deadline Unix seconds

The bounded plan has one action name, `service.try-restart`, one conservative
canonical `.service` name, and the reviewed effective unit/dependency/execution-
input policy digest. Template instances, escaped names, paths, options and other
action names are unsupported. Syntax validation cannot detect systemd aliases or
inspect loaded units; native checks remain required before execution.

The format has no arbitrary command, script, executable path, environment,
output, URL, APT options or extension map. Sequence is a canonical decimal JSON
string to avoid JavaScript number precision loss. Unknown, duplicate, missing,
case-folded and null fields, alternate escaping/number spelling/base64, whitespace,
trailing bytes and unsupported versions are rejected. Input is at most 4096 bytes.

`SigningMessage` and `Encode` do not sign or generate keys. The test files alone
construct deterministic inert fixture keys. The integrated manager requires an
independently provisioned command signer, distinct from enrollment/TLS keys,
and derives the operator/approval from authenticated server-side state. A valid
signature means that this pinned signer signed the description; it does not
independently prove human approval or protect against a compromised signer.

## Local authority stays independent

`NewVerifier(LocalPins)` defensively copies a separately supplied public key and
allowlist. It never takes a key or local policy from permit bytes. Pins bind the
manager, key, endpoint incarnation, policy and exact unit-policy entries. The
allowlist is sorted, unique and limited to 16 entries. `Enabled` defaults false.
Local lifetime is explicit, at most 120 seconds; permitted future issuance skew
is explicit, at most five seconds. The start deadline is exclusive. Not-before
is enforced without early-start skew. An expired deadline never stops a running
process; this core cannot start any process in the first place.

The constructor and these Go types prove no root ownership, administrator opt-in,
Unix peer identity, operator capabilities or transport protection. The helper
production adapter independently loads protected current
identity, command-key pin and policy, authenticates its local peer, and rechecks
current policy, unit state/configuration and original deadline immediately before
start. This core does not queue work or
observe policy-file changes. Its verifier is a snapshot; reopening with updated
pins preserves consumption. Never wire `Verify` or an `admitted` status directly
to an executor.

`CheckSignature` is specifically for validating historical signed metadata. It
does not check enabled state, current policy, expiry or replay. `CheckTime` also
does not establish authority. Neither method returns execution permission.

Production browser/manager and agent/manager action paths still require verified
TLS. The workflow also supports a separately enabled, isolated disposable HTTP
test profile, with no insecure fallback in this core. Its one explicit local
machine opt-in must bound test identity, fixed action scope and policy separately
from production, with a conspicuous warning: stolen HTTP operator sessions can
cause the manager to authorize actions inside that scope. Signatures do not fix
that exposure. No such profile or host grant is created here. Automated fixtures
need neither certificate setup nor real systemd/APT execution.

## Durable consumption and status

The Linux store uses the existing journal-state protection pattern in its own
action domain: anchored no-follow descriptor walk, numeric ownership checks,
private 0700 directory and 0600 single-link regular files, exclusive lifetime
flock, and checked file/directory identity. It detects live replacement and byte
changes. It never repairs unsafe modes, follows symlinks, adopts hardlinks or
accepts unknown directory entries. Storage code is deliberately separate from
the established read-only journal implementation; that package is unchanged.

`Initialize` is create-only, for separately authorized fresh local action setup.
The [create-only service-action setup](guided-service-action-setup.md) now calls
it through a separately approved, permanently fenced helper initializer. Normal
startup never initializes missing used state. `Open` is existing-only and is used
by the root helper runtime. Storage is protected for the current
effective UID; the helper separately verifies its full root identity. Fixtures use
ordinary-user temporary directories. A missing ledger is a hard stop, not an
invitation to reinitialize. Key rotation/incarnation migration is not implemented.

The versioned ledger is bound to manager, command key, endpoint and incarnation,
not to the current allowlist. Updating/disabling policy therefore does not reset
its floor. It retains at most 64 original signed descriptions and structured
consumption records, within 512 KiB. Capacity fails closed; there is no automatic
pruning, floor reset or deletion API. The manager must retain its independent
authoritative sequence and approval history as well.

For a new valid permit, `Admit` performs file fsync, atomic replacement and parent
directory fsync before returning admission metadata. It records the server's
sequence, original signed bytes and microsecond local consumption time. Sequence
gaps are allowed; an earlier/equal consumed sequence is not. There is one unresolved
admission per endpoint. The supported statuses mean exactly:

- `admitted`: durable consumption recorded; no claim of launch or success
- `expired`: an authentic, currently policy-matching permit arrived too late and
  its sequence was consumed; no claim that it ran
- `needs_intervention`: an admission existed when the store reopened; whether a
  later integrated runner started or mutated anything is unknown

An exact byte-for-byte duplicate returns its original metadata without writing,
renewing expiry, returning a new admission indication or launching anything.
Reusing its job ID with changed signed bytes fails. Expiry never transforms an
already admitted job into a retryable job. Status remains readable after policy
disable or a policy revision, provided the manager/key/incarnation binding still
matches. Historical records are rechecked against the pinned signing key.

An admitted, dispatching or needs-intervention record blocks every subsequent
new job. The reviewed runner extension adds fresh-only dispatch and bounded result
transitions; see the helper document. No old admission can acquire an Attempt.
There is still no external cancellation, retry or reconciliation API.

The persisted microsecond clock high-water prevents a backward clock from
admitting later work before its last consumption time. Authenticated expired
permits are durably consumed so clock reversal cannot revive them. Malformed,
foreign, future/not-yet-valid or disallowed permits cannot advance the floor.
Duplicate reads do not require a current clock or grant new authority.

Any write failure poisons the live handle and all copies. Failures after creating
the temporary are uncertain: preserve it for inspection; never delete/promote it
automatically. A final directory-sync failure may leave a coherent replaced
record, but no admission is returned. Reopening an admitted record marks it
`needs_intervention` and does not replay it; an expired record remains expired.
Cancellation after the durable commit returns no admission
metadata, while preserving the consumed record for later status/recovery.

This promises at-most-once durable admission, not exactly-once execution or
effects. It is ordinary local durability, not a cryptographic anti-rollback or
tamper-proof audit system. Root/same-UID modification or restoring the entire
filesystem can defeat local history. Real filesystem power-loss behavior remains
an independent native acceptance gate.

## Implemented versus pending

Implemented and fixture-tested: strict signed contract, pinned verifier snapshot,
default-off allowlist checks, time bounds, dedicated durable floor, duplicate and
conflict status, crash uncertainty, private-state protection and failure poisoning.

The [service workflow](service-action-workflow.md) wires named-operator
capabilities, immutable approval/jobs, protected command signing, first-claim-only
delivery, root-local policy/IPC, fixed systemd try-restart and preview/approve/status
UI. The [fresh setup adapters](guided-service-action-setup.md) add separate local
manager and endpoint planning/apply paths. They still require named authority,
protected keys, a reviewed unit, local grants and native disposable-host acceptance;
source/fixture checks do not establish an installed or executed action.

The [selected-package plan core](selected-package-plan-core.md) remains pure and
inert with no runtime callers. Authenticated native planning, an APT transaction
fence/runner and real package execution/acceptance remain unimplemented. Neither
source publication nor a manager upgrade grants host authority.

## Verification

Focused commands (Go 1.27.1, Linux amd64):

```
go test -race -count=1 ./internal/actionpermit ./internal/actionstate
go test ./internal/actionpermit -run '^$' -fuzz '^FuzzDecode$' -fuzztime=10s -parallel=2
```

Fixtures cover a fixed signing/envelope conformance vector, signed-field/signature
mutation, strict canonical decoding,
default-off/wrong key/manager/endpoint/incarnation/policy/unit denial, original
time bounds, expired consumption, replay and ID conflicts, concurrent duplicates,
copy aliasing, reopen uncertainty, policy changes without floor reset, bounded
capacity, existing-only opening, unsafe paths/ownership/links/replacement and
fault injection for disk-full/short-write and file-sync/rename/directory-sync/
cancellation boundaries.
Tests use only fixture keys, inert temporary files and injected storage faults.
Builds/cross-builds and fixtures cannot prove real-machine action acceptance.

## Service workflow integration

The default-off manager/agent/UI candidate is documented in
[service-action-workflow.md](service-action-workflow.md). It preserves the permit
contract and independent helper ledger. Runtime opening remains existing-only;
the separate [create-only setup](guided-service-action-setup.md) provisions fresh
manager/endpoint action state after explicit local approval. Protected command
trust, reviewed target/local grants and native disposable-host acceptance remain
required.
