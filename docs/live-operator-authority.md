# Live operator authority (TB-14 source candidate)

This document describes a source candidate based on main
`071ed51432395be62fa9c0a42ef914c500f80ddd`. It is not release, deployment or
Issue #141 acceptance evidence. The Linux startup/API/dispatch integration and
initializer have not passed compilation or full integration tests in this
workspace: the existing offline cache lacks `modernc.org/sqlite@v1.60.1`.
No provisioning, host change, browser test or CI change was performed.

## Protected authority and explicit provisioning

Live accounts are TLS-only and opt in through a protected operator-auth reference:

```json
{"schemaVersion":"tracebolt.operator-auth.v3","profile":"tls","authorityId":"authority_<32 nonzero hexadecimal digits>","authorityFile":"<absolute StateDirectory>/operator-accounts.jsonl"}
```

The example is schematic, not valid provisioned material. All four fields are
required; extra, duplicate, null or mixed legacy credential fields are rejected.
The reference has a 4096-byte bound. `Material.AccountAuthority` carries this
reference; it does not itself confer authority. The ID and profile must match the
journal. Static credentials cannot be mixed with a live authority store.

The Linux-only `operator-account-init` source accepts exactly these options:

| Option | Contract |
| --- | --- |
| `--lan-config` | Existing absolute protected TLS LAN configuration; its `operatorAuthFile` names the approved named-v2 seed. |
| `--output` | New absolute v3 reference file, outside both state and served frontend directories. |
| `--runtime-uid` | Explicit nonroot UID, equal to the executing UID. |
| `--acknowledge-live-authority` | Explicit acknowledgement of the permanent create-only authority fence. |

This is a flag contract, not authorization to run provisioning. The manager must
be stopped. State and output directories must already exist with the required
private ownership and protected ancestors. State and frontend directories must
be disjoint; the seed must not be served. No directories, credentials or account
privileges are manufactured. The named-v2 seed must already contain an explicit
`manage_accounts` grant. Existing IDs, usernames, verifiers and capabilities are
retained. `manage_accounts` occupies the new uint32 bit 65536; existing capability
bits, including `read_customers` at 32768, are unchanged.

The initializer takes the manager's exclusive writer lease and requires all
three destinations to be absent. It creates, in order:

1. `StateDirectory/operator-authority-used.json`, pinning the v3 authority ID,
   TLS profile and exact journal path.
2. `StateDirectory/operator-accounts.jsonl`, with global revision 1, account
   revisions 1 and revocation floors 0.
3. The new protected v3 reference at `--output`.

Files use exclusive creation, no-follow checks and private mode; files and
containing directories are synced. The original LAN configuration and v2 seed
are unchanged. Activation requires a separately reviewed configuration change
selecting the new reference and the matching manager binary. The initializer
never overwrites, rolls back, deletes partial files or automatically retries.
Its JSON diagnostics do not echo argument values or credentials. A failure's
`created:false` is not proof that no partial state exists.

## Startup, transitions and failure policy

Startup checks the used marker under the manager writer lease before opening the
journal. Existing marker plus legacy v1/v2 configuration is denied. V3 without a
matching marker is denied. A missing journal is never reseeded. Schema validation,
`LoadMaterial` and doctor do not open, lock or initialize the journal. Doctor
reports live-account authority as **unknown**, requiring the exclusive startup
check; a valid reference does not prove valid stored credentials or audit.

The Linux journal is an exclusively locked append-only chain of canonical JSON
frames, bounded to 32 MiB total and 128 KiB per frame. A frame commits the next
account snapshot and its audit together, then fsyncs. Files must be private,
regular, single-link and owned by the runtime UID under protected ancestors.
Missing files, malformed/torn history, changed chains and uncertain writes fail
closed. Audit records contain global revision, requester/target IDs, previous
and current account revisions, UTC time and operation; they omit usernames,
verifiers, tokens and request text. The protected journal itself necessarily
contains verifiers and must never become a log, Git artifact or public download.

Every accepted account update increments the target revision and advances its
revocation floor, even when privileges are subsequently regranted. Old approval
epochs therefore cannot revive. IDs and usernames remain stable. Updates publish
a target deny fence, cancel its sessions, drain admitted work, durably commit,
and publish the new authority. Unrelated operators retain their own admission
paths. Login compares the credential revision again after hashing. An authority
lease must remain held through the actual local dispatch/write boundary;
a preceding boolean check is insufficient. Live ingress responses are restricted to
HTTP/1 and flush their complete, length-bounded JSON body before releasing the
lease. On write/flush failure the supported write deadline is expired before
handler abort, since HTTP server panic cleanup can otherwise flush buffers.
HTTP/2 live permit output is rejected; no TLS listener configuration is changed.
Already delivered irreversible permits
and already started external provider calls cannot be recalled.

A failed or uncertain transition leaves the target fenced in that process. Do
not retry based only on a missing response. Preserve the marker, journal, audit,
reference and any partial state for reviewed recovery. There is no automatic
repair, journal compaction, rollback or recovery command in this candidate.
Restart requires manual inspection of the journal/audit before admitting the
account again. A failed pre-write revocation is not claimed durable: only a
successfully committed frame proves the new revision. Reopening accepts only a
complete valid chain; storage uncertainty can prevent further transitions. Restore must preserve authority history together with job
approval epochs and existing replay/revocation floors. Local chaining and the
used marker do not prevent a privileged whole-filesystem rollback, deliberate
marker removal or execution of an older binary that ignores this contract.
There is no external monotonic witness or root-compromise guarantee.

## Account API and credential proposals

In live mode, `GET /api/auth/accounts` requires current `manage_accounts` and
returns IDs, revisions, revocation floors, disabled/uncertain flags and
capabilities, never verifiers. `POST /api/auth/accounts/update` additionally uses
the existing exact-Origin/CSRF JSON mutation boundary. Its strict 4096-byte body
requires `actorId`, positive `expectedRevision`, `disabled`, `capabilities`,
`resetSessions` and `resetPassword`; both reset flags must be explicit booleans.
Capabilities are the complete reviewed replacement list. Removing the last
active account administrator is rejected. This API changes existing accounts;
it does not create or rename accounts.

Success returns the new revision and revokes the target's old sessions/grants;
a self-update clears its cookie. A stale revision returns 409, invalid change
400, insufficient current authority 403, and an uncertain transition 503 with
an instruction to preserve state rather than retry. Legacy mode exposes no live
account management API.

`resetPassword:true` never accepts a password, verifier or path in HTTP. A
credential custodian must separately provide the protected adjacent proposal
at `operator-accounts.jsonl.credential-<actorId>.json`. Its maximum size is 4096
bytes, with the same private file/ancestor rules as the journal. It must contain
these fields in this exact order (whitespace is allowed; duplicate/unknown
fields, reordered/noncanonical encodings and trailing values are rejected):

1. `version`: `tracebolt.operator-credential-proposal.v1`
2. `authorityId`: the exact current authority ID
3. `actorId`: the exact existing target ID
4. `expectedRevision`: the target's current numeric account revision
5. `passwordHash`: an accepted Argon2id verifier

No real proposal or verifier belongs in this document or command arguments.
Live password rotation must preserve the original Argon2 memory, iteration and
parallelism policy, including a one-account roster. The immutable unknown-user
dummy workload therefore remains equal to every current account workload.
Changes are rejected before session fencing, and journal transition/replay
validation also preserves this policy. Work-factor migration is not supported
by this reset API or by a restart.

The proposal is read only after administrator admission, then the update
rechecks current authority and revision. Successful use leaves the proposal in
place, but its old revision prevents reuse. Custodian replacement/cleanup is a
separate protected-material operation, not an HTTP capability. `resetSessions`
is a session reset; this candidate does not implement an MFA factor store or
claim an actual factor-credential reset.

This is an unresolved acceptance-scope conflict in #141: its MFA-reset wording
is not satisfied by session invalidation. There is no MFA factor store or factor
reset operation in this candidate, and no #140 product feature has been added.
The MFA-specific criterion must remain open; neither these password tests nor
a session-reset test establishes it. Closure requires an explicit resolution
of that acceptance scope, not an inferred equivalence.

## Acceptance matrix and remaining evidence

| TB-14 boundary | Source mechanism | Remaining acceptance evidence |
| --- | --- | --- |
| Durable, versioned accounts and atomic changes | Protected v3 reference, pinned used marker, journal snapshot/audit transitions | Public-path provisioning/startup and crash/reopen acceptance on a supported protected filesystem; full integration build |
| Immediate account-specific session/grant withdrawal | Deny fence, session cancellation/drain, current account admissions, post-hash revision check; core race suite including self-disable and crossed administrators passed | Compiled API/session transport acceptance on final candidate |
| Deferred dispatch and regrant safety | Durable approval epochs/floors; lease integration for service actions, package/update/software/MSI jobs | SQLite-backed recovery tests and transport write-boundary tests for every path, including MSI Poll/Chunk |
| Personal deferred/external work | Actor-bound test-alarm delivery; named-account route policy denies personal AI analyze/provider-test, including `manage_accounts` administrators | Worker/transport regressions and the real-route AI denial regression (SQLite-blocked); no live AI capability or external-call recall claim |
| Audit and clear failure policy | Revision and audit in the same durable frame; uncertain target remains fenced | Full failure-injection matrix and reviewed recovery procedure; no rollback guarantee beyond stated trust boundary |
| Operationally usable account changes | Account API, explicit credential proposal, administrator preservation | API admission/redaction/negative tests and matching supported deployment artifacts; MFA remains absent |

Recorded tests for the configuration/provisioning slice used Linux, Go 1.27.1
at `/workspace/toolchains/go/bin/go`, existing cache `/workspace/go-cache` and
module cache under `/workspace/go-path`, with `GOPROXY=off GOTOOLCHAIN=local`:

- `go test -race ./internal/lanconfig -run 'Test(AccountAuthority|ManageAccounts|NamedAuthStrict|NamedApplicationCheck|ManageSessions|CustomerRead)' -count=1`: **PASS** (1.034 s).
- `go test -race cmd/operator-account-init/main.go cmd/operator-account-init/initialize_other.go cmd/operator-account-init/main_test.go -count=1`: **PASS** (1.017 s), portable parser/help/redaction harness only; not the Linux initializer.
- `go test -race ./cmd/operator-account-init -run '^$'`: **BLOCKED before compilation**, missing `modernc.org/sqlite@v1.60.1` with module lookup disabled. No download bypass was attempted.

These checks predate a final immutable candidate and do not certify later shared
changes. Core journal descriptor fixtures can exercise real file/fsync/reopen
behavior, but cannot substitute for public constructor protection checks. In
this workspace `/` and `/tmp` are owned by UID 65534 while the process is UID
1000; the required ownership boundary rejects otherwise positive public-path
fixtures. No permissions were changed or checks weakened. Final acceptance
needs an authorized supported filesystem and the required dependency already
available through an approved path, then a compiled final revision, complete
non-GUI integration/race tests and independent review. The separate unchanged
PR #209 addresses the baseline Lookup clock-before-lock defect and remains a
final acceptance dependency; this candidate does not claim that fix. Issue #141
remains open.

Final local package run after the credential-proposal fixes used:

```
GOPROXY=off GOTOOLCHAIN=local GOCACHE=/workspace/go-cache GOPATH=/workspace/go-path /workspace/toolchains/go/bin/go test -race ./internal/operatorauth ./internal/windowsupdatejob ./internal/windowssoftwarejob ./internal/windowsmanagedmsi ./internal/actionjob ./internal/windowsactionjob -count=1
```

Results: operatorauth 11.593 s; windowsupdatejob 104.008 s;
windowssoftwarejob 2.925 s; windowsmanagedmsi 4.073 s; actionjob 1.328 s,
all PASS. windowsactionjob had no tests in this invocation. Vet passed for
operatorauth, windowsupdatejob, windowssoftwarejob and windowsmanagedmsi.
The focused lanconfig command above was repeated successfully (1.078 s).
Isolated alarm worker files (`types.go`, `test_payload.go`,
`account_authority_test.go`) passed race ten times (1.025 s); this excludes
SQLite-backed Settings/store integration. Packageupdate production files
plus contract/native/results/authority-epoch tests passed race (1.518 s);
this excludes the SQLite durable-workflow suite.

The combined command `go test -race ./internal/api ./internal/enrollmentstore
./internal/enrollmenttransport ./cmd/lan-manager ./cmd/operator-account-init`
with the same offline environment failed during dependency setup, before
compilation. New API and live-AI-denial tests are therefore unverified source.
The frontend capability whitelist was updated for `manage_accounts`, but no
frontend build/typecheck ran: this worktree has no installed TypeScript tooling.
No browser or GUI tests ran.

A subsequent independent local review confirmed an HTTP/1 response buffering
ordering defect in the first candidate. All six ingress families now use the
shared account-bound response helper, including MSI Poll and Chunk. Direct
manager lease tests do not prove this transport property; full ingress-path
regressions with SQLite remain a separate mandatory gate. The earlier reported
service Preview-to-Approve epoch blocker was retracted as a false positive;
preview records are distinct from already approved jobs, and no preview-sidecar
change was retained.

The shared response helper's actual local HTTP socket tests passed with race
instrumentation ten times (1.103 s):

```
GOPROXY=off GOTOOLCHAIN=local GOCACHE=/workspace/go-cache GOPATH=/workspace/go-path /workspace/toolchains/go/bin/go test -race internal/enrollmenttransport/account_response.go internal/enrollmenttransport/account_response_test.go -count=10
```

A temporary copy removing only the explicit Flush failed the small buffered
response test deterministically. The unchanged production helper passed. Tests
cover small responses and larger buffered tails, socket errors, wrapper-generated
write/short-write/flush errors, write-deadline expiry before abort under the
lease, HTTP/2 rejection, static compatibility and flush-wrapper support. This
is real HTTP helper evidence, not a SQLite-backed six-family ingress acceptance.

Additional Linux fixture source now exercises the public initializer's create-only
success, existing/partial state rejection, second writer, symlink and file-mode
rejection, protected path separation and a subprocess-only short-write failure
after marker creation. The latter is not a power-loss/fsync crash proof. API
fixture source uses public journal constructors and a real private proposal file,
password/session/epoch rejection after reset and restart, unrelated-account
availability, stale proposals and an actual temporary-journal size-integrity
failure. It does not claim to simulate fsync failure. No test skips the protected
ancestor gate or changes host/ancestor ownership. These new files have not compiled
in this executor because its SQLite source cache is absent; the separately
verified existing offline executor must run them on the published revision.
