# Complete process and mount generations

This additive source candidate keeps current managed-operations-v3 enrollment,
credentials, telemetry and package pending bytes intact. `InitializeOverview`
explicitly installs the exact optional schema in the existing protected DB under
its normal authority transaction. Opening accepts either the exact old schema or
the exact old-plus-extension schema; partial, foreign and modified schemas are
rejected. There is no deletion, migration reset, profile relabeling or adoption.
The schema version remains3. Older binaries with a strict schema allowlist may
refuse the extended database; this is not a downgrade path. Initialization does
not grant endpoint collection consent.

Processes and volumes are two fixed independent domains. The public device is
always resolved from current authority; the internal namespaced device key is
never accepted from the request. Each section has its own sequence floor,
staging/current pointer, deterministic section-bound transfer ID and binding.
Both retain source capture identity and the original UTC capture interval. The
manifest's sibling metadata and reported full-snapshot size are context, not
validation of sibling rows. Only the selected section's complete enumeration,
field-coverage counts, canonical bytes and digests are verified and promoted.
A failed section therefore cannot block the other section or erase/refresh its
own previous complete observation. A complete zero-row section is explicit;
missing, failed, expired and unavailable never become empty success.

The protocol is a fixed typed mechanical adaptation of fullinventory,
inventorywire and inventoryledger. The original package schema, wire, tables and
pending bytes are unchanged. Canonical transfer ordering uses numeric PID or
mount ID. Typed checkpoints retain the previous identity, hash state, byte/count
and field-coverage state, bounded to4KiB; they do not carry all mount IDs. Numeric
ordering rejects duplicate identities across chunk boundaries. The operator
index separately keeps measured-local-first, root-first mount display order.

All admission, append, finalize, status and read operations use the SAME fresh
BEGIN IMMEDIATE authority transaction as lifecycle/credential checks. Current
activated Linux v3 identity, exact certificate, expiry/revocation and both normal
and maintenance clocks are checked live. No provisional result escapes failed
COMMIT. Cleanup is a privileged operator-only method; no agent cleanup endpoint
exists. It only reclaims eligible noncurrent data, including after revocation or
expiry, in batches of256 rows/16 chunks. It never deletes the current pointer,
replay floor, cursor key, credentials or identity. Reservations survive partial
cleanup. Original staging/cursor-retention eligibility remains in force.

Staging expires after15minutes from original begin; cursors after at most15minutes;
observation access after24hours from original capture start. Failed/staging
transfers preserve the previous complete age. Status can retain expired metadata;
expired pages return an error. Operator pages bind device, section, generation,
normalized search and requested limit in a MAC-authenticated cursor. Pages use
an indexed display-key/ordinal seek, scan at most2048 rows, return at most100,
and stay within256KiB including an envelope reserve. Long paths reduce page row
count while preserving continuation. No total-prefix capture or export limit
claims completeness. Search continuation is explicit and never a false no-match.

Rejection ceilings are not supported-capacity promises: source snapshots24MiB,
selected sections16MiB,32768 processes or16384 mounts; chunks64KiB/128 rows,
1024 chunks; runtime retained generation48MiB. Logical accounting includes exact
manifest/checkpoint/chunk/row BLOB bytes and normalized display-key bytes.
Package and overview domains share128MiB global,400000 reserved rows,4096 chunks,
75 generations; packages plus both overview domains share96MiB/device,
200000 rows/device and2048 chunks/device. System observation payload/authority
bytes also count against the global byte cap after extension initialization.
Each fixed overview section allows18 retained generations to cover the existing
15-minute cursor window at a60-second reporting cadence; all the aggregate
ceilings above remain unchanged. This does not promise maximum-size snapshots
for every device or every minute.
The current512MiB DB,640MiB WAL and2MiB SHM physical caps remain shared unchanged.
The inherited WAL reservation can fail closed under checkpoint starvation;
this implementation does not provide DB/WAL deletion or automatic recovery.

The configured complete-profile LAN manager explicitly initializes this optional
extension during startup and starts one trusted maintenance loop with its own
lifecycle. One tick persecond round-robins at most25 freshly resolved issued
devices and the three fixed domains (packages,processes,volumes). It selects one
eligible noncurrent generation and reclaims at most256 rows/16 chunks under the
same live maintenance authority transaction. Package cadence and retention are
unchanged. No agent request invokes reclamation. The loop continues after busy
or failed steps, never deletes current data, and emits only a fixed rate-limited
availability warning; it stops before stores close. A synthetic28-generation
steady-state test advances60seconds per capture for both overview sections,
proves bounded cleanup continues past18 generations, and verifies old package
cleanup and retained original ages/floors. Aggregate ceilings can still reject
new capture admission and never authorize truncation.

Routine authority transactions restore only small typed floor metadata and
normalized ownership/accounting. They never load all row sets, chunks, or every
generation checkpoint. Each selected append/finalize/page restores only its one
bounded checkpoint. Local protected DB checks detect structural corruption;
these hashes are not authentication of an arbitrarily malicious local rewrite.

Synthetic-only evidence: strict add-only initialization preserves existing
credential/ledger/package manifest/checkpoint/chunk/row/cursor bytes; old pending
package transfers continue; partial extensions fail closed; real authority
fixtures cover complete paging, replay, original ages, rollback, real deferred-FK
COMMIT failure, revocation, expiry, bounded cleanup and durable floors; long
escaped mount paths exercise byte-limited progressing pages and exact display
key accounting; query-bound retired cursors/search continuation and zero are
separate. Real disposable TLS/HTTP fixtures cover current authority and delayed
body revocation. No actual host process, mount, journal, service install or
external write is exercised. Native consent/deployment acceptance remains separate.

## Verification boundary caution

The new overview/maintenance/HTTP/golden fixtures above are synthetic. The full
`cmd/lan-manager` test suite is **not** a synthetic-only gate: existing ungated
`TestGuidedThreeBinaryEnrollmentAndForeground` and
`TestOperationalThreeBinaryEnrollmentAndForeground` launch local fixture agent
binaries and the latter performs live basic/operational host collection. Those
pre-existing tests ran during this candidate's broad manager-suite check; that
was outside the requested synthetic-only boundary. They are excluded from the
synthetic evidence and must not be rerun for that gate. Complete-overview,
package-positive and systemd opt-in runtime gates were not enabled. Prefer
compile/vet or explicitly selected synthetic manager tests for this work.

## Fresh request/output clocks

Trusted service and ingress code install `WithOverviewClock` with their own
manager clock. The context key/value are private, never populated from a request
body, header or source timestamp. Every overview transaction samples this clock
only after connection acquisition, BEGIN IMMEDIATE and authority restoration.
The action uses the maximum of its initial trusted timestamp and that new sample,
so an in-request backward clock movement cannot revive expired access. Direct
fixture callers deliberately omit this hook to retain deterministic supplied-time
behavior; production operator and native overview entry points install it.

View/page results retain a private committed validity boundary. Pages use the
minimum of original capture retention, input cursor expiry and retired grace,
also constrained by current certificate expiry. GET output cannot carry an
available/pending label past its next relevant deadline. Both results resample
and validate after COMMIT; rejected outputs are zeroed. The API encodes once,
checks bounded size, rechecks the operator session and trusted deadline, and
emits those exact already-encoded bytes. It does not re-encode after the check.
This is an in-request clock boundary, not detection of arbitrary system-clock
rollback across separate requests or restoration of an old protected database.

Controlled synthetic tests hold the sole DB connection or a separate writer's
BEGIN IMMEDIATE across cursor, capture, staging and certificate deadlines. They
cover native begin/append/finalize/abort/failure/status and operator GET/page,
post-COMMIT expiry, backward-clock revival rejection, and final encoding/session
boundaries. No host-source or native-binary runtime tests are used for these checks.
