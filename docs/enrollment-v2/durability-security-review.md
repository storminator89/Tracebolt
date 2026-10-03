# Enrollment durability and foreground scheduling review

Date: 2026-10-03. This review covers new, initially unwired enrollment storage,
fixed issuing, application-service and foreground scheduling components. It is
separate from the pure-model review and from published checkpoint
`786dbf3a672dd80be9c8ad21f68f3d4abefb16ec`, which contains no enrollment code.
The optional HTTP handler, protected configuration and runtime preparation
subsequently received the focused acceptance below. Combined native enrollment,
foreground operation and UI release acceptance remain separate gates.

## Reviewed boundaries

- The Linux SQLite adapter restores a transaction-local private ledger under
  `BEGIN IMMEDIATE`. Current lifecycle, certificate identity, expiry/revocation,
  replay floor and retained observation are checked in that same transaction.
  There is no process-local authorization cache or two-database telemetry commit.
- Issuance commits exact DER together with the state transition. Delivery returns
  no DER on a failed transaction. Repeated valid deliveries return identical
  committed DER; delivery-count deduplication covers only the most recent
  request ID. Delivery and exact telemetry retries do not refresh observation age.
- Inspection snapshots still cannot restore authority. The new private-ledger
  codec is explicitly trusted local storage material, including invitation
  verifiers, and must never become a network import/export or logging surface.
- The issuer accepts preprovided dedicated intermediate material and an explicit
  offline-root certificate. It generates no private keys. Fixed client-only
  templates and the pinned toolchain produce identical DER after reconstruction;
  signing itself grants neither approval nor delivery authority.
- The service requires Linux-only enrollment and at most 25 retained records,
  including tombstones. Challenges are purpose-bound and one-use, with a global
  issuance rate and bounded proof-operation admission before database reads.
- The foreground loop owns the sender-state lock through waiting. It reuses exact
  pending bytes before collecting again, preserves receipt/collection times on
  retry, and retains unacknowledged data on cancellation. Generic transport
  rejection is retryable, not proof of revocation.

## Findings resolved during this review

1. Rejected existing empty and unrelated SQLite files were modified by journal
   setup before schema validation. Independent byte-preservation tests failed.
   Read-only preflight now checks the exact known schema and complete stored
   contract before mutable pragmas; both independent regressions pass.
   Connection-local untrusted-schema protections precede integrity checking.
2. Invitation result formatting did not protect every formatting verb. It now
   uses an opaque pointer-backed handle and value-safe formatting redaction;
   explicit pointer/value and invalid-verb tests pass.
3. Persisting an issuance start before a newly valid issuer's `NotBefore` could
   strand the intent. The fixed service clamps validity to its issuer before
   persisting; a generated-key regression passes.
4. Retained-nonce capacity alone did not bound churn or expensive proof reads.
   The service now limits global challenge creation to 120/minute and admits
   only two proof operations at a time before database access. Independent tests
   verify capacity, one-use concurrency and that a busy rejection does not consume
   the caller's challenge.
5. Frame validation sized a newly generated exporter envelope containing the
   current clock and unrelated prose. Validation now applies pure observation
   policy and sizes the actual incoming envelope. A maximal legitimate incoming
   bundle and per-field rejection regression pass; the 64 KiB bundle and 72 KiB
   frame caps remain unchanged.
6. A pre-expired foreground context was labeled canceled rather than deadline.
   The distinction is corrected and independently tested.
7. Optional credential responses checked proof purpose after an unrelated
   certificate lookup, producing a state conflict rather than early proof
   rejection. Purpose is now checked first. No credential-delivery bypass was
   observed.
8. Bootstrap PEM parsing could skip unvalidated prefix material and then export
   the original string. Strict certificate-only framing now rejects harmless
   synthetic and malformed prefixes as well as private-key blocks. Bare empty
   query aliases are also rejected by the canonical-path guard.
9. V2 mode preparation could write a new marker before discovering an existing
   unmarked enrollment database. Orphan databases and all SQLite sidecars now
   require explicit recovery; rejected partial state is preserved. Bootstrap
   server trust is checked against the selected listener SANs and key policy.
10. Device display combined identity and observation reads from separate
    transactions. A joined store view now returns both from one validated
    transaction, avoiding inconsistent trust/observation combinations.

## Test evidence

All checks below used ordinary generated ephemeral fixtures, private temporary
databases, fake clocks or loopback TLS. No real deployment or credentials were
used. Existing-v1 weak-key exploit reproduction is outside these checks.

- Five independent store/ledger groups, race detector, five repetitions: pass.
  They cover cross-handle CAS/reopen, cancellation, no cached authority after
  corruption, preservation of rejected files, exact configuration binding and
  strict private-ledger parsing.
- Full enrollment-store race suite: pass. This includes separate-process
  serialization, exact credential persistence, write rollback, delivery purposes,
  activation, replay and expiry checks.
- Nine independent service groups after the stricter rate/work limits, race
  detector, five repetitions: pass. They include lost signing-result recovery
  across durable close/reopen, identical DER and revocation during signing.
- Ten independent optional HTTP groups, combined with the service suite under
  race detection for five repetitions: pass. Actual loopback TLS and explicit
  HTTP-test profiles cover exact authority/context, protocol versions,
  browser/native credential separation, body/nonce limits, trusted socket-peer
  rate limiting, replay/expiry, fixed public errors, one-time secret readback,
  bootstrap public material and logout during body reading before mutation.
- An additional independent actual-TLS operator regression, race detector,
  three repetitions: pass. Invalid confirmation and expired lifecycle actions
  return their scoped errors while the operator's valid session remains usable.
- Five independent scheduler groups and six independent foreground integration
  groups: pass with race detection. The latter use ordinary loopback TLS and
  exercise lock retention, exact retry, stale replacement and cancellation.
- Fixed issuer package race tests, including actual fresh-process deterministic
  reconstruction: pass. Scoped issuer/store vet: pass.
- Bundle, LAN frame and dev-preview package race suites plus the independent
  actual-envelope boundary test repeated five times: pass.
- Seven independent protected-configuration/mode groups plus guided runtime
  preparation tests, race detector: pass. They cover strict material handling,
  both listener SANs, exact trust/origin/instance bindings, concurrent/torn mode
  markers, legacy approval/tombstone refusal and no identity-store fallback.
- The complete new v2 ingress package suite, race detector, three repetitions,
  and vet: pass. Ordinary real TLS/explicit HTTP fixtures cover activated-only
  admission, dedicated-issuer isolation, reused-connection revocation, durable
  retry, unavailable storage and two-slot admission before durable lookups.

## Remaining gates and operational limits

Every store transaction currently loads and validates the complete bounded
ledger, certificates and latest frames. The 25-record exposed-service limit is
mandatory, not a suggested 1000-record default. See
[the store measurements and limitations](durable-store.md); allocation per
operation is not peak resident memory or a production throughput guarantee.

An independent five-iteration rerun with 25 credentials and dense frames padded
to exactly 73,728 accepted wire bytes measured 52.55 ms per read transaction,
36.47 MB allocated and 64,400 allocations per operation. One concurrent
status/observation/revocation run measured 56.55/137.44/235.95 ms including lock
wait. These are measurements of this particular fixture and workspace, not
universal worst-case bounds; acquisition order and machine load affect them.

Read-only WAL access may use existing shared-memory bookkeeping. It must not
change a rejected file's journal mode, schema or checkpointed contents. An
immutable-main preflight is never current authorization; the final SQLite
transaction reloads current state. SQLite's WAL is part of persistent state.
[SQLite WAL documentation](https://sqlite.org/wal.html)

The tests establish rollback after SQLite write failure and durable orderly
reopen. They do not establish injected COMMIT-failure or kill-at-every-crash-point
recovery. A structurally valid older database, including an apparently valid
main file copied without its committed WAL, cannot be detected as rollback by
this local state alone. Recovery needs explicit quarantine/reconciliation or a
new instance epoch; there is no transparent backup restoration guarantee.

Private-first-write native-client persistence and actual three-binary
Add→claim→approve→activate→periodic-report acceptance are now recorded in
[the native-client review](native-security-review.md). Final combined-source
browser/CI acceptance and source-consistent configuration/custody documentation
remain publication gates. Generic failures still
cannot authorize an automatic conclusion of revocation. Installation, reboot,
renewal, migration and production operation remain separate scopes.
