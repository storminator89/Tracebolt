# Bounded journal-content reader candidate

This document records the original isolated reader foundation and its source
boundary checks. Later runtime, retention, transport and UI integration is
described in [the log MVP boundary](journal-content-mvp.md). Validation recorded
below uses synthetic data and an injected synchronous runner. The real journalctl
adapter has not been executed; these checks do not establish journal visibility
or disposable-VM acceptance.

## Authorization and identity gate

A separately and explicitly approved local journal-content read grant is required
before any VM/host source run. Existing telemetry, service inventory, endpoint
identity or HTTP-test acknowledgement does not authorize log message content.
Plaintext HTTP-test log content requires a new explicit acknowledgement. The
caller must bind the request to the approved endpoint/query, authenticated peer,
fixed expiry and disable/cancel state before calling this source.

The planned read helper has a distinct non-login UID, with journal membership
limited to that future helper unit. The existing agent identity and numeric-group
guard stay unchanged. This package creates no account, group, service, ACL,
credential, capability, socket, deployment, or network access. It does not grant
consent. Root real/effective UID execution is refused. Adding supplementary groups
or changing any host permission remains a separate approved host action.

## Public value contract

- Query: unit, start, end, maxPriority. Unit is a bounded 255-byte ASCII .service
  subset. Paths, backslash escapes, wildcard/glob/match syntax, empty template
  instances and multiple @ signs are rejected. The name is matched literally
  against trusted _SYSTEMD_UNIT or the fixed trusted-manager branch described
  below. Aliases are not resolved; syntax does not prove a name is canonical or
  that the unit exists.
- start/end are inclusive, canonical UTC time.Time values, microsecond-aligned;
  start < end, end <= caller-supplied trusted now, span <= 1 hour, and start no
  older than 24 hours relative to that trusted now. maxPriority is 0 through 7.
  Priority zero is most severe; the query includes 0 through maxPriority.
- Scope is agent-visible-system-journal-service-and-manager. It covers only
  service-process messages matched by trusted _SYSTEMD_UNIT, plus manager-
  authored messages with trusted _PID=1 and _UID=0 and exact UNIT=selected unit.
  Coredump, OBJECT_SYSTEMD_UNIT and slice branches are deliberately excluded;
  this is still narrower than the broader set journalctl --unit can assemble.
- Snapshot: schemaVersion, scope, query (the original validated query), observedAt
  (the supplied trusted now), coverage, reason, rows, observedCount, countExact,
  redactionApplied and redactionWarning. No ambient clock changes these values.
- Row: timestamp, unit, priority, message only. unit is the validated selected
  query unit after either allowed attribution branch qualifies; it does not claim
  every source record had that _SYSTEMD_UNIT. Source order and duplicates are
  preserved, without resorting or an unstable live cursor. A later server can
  paginate this immutable, already bounded value by index. Authorization and
  storage of that value remain the caller's responsibility.
- observedCount is the lower bound of matching decoded records encountered,
  including a first omitted record that triggered a retained-row/body limit.
  Malformed or oversized messages not fully decoded do not increment it.
  countExact=true only on complete observations, where count equals row length.
  Failed zero/false means unknown, never a proven empty result.
- coverage complete means the accessible projected source stream was consumed
  for this query. It does not mean global host coverage, an atomic snapshot,
  lifetime retention, or that rotated/deleted/unreadable journals were available.
  A successful empty read is complete/none with zero/true. Explicit access denial
  is failed/permission_denied with zero/false. Successful source diagnostics make
  even an empty observation partial/visibility_restricted. Other source failures
  are fixed read_failed, source_missing, invalid_source or timeout values. A
  failure after observed records remains partial; raw tool errors never escape.

Source rows must be JSON objects with exactly one string value for each of
__REALTIME_TIMESTAMP, PRIORITY and MESSAGE, and at least one unit identity field.
Relevant _SYSTEMD_UNIT, _PID, _UID and UNIT identity fields, when present, must be
bounded scalar singleton strings. PID/UID must be canonical numeric identities;
PID 0, signs, leading zeros, overflow and nonnumeric values fail closed. PID1's
own _SYSTEMD_UNIT may be init.scope; the parser does not relabel that raw field.
Duplicated relevant fields, missing required/null/array values, invalid priorities
and malformed JSON fail closed or make a previously retained prefix partial.

A row is attributed only if _SYSTEMD_UNIT equals the selected unit, or if trusted
_PID is 1, trusted _UID is 0 and UNIT equals the selected unit. UNIT alone is an
application-supplied field and cannot authorize attribution. Valid nonmatching
identities (wrong unit, non-PID1 or nonroot manager branch) are excluded, as with
the common time/priority filters. Malformed relevant identities are rejected even
when another branch could match. No SYSLOG_IDENTIFIER, OBJECT_SYSTEMD_UNIT,
COREDUMP_UNIT or slice fallback exists.

Unexpected metadata is ignored and never represented by the public types.
Journal __CURSOR, _BOOT_ID, _MACHINE_ID, account/executable fields and internally
validated _PID/_UID/UNIT/_SYSTEMD_UNIT are dropped even if journalctl emits more
than the requested projection. Timestamp/unit/priority are independently
validated and filtered again after parsing.

## Pure snapshot pages

SnapshotDigest returns sha256:<lowercase hex> over the canonical validated Encode
bytes. SelectPage(snapshot, expectedDigest, offset, limit) accepts 1 through 100
rows, checks the expected digest, and returns only a bounded slice. Wrong digest,
negative offset, or an offset outside captured rows returns journal_view_page_conflict.
Offset zero is valid for an empty snapshot; offset equal to total is otherwise
invalid. A changed snapshot or changed query/time requires a new digest.

Page preserves the snapshot schema/scope, query, observedAt, coverage/reason,
observedCount/countExact and masking metadata. It adds snapshotDigest,
totalCapturedRows, offset and nextOffset (null at the end). The row slice is copied
so modifying a page does not mutate its source. Each page has at most 100 rows and
64 KiB encoded bytes, with a 3 KiB metadata reserve; it can contain fewer rows to
meet the byte cap. EncodePage validates rows and continuation structure before
allocating its final body. Service order and duplicates survive every page with
no gaps. Diagnostic Page formatting is also content-redacted.

These are local snapshot identity/continuation helpers. A digest is not an
access token, MAC or authenticated cursor; the future server must authorize the
snapshot and bind external cursors to the correct identity, endpoint and query.
EncodePage checks digest shape; only SelectPage proves relation to a snapshot.

## Bounds and content handling

- 8 MiB raw stdout, plus one parser overflow sentinel byte; 8 KiB source stderr.
- 64 KiB maximum JSON-line content and 128 object fields; 4,096 scanned rows.
- 500 retained rows, 4 KiB decoded message and 512 KiB total encoded snapshot.
- 2 KiB reserved metadata budget before row retention. Each bounded row is
  encoded separately before append; final Encode validates values, computes the
  bounded row total and only then allocates the final body. The metadata reserve
  makes a near-limit response slightly smaller than the maximum.
- A raw/line/message/body ceiling produces explicit partial/byte_limit; a scan,
  object-field or retained-row ceiling produces partial/item_limit. No truncation
  is labeled complete. Prefixes remain bounded even when a command fails after
  output overflow. No giant raw token, unbounded read-all, generic command
  interface, or abandoned asynchronous collector is used.
- A process-wide single-flight guard holds through synchronous provider return,
  parsing and close. Concurrent collection is failed/collector_busy. Production
  subprocess work has a four-second timeout and one-second wait-delay bound;
  low-level filesystem opens are synchronous and may not be interruptible.
  Injected providers/readers must honor cancellation cooperatively. The library
  cannot force an arbitrary blocking fixture/provider to return.

Messages can themselves contain secrets. Narrow best-effort patterns mask obvious
password/token/key assignments, Basic/Bearer credentials, URL user:password pairs
and PEM private-key blocks. redactionApplied says whether a retained message was
changed. It is not a safety certification. All snapshots, including empty/failed
ones, carry: "Best-effort masking only. Messages may still contain credentials,
personal data or other secrets; this output is not safe or anonymous."

Row, Snapshot and Page implement String, GoString and fmt.Formatter. Every verb
that fmt dispatches to Formatter emits only a fixed content-redacted label,
including incompatible numeric verbs such as %d and %x. Go handles %T and %p
itself: an unsupported %p applied to a non-pointer struct can bypass Formatter
and expose fields. Do not use that form. This protection also does not cover
separately logged message strings or raw source bytes. Deliberate validated wire
output uses Encode/EncodePage. Do not log or publish content, diagnostic
buffers or raw snapshots. UI rendering must treat messages as plain untrusted
text. Server authorization, bounded retention and content acknowledgement are
required beyond this package.

## Protected Linux source

The only executable path is /usr/bin/journalctl. Root-owned, non-group/world-
writable /, /usr and /usr/bin directories are opened one component at a time with
O_NOFOLLOW and pinned descriptors. The executable must be a regular root-owned
ELF file, executable, not group/world-writable, not set-id and without file
capabilities. Only ENODATA/EOPNOTSUPP or a successful zero-length capabilities
attribute passes. An unexpected error fails closed. There is no PATH or symlink
fallback, configurable executable, journal directory, namespace or remote host.

The checked executable inode is passed as child fd 3 and executed through
/proc/self/fd/3. No shell, pager, sudo/polkit agent, interactive input or inherited
environment is used. The fixed environment contains LC_ALL=C, LANG=C, TZ=UTC,
SYSTEMD_COLORS=0, SYSTEMD_URLIFY=0 and SYSTEMD_PAGERSECURE=1. Child cwd is / and stdin
is closed. Fixed argument shape:

    --system --no-pager --utc --all --output=json
    --output-fields=__REALTIME_TIMESTAMP,_SYSTEMD_UNIT,_PID,_UID,UNIT,PRIORITY,MESSAGE
    --since=@<validated UTC seconds.microseconds>
    --until=@<validated UTC seconds.microseconds>
    --priority=0..<validated 0..7> --
    _SYSTEMD_UNIT=<validated exact unit> + _PID=1 _UID=0 UNIT=<same exact unit>

The adapter does not hide diagnostics with --quiet. Successful stderr output is
conservatively visibility_restricted. A known C-locale insufficient-permissions
diagnostic or permission errno becomes permission_denied; other unsuccessful
commands become read_failed. Raw diagnostics are discarded. Buffer writes are
capped before copying, including allocated capacity. Binary/multivalued MESSAGE
forms are not supported; they fail as invalid_source rather than becoming text.
No package initialization reads a source. Non-Linux production construction is
not_supported, while pure fixtures remain portable.

## Synthetic verification and provenance

The isolated reader was prepared against source revision
`a9a9d4e08233ed8b0e968e074da1fa7cf7916121` with the unchanged dependency files
below. Later integration checks are separate from this original reader evidence.
Original file hashes:

- AGENTS.md: e10e4ab32f13fd8f570427dac099610a2137e3eaa2b5492c6c953d7a2c20126c
- go.mod: 4a84963d66fec98645882eace7170c224f02ec1ddebaa61bcff7b54ec9f33543
- go.sum: c05bd11caeef25dd1baa51ebd151975924ce9ba84fa7a42fd85e5adc6b0f8c4b
- reviewed internal/systeminventory/source_linux.go:
  b8294679e615fdb5260b61f4b32fa380672f665ac7a4a9aedd87343b03d9dd6b

Use the already provisioned Go 1.27.1 toolchain with networking disabled:

    export GOTOOLCHAIN=local GOPROXY=off GOSUMDB=off
    # Put the repository-selected Go 1.27.1 toolchain on PATH.
    GO=go
    "$GO" test ./internal/journalview
    "$GO" test -race ./internal/journalview
    "$GO" vet ./internal/journalview
    "$GO" test -run='^$' -fuzz=FuzzParseAlwaysProducesBoundedEncodableSnapshot -fuzztime=15s -parallel=2 ./internal/journalview
    GOOS=windows GOARCH=amd64 "$GO" test -c ./internal/journalview -o /tmp/tracebolt-journalview-windows.test.exe
    GOOS=linux GOARCH=arm64 "$GO" test -c ./internal/journalview -o /tmp/tracebolt-journalview-linux-arm64.test

The Windows/ARM64 checks are compile-only, not runtime acceptance. Tests cover
strict query/row parsing, metadata omission, time/unit/priority filters, source
order and duplicate preservation, valid empty vs denied/unknown, all limits,
heuristic masking and its warning, body encoding, diagnostic formatting,
cooperative cancellation, synchronous admission/cleanup, composed limit/close
failures, exact arguments/environment, injected root refusal, descriptor cleanup,
executable/capability protection facts, bounded injected output, digest-pinned
multi-page ordering, byte-limited continuation, conflict rejection, page
non-aliasing, trusted PID1/root startup-failure attribution, shared manager-row
filters, exclusion of non-PID1/nonroot/wrong-unit attribution, and rejection of
ambiguous identity fields. Synthetic fuzz testing checks encodability/bounds;
the final source revision and test output identify the checked bytes. No test
constructs the real host provider, opens a journal, executes journalctl/systemctl,
changes host permissions, or performs a network request. Actual journal access,
version support and VM/service acceptance remain separately gated and unverified.

Primary source references for the deliberately limited two-branch unit scope:
[systemd v257 journalctl --unit expansion](https://raw.githubusercontent.com/systemd/systemd/v257/man/journalctl.xml)
and [trusted vs manager-attribution journal fields](https://raw.githubusercontent.com/systemd/systemd/v257/man/systemd.journal-fields.xml).
