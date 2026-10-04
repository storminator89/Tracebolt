# Isolated journal helper runtime: held source candidate

This slice adds the local runtime seam to the held journal reader and policy.
It does not install or run that seam, grant journal access, create accounts,
change groups/ACLs/units, contact a manager or publish anything. All execution
checks use synthetic providers, policy loaders, process facts and peer facts;
connections are `net.Pipe` or inert in-memory listener fixtures. Real `journalctl`
execution, socket activation and disposable-VM host acceptance remain unrun.

## Binary and trust boundary

The existing `lan-agent` binary reserves the exact exclusive invocation
`--journal-reader` before normal sender flag parsing. Combining it with another
argument, including config/enrollment/consent/identity flags, fails before the
helper runtime is called. The normal sender's original flags and identity/state
logic remain byte-for-byte unchanged after this dispatch. No new release role
or executable is introduced. The helper never loads enrollment config, keys,
ledger state, TLS material or a manager URL from request data.

Production `journalhelper.Run` first rejects root and process capabilities. It
loads only these fixed root-protected files:

- `/etc/tracebolt/journal-helper.json`: exact numeric deployment metadata
- `/etc/tracebolt/journal-content-policy.json`: strict held `journalpolicy.Policy`

The metadata is canonical JSON in exactly this field order (one final newline
is allowed), with no unknown, omitted, duplicate, null or alternative members:

```json
{"schemaVersion":"tracebolt.journal-helper-deployment.v1","helperUid":1201,"helperGid":1201,"journalGid":190,"agentUid":1200,"agentGid":1200}
```

Those numbers are inert examples, not assigned accounts or portable group IDs.
The separately reviewed installation must supply the host's real numeric IDs.
The helper account is distinct and non-login, with its own primary group and no
account-level supplementary membership. Only its hardened unit receives the
`systemd-journal` group. The main agent UID and primary/supplementary groups are
unchanged. Reusing the main agent UID, `adm`, `wheel`, root or capabilities is
outside the design. The runtime cannot prove an account's non-login status from
numeric metadata alone; account/unit review is a separate deployment gate.

All real/effective/saved UIDs must equal the declared helper UID, all respective
GIDs must equal the helper primary GID, and the complete kernel supplementary
set must contain only the declared journal GID (the primary GID may also be
present). Nonzero permitted/effective/inheritable capabilities deny. The required
unit has empty bounding and ambient sets. The policy's agent/helper UIDs must
match that deployment. A Go `Context`, `State` or injected dependency is not a
trust certificate: runtime context is built only after protected policy,
independent kernel helper identity and kernel `SO_PEERCRED` checks pass.

The calling agent is responsible for validating its current enrollment before
supplying its public sender binding. The helper verifies the peer's exact UID
and primary GID, positive PID, and exact binding equality with local policy.
Origin, collection profile, transport profile and identity declarations come
from protected policy, not request fields. The origin is never used as a network
destination by this process. Possession of a digest grants nothing.

## Protected files and socket activation

Both files must be regular root-owned single-link files, exactly mode `0640`,
group-owned by the helper primary GID. Every directory component is opened with
`O_NOFOLLOW`, checked root-owned and non-group/other-writable. Reads are bounded
and compared against file descriptor and named-entry identity, ownership, modes,
size, ctime and mtime before/after reading. The fixed policy directory is walked
again after both files. Replacements or unsafe/missing files fail closed. Hashes
of the exact raw declarations and safe file/socket metadata form a public
protected-file revision; formatting changes and same-content replacements also
invalidate already captured content. Atime is excluded.

The helper never binds, creates, chmods or unlinks a socket. It requires exactly
one systemd-passed listener at descriptor 3, with matching `LISTEN_PID`,
`LISTEN_FDS=1`, `LISTEN_FDNAMES=journal-reader`, Unix stream/listening semantics,
and the fixed bound path `/run/tracebolt-journal-reader/reader.sock`. The pathname
must be a root-owned single-link Unix socket, mode `0660`, group-owned by the
unchanged agent primary GID. Its directory chain must also be protected.
`SO_PEERCRED` is obtained from that accepted Unix connection; TCP, alternate
paths, auth cookies/tokens, environment-selected config and caller-provided
credential structs are not runtime alternatives.

## Fixed protocol

Each connection contains exactly one length-prefixed binary request and one
response. A second/trailing request is never processed. Integers are big endian.
The total request ceiling is 4 KiB. Request layout:

- 4-byte magic `TBJ1`, then unsigned 32-bit body length
- 1-byte operation: 1 = capture Query, 2 = metadata-only verify-permit
- 32-byte sender binding (the existing bare lowercase-hex binding decoded)
- 32-byte policy digest and 32-byte protected revision
- unsigned 16-bit unit byte length
- signed 64-bit start and end timestamps as UTC Unix microseconds
- 1-byte max priority, followed by the exact unit bytes

Capture requires zero policy/revision fields. Verify requires both current
nonzero digests plus the same binding and exact query. Unknown operations,
lengths, fields or malformed query semantics deny. Only the held reader's
allowlisted service-name grammar is accepted; there are no arbitrary arguments,
paths, commands, shells, URLs, reflection dispatch or generic operation maps.

Response layout: `TBJ1`, 1-byte status, two 32-byte digests, unsigned 32-bit body
length, then content. The entire frame, including its 73-byte header, is at
most 512 KiB (the content allowance is 512 KiB minus 73 bytes). The status values are fixed: 0 snapshot,
1 verified, 2 denied, 3 invalid, 4 busy, 5 unavailable. Only status 0 has a body;
it is exclusively `journalview.Encode` output. Only 0/1 carry digests. External
Go digest strings use `sha256:` followed by 64 lowercase hex characters. No raw
errors, paths or source diagnostics are serialized.

`EncodeRequest` and `ReadResponse` are inert framing helpers. `ReadResponse`
bounds allocation and requires the entire advertised frame. Its deliberate
`Body()` accessor returns a copy; ordinary formatting cannot reveal payload
bytes, including mismatched verbs. A later agent must
strictly decode and validate canonical snapshot content and bind it to its exact
request; the framing function alone is not that content validation. Partial
frames must be discarded, never displayed or forwarded.

## Authorization, bounds and cancellation

There are at most two admitted connections and one active synchronous capture.
Copied server handles share the same private state/guards. Extra connections
are closed; a competing capture receives only a fixed busy status. Admission
happens before spawning a handler. Each connection gets a hard six-second
read/write deadline and a matching context deadline, shortened by any parent
budget. The held reader separately caps source work at four seconds. A timeout
closes the connection and cancellation propagates to the synchronous provider;
the capture slot is not released and shutdown does not return until that
provider has completed cleanup. No timeout branch abandons a worker. A provider
that violates its cooperative contract can delay shutdown, which is not hidden
by claiming an impossible forced goroutine cancellation guarantee.

`journalpolicy.Authorize` checks current allowlisted unit, time window/lookback,
severity, explicit content consent, transport-specific plaintext consent and
identity before capture. A returned snapshot must preserve the exact authorized
query and the trusted capture timestamp; its serializer validates all content
and size constraints. The helper rereads and checks protected policy plus
process identity/revision before response and again before each bounded 16 KiB
content chunk. Changed or disabled policy suppresses the remaining response,
leaving an incomplete frame to discard. Already-written/kernel-buffered bytes
cannot be recalled; this is why later sender release needs its own check.

After capture, the agent can request the fixed metadata-only verify-permit
operation with the original binding, query, policy digest and protected-file
revision. It rechecks the same authorization without any capture or content
response. A later sender must use this immediately before approved transport
and suppress unsent content on any denial/unavailability/revision mismatch.
The snapshot/permit cannot bridge an observed policy or identity change.

Neither this operation nor pure policy checks supply durable query consumption,
a unique query claim, at-most-once collection across restart, a 15-minute
lifecycle, server/operator authorization, transport authority, retention or a
no-recollection guarantee. Those are separate manager/calling-agent gates. The
helper holds no pending content store or durable query history.

## Inert deployment candidates and remaining gates

`deploy/systemd/tracebolt-journal-reader.service.in` and the matching `.socket.in`
are source text only. They require a separate explicit local content-read grant,
account/numeric-ID review, root-owned file/socket provisioning and installation
approval. The separately reviewed [create-only setup](linux-journal-helper.md) now provides
a read-only plan and explicit apply path with socket enablement; it has not been
applied or runtime-accepted by the synthetic tests. The unit
uses the existing binary path, a dedicated account, exact unit-only journal
group, empty capabilities, private network/AF_UNIX restriction, read-only system,
protected home/kernel/process view and bounded resources. It hides the existing
packaged agent enrollment/state directories. Any nonstandard key/state layout
must be identified and hidden in a separately reviewed template; do not assume
an arbitrary private path is covered. Source code has no enrollment/key read or
network dial path, and distinct UID/file permissions remain mandatory.

Real systemd compatibility, journal visibility, actual socket inode/ownership,
non-login account properties, source subprocess cleanup and installation/reboot
behavior require separately authorized disposable-VM acceptance. A template,
source review, synthetic test or cross-build is not evidence of those host
properties. This slice deliberately leaves current sender collection, agent
identity guard and release artifact roles intact.
