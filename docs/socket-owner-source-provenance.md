# Socket-owner source provenance (source-only candidate)

This slice adds strict transport and durable metadata for the separately
consented socket-owner helper. It does not enable the helper, grant host access,
change identity/enrollment state, install a service, or establish native host
acceptance. No collector, native adapter, command, deployment, or system sender
ledger persistence format changes are part of this slice.

## Source contract

`systeminventory.SocketOwnerProvenance` has exactly eight required fields:

- `schemaVersion`: `tracebolt.socket-owner-source.v1`
- `scope`: `systemd-pid1-local-tcp-udp-socket-owners`
- `grantEpoch`, `policyDigest`, `authorityRevision`, `contextId`: canonical,
  lowercase, nonzero 64-character hexadecimal correlation identifiers
- `startedAt`, `finishedAt`: the original canonical UTC helper interval

The helper interval cannot run backward or exceed five seconds. Its start must
be at or after the snapshot's original batch `collectedAt`. Its finish must fit
the full batch `durationMs`; only a strictly sub-millisecond upper-end allowance
accounts for integer duration truncation. The manager also rejects an initial
submission whose helper finish is after its receipt time. The source object has
a 1024-byte ceiling and rejects unknown/duplicate keys, missing/null values,
noncanonical times and invalid UTF-8.

Socket section `observedAt` keeps its existing meaning as the original batch
start, equal to snapshot `collectedAt`. The separate source interval is the
actual helper timing. Nothing relabels that interval as receipt, retry, later
collection, view, or cleanup time. A helper source marker requires a complete socket section. Failed helper
attempts use ordinary untagged frames. Attribution remains the
existing observed/partial/unavailable per-row evidence.

Public binding/context values are correlation metadata. The manager validates
and preserves the authenticated agent's source statement; it does not thereby
attest to host privilege, a currently active grant, or complete host coverage.
The client/helper integration must authenticate the actual writer and recheck
current identity, consent, grant and runtime context before staging and every
send or retry, discarding the entire stale tagged body with consumed floors
preserved. That integration and native acceptance are separate gates.

## Wire and durable retention

`systemwire.EncodeSocketOwners(sequence, snapshot, provenance, identity, updates)`
emits `tracebolt.agent-system-inventory.v4`. Its required
`socketOwnerProvenance` may coexist with either, both, or neither of the existing
endpoint-identity and cached-update extensions. Each optional extension still
requires its own exact consent pair. There are four enumerated v4 object shapes;
there is no arbitrary extension map. Untagged v4, a source marker labeled v1-v3,
unknown versions and unknown fields fail closed. Existing v1-v3 bytes, body
ceiling, sequence derivation, signed request and exact-body receipt domain remain
unchanged. Older managers reject v4 instead of silently stripping its source.

The enrollment store preserves source metadata on both the latest batch and the
independently retained last-complete socket generation. The latter also retains
the original batch duration internally, so a later failed batch cannot change
the bounds used when reopening old rows. Latest/last-complete source metadata
must match when they reference the same complete generation. Services never
carry the socket-only marker. The SQL schema and other replay/identity domains
are unchanged; canonical metadata restoration makes older readers reject an
unrecognized marker rather than rewriting it away.

A later failed attempt leaves old complete rows and their original provenance
intact. A successful ordinary fallback replaces its own rows and clears the old
helper marker. Exact retry returns the original receipt without refreshing
source timestamps. Existing 24-hour cleanup removes expired source metadata
with its owning batch/section while keeping the system sequence floor and exact
receipt. No grant withdrawal is inferred from an untagged ordinary frame.

The operator API exposes optional `socketOwnerProvenance` in `latest`,
`lastComplete.sockets`, and socket pages. Untagged fields are omitted. The view
and page schema names remain unchanged. Strict UI types/validators must admit
only this explicit optional shape, bind page source to its selected generation,
and clearly label it as reported helper source rather than privileged-host
attestation before this candidate can be used end to end.

## Inert fixture coverage

`TestSocketOwnerProvenance*` covers strict fields/versions, all four v4 shapes,
legacy v1-v3 byte equality, bounded interval/truncation/overflow checks, exact
receipt and synthetic signing, manager rejection without floor advance, retained
last-complete provenance across failures and reopen, ordinary fallback clearing,
paging, metadata corruption, old-reader canonical rejection and independent
retention cleanup. Tests use only synthetic snapshots, temporary SQLite stores,
fixture credentials and in-memory request verification; no real host source,
helper socket, network send, service, privilege, permission or installation is
exercised. Passing fixtures do not establish native acceptance.
