# On-demand service log MVP boundary

Status: integration candidate with bounded reader, local helper, durable query
authority/consumption, authenticated transport and operator pages. Synthetic
checks are distinct from actual helper installation, effective journal access
and service/reboot acceptance. The separate host permission grant has not been
implied by these source tests. See [helper setup](linux-journal-helper.md).

## Useful first scope

An administrator will request one exact supported service unit, an explicit UTC
time window and a maximum severity. The reader retains a bounded snapshot for
paging, not an automatic continuous log feed. Each row contains only journal
timestamp, validated selected service unit, priority and message. Attribution
admits the exact trusted `_SYSTEMD_UNIT` or, for systemd-authored startup/exit
errors, exact `UNIT` only when trusted `_PID=1` and `_UID=0` both match. Other
application-supplied unit claims, coredump/object/slice branches are excluded.
The validating PID/UID fields are then discarded. Raw cursors, boot IDs,
machine IDs, account fields and other metadata are discarded.

The typed reader has a maximum one-hour window within the preceding 24 hours,
500 retained rows, 512 KiB encoded snapshot, 4 KiB per message, 8 MiB raw source,
4,096 scanned rows and 64 KiB JSON lines. A limit becomes an explicit partial or
failed result. A denied or malformed source never becomes a successful empty
log. Source order and duplicates are retained. Complete means the accessible
projected rows for that exact query, not proof of unrestricted host visibility.

Narrow masking removes recognized credential patterns on a best-effort basis.
Messages can still contain passwords, tokens, personal data and other secrets.
Every result carries that warning. Log content must remain inert operator-only
text, outside AI packets, diagnostics, exports and automatic notifications.
Source tests are deliberately invented and do not demonstrate effective journal
permissions or real source completeness.

## Permission design: dedicated helper, no root agent

The main agent keeps its existing numeric identity and group guard. The
reader has its own distinct non-login UID and dedicated primary group. Only its
separate hardened systemd unit receives the local journal-read group. This is a
new persistent access grant requiring an explicit administrator decision before
installation. Source checks perform none of those host changes. The explicit
create-only setup command is the separate local administration boundary.

A root-owned socket directory and socket-activation unit expose one fixed
local Unix endpoint after setup. The helper checks peer UID/GID with
`SO_PEERCRED`; the client checks kernel `SCM_CREDENTIALS` on every received
payload segment against the separately declared helper UID/GID and stable PID. It has no network access, shell, path parameter or
general command operation. The reader should not be able to access the agent's
private enrollment/state directories. A separate UID is required: filesystem
namespace restrictions alone are not claimed as isolation between same-UID
processes. No group name or NSS resolution is accepted as a numeric identity
proof; the eventual deployment must resolve and verify exact local IDs.

The protected root-owned policy declares the exact destination and bound v3
sender, helper and agent UIDs, sorted service allowlist, window/lookback/severity
limits and explicit content acknowledgement. The helper can read the policy;
the agent must not be able to replace it. HTTP-test log content needs a separate
plaintext-content acknowledgement. The existing telemetry consent is not that
acknowledgement. The human notice must disclose possible sensitive message
content, the exact allowed services and the destination.

`internal/journalpolicy` supplies pure strict decoding, authorization and
rechecks. The runtime independently loads current validated enrollment,
root-protected policy/deployment and kernel credentials. A caller cannot turn
request JSON into a trusted context. Separate root-owned client-readable and
helper-readable copies contain identical canonical policy/deployment bytes;
this does not add the main agent to the helper or journal groups. Changed or
inconsistent copies fail closed.

Authorization binds the entire canonical policy and exact query. Before capture
and before releasing unsent content, the caller must reload/revalidate policy and
current context. Disable, allowlist changes, destination/binding changes or query
expiry invalidate the permission. A retained permission is not a reusable lease.
No missing consent, future version or empty policy implies permission.
The pure policy recheck does not supply a lifecycle TTL or a consumed-query
floor; those belong to the separate authoritative request record and native
consumption marker below.

## Integrated request and content flow

An authenticated operator creates one exact request through
`POST /api/devices/{deviceId}/journal/create`, with expected-sequence CAS and
separate unchecked content/plaintext acknowledgements. Cancel, status and query
pages remain under the existing operator session, origin and CSRF boundary.
The already activated v3 agent participates only after the independent local
content policy and create-only consumption marker are present. Polling follows
the configured serialized agent cycle; it does not promise an immediate capture.

The agent paths `/v3/agent/journal/peek`, `/claim`, `/result` and `/status` have a
distinct authenticated purpose and bounded request shapes. Normal TLS or the
explicit signed HTTP-test profile is retained. Claim commits before returning
work; the endpoint durably consumes the exact server query before one helper
capture. A failed or ambiguous claim/capture cannot be retried as a new capture.
No general shell, arbitrary path or command argument is exposed.

A result remains in process memory only until its original 15-minute request
expiry, with one retained result per device (at most 512 KiB) and 25 retained
devices. Local/client and manager buffers are cleared on original expiry on a
best-effort basis; transport and garbage-collected copies are not a guaranteed
memory-erasure boundary. SQLite and the native marker retain only bounded
request/floor/digest metadata, never messages. Lost memory after either restart
is unavailable content, not an empty successful result. A new explicit operator
request is required to collect again. Exact retained-byte retries preserve the
original receipt and expiry and do not rehydrate a restarted manager cache.

Every page checks current device/certificate/revocation and operator authority.
Pages bind the immutable request identity and snapshot digest. The bounded
literal search (128 UTF-8 bytes, case-insensitive) examines captured message text
only, without rereading the journal, a regex engine or source command. A match
count of zero says nothing about omitted rows in a partial capture. Pages retain
original source coverage, collection time and expiry and contain at most 100
rows within 64 KiB. Expired, canceled, revoked and lost results return no rows.

The optional local mode is `--journal-content-consent preview|initialize`, run
under the existing stopped service identity. Initialization requires explicit
content consent and a separate HTTP plaintext acknowledgement, creates only the
new consumption marker, and never recreates any existing ledger. The manager's
profile or a dashboard request alone cannot enable journal access. Existing
release binaries without this mode do not acquire the feature by updating only
the manager; use a compatible reviewed endpoint release.

## Reproducible inert checks

With the repository's Go toolchain and cached modules:

```sh
GOTOOLCHAIN=local GOPROXY=off GOSUMDB=off \
  go test -race -buildvcs=false ./internal/journalview ./internal/journalpolicy \
  ./internal/journalhelper ./internal/journalstate ./internal/journalrequest \
  ./internal/journalwire ./internal/journalcache
GOTOOLCHAIN=local GOPROXY=off GOSUMDB=off \
  go vet ./internal/journalview ./internal/journalpolicy
```

The journal source providers/runners in these tests are injected fixtures.
They do not read the real journal, grant privileges or change services. Separate
transport tests use generated identities and invented rows on loopback handlers;
they do not establish effective host permissions or installed-service behavior.

## Primary-source boundaries

- [systemd journalctl source/options](https://raw.githubusercontent.com/systemd/systemd/v257/man/journalctl.xml)
  defines exact field filtering and the accessible-journal scope.
- [Trusted journal fields](https://raw.githubusercontent.com/systemd/systemd/v257/man/systemd.journal-fields.xml)
  distinguishes journal-supplied attribution from application fields.
- [systemd's exact unit-match implementation](https://raw.githubusercontent.com/systemd/systemd/v257/src/shared/logs-show.c)
  includes the PID1 plus UNIT branch; this MVP adds the root-UID condition and
  deliberately excludes the broader branches used by the general CLI.
- [Linux process access checks](https://man7.org/linux/man-pages/man2/ptrace.2.html)
  support the separate-UID isolation requirement; filesystem hiding alone is
  not treated as separation from another same-UID process.
