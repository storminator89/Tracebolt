# Public bootstrap retrieval for Linux activation

Status: staged implementation candidate. This removes the separate public
bootstrap-file transfer. It does not fetch an installer or executable, provide
publisher authentication, grant deployment authority, or establish real systemd
acceptance. The default ready-only installer still waits in its terminal for dashboard
approval. The explicitly selected `--pending-service` v2 candidate below publishes
a waiting-capable process after a committed same-key claim. Both paths still need
actual disposable-systemd acceptance before any deployment or reboot claim.

## Exact command contract

Build or provision independently selected, verified local `agent-service`,
`enroll-agent`, `lan-agent` and the source archive first. Keep their full SHA-256
values independent of the bootstrap checksum. The manager cannot supply or
replace those executable hashes through public bootstrap data.

For a reviewed TLS installation, replace the existing `--bootstrap` path with:

```
sudo /absolute/path/agent-service --action install --apply \
  --agent-binary /absolute/path/lan-agent --agent-sha256 EXPECTED_AGENT_SHA256 \
  --enroll-binary /absolute/path/enroll-agent --enroll-sha256 EXPECTED_ENROLL_SHA256 \
  --source-archive /absolute/path/source.tar --source-sha256 EXPECTED_SOURCE_SHA256 \
  --manager-origin 'https://configured-manager.example:8443' \
  --invitation-id 'invite_PUBLIC_ID' \
  --bootstrap-sha256 EXPECTED_PUBLIC_BOOTSTRAP_SHA256 \
  --server-ca-base64 'STANDARD_PADDED_BASE64_PUBLIC_CA_PEM'
```

The actual UI-generated origin is exactly `bootstrap.enrollmentOrigin`, the
public ID is `bootstrap.invitationId`, and the hash is the server-returned
`bootstrapSHA256`. The public CA is standard padded base64 of the exact UTF-8
`bootstrap.serverCaPem`. The UI must not recompute the bootstrap hash using
JavaScript serialization. Quote each field as a shell argument; the invitation
secret is never an argument, environment variable, URL, script, or file.

For an explicitly authorized isolated HTTP test, use the configured `http://`
origin, omit the CA argument and add `--insecure-http-test`. The command emits an
unencrypted/unauthenticated transport warning before fetching. HTTP checksum
matching is not manager authentication; a modified UI/command can replace both
the bytes and expected hash. Keep the existing hidden invitation prompt and
full fingerprint/comparison approval.

Online flags require `--action install --apply`. Without explicit apply, they
are rejected before network activity, temporary-file creation, or backend
inspection. Existing local `--bootstrap` planning remains read-only. Before
online retrieval the installer validates real/effective root, running systemd,
foreground terminal and selected local artifact hashes. Full owned-path/account/
state preflight runs after retrieval and again in the existing transaction.

Only public bootstrap bytes are stored temporarily in a fresh mode-0700 `/tmp`
directory with a mode-0600 file. The installer independently hashes/parses the
same public snapshot, then performs its existing protected publication. The
helper removes its own temporary file/directory after the operation. It never
uses an environment-selected temporary directory or recursively removes unknown
contents. The invitation itself remains transient hidden terminal input in the
existing native enrollment client.

## Public server contract

`GET /v2/enrollment/bootstrap/{publicInvitationID}` returns exactly the existing
bootstrap JSON object, serialized by Go `json.Marshal` in its declared field
order, without a newline. The successful invitation-creation response adds
`bootstrapSHA256`, the lowercase SHA-256 of those same bytes. No timestamp or
other changing field is part of this byte contract.

The public route deliberately performs no invitation lookup: any syntactically
valid public ID receives the configured immutable bootstrap with that ID. It
therefore discloses no invitation existence, state, revision, secret, key or
approval information. Fetching it grants no identity or authority. The existing
proof endpoint alone validates an actual invitation and its hidden secret.

Configured TLS/Host/canonical-path guards apply before route handling. The route
accepts only bodyless GET without cookies, authorization, browser Origin, CSRF,
forwarded headers, content encodings, conditional requests, or query strings.
It has a separate bounded per-peer/global admission budget. Responses are
`application/json`, `Cache-Control: no-store`, and at most 64 KiB.

## Native verification

A separate GET-only transport pins the exact origin and invitation path without
broadening the POST-only enrollment proof transport. It disables environment
proxies, compression and redirects. Every DNS answer is vetted before dialing a
selected literal address; unsafe or mixed answer sets fail closed. HTTP test
remains limited to loopback/private destinations.

TLS uses the explicitly supplied public CA and ordinary CA-chain plus hostname
verification, with the existing TLS 1.3/key-strength policy. It never installs
trust globally, discovers trust from an unverified connection, or skips
certificate verification. The body is bounded before hashing. The exact hash
must match before strict bootstrap parsing; parsed origin, public invitation,
profile and public CA must exactly match the command's pinned inputs.

## Fixture evidence

Tests exercise ephemeral HTTP/TLS listeners only, including wrong trust and
hostname, strict JSON failures, altered origin/ID/profile/CA, wrong hashes,
oversized/chunked bodies, redirects, encodings, environment proxies, unsafe DNS
answer sets, admission limits, CLI early rejection and protected public temporary
snapshots. They do not run a real installer, systemd service, APT or host inventory.

## Explicit pending-service v2 candidate

For a fresh, authorized installation, add `--pending-service` to the command above.
The flag also works with a separately provisioned local `--bootstrap`. It is
accepted only for install; an explicit retained install resume must repeat the
same mode. A v1 retained preparation cannot become v2 by changing this flag.

The installer runs hidden invitation entry and displays the public fingerprint
and comparison value. It returns from the interactive enrollment child only after
a fresh same-key status response confirms the exact saved claim. The invitation
secret is not retained. An ambiguous uncommitted claim cannot publish or start a
service; it keeps the same private preparation for explicit inspection/resume.

The v2 manifest, ownership record, transaction journal and fixed unit carry the
mode. Restart/upgrade derive it from the existing owned installation. Existing v1
units/upgrades keep the ready-only behavior; there is no silent migration.
HTTP-test v2 units include their explicit unencrypted-profile acknowledgement.

Before a service starts, the installer validates the existing service enrollment
as the dedicated numeric identity, without network or collection. A successful
install means the waiting-capable unit was installed and its process start was
observed. `Type=simple` does not establish a successful status poll, approval,
activation, or a first report. Those remain separate phases.

The background process validates real/effective/saved UID and GID plus allowed
supplementary groups before opening private state. It opens only the existing
protected directory, lock, ledger and service marker. It cannot create a new key,
claim, missing lock or missing marker. Before activation it performs only the
bounded enrollment protocol; no inventory/log collector or telemetry sender is
constructed. Dashboard approval still requires the independently compared full
fingerprint and comparison value.

After activation, the existing protected handoff initializes the sender sequence
domain exactly once. First initialization writes its intent before creating the
domain. Once initialization has begun, a missing/replaced domain fails closed;
no counter or identity reset is attempted. Valid interrupted publication can
finish only the existing exact phase. A durable `ReadyObserved` transition follows
complete ready/config/certificate/counter validation. Missing or changed ready
material afterward is rejected, including direct enrollment-resume calls.

A complete valid Ready handoff restarts through the ordinary sender path without
contacting the manager first. Manager unavailability therefore does not become a
new boot dependency. Certificate/state validity still applies. The original
pending-approval deadline does not limit an already activated Ready identity.

Pending operations retain their original bounded deadline across restarts. Each
attempt and wait is bounded by that deadline, and responses arriving afterward
cannot advance the local service into Activated/Ready. A local deadline stop is
latched durably. Generic HTTP 401/409 or a local deadline does not prove that the
manager expired or revoked the identity. If an activation committed remotely but
its acknowledgement was not established locally before the deadline, this
candidate stops for manual inspection; it performs no post-deadline reconciliation,
activation retry, new claim, or automatic reset.

Observed canceled/rejected/revoked/expired enrollment outcomes are retained as
terminal. Invalid state and permanent sender-state/configuration errors stop with
exit 2, excluded from systemd automatic restart. Transient pending transport
failures retry within the fixed deadline. HTTP-test commitment/activation remains
unauthenticated and is always described that way.

Once normal reporting begins, post-activation remote revocation is enforced by
manager ingress. This candidate does not add a revocation poller or promise that
local collection stops immediately on a remote revocation. It preserves existing
sender transport/retry semantics and reports no stronger guarantee.

### Additional fixture evidence

Synthetic tests cover committed claim versus lost acknowledgement; no sender
construction before complete ready; no recreation of missing directory, lock,
ledger or marker; immutable expiry and terminal latches; late status, credential,
activation and challenge responses; matching remote Activated with locally lost
acknowledgement at deadline; partial-publication boundaries; retained counter
identity; complete Ready boot while the fixture manager is offline; v1/v2 mode
mismatch; versioned restart/upgrade/uninstall/resume; and canceled-start stop/drain
with private identity retained. Inert installer adapters never invoke host useradd,
systemd or real inventory. These checks are source/fixture evidence only.
