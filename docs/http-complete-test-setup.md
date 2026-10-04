# Held preparatory complete-v3 HTTP-test setup reference

This future-source extension prepares a new, explicitly consented
`managed-operations-v3` test instance. It is not publication, deployment or
runtime acceptance. The basic default and `managed-operations-v2` selected-row
behavior remain unchanged. Complete supported dpkg inventory does **not** mean
all software installed on the machine.

## Exact selection and fixed target

Build from the reviewed composed source, then print the nonsecret plan:

```sh
go build -buildvcs=false -trimpath -o bin/http-test-setup ./cmd/http-test-setup
./bin/http-test-setup --lan-ip 192.168.1.50 \
  --collection-profile managed-operations-v3 --ack-managed-metadata \
  --ack-disposable-http-test
```

Use the exact selected private IPv4 address of the test VM. The v3 selector and
metadata acknowledgement must both be present even for plan-only mode. Unknown
profiles and missing acknowledgement fail before generation, prompts or writes.
Without `--apply`, there is no password prompt, key generation or file effect.
No path, port, reset, adoption, reuse or migration flags exist.

The fixed new target is `/etc/tracebolt-http-complete-test`. It contains exactly
`http-test.json`, `operator-auth.json`, `enrollment.json`, `client-issuer.pem`,
`client-issuer.key`, and public `client-root.pem`. Public selected-IP origins and
container listeners use ports **8787/8788**. Keep all older configurations,
identities, state and volumes retained unused; never rewrite or copy them into
the new profile. A separate project, fresh state volume and fresh endpoint
identity are required. The old container must be stopped by an authorized human
before another container publishes those same host ports. This helper neither
stops nor starts containers and does not change endpoint state.

An independently authorized human may later add `sudo` and `--apply` in the
selected VM's local foreground terminal. This is persistent credential creation,
not an action this source-only task executes. Apply retains the real/effective
root check, separate plaintext acknowledgement, hidden `/dev/tty` password and
confirmation, 12–1024 UTF-8-byte bound, and no argument/environment/stdin/file
password fallback. Choose a new disposable password. There is no automatic
permission to enroll endpoints, make invitations or install a service.

## Complete scope, limits and privacy

The v3 consent covers complete generations from the **supported dpkg source**,
transferred in validated chunks and exposed through generation-bound pagination.
Package fields include names, exact installed/source versions, architecture,
source mappings and install state, alongside OS release identifiers. The coherent
v3 consent target also includes:

- System service names and active, failed and enablement states
- Locally observed TCP listeners, UDP-bound sockets and connections
- Numeric local/remote addresses and ports
- PID/name attribution where permitted; unavailable or denied attribution stays
  explicitly unknown

Private network topology and service/process labels may be sensitive. This is
local observation only: no scans, firewall changes, namespace changes or global
privilege changes. Raw logs, command lines, environment, usernames, payloads and
DNS queries are excluded. Existing basic/v2 collection scopes remain unchanged.
Service/socket collector integration is being completed separately; this helper
only declares the agreed v3 consent target and does not establish collector or
runtime availability. It must not be described as a feature-ready result.

Unsupported software managers and unobserved software remain unknown, not a
complete empty inventory. Agent-visible namespaces may differ from the full host.

Source, row, byte, chunk, transfer and storage quotas remain finite. A source or
quota failure is an explicit failed/unavailable result. A partial prefix must
never be labeled complete. Successful setup itself proves no collection,
transfer, pagination, fleet-size or host-runtime acceptance.

Current and previous observations retain their original collection ages. Row
visibility is bounded to 24 hours, and previous-generation cursors may expire
earlier. Last-complete bytes can remain after row visibility expires until
replaced or eligible cleanup occurs. **There is no promise of physical deletion
at 24 hours**, including retained database/WAL/backup bytes.

Package names/source metadata and existing operational labels may be sensitive.
HTTP exposes metadata, passwords, sessions and enrollment traffic on the network.
Use an isolated disposable test and honor subsequent operator/endpoint consent
and trust checks. This profile enables no AI export and grants no authority for
external submission. It makes no CVE coverage, trusted package provenance,
update availability or update-installation guarantees. No APT action is run.

## Material/schema and protection

Each apply creates a new random manager identity, fresh salted Argon2id verifier
and dedicated Ed25519 ClientAuth-only pathLen0 issuer. Its distinct root key is
memory-only and discarded; no offline custody or guaranteed erasure claim is made.
`enrollment.json` uses the existing strict `tracebolt.enrollment-config.v2` schema
with exactly `collectionProfile: "managed-operations-v3"`; this is not a schema
rename. The later native handoff uses `tracebolt.lan-agent.v5`/CompleteConfigVersion
for v3; this helper does not produce endpoint credentials or configurations.
Basic setup still omits collectionProfile and v2 retains its own value.

Container paths remain `/run/tracebolt/…`, `/data/state`, and `/tracebolt/web`.
`bootstrapServerCAFile` stays empty. Ingress trusts only the fresh dedicated issuer.
Directory mode `0700`, file modes `0600`, and runtime UID/GID `65532:65532` remain
unchanged. Existing selected output of any kind or complete-setup staging names
cause refusal. Protected ancestors, private-first exclusive/no-follow creation,
sync, no-replace publication and final pinned-FD ownership handoff are unchanged.
Late uncertainty preserves output for local inspection. No old setup is adopted,
removed or altered, and no privileged path cleanup follows ownership handoff.

Focused tests use deterministic synthetic material, temporary paths/current
owners and inert prompt seams. No real apply, root provisioning, UID65532 change,
listener, service or endpoint action is exercised:

```sh
go test ./cmd/http-test-setup
go test -race ./cmd/http-test-setup
go vet ./cmd/http-test-setup
```
