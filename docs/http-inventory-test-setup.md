# Fresh managed inventory HTTP-test setup reference

This extension selects one fresh, temporary `managed-operations-v2` acceptance
instance. The default `basic-readonly-v1` behavior stays unchanged. It does not
upgrade existing device identities or rewrite a manager's immutable profile.

## Exact selection

From the reviewed source, build the helper and print its nonsecret plan:

```sh
go build -buildvcs=false -trimpath -o bin/http-test-setup ./cmd/http-test-setup
./bin/http-test-setup --lan-ip 192.168.1.50 \
  --collection-profile managed-operations-v2 --ack-managed-metadata \
  --ack-disposable-http-test
```

Replace the example with the exact selected private IPv4 address of the test VM.
The managed profile and metadata acknowledgement must be present together, even
for plan-only mode. Unknown profiles, managed without acknowledgement, and basic
with a managed acknowledgement are rejected before any prompt or generation.
Omitting `--collection-profile`, or explicitly selecting `basic-readonly-v1`,
keeps the original basic setup. No path, port, reset, adoption or reuse flags exist.

The managed plan creates only `/etc/tracebolt-http-inventory-test`, with these
six files: `http-test.json`, `operator-auth.json`, `enrollment.json`,
`client-issuer.pem`, `client-issuer.key`, and `client-root.pem`.
Both profiles use the selected IP's public HTTP ports **8787/8788** and container
listeners **8787/8788**. They cannot run on those same host bindings together.
The old test container must be stopped before a human starts the fresh test.
Keep the old `/etc/tracebolt-http-test` configuration and old volume/state unused;
the helper never reads, modifies, adopts, reuses or removes their contents.

Only after authorization for this exact fresh test may the human run the same
command with `sudo` and `--apply` in the VM's foreground local terminal. This
creates new persistent test credentials; do not run it from automation or chat.
A unique disposable password is entered and confirmed through hidden `/dev/tty`
input. Password arguments, environment, stdin and file input are unsupported.
Both real and effective UID must be root. Default plan mode has no file/key or
password-prompt effects. The existing 12–1024 UTF-8 byte password policy applies.

## Expanded metadata and plaintext warning

`managed-operations-v2` includes the basic CPU/RAM/uptime/OS metrics plus bounded,
agent-visible inventory:

- Volume/mount labels and utilization
- Interface names, state, counters and address counts
- Service unit names/states
- Process IDs/names and resource usage
- Package names, installed/source versions, architecture, source mappings and
  install state; OS release identifiers
- Event source/unit/priority/message IDs, counts and timestamps

Labels and package/source metadata may themselves be sensitive. HTTP exposes
this metadata, passwords, sessions and enrollment traffic to the network. Use
only an isolated disposable test with explicit operator and endpoint consent.
The setup acknowledgement does not create an invitation, enroll an endpoint or
replace the later profile-specific consent and trust checks. The helper does
not collect inventory, run APT, start a service or enable external submission.
Nested operational data retains its existing v1 schema; this outer managed-v2
profile selects the already implemented package-inventory contract.

## Fresh material and protected publication

Each apply generates a fresh manager ID, salted Argon2id verifier and dedicated
Ed25519 ClientAuth-only pathLen0 issuer. Its distinct root key remains in memory
and is discarded; no offline-custody or guaranteed memory-erasure claim is made.
The current strict `tracebolt.enrollment-config.v2` shape adds exactly
`collectionProfile: "managed-operations-v2"` for this selection. Basic JSON still
omits `collectionProfile`; the loader defaults it to `basic-readonly-v1`.
`bootstrapServerCAFile` remains empty. Internal paths stay `/run/tracebolt/…`,
`/data/state`, and `/tracebolt/web`; ingress trusts only the new dedicated issuer.

The new directory is `0700` and its six files are `0600`, owned by runtime
UID/GID `65532:65532`. Protected root-owned ancestors, no-follow/exclusive file
creation, sync, no-replace publication and final pinned-FD ownership handoff are
unchanged. Existing selected output of any kind and selected leftover staging
names cause refusal. Late publication uncertainty preserves output for manual
inspection. There is no privileged path cleanup after ownership handoff.

A separate Compose project and **fresh dedicated state volume** are required.
The publisher-owned first-start guide handles that deployment gate and the
human stopping the old container. Setup success starts no listener/container,
changes no firewall/global trust, and is not runtime acceptance. Preserve the
old config/volume/state; do not delete or rebind them to the richer profile.

Focused synthetic verification uses temporary paths/owners, deterministic test
material and injected prompts. The inherited synthetic PTY tests still cover
hidden input/restoration. No actual apply or host provisioning is exercised:

```sh
go test ./cmd/http-test-setup
go test -race ./cmd/http-test-setup
go vet ./cmd/http-test-setup
```
