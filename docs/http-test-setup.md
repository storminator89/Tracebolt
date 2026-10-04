# Disposable HTTP-test provisioning helper (Linux)

This narrow manual-operator helper creates a **new** Docker configuration directory
for an isolated, disposable HTTP LAN test. HTTP exposes passwords, sessions,
enrollment traffic and telemetry. Use an isolated trusted LAN, a throwaway
password and test devices. This is not a production provisioning workflow.

Build from the reviewed source, then inspect the plan as an ordinary user:

```sh
go build -buildvcs=false -trimpath -o bin/http-test-setup ./cmd/http-test-setup
./bin/http-test-setup --lan-ip 192.168.1.50 --ack-disposable-http-test
```

Replace that example with the exact selected RFC1918 IPv4 address on the test VM.
No address discovery, DNS, interface change, port probing or network request occurs.
The plan does not create files, generate keys, or prompt for a password. This page describes the default basic layout. Its main flags are `--lan-ip`,
`--ack-disposable-http-test`, `--apply`, and help. The separate
[`managed-operations-v2` selector](http-inventory-test-setup.md) additionally
requires `--collection-profile` and `--ack-managed-metadata`, and uses a different
fixed output directory; it does not modify this basic configuration.

Only after reviewing and separately authorizing the credential creation on that
specific disposable VM, its administrator runs this manually in a local terminal:

```sh
sudo ./bin/http-test-setup --lan-ip 192.168.1.50 --ack-disposable-http-test --apply
```

Both real and effective UID must be root. A foreground controlling terminal is
required. Enter and confirm a unique disposable password of 12–1024 UTF-8 bytes
with no control characters. Input is hidden, bounded and never accepted through
arguments, environment, stdin, a file or chat. Ctrl+C, Ctrl+D or Ctrl+Z cancels.
The terminal is restored on normal return and handled cancellation; SIGKILL,
power loss and terminal-device failures cannot be recovered by the process.

The fixed output is `/etc/tracebolt-http-test`, mode `0700`, owned by Docker runtime
UID/GID `65532:65532`. Exactly these six files are created, each initially private
and finally `0600`, single-link, owned by that UID/GID:

- `http-test.json`
- `operator-auth.json` (Argon2id PHC: 64 MiB, time 2, parallelism 1, 16-byte salt,
  32-byte output)
- `enrollment.json`
- `client-issuer.pem`
- `client-issuer.key` (Ed25519 PKCS#8)
- `client-root.pem` (public only)

The issuer is dedicated ClientAuth-only, pathLen0, valid for 30 days. A distinct
31-day test root signs it; the root private key is generated only in memory, never
encoded or written, and discarded with best-effort buffer clearing. This is not
an offline-root custody guarantee. No endpoint keys, certificates or invitations
are created. Public authority is checked with the existing enrollment validator.
The published enrollment-config.v2 schema intentionally **omits collectionProfile**;
its strict loader selects `basic-readonly-v1`. `bootstrapServerCAFile` is empty.

The configuration uses exact origins `http://SELECTED_IP:8787` and
`http://SELECTED_IP:8788`, container listeners `0.0.0.0:8787/8788`, material paths
under `/run/tracebolt`, state `/data/state`, and web assets `/tracebolt/web`.
`agentClientCAFile` trusts only the dedicated issuer. Host publication must bind
the selected IP explicitly; the helper does not publish any ports.

Only existing protected, root-owned `/` and `/etc` are traversed with no-follow
file descriptors. Existing output of any kind, symlinked ancestors, or leftover
setup staging directories cause refusal. Files are synced in a new root-private
staging directory and atomically renamed without replacement. The directory is
handed to UID/GID 65532 only after publication; later uncertainty preserves it.
No existing file is adopted, reset, overwritten, recursively chmodded or removed.
On a fixed failure-stage message, inspect locally; do not paste private material
or retry by deleting an existing directory. Success prints only a public config
path after the plan. Password buffers are cleared best effort; Go/runtime/OS
memory copies cannot be guaranteed erased.

## Separate deployment gate

This command starts no server, account, service, listener or outbound request. It
changes no global trust, firewall, Docker settings or state volume. The existing
`deploy/compose.http-test.yaml` starts manual enrollment mode. Guided enrollment
requires a separately reviewed command override containing both
`--lan-config /run/tracebolt/http-test.json` and
`--enrollment-config /run/tracebolt/enrollment.json`, along with the fixed config
mount, selected host bind IP, and a fresh dedicated HTTP-test state volume.
Provisioning success is not runtime acceptance or permission to start that stack.

## Verification scope

Tests use deterministic synthetic credentials, in-memory prompt injection,
temporary output/owner seams, and synthetic PTYs. They do not invoke the actual
CLI apply mode, touch `/etc`, use UID 65532 or perform real provisioning. Run:

```sh
go test ./cmd/http-test-setup
go test -race ./cmd/http-test-setup
go vet ./cmd/http-test-setup
```
