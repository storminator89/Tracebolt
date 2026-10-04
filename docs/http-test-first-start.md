# First disposable HTTP test: Docker manager and Linux client

This manual path targets a **fresh disposable Linux VM** with Docker Engine,
Docker Compose v2 and Git already installed. It builds the current checkout;
no host Go or Node installation is needed. It provisions new credentials and
publishes two ports on the one LAN IP you choose. Perform these steps only as
the authorized administrator of that test VM.

**HTTP is unencrypted:** another party on the network can read passwords,
sessions, invitations and telemetry, impersonate the server or hijack sessions.
Use an isolated trusted LAN and a unique throwaway password. Do not reuse this
configuration for production. This path uses `basic-readonly-v1`. For a fresh explicitly acknowledged metadata
profile and native background service, follow the separate
[inventory first-start guide](http-inventory-first-start.md).

## 1. Obtain and build the source

Use a new checkout directory; preserve any existing checkout and local changes.

```sh
git clone https://github.com/storminator89/Tracebolt.git tracebolt-http-pilot
cd tracebolt-http-pilot
git rev-parse HEAD
mkdir -p bin
docker run --rm --mount "type=bind,src=$PWD,dst=/src,readonly" \
  --mount "type=bind,src=$PWD/bin,dst=/out" --workdir /src \
  golang:1.27.1-bookworm sh -ec '
    CGO_ENABLED=0 go build -buildvcs=false -trimpath -o /out/http-test-setup ./cmd/http-test-setup
    CGO_ENABLED=0 go build -buildvcs=false -trimpath -o /out/enroll-agent ./cmd/enroll-agent
    CGO_ENABLED=0 go build -buildvcs=false -trimpath -o /out/lan-agent ./cmd/lan-agent
  '
docker build -t tracebolt-manager:local .
```

The first build downloads official Go/Node builder images and the repository's
locked dependencies. The three client/helper binaries match the build host's
architecture. The image build produces the LAN manager and its UI. If you already
built `tracebolt-manager:local` from the preceding `f78123c` revision, keep that
image: this helper checkpoint changes neither manager nor UI runtime. Only the
new helper/client build and configuration are needed. An optional repeated image
build can reuse Docker layers.

## 2. Inspect and create the new test configuration

In the same terminal, replace this example address with the test VM's actual
selected private IPv4 address. Keep the value for all subsequent commands.

```sh
export TRACEBOLT_HTTP_TEST_BIND_IP=192.168.1.50
export TRACEBOLT_HTTP_TEST_CONFIG_DIR=/etc/tracebolt-http-test
./bin/http-test-setup --lan-ip "$TRACEBOLT_HTTP_TEST_BIND_IP" --ack-disposable-http-test
```

That command prints a plan only. After checking the address and authorizing this
specific VM's credential creation, run the following **as root in its local
terminal**. A normal user can use `sudo`; an existing root shell does not need it.

```sh
./bin/http-test-setup --lan-ip "$TRACEBOLT_HTTP_TEST_BIND_IP" --ack-disposable-http-test --apply
```

Enter and confirm a new disposable password at the hidden prompt. Do not put it
in chat, command arguments, environment variables or a shell script. The helper
creates the six private files described in [the setup reference](http-test-setup.md).
It refuses any existing destination or staging directory. If it fails, stop and
inspect the fixed error stage; do not delete or overwrite existing material to
make a retry pass. It does not start a server.

## 3. Start the guided manager

Choose a new, unused project name for this first test. Retain it for later
status/stop/start commands. A different name creates a different state volume;
do not change it to bypass an existing-state failure.

```sh
export TRACEBOLT_TEST_PROJECT=tracebolt-http-pilot
docker compose -p "$TRACEBOLT_TEST_PROJECT" \
  -f deploy/compose.http-test.yaml -f deploy/compose.http-guided-test.yaml \
  --profile http-test config --quiet
docker compose -p "$TRACEBOLT_TEST_PROJECT" \
  -f deploy/compose.http-test.yaml -f deploy/compose.http-guided-test.yaml \
  --profile http-test up -d --no-build
docker compose -p "$TRACEBOLT_TEST_PROJECT" \
  -f deploy/compose.http-test.yaml -f deploy/compose.http-guided-test.yaml \
  --profile http-test ps
```

The override supplies both required flags, `--lan-config` and
`--enrollment-config`. The manager runs as UID/GID 65532 with a read-only root
filesystem, dropped capabilities, no automatic restart and a dedicated state
volume. Ports 8787 and 8788 bind only to the chosen LAN IP. No manual firewall or global
certificate-store edit is part of these instructions; Docker configures its
networking and the published ports.

Open `http://YOUR_SELECTED_IP:8787` in your browser and enter the disposable
operator password. Keep the permanent HTTP warning visible. A successful login
and an empty inventory are expected before enrolling a device. If startup fails,
inspect status locally; share only the fixed stage/status, never private config,
keys, passwords, cookies or raw telemetry.

## 4. Add a Linux test device and report

In the UI choose **Add device**, create a Linux invitation and download its
public bootstrap JSON. Transfer that bootstrap to the intended Linux endpoint
through a trusted channel. The invitation secret is shown separately; enter it
only into that endpoint's hidden enrollment prompt.

For a first test on this same Linux VM, create a new protected parent:

```sh
mkdir -m 0700 /root/tracebolt-first-device
```

Stop if that directory already exists; inspect it instead of adopting or deleting
it. Transfer the downloaded **public** bootstrap into that directory, using the
actual downloaded filename. The next command assumes you chose
`/root/tracebolt-first-device/bootstrap.json`.
The directory must already exist, be owned by the running user and mode 0700;
the bootstrap must be a protected regular file without symlink ancestors. Use
a new, unused child state path, then run:

```sh
./bin/enroll-agent --bootstrap /root/tracebolt-first-device/bootstrap.json \
  --state-directory /root/tracebolt-first-device/state --insecure-http-test
```

Read the displayed manager/agent origins and profile. Enter the invitation in
the hidden prompt, compare the **complete** locally displayed fingerprint and
comparison value with the pending UI claim, and approve only the intended device.
After enrollment completes, run the exact sender command it prints, equivalent to:

```sh
./bin/lan-agent --config /root/tracebolt-first-device/state/agent.json --foreground
```

Reporting is read-only and continues only while this foreground command runs.
Ctrl+C stops it. This does not install an agent service or prove reboot behavior.
See [native enrollment](enrollment-v2/native-client.md) for resumable and rejected
enrollment handling. Preserve identity and sender state; do not reset a ledger.

## Stop without removing state

```sh
docker compose -p "$TRACEBOLT_TEST_PROJECT" \
  -f deploy/compose.http-test.yaml -f deploy/compose.http-guided-test.yaml \
  --profile http-test stop
```

Keep the configuration directory and named volume private. Do not use `down -v`
or delete directories as a recovery shortcut. The setup helper's source and
synthetic tests are reviewed; actual provisioning and this guided Docker startup
still require verification on the selected VM. Earlier container tests cover the
separate manual identity mode and do not establish this new end-to-end path.
