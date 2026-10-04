# Fresh Linux inventory server and background agent

This is the short, manual path for a **fresh Debian/Ubuntu Linux test** with
Docker Compose v2 and systemd. Use the exact reviewed commit supplied with this
checkpoint. The v3 manager, helper and native programs must come from that same
revision. Combined v3 runtime and real service acceptance remain pending until
recorded for that revision; source tests alone do not establish them.

The new manager uses ports **8787/8788**, a fresh Docker project/volume and
`/etc/tracebolt-http-complete-test`. Stop the old test container first and retain
its files and volume unused. The endpoint needs a fresh service identity: do not
reuse old basic/v2 state or overwrite an existing Tracebolt installation.

**Disposable HTTP test only:** passwords, invitations, sessions and telemetry are
visible on the network; another participant can impersonate the server. Use an
isolated trusted test LAN and disposable credentials. The v3 consent includes
supported dpkg inventory, system-service states and locally observed sockets,
numeric addresses/ports and permitted process attribution. These can reveal
sensitive topology. Unsupported sources, quotas and sandbox visibility remain
explicitly limited. No APT, network scan, update installation or AI export runs.

## 1. Prepare the selected source once

Run as the authorized administrator on the intended Linux test host. Replace
`REVIEWED_COMMIT_SHA` with the exact supplied SHA. Use a new directory; this
fail-stopping block preserves existing checkouts and prepares everything before
an invitation starts expiring:

```sh
git clone https://github.com/storminator89/Tracebolt.git tracebolt-complete-pilot &&
cd tracebolt-complete-pilot &&
git checkout --detach REVIEWED_COMMIT_SHA &&
git rev-parse HEAD &&
git diff --quiet && git diff --cached --quiet &&
test -z "$(git ls-files --others -- cmd internal web tests)" &&
mkdir bin &&
docker run --rm --mount "type=bind,src=$PWD,dst=/src,readonly" \
  --mount "type=bind,src=$PWD/bin,dst=/out" --workdir /src \
  golang:1.27.1-bookworm sh -ec \
  'CGO_ENABLED=0 go build -buildvcs=false -trimpath -o /out/ ./cmd/http-test-setup ./cmd/enroll-agent ./cmd/lan-agent ./cmd/agent-service' &&
(umask 077; set -o noclobber; git archive --format=tar HEAD > "$PWD/tracebolt-selected-source.tar") &&
sha256sum bin/agent-service bin/enroll-agent bin/lan-agent tracebolt-selected-source.tar &&
docker build -t tracebolt-manager:http-complete-test .
```

Stop on failure. Preserve any partial output for inspection. Keep this terminal
in the checkout. Hashes pin the selected local bytes; they do not authenticate a
publisher or prove a source-to-binary relationship. Build the native programs on
the target architecture. The manager image does not install an endpoint service.

## 2. Start the new manager

Set the host's selected private IPv4 address, then inspect the read-only plan:

```sh
export TRACEBOLT_HTTP_TEST_BIND_IP=192.168.1.50
./bin/http-test-setup --lan-ip "$TRACEBOLT_HTTP_TEST_BIND_IP" \
  --collection-profile managed-operations-v3 --ack-managed-metadata \
  --ack-disposable-http-test
```

The plan must name `managed-operations-v3` and the new complete-test directory.
After authorizing this test's credential creation, exposure and collection scope,
run as root in a real local terminal:

```sh
./bin/http-test-setup --lan-ip "$TRACEBOLT_HTTP_TEST_BIND_IP" \
  --collection-profile managed-operations-v3 --ack-managed-metadata \
  --ack-disposable-http-test --apply
```

Enter and confirm a new password at the hidden prompt. Never put it in a command,
environment variable, file or chat. The helper refuses existing output; do not
remove or adopt old state to bypass that check.

Identify and stop only the old test container, and stop its foreground sender
with Ctrl+C if one is still running. Keep its state:

```sh
docker ps --format 'table {{.Names}}\t{{.Ports}}'
docker stop OLD_TRACEBOLT_TEST_CONTAINER_NAME
```

Choose a **new unused** project name below. Inspect any existing matching project
or volume instead of deleting it. Start the new stack:

```sh
export TRACEBOLT_COMPLETE_PROJECT=tracebolt-complete-pilot
docker compose -p "$TRACEBOLT_COMPLETE_PROJECT" -f deploy/compose.http-complete-test.yaml config --quiet &&
docker compose -p "$TRACEBOLT_COMPLETE_PROJECT" -f deploy/compose.http-complete-test.yaml up -d --no-build &&
docker compose -p "$TRACEBOLT_COMPLETE_PROJECT" -f deploy/compose.http-complete-test.yaml ps
```

Open `http://YOUR_SELECTED_IP:8787`, sign in with the new password and confirm the
HTTP warning. The dedicated image mounts only the new private config, uses its
own volume and runs as UID65532 with a read-only root and dropped capabilities.
Docker configures networking and published ports; this guide makes no manual
global-trust or firewall edits.

## 3. Copy one install command, approve, then close the terminal

1. In **Add device**, read and acknowledge the v3 collection notice. Create a new
   invitation only after the preparation above is complete.
2. Copy **the public installation command** from the dialog. If the HTTP browser
   does not offer a clipboard button, select and copy the displayed command.
   Run it as root from this prepared checkout on the intended endpoint. It uses
   `--pending-service`, fetches only the checksum-bound public bootstrap and
   selects the already built local programs/archive. No separate bootstrap-file
   download or transfer is needed. This command authorizes account/service and
   persistent endpoint-key creation; inspect it before running.
3. Enter the separate invitation secret only at the native hidden terminal
   prompt. The command contains no secret. Compare the complete local fingerprint
   and comparison value with the dashboard claim, then approve only that device.
   After a committed claim, the installed service can wait for this approval in
   the background; it collects nothing before approval and activation.
4. Confirm the service and real reports before calling the installation complete:

```sh
systemctl is-active tracebolt-agent.service
systemctl is-enabled tracebolt-agent.service
```

The terminal may close once installation succeeds; the background service owns
reporting. A started process can still be awaiting approval and does not prove a
first report. In the dashboard, confirm new receipt times across several samples,
package-generation status and service/socket coverage. A partial, denied, stale
or unavailable section is not a complete empty inventory. The dedicated identity
and sandbox may see less than the host root namespace. Confirmed CVE and offered
update counts remain unknown.

On any failure, retain identity/state and inspect the fixed stage. Do not rerun
with a fresh invitation, change protected permissions or run a foreground sender
against service-owned state. Use the exact documented resume conditions in
[the service contract](linux-agent-service.md). Observed start/reporting, controlled
restart and an actual OS reboot are separate acceptance outcomes.

To stop only the new manager while retaining state:

```sh
docker compose -p "$TRACEBOLT_COMPLETE_PROJECT" -f deploy/compose.http-complete-test.yaml stop
```

See [setup scope](http-complete-test-setup.md) and
[public bootstrap/pending-service behavior](activation-bootstrap.md) for details.
