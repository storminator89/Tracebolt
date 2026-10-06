# Fresh Docker manager and one-command Linux read-admin setup

Use a **fresh Debian 13 or Ubuntu 24.04 amd64 test VM**, systemd as PID 1,
cgroup v2 and kernel 6.5+. Docker Engine, Docker Compose v2, Git and Python 3
must already be available. Run the following in a real local root terminal.
Use the exact manager activation revision supplied with the rc.2 handoff; the
manager includes the verified complete-profile installation command.

**Disposable HTTP test only:** passwords, invitations, sessions, inventory and
requested journal content are unencrypted and the manager can be impersonated.
Use an isolated trusted LAN and a unique throwaway password. The recorded full
[native acceptance](https://github.com/storminator89/Tracebolt/actions/runs/37508637893)
used Ubuntu TLS; this fresh Debian/HTTP VM and an OS reboot are separate local
acceptance observations.

## 1. Prepare the manager

Each command is one physical line. Replace `REVIEWED_MANAGER_COMMIT_SHA` with the
full revision supplied in the handoff. Stop on any failed command; do not erase
existing state to make the create-only helpers accept it.

```sh
cd /root
```
```sh
git clone https://github.com/storminator89/Tracebolt.git tracebolt-rc2-test
```
```sh
cd /root/tracebolt-rc2-test
```
```sh
git checkout --detach REVIEWED_MANAGER_COMMIT_SHA
```
```sh
git rev-parse HEAD && git diff --quiet && git diff --cached --quiet && docker compose version
```
```sh
mkdir -m 0700 bin
```
```sh
docker run --rm --mount "type=bind,src=$PWD,dst=/src,readonly" --mount "type=bind,src=$PWD/bin,dst=/out" --workdir /src golang:1.27.1-bookworm sh -ec 'CGO_ENABLED=0 go build -buildvcs=false -trimpath -o /out/http-test-setup ./cmd/http-test-setup'
```
```sh
docker build -t tracebolt-manager:http-complete-test .
```

This builds the manager/UI and its create-only configuration helper. The endpoint
programs are downloaded from the verified rc.2 release by the later command;
no endpoint Go build or manual source-archive transfer is needed.

## 2. Configure and start the manager

Replace the example with this VM's selected private LAN IPv4. Keep the same terminal.

```sh
export TRACEBOLT_HTTP_TEST_BIND_IP=192.168.1.50
```
```sh
./bin/http-test-setup --lan-ip "$TRACEBOLT_HTTP_TEST_BIND_IP" --collection-profile managed-operations-v3 --ack-managed-metadata --ack-disposable-http-test
```

Inspect the plan: `/etc/tracebolt-http-complete-test`, UI port 8787 and ingress 8788.
The next command creates the new protected configuration and credentials after
you approve those effects. Enter and confirm the disposable password at its
hidden prompt, never in command arguments, environment variables, files or chat.

```sh
./bin/http-test-setup --lan-ip "$TRACEBOLT_HTTP_TEST_BIND_IP" --collection-profile managed-operations-v3 --ack-managed-metadata --ack-disposable-http-test --apply
```
```sh
export TRACEBOLT_COMPLETE_PROJECT=tracebolt-rc2-test
```
```sh
docker compose -p "$TRACEBOLT_COMPLETE_PROJECT" -f deploy/compose.http-complete-test.yaml config --quiet
```
```sh
docker compose -p "$TRACEBOLT_COMPLETE_PROJECT" -f deploy/compose.http-complete-test.yaml up -d --no-build
```
```sh
docker compose -p "$TRACEBOLT_COMPLETE_PROJECT" -f deploy/compose.http-complete-test.yaml ps
```

Open `http://YOUR_VM_IP:8787` and sign in. Docker binds both ports to the chosen
address, uses a dedicated state volume and runs the read-only manager as UID 65532
with dropped capabilities. No endpoint is installed by these manager commands.

## 3. Install and approve the endpoint

1. In **Add device**, review the complete-profile notice and create a Linux
   invitation after the manager build is finished.
2. Copy its **verified rc.2 installation command** and run it deliberately in the
   endpoint's local root terminal. The command contains only validated public
   enrollment data. It verifies the pinned bootstrap, release provenance and all
   selected files before entering the existing installer.
3. Review the single combined read-admin scope, including the separate journal
   helper and broad CAP_SYS_PTRACE process-memory authority of the socket helper.
   For this HTTP profile, confirm `INSTALL READ ADMIN OVER HTTP` at the prompt.
   The main agent remains nonroot; no arbitrary shell or package-install grant is added.
4. Enter the separate invitation secret only at the hidden prompt. Compare the
   full fingerprint and comparison value with the pending dashboard claim and
   approve only that endpoint. **Keep the terminal open** through configuration
   of all three phases: inventory, journal and socket-owner support.
5. Confirm the completed result and fresh dashboard observations before closing
   the terminal. No separate per-view collection/helper setup commands are required.

```sh
systemctl is-active tracebolt-agent.service
```
```sh
systemctl is-enabled tracebolt-agent.service
```

Check each complete generation's capture time, completed status and latest
attempt outcome, not only retained rows. Processes/mounts retain their 60-second
cadence; full dpkg and cached APT use the existing six-hour cadence. APT is not
refreshed or installed. CVE processing, unknown vendor/package coverage and source
limits remain explicit. An on-demand log request still requires selection of an
exact service/window and content acknowledgement in the UI.

On failure keep the installation evidence and report only its fixed stage.
Passwords, private keys, invitation secrets and raw logs do not belong in chat.
Do not reset identities, grant extra groups or run a competing foreground sender.

To stop the manager without deleting state:

```sh
docker compose -p "$TRACEBOLT_COMPLETE_PROJECT" -f deploy/compose.http-complete-test.yaml stop
```

See the [combined scope](read-admin-onboarding.md), [release verification](dashboard-verified-download.md)
and [native service contract](linux-agent-service.md) for the exact boundaries.
