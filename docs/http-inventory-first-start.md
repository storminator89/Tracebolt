# Fresh Linux inventory pilot over disposable HTTP

Use this manual guide only with the reviewed source revision that contains the
`managed-operations-v2` setup selector and its matching manager and clients.
The administrator must authorize the new credentials, network exposure and
expanded collection on the selected test devices before running apply/enrollment.

This creates a **separate** test manager on operator port **8787** and agent port
**8788**, using a new configuration directory, Docker project, named state volume
and endpoint identity. First stop the old test container manually; retain its configuration, volume and
endpoint state unused. The two stacks cannot bind these ports simultaneously.
Existing basic identities retain their original collection policy. This guide
does not migrate, reset or relabel them.

**HTTP exposes passwords, sessions, invitations and telemetry.** Other network
participants can impersonate the server and hijack sessions. Use only an isolated
trusted test LAN, disposable credentials and approved test devices. The metadata
includes bounded process/service names, interface labels, mount paths, software
versions and event metadata that can be sensitive. Process arguments, environment
contents and journal message bodies are excluded. Data availability still depends
on platform support, permissions and the documented collection limits.

## 1. Build a fresh checkout of the reviewed revision

Preserve the existing checkout and basic test. Clone into a new unused directory
and select the exact reviewed commit supplied with the checkpoint. Replace
`REVIEWED_COMMIT_SHA` below; do not build an arbitrary moving revision. Verify
there are no untracked build inputs, including ignored files, under the source
directories. Stop on any failed check before building:

```sh
git clone https://github.com/storminator89/Tracebolt.git tracebolt-inventory-pilot &&
cd tracebolt-inventory-pilot &&
git checkout --detach REVIEWED_COMMIT_SHA &&
git rev-parse HEAD &&
git diff --quiet &&
git diff --cached --quiet &&
test -z "$(git ls-files --others -- cmd internal web tests)" &&
mkdir -p bin &&
docker run --rm --mount "type=bind,src=$PWD,dst=/src,readonly" \
  --mount "type=bind,src=$PWD/bin,dst=/out" --workdir /src \
  golang:1.27.1-bookworm sh -ec '
    CGO_ENABLED=0 go build -buildvcs=false -trimpath -o /out/http-test-setup ./cmd/http-test-setup
    CGO_ENABLED=0 go build -buildvcs=false -trimpath -o /out/enroll-agent ./cmd/enroll-agent
    CGO_ENABLED=0 go build -buildvcs=false -trimpath -o /out/lan-agent ./cmd/lan-agent
    CGO_ENABLED=0 go build -buildvcs=false -trimpath -o /out/agent-service ./cmd/agent-service
  ' &&
docker build -t tracebolt-manager:http-inventory-test .
```

This rebuild is required for the new manager/UI and collection protocol. It uses
a different image tag from the working basic manager. The native clients must
come from the same selected source revision; the manager image contains no agent
installation or automatic update mechanism.

Prepare the source archive and binary hashes **before creating an invitation**,
so its short deadline is not spent building or reconciling source changes. These
hashes identify selected bytes; they do not establish publisher authenticity or
reproducible builds. The archive command refuses any existing output path.

```sh
unset TRACEBOLT_AGENT_SHA TRACEBOLT_ENROLL_SHA TRACEBOLT_SOURCE_SHA
if git diff --quiet && git diff --cached --quiet &&
   test -z "$(git ls-files --others -- cmd internal web tests)"; then
  (set -o noclobber; git archive --format=tar HEAD > "$PWD/tracebolt-selected-source.tar") &&
  TRACEBOLT_AGENT_SHA=$(sha256sum bin/lan-agent) &&
  TRACEBOLT_AGENT_SHA=${TRACEBOLT_AGENT_SHA%% *} &&
  TRACEBOLT_ENROLL_SHA=$(sha256sum bin/enroll-agent) &&
  TRACEBOLT_ENROLL_SHA=${TRACEBOLT_ENROLL_SHA%% *} &&
  TRACEBOLT_SOURCE_SHA=$(sha256sum tracebolt-selected-source.tar) &&
  TRACEBOLT_SOURCE_SHA=${TRACEBOLT_SOURCE_SHA%% *} &&
  sha256sum bin/agent-service
else
  printf 'STOP: reconcile tracked changes or untracked build inputs before installation.\n'
fi
```

Stop on any command failure. Preserve an existing or partially created archive
for inspection; choose a new reviewed output path explicitly if needed and use
that exact path later. Record and verify the installer hash against the selected
build. Keep this terminal and these selected hash values for installation.

## 2. Inspect the new metadata profile and provision it manually

Replace the example with the VM's actual selected private IPv4 address:

```sh
export TRACEBOLT_HTTP_TEST_BIND_IP=192.168.1.50
./bin/http-test-setup --lan-ip "$TRACEBOLT_HTTP_TEST_BIND_IP" \
  --collection-profile managed-operations-v2 --ack-managed-metadata \
  --ack-disposable-http-test
```

Check that the plan says `managed-operations-v2`, ports 8787/8788 and the **new**
directory `/etc/tracebolt-http-inventory-test`. It must not target the basic
directory. The plan does not create credentials or files.

After authorizing this specific new test configuration and metadata scope, run
the following as root in a local controlling terminal:

```sh
./bin/http-test-setup --lan-ip "$TRACEBOLT_HTTP_TEST_BIND_IP" \
  --collection-profile managed-operations-v2 --ack-managed-metadata \
  --ack-disposable-http-test --apply
```

Enter and confirm a new disposable password at the hidden prompt. Keep it out of
chat, arguments, environment variables, files and logs. Existing output or
uncertain staging causes refusal; inspect the fixed error stage instead of
deleting or adopting anything. Do not copy basic configuration or edit an
existing identity's `collectionProfile` to make startup pass.

## 3. Stop the old test container and start the fresh manager

Identify the old Tracebolt test container and stop **that container only** before
publishing these same ports. Substitute its verified name below; do not stop
unrelated services. Stop the old foreground client with Ctrl+C as well.

```sh
docker ps --format 'table {{.Names}}\t{{.Ports}}'
docker stop OLD_TRACEBOLT_TEST_CONTAINER_NAME
```

Keep the old container, its configuration and volume. No deletion or credential
reuse is needed. Then choose a new unused project name. Keep that exact name for subsequent status,
stop and start commands. If that project or its volume already exists, inspect
it before proceeding; do not delete/reset it as a shortcut.

```sh
export TRACEBOLT_INVENTORY_PROJECT=tracebolt-inventory-pilot
docker compose -p "$TRACEBOLT_INVENTORY_PROJECT" \
  -f deploy/compose.http-inventory-test.yaml config --quiet
docker compose -p "$TRACEBOLT_INVENTORY_PROJECT" \
  -f deploy/compose.http-inventory-test.yaml up -d --no-build
docker compose -p "$TRACEBOLT_INVENTORY_PROJECT" \
  -f deploy/compose.http-inventory-test.yaml ps
```

The stack binds only the selected IP's 8787/8788 ports, mounts the new private
configuration read-only and runs as UID/GID 65532 with dropped capabilities and a
read-only root filesystem. Docker configures its network and published ports;
no manual global trust or firewall edit is part of this guide.

Open `http://YOUR_SELECTED_IP:8787` and sign in with the new password. The UI must
display the HTTP warning. An empty inventory is expected before new enrollment.

## 4. Install the native background agent with a fresh identity

Use **Add device** in this new manager. Read the collection notice and explicitly
acknowledge it before creating the invitation. Download only the public bootstrap;
the invitation secret is entered separately into the installer's hidden native
enrollment prompt. Do not enroll a root-owned foreground identity first: the
installer creates the dedicated service identity itself.

Create a new protected bootstrap parent as root:

```sh
mkdir -m 0700 /root/tracebolt-inventory-device
```

Stop if it already exists. Transfer the public bootstrap through a trusted
channel into this directory using its actual downloaded filename. The example
below assumes `/root/tracebolt-inventory-device/bootstrap.json`.

The installer requires Linux with systemd PID1, cgroupv2, protected fixed parent
paths and no foreign account/unit/install state. It checks these without relaxing
permissions. Read [the service contract](linux-agent-service.md) before applying.
Do not change `/opt` or another protected parent to force a failing preflight.

Select only the just-downloaded public bootstrap and compute its hash immediately
before the plan. All binaries and the source archive were prepared in step1.

```sh
TRACEBOLT_BOOTSTRAP_SHA=$(sha256sum /root/tracebolt-inventory-device/bootstrap.json) &&
TRACEBOLT_BOOTSTRAP_SHA=${TRACEBOLT_BOOTSTRAP_SHA%% *}
```

In the same real terminal, run this **read-only plan** as root:

```sh
./bin/agent-service --action install --insecure-http-test \
  --agent-binary "$PWD/bin/lan-agent" --agent-sha256 "$TRACEBOLT_AGENT_SHA" \
  --enroll-binary "$PWD/bin/enroll-agent" --enroll-sha256 "$TRACEBOLT_ENROLL_SHA" \
  --source-archive "$PWD/tracebolt-selected-source.tar" --source-sha256 "$TRACEBOLT_SOURCE_SHA" \
  --bootstrap /root/tracebolt-inventory-device/bootstrap.json --bootstrap-sha256 "$TRACEBOLT_BOOTSTRAP_SHA"
```

After checking that plan and authorizing the dedicated account, credentials,
fixed paths and service installation, repeat it with `--apply`:

```sh
./bin/agent-service --action install --insecure-http-test --apply \
  --agent-binary "$PWD/bin/lan-agent" --agent-sha256 "$TRACEBOLT_AGENT_SHA" \
  --enroll-binary "$PWD/bin/enroll-agent" --enroll-sha256 "$TRACEBOLT_ENROLL_SHA" \
  --source-archive "$PWD/tracebolt-selected-source.tar" --source-sha256 "$TRACEBOLT_SOURCE_SHA" \
  --bootstrap /root/tracebolt-inventory-device/bootstrap.json --bootstrap-sha256 "$TRACEBOLT_BOOTSTRAP_SHA"
```

The installer drops to its dedicated identity for enrollment. Check the displayed
origins/profile and enter the invitation only at the hidden terminal prompt.
Compare the complete local fingerprint and comparison value with the pending UI
claim, then approve only the intended device. No invitation argument, environment
variable, file or pipe is accepted. Existing basic bootstrap/state/keys are not
reused. A failure is an unresolved stage to inspect, never permission to delete
state or silently retry with a different identity. Use the documented explicit
resume procedure only when its exact retained-state conditions are satisfied.

After successful installation, confirm the actual systemd state:

```sh
systemctl is-active tracebolt-agent.service
systemctl is-enabled tracebolt-agent.service
```

The service owns reporting and survives closing the terminal. Observe advancing
receipt times across several reporting intervals. A controlled service restart
and successful subsequent report are separate checks; a true OS reboot remains
an additional acceptance gate. Do not run another foreground sender against the
service's private identity or state directory.

## 5. Check the actual observations

Open the new device's Inventory and Security views. Confirm advancing collection
and receipt times, the explicit profile and per-section coverage/quality. Check
services, processes, interfaces, volumes, software and package observations;
unknown, denied, partial and stale data must remain visible. The dedicated service
account and systemd sandbox permissions/namespaces can reduce available inventory
compared with a root foreground process. No section promises
complete system coverage or privilege escalation to obtain missing data.

Package observations support exact documented Debian 13/Trixie and Ubuntu
24.04/Noble facts. An offline catalog is explicitly imported and unverified.
Debian review candidates are conditional comparisons, not confirmed vulnerabilities;
Ubuntu observations do not enter Debian rules. Confirmed CVE and offered-update
counts remain unknown. This path does not run APT, install updates or remediate.

Keep real device names, telemetry, credentials and screenshots with private data
out of public reports. Share only a bounded status when troubleshooting.

To stop this new stack while keeping its state:

```sh
docker compose -p "$TRACEBOLT_INVENTORY_PROJECT" \
  -f deploy/compose.http-inventory-test.yaml stop
```

The helper, local tests and synthetic browser fixtures have distinct evidence
scopes. Actual new-profile setup, Docker startup and endpoint observations must be
confirmed on the selected host. A successful observed install/start can establish only that host
and revision's service result; it does not establish OS-reboot or production-fleet
acceptance. See the [collection contract](operational/contract.md)
and [package contract](linux-assessment/package-contract.md) for bounded fields.
