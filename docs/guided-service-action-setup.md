# Guided create-only service-action setup (source candidate)

This source adds one local manager guide and one local endpoint guide for one
**already activated complete-profile Linux endpoint** and one independently
reviewed simple service. It does not perform the first service action. After
both hosts are ready, a named maintenance operator uses the existing central
Services preview/approval UI for each `service.try-restart`.

**Source and fixture verification are not native acceptance.** No real command
key, host grant, account, group, unit, socket or service restart was created while
implementing these tests. A later separately authorized disposable host gate is
required for Docker lifecycle, real root writer credentials, systemd activation,
nonroot readiness, interruption/restart and the first UI-approved target action.
The currently pinned dashboard release predates this setup/runtime; the guide
refuses an incompatible installed binary and never upgrades it. Deploying a
reviewed compatible image/endpoint release is a separate prerequisite.

## Supported first setup

- Linux manager, existing single-service local Docker Compose project, existing
  state volume, already running compatible image, numeric nonroot UID:GID,
  explicit `--lan-config … --enrollment-config …` command. The guide verifies
  PID 1's actual real/effective/saved/filesystem UID/GID in the container.
- Existing named operators. The plan lists **every** configured operator with
  `restart_service`; choosing a setup operator does not make them exclusive.
  Setup never creates or promotes an operator account.
- Existing installer-owned systemd endpoint and activated complete-profile
  sender, nonroot agent account/group, root-owned compatible installed binary.
- Existing verified TLS/mTLS, or the explicitly disposable HTTP profile with
  independent `--ack-http-action-risk` on **both** hosts. A stolen plaintext
  operator session can authorize actions within the enabled local grant.
- No existing action domain/artifacts. Existing legacy domains keep working but
  cannot be adopted or migrated by this create-only guide. Later endpoints need
  a separately reviewed add-only operation; do not repeat manager initialization.

For the shipped disposable HTTP Compose template, also supply the existing
`--lan-ip 192.168.1.50` and `--ack-http-action-risk`. Only an explicit RFC1918 IPv4
can populate its `TRACEBOLT_HTTP_TEST_BIND_IP` interpolation. It is bound to the
plan and must match the running Compose hash; it cannot change exposure. This
option is refused for TLS. No other inherited environment variable is forwarded.

Unknown launchers, multiple Compose services, drifted Compose definitions,
foreign units, existing leftovers, missing used state, unreviewed service inputs,
changed identities, aliases/templates and protected connectivity/Tracebolt units
are explicit blockers. No automatic repair, reset, resume, key rotation,
re-enrollment or transport conversion exists.

## Reviewed-source commands

Use a separately verified copy of this exact source in a protected root-owned
checkout on the target host. The guide verifies its dependency manifest. It
requires existing Docker/systemd tools and does not install dependencies. The
commands below are actual source commands, not a claim of a published release
bootstrap. Values are public placeholders; never paste private keys or invitation
secrets into chat, command arguments, environment variables or configuration
examples.

Manager plan, run locally on the manager host:

```sh
python3 /approved/Tracebolt/deploy/actions/guide.py manager \
  --compose-file /etc/tracebolt/compose.yaml --project tracebolt \
  --service manager --endpoint agent_EXISTING_32_HEX_ID
```

The default command is read-only: no stop, key generation, file creation,
state initialization or socket activation. Add `--apply` to the same command to
see a freshly inspected plan and type its exact `APPLY sha256:…` line once in
that local terminal. Cancellation creates nothing. Changed plans fail before
any effect. There is no blanket yes flag or noninteractive approval shortcut.

The manager apply preserves the original LAN configuration. It writes protected
manager-owned files below the existing state directory, adds the selected
identity's fenced domain atomically, writes a create-only Compose overlay, and
recreates only that exact known manager using its already installed image ID.
No build, pull, extra service, new network or new volume is requested. The guide
rechecks all source/resolved inputs after provisioning, then launches only the
create-only `.actions.resolved.json` snapshot. It references existing named
networks/volumes as external and contains no unresolved interpolation/imports.
Preserve and use that frozen file for later ordinary starts; starting only the
old Compose file would omit the new LAN sibling. The smaller `.actions.override.json`
is also retained for review, but is not the setup activation input.

It produces a public `.actions.bundle.json` beside the original Compose file
and prints its whole-bundle digest. Transfer only this public bundle to the
endpoint through an approved local method. Independently compare the digest
against the manager's trusted local terminal. The endpoint never learns trust
from an unauthenticated HTTP response. The private raw 64-byte Ed25519 command
key stays in manager-owned 0600 storage; no private material is printed/exported.

Endpoint plan, run locally on the selected endpoint:

```sh
python3 /approved/Tracebolt/deploy/actions/guide.py endpoint \
  --bundle /root/manager-actions.bundle.json --fingerprint sha256:PUBLIC_BUNDLE_DIGEST \
  --review /root/example-service-review.json --allow-unit example.service
```

The review file is the protected canonical `actionhelper.Target` manifest
specified in [the helper contract](controlled-action-helper.md). A local
administrator must review the exact service's relevant stop/restart effects,
related units, fragments/drop-ins, systemctl binary and execution inputs, then
provide their pinned hashes and review-record digest. The guide checks these
pins but does not infer arbitrary script safety or complete dependency scope.
It neither installs nor starts a demonstration target.

Again, add `--apply` for one exact local plan approval. Default endpoint planning
does not stop the agent, acquire its writer locks, create authority, or connect
to the activation socket. It reads stable existing protected snapshots; a
concurrent change may require a new plan, never a lock takeover or repair.

## Apply order and custody

Manager:

1. Durably create host intent before stopping the identified manager.
2. Use that exact already present image without networking, as the actual manager
   UID:GID and with its existing mounts. Revalidate the public manager plan.
3. Durably create manager-owned intent before generating the distinct command key.
4. Create key/config/new LAN sibling/public bundle without replacing old leaves.
5. In one enrollment transaction commit the immutable credential setup marker,
   new action schema/key and exact endpoint-incarnation row.
6. Create completion receipt, exact-image launch overlay/frozen configuration and public bundle.
7. Start that manager only and verify running identity/configuration. This says
   nothing yet about endpoint readiness or service/application health.

Endpoint:

1. Validate and lock the existing installer-owned installation; create durable
   intent under `/var/lib/tracebolt-agent-installer` before stopping anything.
2. Stop/drain the exact owned agent, preserve enablement, validate the existing
   guided sender as its actual UID:GID with empty supplementary groups.
3. Recheck bundle/identity/service review. Create only absent root policy/public
   pin, separate client grant, helper service/socket and dedicated ledger.
4. The root initializer creates/fsyncs an independent permanent
   `action-ledger-started.json` fence before ledger initialization. It is outside
   the ledger, so deleting a used ledger cannot make initialization eligible.
   Any retained completion receipt also blocks the initializer, even if the
   ledger and started fence were both lost.
5. Reload systemd and enable/start only the action socket. Run capabilities-only
   authenticated IPC as the **nonroot agent**, checking the full grant binding.
   No claim, submit, permit, shell or managed target restart is involved.
6. Restore an originally active agent only after readiness and unchanged input
   checks, preserve its enablement, and write the completed ownership receipt.

The root helper has no IP networking, receives one fixed systemd-activated Unix
socket, and can write only its pre-existing ledger. It uses `Restart=no`,
`KillMode=mixed`, and a 60-second graceful-stop allowance. Neither systemd
`StateDirectory` nor `ConfigurationDirectory` can silently create or repair
missing authority. The ordinary agent stays nonroot with no new group, sudoers,
polkit rule or capabilities.

## Durable state, partial failure and repeat

The manager credential's optional marker preserves exactly the legacy canonical
bytes when absent. Fenced action rows have a distinct exact schema and reciprocally
bind that marker: missing row, schema, key or marker is rejected. Legacy unfenced
runtime rows remain compatible but cannot enter this new setup path. Marker and
row creation are atomic; there is no startup migration.

Read-only manager inspection opens only existing protected DB/sidecars and uses
SQLite's read-only shared-memory mode for a live WAL. A same-process open writer
is rejected because SQLite otherwise reuses its writable mapping. The Docker
planner is a separate process. Closed DB inspection uses immutable mode only
when there is no WAL/recovery journal and checks that condition again afterward.
No missing DB/SHM/WAL, lease or schema is created by planning.

There is no transaction covering files, SQLite and systemd. Any partial or
uncertain failure retains its intents, keys, configuration, marker and ledger.
The endpoint may compensate by stopping only its newly owned helper/socket and
the authorized existing agent; it reports stopped/active/unconfirmed state.
Manager activation failures preserve all evidence and require inspection. Do not
delete artifacts or restore an old full backup to make a retry appear fresh.
Full-backup rollback resistance is not provided.

A completed identical rerun validates existing provenance and reports status
without a second key/domain. It does not probe endpoint readiness during plan.
Changing policy/profile/key/incarnation, adopting legacy setup and removing or
repairing setup artifacts require separate future workflows. Even after an
operational disable/uninstall, keep the permanent fences and histories.

## Fixture gates

```sh
go test ./internal/actionsetup ./cmd/action-setup ./internal/actionhelper \
  ./internal/lanclient ./internal/enrollmentstore ./internal/enrollmentstate ./cmd/lan-agent
python3 -B -m unittest discover -s deploy/actions -p 'test_*.py' -v
python3 -O -B -m unittest discover -s deploy/actions -p 'test_*.py' -v
```

Tests inject effect adapters, deterministic invented keys and temporary synthetic
stores. They cover plan-only/cancel/change, exact approval, legacy bytes, atomic
marker/row state, deleted used rows/schema/ledger, no repeated generation,
wrong identity/profile/key, unsafe/foreign artifacts, separate HTTP consent,
nonroot capabilities-only readiness, and before/after-effect failure retention.
They never invoke a production Docker/setup/systemd adapter or a real service
restart. Existing native IPC gates and browser action gates remain separate;
passing these fixtures does not establish installed-host acceptance.

Docker command semantics used by the adapter are documented in
[Compose config](https://docs.docker.com/reference/cli/docker/compose/config/) and
[Compose up](https://docs.docker.com/reference/cli/docker/compose/up/).
