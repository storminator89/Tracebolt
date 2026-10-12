# Fresh selected Windows update setup

This is a create-only **source workflow** for one already activated Windows TLS
identity and one manager update domain. It supplies both sides of the separate
`windows-selected-cached-update-install-v1` grant. It does not grant observation
scopes, change existing consent, start an executor, scan Windows Update, install
an update, or establish native acceptance. Existing or partial update state is
never adopted, reset, migrated, or overwritten.

Actual key creation, persistent local grants and process-query permissions need
separate approval on the inspected hosts. Compilation and inert fixtures do not
provide that approval. Use matching reviewed source artifacts for the manager,
Windows service and executor, including the exact executor artifact manifest.
The ordinary Read admin installer is not this update grant.

## Preconditions and public exchange

- Complete ordinary TLS enrollment and explicit device approval first. Inspect
  the exact manager ID, device ID, immutable original certificate anchor, current
  transport leaf and its expiry. A renewed leaf does not replace the anchor.
- Use the Linux manager's existing protected LAN/enrollment files and state
  directory, as its approved runtime UID/GID. All output ancestors must be owned
  by that UID or root and must not be group/world writable or symlinks. Output
  files are create-only mode 0600; the new setup directory is mode 0700. No modes,
  owners, accounts, operator capabilities or existing configuration are repaired.
- The LAN profile must already enable Windows inventory and named operators must
  already have the deliberately approved `windows_update_install` capability.
  The update config must be absent. TLS is mandatory; there is no HTTP override.
- Stop the existing owned Windows observer using its separately approved service
  procedure before local provisioning. Inspect its activated identity, original
  anchor, TLS authority and exact observer/executor binary pins. The endpoint
  setup requires an elevated administrator and an exact artifact manifest.

Only the public offer and public registration cross hosts. They contain identity,
origin, public keys, fixed expiry and explicit scope consent. Protect them against
replacement and compare their digests through the approved transfer/review path.
Never copy or print `manager.key`, the executor key, enrollment credentials,
invitation secrets, operator password/verifier files or the full private state.
Do not paste keys into command arguments or environment variables.

## 1. Prepare the manager's purpose-specific key

The matching manager image contains `/tracebolt/windows-update-manager-setup`.
It is a scratch image with no shell. For the already approved, running Compose
manager, invoke the helper directly; retain its existing read-only config mount,
private state volume, runtime UID/GID and network settings:

```sh
docker compose -f "$COMPOSE_FILE" -p "$PROJECT" exec -T "$SERVICE" \
  /tracebolt/windows-update-manager-setup prepare \
  --lan-config "$LAN_CONFIG" --enrollment-config "$ENROLLMENT_CONFIG" \
  --device-id "$DEVICE_ID" --expires-at "$EXPIRES_AT"
```

Here the Compose project/service and in-container config paths must match the
inspected running manager, not a new project or volume. The input files, including
the transferred public registration for finalization, must already be readable
through those reviewed protected mounts. No image rebuild, mount change or
container recreation is performed by the helper. The same direct `exec -T`
prefix works for `finalize` and approved apply flags below; never invoke `sh -c`.

For a separately approved native Linux manager, `MANAGER_SETUP` below is the
verified source-built helper path. Use the same runtime UID/GID and the existing
protected configuration paths. `DEVICE_ID` is the approved Windows identity and
`EXPIRES_AT` is the explicitly chosen absolute Unix expiry in seconds. It cannot
outlive the enrollment issuer. Do not derive a new expiry each time you retry a
command. The existing current leaf still limits every subsequent operation.

Read-only review:

```sh
"$MANAGER_SETUP" prepare \
  --lan-config "$LAN_CONFIG" --enrollment-config "$ENROLLMENT_CONFIG" \
  --device-id "$DEVICE_ID" --expires-at "$EXPIRES_AT"
```

Review the exact scope, manager/origin, original anchor and current leaf,
expiry, named operators, UID/GID, protected paths and public purpose-key pins.
After explicit approval, repeat that command with:

```sh
--apply --approve-plan "$PREPARE_PLAN_DIGEST" \
--ack-selected-windows-update-install
```

Apply creates a durable started fence before generating a new manager-only
Ed25519 key. It writes the canonical public offer to
`windows-update-setup/offer.json` beneath the existing manager state directory
and returns the same public offer on stdout. `prepared.json` binds that offer to
the reviewed plan. Capture only the public stdout using a byte-preserving local
transfer; do not run a shell inside the image. If only that stdout was lost,
copy only the existing public `offer.json` from the inspected container/state
path using the approved host file-transfer procedure, without rerunning prepare. No enrollment update domain exists yet. Transfer only this
public offer to the inspected Windows host; retain the protected original.

## 2. Review and provision the stopped Windows endpoint

Use the matching source-built Windows service executable. The following is the
read-only review command; its file arguments are the inspected public offer,
exact executor image and matching executor manifest:

```powershell
& $WindowsService --selected-updates-provision `
  --manager-offer $ManagerOffer `
  --executor-file $ExecutorFile `
  --artifact-manifest $ExecutorManifest
```

Review all identity/expiry/scope and image pins plus the disclosed local observer
relay and observer process-query permissions. Explicit apply adds:

```powershell
--apply --approve $WindowsPlanDigest `
--acknowledge-selected-updates `
--acknowledge-observer-relay `
--acknowledge-observer-process-query
```

Successful apply emits only the canonical public registration plus a newline.
It includes the exact original offer, separately generated executor public key,
executor/grant IDs and fixed-expiry consent. Transfer that public output into a
protected 0600 file owned by the Linux manager runtime UID. Use byte-preserving file transfer or cmd.exe redirection; classic Windows
PowerShell redirection may transcode stdout to UTF-16. Do not pretty-print,
re-encode, add a BOM or manually edit JSON. The manager accepts canonical registration JSON with at most one final LF.
If only stdout was lost after completed Windows setup, the read-only
`--selected-updates-export` command returns the original completed registration;
it does not generate new keys, renew expiry or resume partial setup.

## 3. Finalize reciprocal manager registration

Use the same original manager LAN/enrollment paths and exact device ID. The
registration fixes the expiry; there is no new expiry argument for this phase.

```sh
"$MANAGER_SETUP" finalize \
  --lan-config "$LAN_CONFIG" --enrollment-config "$ENROLLMENT_CONFIG" \
  --device-id "$DEVICE_ID" --registration-file "$REGISTRATION_FILE"
```

Review this fresh plan, including both public-key pins, original anchor, current
leaf, exact registration and consent, expiry and named operators. Apply adds:

```sh
--apply --approve-plan "$FINALIZE_PLAN_DIGEST" \
--ack-selected-windows-update-install
```

After its own durable started fence, apply calls the enrollment-owned create-only
transaction. That transaction checks the reviewed current leaf after lock waits,
checks exact protected inputs before its last fresh clock/authority sample, and
commits the reciprocal immutable marker and update record together. Revocation,
renewal during the reviewed apply window, expiry, changed input or any existing
update domain blocks the operation. A renewed current leaf between completed
preparation and the new finalization review is allowed; the original anchor and
consent expiry remain unchanged.

Successful finalization creates `manager.json`, staged `lan.json` and
`complete.json` under the same `windows-update-setup` directory. The original LAN
config is unchanged. The generated manager config requires an exact protected
completion receipt binding its canonical bytes, reviewed plan and registration,
both when loaded and during use. Missing, partial or changed completion evidence
blocks activation even if the staged LAN file already exists.

## Activation and limits

Selecting the returned staged LAN config for a separately approved manager
restart is a distinct host step. Starting the observer and explicitly launching
the elevated executor with `--run-foreground --allow-observer-process-query`
are also separate steps; setup launches neither. The process-query flag is a
real permission disclosure, not permission to install any update. Each install
still needs a fresh exact GUID/revision readiness report and a named operator's
specific preview approval. No download, EULA acceptance or reboot is authorized.

The default workflow remains **one fixed Windows device/update binding** and
rejects an existing domain. The separate additional-device mode below extends a
complete explicitly activated registry without renewing any old consent. Each
device retains its original expiry and 32-approved-job lifetime bound. Expired,
failed, uncertain and consumed history is retained.

Any failed apply may have created protected keys, fences or reciprocal state.
Preserve all of it and stop. Never delete a marker, substitute a new key, restore
an older database, rerun initialization as recovery, or remove a receipt to make
setup look fresh. Removal/disabling on one side does not erase or reset the other
side's consent and history. Native Linux-manager/Windows interoperability,
protected write/ACL acceptance, foreground launch and selected cached install
acceptance must be separately approved and verified before release claims.


## Additional devices: explicit create-only extension

For a second or later exact activated Windows identity, add `--additional-device`
to both the manager `prepare` and `finalize` review commands above, and to their
approved apply commands. Supply the currently activated protected LAN config,
which must already point to the completed first-device v1 config or a complete v2
registry. The ordinary first-device mode still requires that setting to be absent.
Use a new device ID and an explicitly chosen fixed expiry; endpoint provisioning
still requires its separate local approval and independent executor key/grant.

Additional preparation reuses only the existing purpose-specific manager key by
its exact protected path and public pin. It generates no key. The v2 review binds
all original registry/config digests and paths, exact enrolled bindings, key
reference, named operators, original target identity and current leaf. Existing
entries need valid original completion receipts; their exact count and bindings
must match the enrolled update records. The new total cannot exceed either the
enrollment record limit or 25 devices. Duplicate device, executor ID/key pin or
grant is rejected. Partial state, including a prior registration whose new config
was not explicitly activated, blocks a further extension.

The new public offer and receipts live under the create-only directory
`windows-update-setup-<exact-device-id>` with a distinct sibling started fence.
Finalize stages a new v1 `manager.json` referencing the unchanged original manager
key, a v2 `registry.json` containing every original config path plus the new one,
`lan.json` pointing to that registry, and `complete.json` last. No previous file,
receipt, key, expiry, grant or per-device job history is rewritten. Files or fences
already present for that target are never adopted or resumed. Every blocking
output is followed by fresh original-expiry/current-leaf/input checks.

Review and separately approve activation of the returned staged LAN config before
adding another device. No helper step restarts a manager, launches an endpoint,
changes ACLs, scans WUA or installs an update. This is source behavior only;
native setup and interoperability acceptance remain separately approved gates.
