# Fixed socket-owner provisioning source candidate

This is source-only work for the fresh, explicitly approved read-admin v2 flow.
It does not update the published release, authorize a host operation, or establish
native acceptance. The final socket phase follows the completed journal phase;
it is not an additional normal setup command. The existing main agent unit is
unchanged and keeps zero capabilities.

## Grant and supported shape

The first profile is Linux amd64, kernel 6.5 or newer, systemd as PID 1 and cgroup
v2, with local-files/systemd NSS only. A separate fixed non-login
`tracebolt-socket-owner-reader` user and primary group run the verified
`/opt/tracebolt-agent/socket-owner-reader` binary. No extra group is added to the
agent. The helper requires exactly CAP_SYS_PTRACE in effective, permitted,
inheritable, ambient and bounding sets at runtime.

CAP_SYS_PTRACE is broad process-memory authority. The fixed protocol offers only
local TCP/UDP socket ownership metadata, with no requested paths, process IDs,
namespaces or shell. That protocol restriction is not an OS read-only guarantee.
The unit denies direct ptrace/process_vm memory syscalls and selected system-wide
operations; effective seccomp and LSM behavior remain native acceptance gates.
No namespace entry is implemented. The helper, systemd PID 1 and authenticated
agent must share the runtime's required PID, network and user namespaces.

The socket unit creates a root:root 0755 parent at
`/run/tracebolt-socket-owner-reader`, with a root:agent-GID 0660 `reader.sock`.
Its inherited descriptor name is exactly `socket-owner-reader`; there is no
PassPIDFD setting. The service does not chown a RuntimeDirectory, enable a private
network/user/PID namespace, or hide proc entries. Root-owned policy and deployment
files are 0640 with the helper primary GID. The installed helper is root:root 0755; the main agent retains the native
installer's exact root:root 0555 mode. Units are root:root 0644. The policy and deployment JSON preserve Go struct
field order, and deployment v2 binds the activated-client contract and exact agent,
helper and unit hashes.

## Create once, then verify original evidence

The pre-install check rejects any preexisting helper account, fixed path, unit,
unit override, enablement link or socket receipt. Global read-admin preflight
also rejects preexisting journal/configuration state. At the final socket phase,
`/etc/tracebolt` must contain exactly this workflow's completed journal artifacts;
the adapter snapshots and preserves their bytes and object metadata.

Under the existing installer lock and a durable parent socket-start receipt, the
adapter stops the exact owned agent and checks inactive state, MainPID zero and
empty fixed cgroup (including descendants through `cgroup.events populated`).
The offline CLI runs as the existing nonroot service identity. It validates the
activated sender/incarnation and private consent without helper IPC or capture;
root never reads the agent's enrollment keys.

The helper source is the independently verified release artifact from the
bootstrap's fixed root-private staging directory. The adapter pins no-follow
file and directory descriptors, verifies root ownership, mode, link count, inode,
size and SHA-256 before and after copying, and creates the destination exclusively.
It creates a fresh epoch, root declarations, fixed units and private consent;
only then does it enable the socket and compare loaded settings and local state.
The loaded-unit comparison covers exact executable arguments, numeric IDs,
supplementary groups, capabilities, NoNewPrivileges, KillMode, Delegate,
namespace/proc settings, and exact socket listener, ownership, modes, descriptor
name, Accept and activation target. Socket activation target is the Unit
`Triggers` property; `Service=` is a unit-file directive, not a Socket D-Bus
property. The source-derived parser fixtures follow upstream
[systemd v255 socket properties](https://github.com/systemd/systemd/blob/v255/src/core/dbus-socket.c),
[v255 show rendering](https://github.com/systemd/systemd/blob/v255/src/systemctl/systemctl-show.c)
and [v257 unit properties](https://github.com/systemd/systemd/blob/v257/src/core/dbus-unit.c).
PrivatePIDs is checked when exposed by the manager; older managers do not expose
or implement that setting. Native namespace and actual capability checks remain
independent requirements.

An exclusive root-private `socket-owner-install-complete.json` in the existing
installer directory binds the original parent intent, sender/incarnation,
origin/profile, agent and allocated helper IDs, epoch, policy/deployment bytes and
digests, installation ownership and every fixed executable/unit hash. Verify-only
compares that original evidence. It never adopts a current epoch, enables a
disabled grant, or replaces the receipt. An inner receipt does not complete an
uncertain outer read-admin phase. The parent fail-stops the exactly owned agent if
its own socket completion write is uncertain.

Success means local configuration confirmed only. No offline CLI can prove
helper runtime readiness: the native client must be the real agent service in its
fixed cgroup. Prior agent activity is restored only after identity, configuration,
private consent and baseline validation all succeed. Uncertain writes, account
creation, consent, socket, readback or restart failures retain evidence and keep
or attempt to keep the owned sender stopped. There is no automatic replay,
rollback, deletion of evidence, adoption or repair.

## Explicit maintenance revoke

The verified bootstrap's deliberate maintenance dispatcher invokes `revoke` for
one originally completed read-admin socket grant. It validates the original
parent and socket completion evidence, durably creates revoke-started evidence,
stops/drains the owned sender, disables socket admission, durably replaces only
the exact root policy with its enabled=false form, and stops/drains the helper.
Only then does the nonroot offline CLI write the disabled private tombstone and
discard tagged privileged pending data. Ordinary pending inventory is preserved.
The original install receipt and deployment remain untouched. An immutable
revoke-complete record binds the same identity, epoch and original receipt.

Partial revoke never resumes the sender, retries a policy/consent write, or
removes evidence. A safety failure handler attempts to stop the socket and helper
without replaying authority changes. A failed stop is a blocker, not confirmed
shutdown. Baseline identity validation and exact disabled readback must complete
before restoring only the sender's prior activity; helper/socket remain disabled.
Same-epoch re-enable, renewal and replay of uncertain revoke are not supported.
The explicit [same-scope read-admin update](read-admin-upgrade.md) uses a separate
verified current-binding record and immutable upgrade history while preserving
these original receipts. An ordinary agent upgrade cannot rewrite that binding
and is rejected for a read-admin installation.

If explicit revoke is blocked by corrupt current policy/deployment bytes, its
failure path can still contain an independently proven owned helper: it checks
the original immutable receipt, exact executable/unit hashes, dedicated account
and loaded security settings without accepting those current declarations. It
then disables/stops the socket and drains the helper while retaining all corrupt
bytes and the original receipt. It never reports revoke complete or rewrites
policy/consent in this containment path. A corrupt/foreign original receipt,
artifact, account or loaded unit permits no helper action and reports helper
shutdown unconfirmed; only the independently proven sender is stopped.

## Inert validation and remaining gates

Run only the generated fixture suite for this source change:

```
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s deploy/socket-owner -p 'test_*.py' -v
```

The fixtures replace all host effects. They do not inspect live proc, accounts or
services, execute the helper, create host accounts/units/sockets, or grant any
capability. Real Debian/Ubuntu systemd loading, actual five-set capabilities,
SO_PEERPIDFD and inherited sockfs proofs, effective seccomp/LSM permissions,
privileged-owner attribution and denial cases, pending revoke/restart behavior,
and reboot remain separately authorized disposable-host acceptance gates.

The existing native installer publishes the main agent binary as root:root 0555.
Socket provisioning and runtime proof require that exact mode; they never chmod
the main binary to fit the helper. The separately copied helper is root:root 0755.
