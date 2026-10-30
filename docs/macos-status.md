# macOS source status

This is an unreleased source candidate. Windows `v0.1.0-windows-preview.3`
artifacts, tags and published acceptance evidence are unchanged. A Darwin
cross-build is compilation evidence, never native macOS acceptance.

## First connected scope

The first macOS path is fresh guided **basic TLS** enrollment and bounded
foreground reporting. It uses the existing same-key renewal protocol only when
both the manager's immutable renewable policy and explicit local renewal approval
are present. Existing identities are not adopted or reset.

The intended operator experience is one manager and one device list for Linux,
Windows and macOS. The macOS store is explicitly enabled with
`macosBasicEnabled: true` in the protected LAN manager configuration and isolated
from the Linux managed and
Windows inventory stores. Its protected database is
`<stateDirectory>/enrollment-macos.db`; its immutable configuration fences
`Platform: darwin` and `basic-readonly-v1`. HTTP-test is rejected. It must retain
its original platform,
profile, issuer, identity and renewal policy on reopen. A manager upgrade alone
must not enable this domain or widen an existing grant.

First initialization durably creates separate initializing and ready markers.
Reopen requires their exact original configuration binding and the existing
nonempty ledger. Orphan SQLite fragments, interrupted initialization or loss of a
used ledger stop startup, even when the Mac flag is subsequently disabled.
No missing state is silently recreated, adopted or repaired. Preserve both
`identity-mode-macos-initializing-v1.json` and
`identity-mode-macos-ready-v1.json` together with the database.

The existing identifier-minimizing macOS collector reports:

- Product version and Darwin kernel release
- Wall-clock elapsed uptime estimate, including sleep
- Physical memory capacity
- Root filesystem allocation percentage

CPU and used-memory percentages remain unavailable. Root filesystem allocation
is not whole-device storage usage: APFS shared containers, snapshots, purgeable
space and other volumes are not reconciled. Unknown and denied observations stay
explicit. No hostname, IP addresses, serials, accounts, process inventory,
software inventory or log content is added by this basic scope.

## Commands and local identity

Build only with the Go version pinned in `go.mod`. `make macos-source` cross-builds
`enroll-agent`, `macos-agent` and `macos-agent-service` for Apple Silicon
(`arm64`) and Intel (`amd64`).
It does not execute or install any target binary.

The source `enroll-agent` accepts a reviewed absolute public bootstrap path and a
new dedicated private state directory. On macOS it must run as the intended
nonroot reporting identity. For TLS basic and inventory domains without renewal,
Add device now defaults to automatic registration: a fresh public
`tracebolt.enrollment-bootstrap.auto.v1` artifact registers without token entry.
The optional invitation-token checkbox keeps the hidden controlling-terminal
prompt. Invitation secrets are never command arguments, environment variables,
stdin, URLs or files. Compare the complete local public fingerprint and comparison
value with the manager before approving the identity.

After completed enrollment, the command prints the actual configuration path for
`macos-agent --config ABS_PATH --foreground`. This stops when its process stops.
`--interval` accepts 15 seconds through one hour; the default is 30 seconds.
`--validate-guided` validates retained local state without collection, network,
initialization or repair. `--service-identity UID:GID` is only for the separately
provisioned dedicated nonroot launchd identity and only in foreground mode.

The enrollment CLI deliberately rejects Linux pending-service/claim-only flags
on macOS. There is no published Mac installer or verified download command.
A local build hash alone does not establish publisher trust or native acceptance.

## launchd source and test package

The source-built [macOS service test package](macos-test-package.md) contains
Apple Silicon and Intel endpoint binaries, the service CLI, a standalone Go
preparation helper, exact source and hash manifests. Building these review
artifacts does not require native installation or acceptance. They remain
publisher-unsigned, unreleased test candidates; the Mac runtime does not need
Python, Homebrew or Xcode.

The preparation helper verifies the selected package and public TLS bootstrap.
Its separate `stage --apply` operation prepares a fresh dedicated account and
fixed protected paths only after explicit local approval. Enrollment remains a
separate enrollment and fingerprint-approval step (automatic registration needs
no invitation prompt). Existing
identities, accounts and uncertain partial state are not adopted or reset.

`macos-agent-service` retains its read-only nonroot preflight and host-free
`--render-only` plist rendering. Separate root-only `--action install` and
`--action uninstall` operations review exact existing handoff, artifact,
identity, custody and launchd state. Only explicit `--apply` attempts the
corresponding host mutation. Installation starts the background job; owned
removal retains the account, binaries, credentials and sender state. The
planning output's false installation fields describe planning only.

Source fixtures and Darwin cross-builds do not establish launched credentials,
manager reporting, process drain, reboot persistence or native uninstall.
See [macOS launchd source](macos-agent-service.md) for phase-bound registration
evidence, one-attempt uncertainty and exact native test boundaries. There is
no restart, binary upgrade, automatic repair or published download command.

## Protected state and renewal

The Darwin port uses descriptor-anchored components, no-follow opens, explicit
ownership/mode checks and bounded native ACL inspection. It accepts no ACL or
conservative deny-only ACLs; expanding, unknown, unsupported or malformed ACL
metadata fails closed. Symlink aliases such as `/var` are not silently normalized.
Use independently reviewed canonical paths. Unsupported/network filesystems are
not substitutes for the required protected local filesystem.

Enrollment and telemetry hold exclusive locks. First publication is no-replace;
replacement verifies the expected inode and bytes. File synchronization, regular
file full flush and directory synchronization remain part of the write contract.
Missing used ledgers, altered files and durability failures stop the operation.
Do not repair them by deleting state, changing ownership or loosening permissions.

Renewal retains the original identity/key, profile/scopes, pending telemetry bytes,
sequence floors and collection times. It uses a separate current-leaf manifest,
not a rewrite of original enrollment artifacts. Cutover joins the old sender
before activating the successor. Expired/revoked current credentials and final
revocation checks remain authoritative. See
[automatic certificate renewal](automatic-certificate-renewal.md).

## Fresh read-only inventory source

The separately enabled `macosInventoryEnabled` domain now connects fresh explicit
local consent, protected sender state, fixed native collectors, dedicated TLS
transport, latest-only manager storage and private views in the same manager UI.
See [fresh runtime](macos-read-inventory-runtime.md) and
[manager integration](macos-read-inventory-manager.md) for exact commands and
boundaries. This is source integration, not native execution or a Mac release.

The new profile collects the hardware model identifier, physical/logical CPU
counts and RAM capacity; Installer receipt identifiers; caller-visible process
IDs/parent IDs and short accounting labels; and separate passive numeric IPv4/IPv6
interface metadata. Receipts are not a complete installed-application inventory.
One-minute collection and latest-generation retention up to the original 24-hour
expiry are bounded defaults pending native performance acceptance. Full, partial,
denied and unknown sources remain separate from fresh/stale/expired data age.
The compact English/German UI labels each source and its limitations explicitly.

The first separately approved [native collector/log probe](macos-native-evidence-20261013.md)
ran on standard ARM64 and Intel macOS 15.7.9 runners. Hardware, receipt IDs and
process snapshots passed; both interface-family parsers rejected metadata, and
the first synthetic log query rejected its event schema. Both jobs failed with
bounded metadata-only evidence and verified cleanup. This partial native result
does not establish foreground endpoint enrollment/reporting or a release.

Only the distinct fresh `--macos-read-inventory` enrollment path can create this
scope. It requires typed local acknowledgement before keys, state or network, a
new identity and the independent protected inventory used/checkpoint/ready state.
The original basic Mac, Linux and Windows grants are never adopted or expanded.
Same-key renewal retains exact pending bytes, floors and original capture ages.
Foreground reporting stops when its process stops. The separate service test
package prepares explicitly selected inventory background execution; native
installation and reporting are still unaccepted. Public package sources may be
reused; no private catalogue is added.

The [collector](macos-read-inventory-source.md),
[wire](macos-read-inventory-wire.md), [sender state](macos-read-inventory-state.md)
and [protected sender](macos-read-inventory-sender.md) remain separate reviewed
contracts. Their earlier inactive-slice notes are superseded only by this explicit
runtime composition, not by broader collection or authority.

## Inactive bounded log contract

The [bounded log-window contract](macos-log-window-contract.md) prepares canonical
internal requests and projections with synthetic fixtures only. It adds no Apple
raw-format parser, native provider, content grant, runtime route or UI. Actual
Apple schema acceptance and visibility under the intended non-admin identity
remain unverified; log collection remains unavailable. The separate synthetic
native probe rejected its first event schema; it did not activate this contract.

## Remaining scopes and native gates

Log content, service actions, package changes, unattended installation and software
updates remain outside these source scopes. They need their own reviewed sources,
explicit authority, durable replay/uncertainty contracts and native acceptance.
No TCC, Full Disk Access, administrative privileges or system extensions are
requested by the basic reporting source.

Before any macOS release, separately authorized native tests must establish:

1. Apple Silicon and Intel syscall/ACL/descriptor/rename/flush behavior on the
   supported macOS/APFS versions, including inherited expanding ACL rejection.
2. Hidden input, cancellation and terminal echo restoration.
3. Fresh TLS enrollment, independent fingerprint approval and actual reports.
4. Interrupted enrollment, exact pending retry, lock exclusion and restart without
   new keys, reset counters or refreshed old observations.
5. Same-key renewal, lost activation reply reconciliation, leaf expiry and
   revocation with the unchanged original identity.
6. Separately approved dedicated-account/launchd setup, persistence after a real
   reboot, service stop/restart and safe uninstall behavior.

Synthetic manager/provider fixtures and target test-binary compilation cover
source behavior only. None of these native gates has been executed by this change.

Automatic onboarding requires the updated manager and source-built enrollment
client; old downloadable packages are not retroactively compatible. The existing
nonroot account preparation, explicit collection consent, launchd installation,
and fingerprint approval still apply. Linux integration tests and Darwin builds
do not establish native macOS installation acceptance.
