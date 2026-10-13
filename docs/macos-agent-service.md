# macOS launchd source candidate

Status: explicit-profile plist/preflight plus a fake-backed create-only lifecycle
source foundation. There is **no native mutation adapter**, usable installer,
restart, upgrade or uninstall operation.
Nothing here establishes a native installed service, reporting or boot persistence.
Linux/systemd and Windows release behavior is unchanged.

## Exact boundary

`cmd/macos-agent-service` emits a JSON review result with a complete XML plist and
its SHA-256. The default performs local read-only checks. `--render-only` emits
an explicitly unchecked candidate without reading host accounts, files or state.
`--profile basic-readonly-v1` retains the default basic scope. Only explicit
`--profile macos-read-inventory-v1` selects the separate fresh inventory handoff;
selection never grants, adopts or expands scope. Configuration overrides,
invitations and shell commands are not accepted.

`--action install` selects the lifecycle foundation described below. `--apply` is
a separate explicit mutation boundary and is accepted only with that action,
never with `--render-only`. The native lifecycle adapter is unavailable: both
forms return an `unavailable` result **before host inspection or mutation**.
The program never executes an artifact or `launchctl`. Native preflight only
runs two fixed read-only `/usr/bin/dscl /Local/Default -read` queries to verify
the dedicated local user/group IDs; no caller-selected node, record, arguments
or shell is accepted.

Build the planning CLI and `cmd/macos-agent` from the same reviewed source.
Use independently selected lowercase SHA-256 values for the native agent and a
local source archive. Hash and Go/Mach-O checks identify selected bytes, role and
architecture. They do not establish publisher authenticity, signing, notarization
or a reproducible relationship between the archive and binary. Universal/fat
binaries and other program roles are rejected by local preflight.

The selected host must already have all of the following, separately approved:

- A dedicated nonroot `_traceboltagent` user and group with the exact reviewed
  numeric UID:GID. This tool cannot create accounts, alter group membership or
  adopt an ordinary user. The fixed local Directory Service lookup must confirm the mapping;
  missing, malformed, multiple-valued, timed-out or unavailable results block
  preflight. The read-only queries have two-second deadlines, bounded output
  and a fixed locale, and work independently of Go cgo account lookup.
- Root-owned, non-group/world-writable installation and ancestor directories;
  root-owned bounded executable at
  `/Library/Application Support/TraceboltAgent/macos-agent`.
- Selected UID:GID-owned mode-0700 directories at
  `/Library/Application Support/TraceboltAgent/state`, its `enrollment` child,
  and the enrollment `telemetry` child.
- An existing activated explicitly selected TLS enrollment at
  `/Library/Application Support/TraceboltAgent/state/enrollment/agent.json`,
  with `agent-key.pem`, `agent-cert.pem`, `server-ca.pem`, `ready.json` and its
  original bound sender state in that enrollment directory. Basic accepts only
  guided-v2 or explicitly renewable-v6 `basic-readonly-v1`. Fresh inventory accepts
  only canonical `tracebolt.lan-agent.macos-inventory.v1` with the exact original
  `macos-inventory-consent.json`, `macos-inventory-enable.json` and independent
  inventory used/checkpoint/ready state. Enrollment must
  have been performed as the same selected nonroot identity after its separate
  key/trust approval. Pending, manual-v1, HTTP, mismatched/implicit inventory scope and implicit
  renewal adoption are rejected. A valid basic handoff cannot satisfy inventory
  selection, nor can inventory silently replace the default basic selection.
- A separately reviewed root-owned source archive outside the fixed installation
  directory, with protected root-owned parent directories.
- A protected `/Library/LaunchDaemons` directory and no entry at
  `/Library/LaunchDaemons/com.tracebolt.agent.plist`. Any existing file, symlink,
  directory or uncertain read blocks this fresh candidate; no existing plist is
  adopted or removed.

All path components are descriptor-anchored, symlink-free and checked for local
filesystem ACL support. Private files require protected owner-only access.
Permissive or uncertain ACLs fail closed. Standard aliases such as `/var` are not
silently resolved. This may reject a host layout that needs separate review; it
never repairs modes/ACLs, creates directories or changes ownership.

## Read-only review

Run local preflight as the exact dedicated service identity with no supplementary
groups beyond the selected GID, never as root or as an ordinary desktop user.
Arranging that identity and the protected prerequisites requires separate host
administration approval. Stop any sender using this identity through an already
authorized procedure before local validation; its existing ledger is checked
under an exclusive lock without initialization or temporary-file cleanup.

Inventory service preflight separately requires a currently live local leaf and
valid existing renewal manifest/transaction when renewal was consented. An expired
leaf, missing/corrupt renewal state or locally recorded revocation blocks it;
a valid same-key successor can pass after the original leaf expires. The original
config, identity, consent and sender checkpoint stay unchanged. Context, local
authority and close failures are checked before success. This is read-only local
validation, so current manager-side revocation is still checked when reporting.
The agent's `--validate-guided` remains a retained-state validator.

For illustration only, replace every placeholder with independently reviewed
values. This command is not an invitation to provision the prerequisites:

```sh
/absolute/reviewed/macos-agent-service \
  --service-identity REVIEWED_UID:REVIEWED_GID \
  --agent-sha256 REVIEWED_AGENT_SHA256 \
  --source-archive /absolute/protected/reviewed-source.tar \
  --source-sha256 REVIEWED_SOURCE_SHA256
```

Add `--render-only` to review the candidate on another platform without host
inspection. The JSON always has `installationAvailable: false` and
`readyForInstallation: false`. `localPreflightPassed: true` means only that the
listed local checks passed at that moment. It is not a reusable authorization,
installation receipt or promise that later state is unchanged.

The plist fixes the label `com.tracebolt.agent`, the binary/config paths, a
30-second basic or one-minute fresh inventory foreground interval, the `_traceboltagent` user/group, numeric runtime
`--service-identity`, `InitGroups=false`, umask 0077 (decimal 63), a 30-second
exit timeout and background process classification. Each argument is a separate
XML array string, including paths containing spaces; no shell is involved.

`RunAtLoad` requests a start when the job is loaded. `KeepAlive.SuccessfulExit`
false requests retry after unsuccessful exits, spaced by `ThrottleInterval=30`.
This is not systemd's bounded restart budget and can retry permanent failures
indefinitely until stopped. There is no claim of a Linux-equivalent filesystem
sandbox or a TCC/Full Disk Access grant. The service process remains nonroot and
must reject unexpected real/effective/saved IDs and supplementary groups before
reading private state. No extra log files are created by the plist.

## Create-only lifecycle foundation (fake backend only)

This source depends on the fresh inventory endpoint runtime composition, including
`ParseMacOSInventoryConfig` and `ValidateMacOSInventoryServicePreflight`; the earlier
manager-only slice does not supply them. It does not alter the released Windows
`v0.1.0-windows-preview.3` artifacts or the Linux service implementation.

`Install` separates inert preflight from explicit apply. Its adapter interface is
implemented only by in-memory tests. No concrete receipt files, service jobs or
plist files are written by this candidate CLI. Native availability is not inferred
from an OS build tag, the existing read-only `Backend`, or a successful preflight.

The coordinator requires verified protected account/artifact/path prerequisites,
the existing activated current TLS handoff and positive absence of all three:
fixed plist, system-domain label and retained enabled/disabled override. A failed
command, inaccessible domain, unknown output or unsupported OS is not absence.
Any pre-existing foreign, transient or retained job blocks a fresh operation.

The immutable owner binds:

- Fixed label, agent/config/plist paths and selected service UID:GID
- Explicit basic or fresh inventory profile
- Independently selected binary and source archive paths/hashes
- Exact config and generated plist hashes
- Original enrollment identity/issuer/key/ready/profile/consent anchor

The current same-key renewal leaf and mutable sender counters are not rewritten
into ownership. The adapter must validate them and the original used sender state
on every inspection. Ownership never authorizes initial enrollment, new keys,
renewal, a larger profile, account creation or permission repair. The coordinator
contains no certificate, key, grant or account mutation API.

Apply proceeds under an exclusive protected session with these durable steps:

1. Create an independent used fence and immutable owner, both no-replace.
2. Append `publish-plist/started`, then publish only the exact absent fixed plist.
3. Inspect exact protected bytes and collisions, then append
   `publish-plist/completed`.
4. Append `bootstrap/started`, then request only the exact owned system job.
5. Independently inspect the job's full execution/credential binding and exact
   plist, then append `bootstrap/completed` and re-inspect all final evidence.

Each of the four phase receipts has a fixed sequence, schema and owner hash.
Persisted decoders accept exact canonical bytes only, rejecting duplicates,
unknown fields, reordered/gapped records and profile substitution. Before and
between every effect, selected bytes, identity, active handoff, ownership,
receipt prefix, plist/job binding and override absence are rechecked. Backend
mutation methods must additionally close native races; the coordinator alone
cannot make launchd operations transactional.

Any write/durability/close error, cancellation or changed evidence after the first
mutation attempt returns `indeterminate`. There is no rollback, deletion, retry,
resume, replacement or inferred completion of a started phase. A repeated
invocation can only inspect the original receipts and current state. Even an
absent job after an uncertain bootstrap does not authorize replay. An already
fully completed receipt sequence plus exact live binding returns
`registration-confirmed` without changing anything. A success response lost after
the final receipt may therefore be resolved read-only. This is evidence of that
adapter's registration observation, never process health, manager reporting,
reboot persistence or native acceptance. `nativeAcceptanceVerified` remains false.

### Native adapter obligations and remaining gate

A future adapter must establish independently reviewed current macOS semantics
for system-domain collision/override detection, exact native job binding and a
safe enrollment/sender-lock handoff. It must keep root-owned lifecycle custody
outside service-writable state; preserve an independent used fence on partial
creation; perform descriptor-anchored no-replace publication with full flush and
directory durability; reject missing/partial/foreign custody; and never adopt,
repair or delete used state. Read-only `Open(false)` must not create lock files or
directories. Holding enrollment locks across bootstrap without a reviewed handoff
would prevent the sender from starting and is not an implementation shortcut.

Apple's archived launchctl source manual documents older `load`/`unload` behavior,
not a verified contemporary `bootstrap`/`bootout` and machine-readable collision
contract. This source deliberately provides no guessed native command parser,
error-code-to-absence mapping, enable override or automatic cleanup. The current
preflight's plist absence alone remains insufficient for installation.

After exact host/account/artifact/path/service approval, a separate disposable
Mac gate must verify native account mapping, ACL/descriptor behavior, launchd
credential isolation and supplementary groups, rejected mismatched identity,
foreground stop/SIGTERM drain, current TLS activation and fresh real manager
reports. It must independently cover actual reboot persistence, failure behavior
and owned removal retaining all identity/counter state. Source fixture tests and
Darwin cross-compilation do not satisfy any of these runtime gates.

Implementation references: Apple's
[launchd property-list manual](https://github.com/apple-oss-distributions/launchd/blob/main/man/launchd.plist.5),
[archived launchctl manual](https://github.com/apple-oss-distributions/launchd/blob/main/man/launchctl.1), [dscl read command](https://github.com/apple-oss-distributions/DSTools/blob/main/dscl/dscl.1)
and [Creating Launch Daemons and Agents](https://developer.apple.com/library/archive/documentation/MacOSX/Conceptual/BPSystemStartup/Chapters/CreatingLaunchdJobs.html).
These describe the plist contract; the selected macOS release still requires its
own separately approved native acceptance.

Explicit renewable basic TLS uses `tracebolt.lan-agent.v6`, collection profile
`basic-readonly-v1` and the exact enrollment-directory `renewal-manifest.json`.
The existing guided-handoff validator checks the original ready binding and the
current same-key certificate manifest; this preflight never grants or starts
renewal. A broader profile, alternate manifest path or HTTP mode is rejected.

## Source verification

Focused fake-backend tests cover both profiles, exact scope/path dispatch, inert
defaults, every lifecycle effect and receipt interruption (including durable writes
whose replies fail), missing/foreign/unknown collision evidence, immutable selection
changes, malformed receipts, cancellation, postcondition drift and repeat read-only
reconciliation. Darwin cross-compilation establishes only compilation. Tests do
not invoke launchctl, dscl, collectors, network enrollment, native host preflight,
accounts, keys, permissions or service installation.
