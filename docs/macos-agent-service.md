# macOS launchd source candidate

Status: deterministic plist generation and read-only preflight source only.
There is no installer, launchctl adapter, restart, upgrade or uninstall operation.
Nothing here establishes a native installed service, reporting or boot persistence.
Linux/systemd and Windows release behavior is unchanged.

## Exact boundary

`cmd/macos-agent-service` emits a JSON review result with a complete XML plist and
its SHA-256. The default performs local read-only checks. `--render-only` emits
an explicitly unchecked candidate without reading host accounts, files or state.
`--apply`, `--action`, configuration overrides, invitations and shell commands are
not accepted. The program never executes an artifact or `launchctl`. Native preflight only
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
- An existing activated basic guided-v2 or explicitly renewable-v6 TLS enrollment at
  `/Library/Application Support/TraceboltAgent/state/enrollment/agent.json`,
  with `agent-key.pem`, `agent-cert.pem`, `server-ca.pem`, `ready.json` and its
  original bound sender ledger in that enrollment directory. Enrollment must
  have been performed as the same selected nonroot identity after its separate
  key/trust approval. Pending, manual-v1, HTTP, expanded scopes and implicit
  renewal adoption are rejected.
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
30-second foreground interval, the `_traceboltagent` user/group, numeric runtime
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

## Next implementation and native gate

A future create-only installer needs reviewed native service-collision detection,
protected publication and durable ownership/recovery receipts before any
registration. Plist absence does not prove the launchd system domain has no
foreign or retained job. Those checks are deliberately listed as remaining gates
rather than inferred from a successful file preflight.

After exact host/account/artifact/path/service approval, a separate disposable
Mac gate must verify native account mapping, ACL/descriptor behavior, launchd
credential isolation and supplementary groups, rejected mismatched identity,
foreground stop/SIGTERM drain, current TLS activation and fresh real manager
reports. It must independently cover actual reboot persistence, failure behavior
and owned removal retaining all identity/counter state. Source fixture tests and
Darwin cross-compilation do not satisfy any of these runtime gates.

Implementation references: Apple's
[launchd property-list manual](https://github.com/apple-oss-distributions/launchd/blob/main/man/launchd.plist.5), [dscl read command](https://github.com/apple-oss-distributions/DSTools/blob/main/dscl/dscl.1)
and [Creating Launch Daemons and Agents](https://developer.apple.com/library/archive/documentation/MacOSX/Conceptual/BPSystemStartup/Chapters/CreatingLaunchdJobs.html).
These describe the plist contract; the selected macOS release still requires its
own separately approved native acceptance.

Explicit renewable basic TLS uses `tracebolt.lan-agent.v6`, collection profile
`basic-readonly-v1` and the exact enrollment-directory `renewal-manifest.json`.
The existing guided-handoff validator checks the original ready binding and the
current same-key certificate manifest; this preflight never grants or starts
renewal. A broader profile, alternate manifest path or HTTP mode is rejected.
