# Bounded Linux operational collector

`internal/operational` is a read-only observation adapter for the separately
selected `managed-operations-v1` profile. It is not an installer, agent scheduler,
remediation mechanism, security assessment, or proof of an installed fleet.
Its only collection entry point is `Collect(context.Context, time.Time) Snapshot`.
`Empty` creates explicit unavailable sections and `Validate` checks the typed
wire contract. Six pure `Validate*Section` functions validate independently retained sections
against their original generation/time without requiring a common snapshot or
generating new labels. Unknown/duplicate JSON keys must additionally be rejected by the
transport decoder. Non-Linux builds return `not_supported`.

## Bounds and provenance

Every section carries its own generation ID and trusted window-start timestamp.
A fresh raw snapshot requires all section generations/timestamps to match the
snapshot. Retained views must preserve these original values. A generation label
is random observation metadata, not a credential or endpoint identity.

There is exactly one in-flight collection per process. A caller waiting for that
slot can cancel; the active collector checks its context between local reads.
A ten-second cooperative context bounds subsequent work and each fixed command
has a two-second timeout plus 200ms pipe-wait bound. An in-progress kernel read
or filesystem syscall cannot be forcibly cancelled by Go. Duration is measured
and may exceed the requested deadline; there are no abandoned workers or an
accumulation of background collection goroutines. The sender must recheck its
own deadline before staging or sending the result.

The encoded snapshot is limited to 48KiB. Item caps are volumes 32, interfaces
32, services 128, processes 64, installed dpkg packages 256 and event groups 64.
Truncation preserves observed counts and explicitly marks incomplete coverage.
Failed services and higher-RSS processes are sorted ahead of lower-priority
records. Byte trimming removes software first, ordinary services and lower
severity events next, then lowest-RSS processes, interfaces and volumes before
severe events/failed services. Nothing silently becomes a complete empty list.
Counts cover eligible records discovered within bounded source enumeration;
`countExact=false` means the count is a lower bound or coverage is unknown.
Event `observedCount` counts source records, while each item aggregates matching
unit/priority/message-ID events and carries its own count. A complete event
section can therefore have fewer items than observed source records.

## Sources and deliberate gaps

- **Volumes:** at most 2MiB / 4,096 mountinfo records. Discovery uses
  `/proc/self/mountinfo`; source devices, mount options, UUIDs and serials are not
  retained. `/home/<name>` and `/run/user/<id>` prefixes are redacted.
  Local measurement allows only ext2/3/4, xfs, btrfs, f2fs, jfs, reiserfs, vfat,
  exfat, ntfs3, zfs, bcachefs, erofs and squashfs. Remote, FUSE, virtual and unknown
  filesystems remain explicitly unmeasured. Remote/FUSE/automount ancestors are
  rejected before opening a local mount. An O_PATH descriptor pins the target;
  its kernel mount ID must match the discovered local record, then a fresh
  mountinfo read must confirm that pinned ID/path/local type before Fstatfs.
  Incomplete initial mount enumeration disables measurement.
  Replaced mounts/final symlinks fail closed. Measurement errors remain per-item
  unknown/denied; missing sizes and percentages are null.
- **Network:** `/proc/net/dev` is capped at 256KiB / 1,024 interface rows;
  only counters, fixed interface-name-derived sysfs MTU and operational state are
  collected. Address counts are deliberately null with `not_implemented`
  incomplete coverage. There is no address enumeration, IP/MAC/SSID/route export,
  network socket, reachability test or active probe.
- **Processes:** at most 8,192 procfs directory entries and 4,096 numeric PIDs;
  only the fixed `/proc/<pid>/stat` metadata file (16KiB each) is read. Process
  names, parent PIDs, state, RSS, CPU time and thread count are selected. No
  cmdline, environment, executable/CWD link, account IDs or user files are read.
  CPU conversion is currently supported on Linux amd64/arm64 (USER_HZ=100);
  other architectures return unsupported for this section.
- **Software:** only the fixed regular `/var/lib/dpkg/status` database, capped
  at 32MiB with the existing assessment parser's line/record/field limits. Only
  installed records and name/version/architecture/manager survive. The result
  is a deterministic bounded dpkg package sample, not an all-software inventory
  or an update/vulnerability assessment. Missing database means unknown, not
  zero installed software.
- **Services:** fixed `/usr/bin/systemctl --system --no-pager --no-ask-password
  --all --property=Id,LoadState,ActiveState,SubState show *.service`, with no shell
  expansion. This covers matching system-manager-loaded service units; it does
  not enumerate all disabled unit files or user-manager services. At most 1MiB
  of command output / 4,096 parsed records are admitted. Descriptions and Exec
  properties are never requested.
- **Events:** fixed `/usr/bin/journalctl` commands. The first uses `--system
  --no-pager --disk-usage` to expose missing/partial journal-access diagnostics
  without reading message bodies into output. The actual query selects JSON
  fields `__REALTIME_TIMESTAMP,_SYSTEMD_UNIT,PRIORITY,MESSAGE_ID`, a fixed window
  of at most fifteen minutes ending at the caller's trusted start time, reverse
  order, and 2,049 records (one lookahead). At most 2,048 source records / 1MiB
  are parsed, then grouped and sorted by severity and recency. MESSAGE text is
  never selected. Mandatory cursor, boot and sequence identities are discarded.
  Unrecognized fields, duplicate keys, binary/array field values, invalid
  identifiers and out-of-window timestamps are rejected, not copied into errors.
  Journal coverage always remains incomplete with `countExact=false`: even the
  metadata access preflight can suppress partial-access notices for root or
  journal-group/ACL members. A successful query is a sample of visible records in
  the default system journal namespace, never proof that every system journal
  was readable. `not_supported` denotes this unverifiable full coverage (unless
  a more specific parse/limit/denial reason applies). No returned records means
  unknown, not a successful empty system event list. Permissions/rotation can
  also change between queries. No group membership, ACL or privilege changes
  are attempted.

Both commands require root-owned regular executables and root-owned, non-group/
world-writable ancestors at the fixed paths. Symlinks fail closed. The environment
is replaced with fixed locale, pager/color and home settings; ambient PATH,
D-Bus addresses, pager programs and preload variables are not inherited. Stdout
is capped at 1MiB and stderr at 4KiB. Diagnostics are mapped to fixed reasons and
never exported. No fallback PATH search, shell, install or elevated execution is
provided. Missing systemd and rejected binaries are honestly unavailable.

These exclusions reduce collection scope, but the retained process/package/unit
names and mount labels may themselves contain personal or secret-like text.
Prefix redaction does not guarantee anonymity or secret removal. Treat snapshots
as private operational metadata and use the authenticated profile boundaries.

## Primary source verification

The upstream systemd v257 sources were checked on 2026-10-03:

- [journalctl output-fields documentation](https://github.com/systemd/systemd/blob/v257/man/journalctl.xml): selected JSON fields exclude MESSAGE; certain internal metadata is always printed.
- [JSON output implementation](https://github.com/systemd/systemd/blob/v257/src/shared/logs-show.c): `update_json_data_split` filters fields before JSON values are emitted; `output_json` adds cursor/time/boot/sequence metadata, which this adapter discards.
- [journalctl argument handling](https://github.com/systemd/systemd/blob/v257/src/journal/journalctl.c): JSON output implicitly enables quiet mode.
- [journal access checking](https://github.com/systemd/systemd/blob/v257/src/shared/journal-util.c): quiet mode can suppress partial-access and no-file notices, which is why the metadata-only access preflight is useful. The same source shows
  that privileged/group members can still have undetected partial access, so this
  collector never marks the journal sample complete.
- [systemctl show documentation](https://github.com/systemd/systemd/blob/v257/man/systemctl.xml): patterns select units and `--property` limits output to the four selected properties.

Older or incompatible tools that reject the fixed options remain unavailable;
there is no fallback to a raw-log format.

## Verification scope

Run with the repository's official Go1.27.1 toolchain:

```
go test -count=1 ./internal/operational
go test -race -count=1 ./internal/operational
go vet ./internal/operational
```

The package tests include pure/inert fixtures and one explicitly read-only Linux
host smoke test. The smoke prints only encoded byte size and quality labels,
never inventory records. This cloud host has no systemd and no dpkg status file:
services/events and installed software are therefore unavailable here. Fixture
success and Windows/macOS/arm64 cross-compilation do not establish native systemd,
nonprivileged journal permissions, Debian package-database runtime or deployment
acceptance. Those require a separately authorized host matrix.
