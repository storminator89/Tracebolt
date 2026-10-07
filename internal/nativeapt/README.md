# Native APT preparation candidate

This directory contains a real libapt preparation implementation and pure Go
contracts. It is **source-only, default-off, not native-accepted**. No APT, dpkg,
systemd, native helper, installation or host-privilege operation was run while
implementing or testing it. The native program is a separately built executable,
not cgo initialized by a Go test or manager process.

## Exact integration contract

The broker creates a new protected
`/var/lib/tracebolt/package-updates/update_<32 lowercase nonzero hex>/` directory,
then writes `selection.tsv` using `SelectionBytes` and `apt.conf` using
`ConfigBytes`. It invokes only `/usr/libexec/tracebolt-apt-prepare update_ID` with
the fixed environment. Files and directories must be owned by root and have no
group/other write bits; final data files cannot be symlinks or hardlinks. Every
ancestor is checked with `openat` and `O_NOFOLLOW`. Existing staging directories
or evidence files cause a create-only failure, never reuse or cache adoption.

The native program requires all of these locally provisioned, protected files:

- `/etc/tracebolt/package-actions/sources.sources`
- `/etc/tracebolt/package-actions/preferences` (may be empty)
- `/etc/tracebolt/package-actions/keyring.gpg`
- `/etc/tracebolt/package-actions/native-opt-in`

The opt-in file is exactly two LF-terminated lines. The first is
`tracebolt-reviewed-isolated-apt-config-debian13-amd64-v1`. The second is the
`sha256:`-prefixed `ConfigSnapshotDigest` of the excluded host configuration.
The digest covers existing `/etc/apt/apt.conf`, every immediate file in
`/etc/apt/apt.conf.d`, `/etc/dpkg/dpkg.cfg`, and every immediate file in
`/etc/dpkg/dpkg.cfg.d`. File names are relative to `/`, sorted, and include ignored
files as well. Symlinks, subdirectories, unexpected owners and writable modes
fail closed. This is explicit local approval of reviewed immutable isolated APT
configuration and the exact excluded host configuration, **not** silent hook
suppression. Changing any covered file blocks preparation and must also block
capture/start in the broker. Dpkg configuration remains effective when actual
dpkg runs and its reviewed snapshot is bound as well. Every non-comment dpkg
configuration line must be exactly `no-debsig` or `log /var/log/dpkg.log`. Any
other directive, including conffile/force/path/pre-invoke options, fails closed;
a matching snapshot hash does not allow it. Dpkg files are reviewed and pinned,
not excluded. `ValidateDPKGConfig` exposes the same check to the guard.

This marker alone is not an execution grant or proof of native acceptance. The
separate root policy, signed permit, durable mutation fence, consumed runner
admission, native acceptance setting and mandatory guard remain required.
Provisioning any of them is a separately authorized administrator operation.

The source file accepts bounded, explicit deb822 `deb` stanzas with one HTTPS
URI, one of `trixie`, `trixie-updates`, `trixie-security`, standard Debian
components and `Architectures: amd64`. Every stanza must have exactly `Types`,
`URIs`, `Suites`, `Components`, `Architectures`; unknown fields, continuation
lines, comments, source options, embedded keys and trust overrides fail closed.
The copied root-approved keyring is the sole APT keyring. Pin preferences are
copied without alteration and interpreted by libapt policy. No remote request
can choose a source, key, pin, option, environment variable, executable or path.

## Native evidence

The native program requires Debian 13, x86_64, APT library version exactly 3.0.3,
and an installed dpkg 1.22.x. This is a build/API compatibility constraint, not a
claim that every dpkg patch version has passed native acceptance. The production
root policy must pin separately tested tool artifacts before availability.

A create-only private source/key/pin snapshot, lists directory and archive cache
are used. `ListUpdate` requires `APT::Update::Error-Mode=any`, signature/hash
checks and valid-time checks; inherited configuration, hooks, proxies, keys and
lists are not loaded. The complete dependency cache is acquired with native
locks. Pending dpkg updates, pending triggers, error/partial states, broken
packages, held targets, architecture changes and non-upgrades fail closed.
Libapt marks the exact candidate versions and resolves the whole transaction;
any extra/new/remove/reinstall/downgrade/missing action is rejected. Architecture
`all` and non-amd64 version records are unsupported in this first slice.

For each target, exactly one eligible `Version.FileList` record is required.
`pkgRecords` provides the actual archive SHA-256, size and filename. The selected
package-file name is matched to `metaIndex.GetIndexTargets()`'s
`EXISTING_FILENAME`. The same `metaIndex.FindInCache(cache,false)` identifies the
signed InRelease file; the target `MetaKey` selects its SHA-256/size entry. The
private uncompressed Packages file must match that entry. Missing, compressed,
ambiguous or otherwise unsupported mapping fails closed. No filename guessing,
apt-list/apt-cache text parsing, per-source synthetic Release digest, or fake
hook configuration digest is used. Source display fields come from the matched
native metadata.

`pkgAcqArchive` downloads authenticated archives into the private cache. The
adapter verifies status, trust, exact bytes, bounded size, ownership and path.
Limits are 32 packages, 1 GiB/archive, 2 GiB/batch, 512 MiB/Packages file,
240-second acquisition windows, available staging space and conservative
installation-space checks. Native acceptance must verify these bounds and
acquisition behavior on the real tools.

The create-only `prepared.json` is exact canonical Go-compatible JSON in the
`Prepared` field order; `DecodePrepared` rejects other encodings. Its
`InventoryDigest` and `DpkgStateDigest` are both SHA-256 of the exact protected
`/var/lib/dpkg/status` bytes, rechecked under the native lock after downloads.
`HoldsDigest` hashes sorted held `name<TAB>architecture<LF>` rows, including an
empty list as the hash of zero bytes. All exposed hashes use `sha256:` prefixes.
The broker must validate protected file origin, current approved source/key/pin
snapshot, tool/policy bindings and timestamps, not accept this type over an API.

## Capture and execution

`BuildInvocation` supplies a single fixed apt-get invocation with exact
`name:amd64=version`, `--no-download`, `--only-upgrade`, `--no-remove` and one
mandatory v3 Pre-Install-Pkgs guard. The generated config is shared between Go
and C++ through `config.template`. Capture and execution use byte-identical
executable/argv/environment/APT_CONFIG/config; only separately protected
out-of-band guard state selects capture versus approved execution. A simulation
or download-only run cannot produce this evidence. Capture must durably store
the actual v3 bytes and fail before dpkg, and the broker must establish that
failure came from the mandatory guard before exposing a plan.

`FinalizeCapture` derives `ConfigDigest` exclusively from the supplied actual
hook stream and runs `packageplan.Match` against trusted actual archive
observations. It does not authenticate those observations, authorize execution,
or replace the broker/fence. The entire raw ordered configuration block remains
bound. The configuration uses only `--force-confold`; no `--force-confdef`
overrides the promise to preserve modified dpkg conffiles. Ucf and custom
maintainer scripts have separate behavior and can require intervention.

A native gate must still establish: first-and-only guard ordering and abort,
frontend/inner lock custody, clean state inside the execution fence, parent
identity, archive ownership and no replacement between guard hashing and dpkg
use, authentication and full refresh behavior, hooks, unknown/pending operations,
APT configure ordering, native cancellation/failure behavior, root policy
revalidation, durable consumption, and crash/reboot reconciliation. The hook is
not a sandbox: scripts/triggers may restart services and make broad changes.
There is no automatic reboot, rollback, repair, competing-manager termination or
lock-file deletion.

## Source and fixture checks

Go tests are pure builders and invented evidence comparisons:

    go test -race ./internal/nativeapt

Native compile/link only, on a machine with explicitly provided matching headers:

    python3 internal/nativeapt/native/embed_config.py /tmp/nativeapt-build/config.generated.hpp
    c++ -std=c++20 -O2 -Wall -Wextra -Werror \
      -I/path/to/apt-3.0.3-headers/usr/include -I/tmp/nativeapt-build \
      internal/nativeapt/native/prepare.cc /usr/lib/x86_64-linux-gnu/libapt-pkg.so.7.0 \
      -o /tmp/nativeapt-build/tracebolt-apt-prepare

Do not run the output as part of these checks. Headers were downloaded as data
from Debian's official `libapt-pkg-dev_3.0.3_amd64.deb` and extracted using ar/tar,
without package installation or maintainer scripts. That download's observed
SHA-256 is
`160c8b31304126b897cc145b95b74d9b660edfa990b805b048c857bf8143c62c`.
This observed checksum is reproducibility information, not independent package
signature verification.

Primary implementation references:

- https://raw.githubusercontent.com/Debian/apt/3.0.3/apt-pkg/metaindex.h
- https://raw.githubusercontent.com/Debian/apt/3.0.3/apt-pkg/acquire-item.h
- https://raw.githubusercontent.com/Debian/apt/3.0.3/apt-pkg/deb/debmetaindex.cc
- https://raw.githubusercontent.com/Debian/apt/3.0.3/apt-pkg/update.cc
- https://raw.githubusercontent.com/Debian/apt/3.0.3/apt-pkg/deb/dpkgpm.cc
- https://deb.debian.org/debian/pool/main/a/apt/libapt-pkg-dev_3.0.3_amd64.deb
