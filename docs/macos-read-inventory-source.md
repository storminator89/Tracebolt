# macOS read-inventory source candidate

This is inactive source in `internal/macosinventory`. It has no CLI, enrollment,
service, sender, manager, UI, storage or AI integration. The existing basic macOS
sample and all Linux/Windows grants and bytes are unchanged. Windows preview.3
is unaffected. Fixtures and Darwin crosscompiles are not native acceptance and
never authorize a host read, installation, credential, grant or launchd change.

## Fresh scope and integration contract

`macos-read-inventory-v1` is a new, default-off combined local scope. Its own
`tracebolt.macos-read-inventory-consent.v1` consent binds an enabled decision to a
64-character lowercase-hex sender binding and independent 32-character grant ID.
No basic, Linux or Windows consent is accepted. `Privacy` and `HTTPPrivacy` carry
the complete scope and plaintext risk disclosure for a future fresh profile.

- `CollectWithSources(context.Context, Request, Sources)` is the synthetic-test
  and integration seam. Consent and request validation happen before any source.
  A Network adapter returning no aggregate error must account for each family
  independently, including deadlines. Valid completed-family results survive a
  later family timeout; caller cancellation still returns no snapshot.
- `CollectNative(context.Context, Request)` selects fixed macOS sources only on
  Darwin. Other builds return explicit unavailable/unsupported source results.
- `Snapshot` carries schema/scope, grant ID, generation ID and original UTC capture
  time, with independently sourced hardware, receipts, processes, IPv4 and IPv6.
- `Encode`, `Decode`, `Validate` and `ValidateBinding` reject unknown fields,
  duplicate/noncanonical JSON, extra documents, mismatched bindings, invalid
  availability combinations and over-budget results. No captured text becomes an
  error reason; reasons are a closed vocabulary.

The library does not establish that a passed-in consent is authentic. A future
integrator must independently load and check a freshly acknowledged, protected
identity-bound macOS profile and current authority before and after collection.
It also needs durable generation floors, exact retry bytes, original capture age,
private operator-only transport/retention/session guards and explicit supported
frame/paging budgets. `Snapshot` permits up to 512 KiB; it must not be inserted
into an existing smaller telemetry envelope or silently truncated to fit one.
The package must not be connected to `collector.Snapshot()` or auto-enabled by a
manager upgrade. Native acceptance is a separate authorized exact-artifact gate.

## Sources and interpretation

### Hardware

One fixed `/usr/sbin/sysctl -n hw.model hw.physicalcpu hw.logicalcpu hw.memsize`
read returns model identifier, physical/logical CPU counts and RAM capacity.
Four exact bounded fields are required; invalid/missing data makes this source
unavailable. Capacity is not used-memory percentage, pressure, CPU utilization,
processor marketing name, battery health or machine-serial identity.

### Installation receipts

One fixed `/usr/sbin/pkgutil --pkgs-plist` read returns Installer receipt IDs on
the default root volume. The parser accepts a plist containing one string array,
with no nested objects, unknown fields or external entity resolution. Duplicate
and malformed IDs fail the entire source. An observed empty array means no IDs
were returned by that receipt source.

These are installation receipts, not a complete installed-software inventory.
Receipts may outlive removed files; portable apps, App Store apps and Homebrew
formulae/casks need independent source coverage. No filesystem scan, receipt
file list, application paths, versions inferred from IDs, Homebrew execution,
package catalogue, update check or network call is performed. Future public
Homebrew metadata reuse should remain separate from local installed evidence.

### Processes

One fixed `/bin/ps -A -o ucomm=,pid=,ppid=` read returns caller-visible PIDs,
parent PIDs and kernel accounting names. Apple's `ucomm` reads `p_comm` directly;
`comm`/`command` are deliberately excluded because their code accesses process
argument space. The fixed 16-byte first column makes embedded newline names fail
closed rather than forge rows. Invalid, non-ASCII, path-like or empty labels are
blank with explicit name-unavailable quality. Invalid UTF-8 confined to the
fixed-width name field, including a truncated multibyte sequence, does not erase
valid PID rows. Names can be truncated and are
untrusted labels, not executable identity or a complete process inventory claim.

PIDs are snapshot-only; there is no creation-time association or cross-snapshot
join. CPU/RSS/state are omitted because this text path does not reliably expose
per-field provider denial. No owners, arguments, environment, paths, task access,
process controls or security/health inference are authorized.

### Passive interface context

Two independent fixed commands, `/sbin/ifconfig -a inet` and
`/sbin/ifconfig -a inet6`, project local interface name, MTU, UP/RUNNING flag bits,
numeric local addresses and prefix lengths. Families remain separate snapshots;
rows are not merged into a claim of atomic cross-family topology. IPv6 zone
suffixes must match the containing interface and are omitted from address text.
Unselected indented command metadata is discarded, never returned or logged.
Well-formed opposite-family addresses, including the CLAT46 IPv6 line that Apple
prints even for `-a inet`, are validated and discarded. They neither enter the
selected-family result nor establish an opposite-family observation or an atomic
complete-network claim.
Malformed selected records, duplicate rows/addresses, noncontiguous IPv4 masks,
hostnames, unknown top-level records and IPv4-mapped IPv6 addresses fail closed.

Up/running flags are local OS state, not Internet reachability. Interfaces without
addresses are valid. There is no DNS lookup, connectivity probe, socket/route
inventory, traffic payload, MAC/Wi-Fi name retention, rate or health inference.

## Bounds and failure semantics

- Native collection uses fixed absolute executables/arguments, no shell, no caller
  paths, no inherited environment, no stdin and no persistent files.
- Each native command has a one-second context deadline and 200 ms pipe-wait
  bound. A started owned child is killed on cancellation/overflow and waited.
  The bound does not claim control over OS-service work internal to a utility.
- Combined stdout/stderr is capped at 4 KiB for hardware and 256 KiB for each
  other command. Stderr is counted but never retained. Nonempty stderr, nonzero
  exit, malformed output and cutoffs never become successful partial results.
- Provider adapters get a two-second context; the collection budget is eight
  seconds. Injected source functions are trusted adapters and must cooperate with
  cancellation; there is no unbounded background goroutine escape hatch.
- Maximums: 4,096 processes, 2,048 receipt IDs, 128 interfaces per address family,
  16 addresses per interface, 4 KiB per source line, 512 KiB encoded snapshot.
  Bounds fail the affected source or final snapshot, never promote a prefix.
- Failed sources contain no rows or measurement fields. Successful siblings stay
  useful. Caller cancellation returns no snapshot. Fixed safe reasons distinguish
  denial, unsupported platform, malformed data, bounds and budget exhaustion.

## Verification and remaining native gate

Synthetic tests cover exact consent/binding/default-off admission, strict wire
round trips, malformed/duplicate metadata, bounds without prefixes, XML entity
and newline row injection, process-name suppression, numeric address/prefix
validation, source-failure isolation, raw-error exclusion, exact command allowlist
and concurrent stdout/stderr output bounds. Parser fuzzing uses synthetic input.
No test invokes native OS reads. Darwin arm64/amd64 builds establish compilation
only. Native macOS utility output, permission behavior and practical coverage
remain unverified. There is no release or installed-service claim.

Apple source references:
- [ps keyword definitions](https://github.com/apple-oss-distributions/adv_cmds/blob/main/ps/keyword.c)
- [ps field rendering](https://github.com/apple-oss-distributions/adv_cmds/blob/main/ps/print.c)
- [ifconfig manual](https://github.com/apple-oss-distributions/network_cmds/blob/main/ifconfig.tproj/ifconfig.8)
- [sysctl utility](https://github.com/apple-oss-distributions/system_cmds/tree/main/sysctl)
