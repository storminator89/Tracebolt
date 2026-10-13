# Hosted macOS fixture checks

This workflow executes a reviewed subset of the published macOS source on native
GitHub-hosted Macs. A passing result establishes only the selected fixtures on
the recorded runner image and source revision. It does **not** establish actual
agent acceptance, enrollment, installation, release readiness or user-host safety.
The separate `macos-source.yml` cross-build/UI checks are unchanged.

## Runner and source identity

The standard `macos-15` runner is arm64; `macos-15-intel` is Intel/amd64. These
explicit labels avoid changes in the `macos-latest` alias. They do not freeze a
particular image patch version. The workflow verifies native Go/OS architecture
and the pinned Go version/macOS major version. It checks for a clean checkout
before and after execution and records the actual macOS version, image metadata, selected label, checkout
commit/tree, Go version and fixture-manifest SHA-256 in each result.

GitHub documents standard public-repository runners as free. The job is skipped
for private repositories to avoid consuming a potentially billable private
allotment. There are no larger runners, self-hosted machines or optional secrets.
See the [official runner reference](https://docs.github.com/en/actions/reference/runners/github-hosted-runners),
checked on 2026-10-13. Dependency setup uses this repository's pinned actions,
`go.mod` and `go.sum`, with no persistent dependency cache. Test execution disables
module-network access and automatic Go toolchain switching.

## Exact execution scope

`tests/macosfixtures/suite.json` is the explicit 20-test allowlist. The driver
checks that each named test exists, uses an anchored selection, disables cached
test results and requires every selected test and subtest to pass. Skipped or
missing tests cannot produce passing evidence. It does not run `go test ./...`,
benchmarks, fuzzing, CLI programs or other tests in these packages.

- `darwinprotect`: malformed security/volume metadata fixtures and a new
  temporary file's descriptor ACL checks and full-file flush. The existing
  native fixture invokes `/bin/chmod +a` only on that synthetic file to test
  deny-only acceptance and expanding-ACL rejection. Its cleanup removes only
  that file's test ACL with `/bin/chmod -N` before deleting the temporary tree.
- `macosinventory`: literal parser inputs and injected callbacks for hardware,
  receipt XML, process labels and numeric interfaces. The native provider
  implementation is compiled but never selected by these tests.
- `macosinventorystate`: fake in-memory committers, fabricated protocol values,
  missing-used-state rejection, consumed sequence/pacing, exact pending bytes,
  immutable original bindings and receipt validation. These include wire
  encode/decode behavior without running unrelated wire-package tests.
- `macosinventorysender`: new temporary directories and synthetic checkpoints
  for native exclusive locks, roundtrip/reopen, verified no-op, no-replace and
  replacement publication, inode/byte/mode/symlink/hardlink rejection, missing or
  unexpected entries and uncertain rename/panic behavior. The cross-process
  lock test invokes only its own test executable and passes only its temporary
  fixture path to the fixed child-test entrypoint.

The driver creates a private temporary root beneath canonical `RUNNER_TEMP` and
sets `TMPDIR` only for its child Go commands. Existing native tests resolve their
own `t.TempDir()` roots. Product no-follow checks, ACL policy and canonical path
requirements are unchanged. Native storage reads ancestor metadata only to
validate the chain to its own fixture directory. All file/ACL mutations are
confined to newly created task-owned fixtures, cleaned up at the end of the run.
Only result metadata is uploaded, never temporary state, generated test binaries
or captured provider data.

## Exclusions and remaining gates

No real `sysctl`, `pkgutil`, `ps`, `ifconfig` or `log` provider executes. No account
enumeration, enrollment listener/network exchange, persistent endpoint key or
grant, trust store, launchd, TCC, service command, installation or security setting
is involved. The only host-version command is `sw_vers -productVersion` for runner
evidence. Normal CI checkout, pinned toolchain/dependency acquisition and result
upload still use GitHub/module services; this is not an OS network sandbox.

The allowlist is a review boundary, not a security sandbox. Changes to selected
tests, helpers, package initialization, dependencies or the driver require a new
scope review. The structural initializer check is only an additional guard.

A successful `F_FULLFSYNC`, rename or lock fixture does not prove survival of
power loss/reboot, production filesystem suitability or all supported OS patch
versions. Inherited ACL acceptance/rejection, hidden terminal input, real TLS
identity approval/reporting, renewal/revocation, dedicated-account and launchd
lifecycle, reboot persistence and safe uninstall remain separate native gates
in [macOS status](macos-status.md). No product permissions are relaxed to make
these fixtures pass. A hosted failure must be diagnosed before claiming coverage.

For source-only selection validation, run
`python3 tests/macosfixtures/run.py --check`.
This does not invoke Go, native APIs or any test. Preparation of this
workflow alone provides no native run evidence.
