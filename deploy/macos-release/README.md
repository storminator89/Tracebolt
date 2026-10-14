# macOS foreground review bytes (source-only)

`build-foreground-candidate.py` prepares four **publisher-unsigned**, non-installable
Darwin binaries and an exact Git source archive for offline review. It cannot
publish a release, install a service, enroll a device, execute a Mac binary,
create signing credentials or obtain native acceptance. The asset set contains
only `enroll-agent` and `macos-agent` for amd64 and arm64;
`macos-agent-service` is deliberately excluded from the foreground-only asset
set. The separate service test package below has its own lifecycle source and
native gates. This is not a verified download or end-user installation path.

From a clean exact Git checkout, with the version from `go.mod` already on PATH
and all locked modules already in its cache:

```sh
python3 -I -B deploy/macos-release/build-foreground-candidate.py \
  --version v0.0.0-macos-candidate.1 \
  --source-commit FULL_40_CHARACTER_REVIEWED_COMMIT \
  --output /absolute/new/directory/outside/the/checkout
```

The build refuses a mismatched HEAD/tree, staged or unstaged changes, visible
untracked files, unusual index flags, linked tracked inputs, a
linked/noncanonical/existing output path, unexpected Go version or missing cached
modules. Existing output-parent directory identities are also checked against
the source checkout, including case-variant aliases; native case-insensitive
APFS behavior remains untested. It does not fetch an alternative toolchain or modules. It compiles from
a bounded, link-rejecting extraction of `git archive` for the exact reviewed
commit. Ignored or globally excluded files in the ambient checkout cannot enter
that compile tree. Every build is bounded by repeated point-in-time source lease
checks; the manifest and source archive, rather than embedded VCS build fields,
bind the committed source identity.

This preparation trusts the selected Git, Go and Python executables and the
verified Go module cache. Use a quiescent checkout and output parent controlled
by the builder's user. Path `lstat`/inode checks and later path operations do
**not** provide descriptor-held, adversarial same-user filesystem-race defense,
atomic custody or detection of a change that is restored between checks. This
is a source-review artifact builder, not a privileged installer.

Each role/target is built twice with cgo disabled, fixed architecture baselines,
trimmed paths, read-only modules and embedded VCS metadata disabled in the
extracted source. It checks identical bytes, the thin Mach-O CPU/executable
header, Go role/OS/architecture metadata,
bounded regular files and final hashes. The canonical closed
`build-manifest.json` binds the exact commit/tree, Go version, build flags and
five assets. Its status fields explicitly remain false for native acceptance,
installability, signing and publication. Outputs are owner-only private files.
The output folder is new and mode 0700. A failed build can leave a partial
folder for inspection; the tool never adopts, overwrites or repairs it.

Go's Darwin/arm64 linker can insert an **ad-hoc** `LC_CODE_SIGNATURE` even
without a Developer ID identity. An arm64 Go 1.27.1 cross-build from this source
showed that load command. `publisherSigned: false` means no verified publisher
signature was applied by this builder; it does not assert that the Mach-O has
no code-signature load command. The builder does not inspect signature validity.

Hash equality establishes byte identity for the selected inputs. It is not
publisher authentication, Developer ID signing/notarization, target execution,
reproducibility across build hosts or supported-Mac acceptance. Review
[macOS release readiness](../../docs/macos-release-readiness.md) before any
separately approved native or public-release work.

Inert tests (fake Git/compiler and synthetic Mach-O bytes, no target execution):

```sh
python3 -I -B -m unittest discover -s tests/release \
  -p 'test_macos_foreground_candidate.py' -v
```

## Separate service test-package source

`build-service-test-package.py` prepares deterministic **publisher-unsigned**
Apple Silicon and Intel test archives from a clean, exact reviewed Git commit.
Each has native `enroll-agent`, `macos-agent`, `macos-agent-service` and a Go
`macos-package-prepare` entry, plus the exact source tar and a test runbook.
A matching standalone Go helper is emitted beside each archive so package
verification does not require extracting an untrusted tarball first. This
does not modify or relax the independently cleared foreground builder above.

The service builder reuses the foreground builder's clean/index/path and
Git-archive extraction defenses, Go 1.27.1 offline inputs, double-build byte
comparison and thin Mach-O/Go role checks. It additionally compares two
assembled archives byte-for-byte. The developer build needs Python; the Mac
package entry is a cross-compiled Go binary and needs no Python, Homebrew or
Xcode at runtime. No executable is run on the build host. Nothing is signed,
notarized, enrolled, installed, dispatched or published by this builder.

```sh
python3 -I -B deploy/macos-release/build-service-test-package.py \
  --version v0.0.0-macos-candidate.1 \
  --source-commit FULL_40_CHARACTER_REVIEWED_COMMIT \
  --output /absolute/new/directory/outside/the/checkout
```

Source/fixture validation, with no host, Directory Service, launchctl, network
or provider action:

```sh
python3 -I -B -m unittest discover -s tests/release \
  -p 'test_macos_service_test_package.py' -v
go test ./deploy/macos-release/prepare
```

For exact target selection, public-bootstrap custody, root-only staging,
hidden-terminal enrollment, service install/uninstall, owned rollback and the
remaining native gates, read the packaged
[macOS test runbook](../../docs/macos-test-package.md). The unsigned manifest
is byte identity, not publisher trust or native acceptance. An ad-hoc arm64
Go signature load command is not Developer ID signing. Never bypass Gatekeeper
or treat a source fixture as a completed installation.
