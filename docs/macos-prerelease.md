# Unsigned macOS service-test prerelease

This release distributes exact, source-built `darwin/arm64` and `darwin/amd64`
**test candidates**. It provides the full per-architecture `service-test-package.tar.gz`
and matching standalone `macos-package-prepare` helper as direct download assets,
plus `build-manifest.json` and `release-manifest.json`. No split chat transfer is
needed. The release manifest binds the exact source commit/tree, publisher run,
seven exact source-push CI runs and SHA-256/size of every other public asset. The source builder
checks repeated binary and archive builds. These are unsigned publisher bytes,
not Developer ID signatures or notarization. A SHA-256 value verifies selected
bytes only after the release/source is independently trusted.

The package's `TESTING.md` is an exact copy of the reviewed source runbook. Its
source-candidate wording predates the separate public prerelease action. Follow
its custody, hash comparison, enrollment and service review instructions, and
independently verify the complete helper/archive hashes before running anything.
The public download changes no Mac host or manager state. Native enrollment,
account preparation, launchd installation and monitoring still require distinct
local approvals on a disposable test Mac. No native acceptance, reboot
persistence, production readiness, Developer ID trust or notarization is claimed.
Never bypass a Gatekeeper or security warning to use this unsigned candidate.
The full archive and matching helper must be selected for the Mac's actual
architecture. Do not use a package intended for the other architecture.

The manual publisher is default-off. A reviewed exact source commit/tree,
independent publisher commit on the current main branch, seven successful
exact-source push run IDs from main, a fresh
`vMAJOR.MINOR.PATCH-macos-preview.N` version and an explicit `publish` choice
are required. Enter the run IDs as a comma-separated list, in this order:
Windows service source, Windows restart source, macOS source, Focused, Windows
Setup build, Windows prerequisites, Windows readonly. Read-only verification uses only read
permissions; the separate write job independently rebuilds the same package.
The release is a prerelease and explicitly not latest. Existing tags, drafts,
releases and assets are never adopted or replaced. A failed publication can
leave a partial tag or draft for inspection; do not retry it as though it were
fresh.
