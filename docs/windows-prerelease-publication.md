# Manual promotion of exact accepted Windows Setup bytes

This is a separate unsigned x64 prerelease publication candidate. It adds no
installer/service changes. It neither grants native execution nor proves that a
native run or public release exists. Source fixtures are not publication approval.
Independently review the exact v2 publisher source and its required accepted
evidence before dispatch.
The earlier [`windows-setup-release.md`](windows-setup-release.md) contract still
applies. Signing and ARM64 runtime acceptance require separate reviewed work.

## Required review and inputs

Independently review this publisher, workflow, fixtures and both attached guides
before dispatch. The selected publisher branch must remain at the reviewed exact
publisher SHA throughout verification/publication. No new credentials, OIDC,
signing, repository administration or immutability-setting changes are involved.

The manual `windows-prerelease.yml` workflow has five inputs:

- `expected_source_sha`: the exact native-tested Setup commit. Its Git tree must
  be the frozen reviewed `93001dc899c69f4590c3477dcd2e8b29899274ce`.
- `acceptance_run_id`: one explicitly selected successful first-attempt owner-
  dispatched `windows-setup-acceptance.yml` run on `refs/heads/main` at that source.
  All four distinct packaged GUI case jobs and the accepted-package aggregation
  must have passed under their own source-specific native approval.
- `version`: a fresh `vMAJOR.MINOR.PATCH-windows-preview.N` tag. Existing tags,
  drafts or releases cannot be reused, even if their bytes appear identical.
- `expected_publisher_sha`: the full reviewed later publisher commit. It must
  equal the dispatched workflow and checkout commit and the live branch lease.
- `publish`: defaults to `false`. Only an explicitly approved `true` dispatch
  permits creation/publication of the fresh tag and release.

Use the existing repository owner's manual workflow controls. The workflow must
be available for manual dispatch in GitHub; publishing or merging its source is
separate from authorizing its `publish=true` operation. Do not replace the accepted
source input with the later publisher SHA. Never select a run by “latest.”

The seven-day retained accepted artifacts and three-day original case artifacts
must still be available. This pipeline deliberately requires all seven exact
run artifacts; if any has expired or was removed, stop. A source rebuild cannot
replace accepted bytes, and a repeated native attempt cannot be relabeled attempt
one. Any new native acceptance run needs its own scope/approval.

## Read-only first, then explicit publication

The read-only job uses `contents: read` and `actions: read`. It resolves exactly
one of each fixed artifact name *inside the explicit accepted run* through the
GitHub API. The publisher independently authenticates the current run, attempt-one
record, repository/owner IDs, dispatching and triggering actors, exact workflow
path/ID, source commit/tree, `main` branch, completed success and first attempt.
It checks all five job IDs/statuses, the four case jobs' exact native/report/package
step names, order and conclusions, and the expected `windows-2025` labels (with
`ubuntu-24.04` for aggregation). The four case jobs must have distinct positive job
IDs and distinct positive runner registration IDs.

Name resolution is never a repository-wide search and is never enough by itself:
every resolved immutable artifact ID is re-read through its API route and bound
to that source/run, explicit `main` head branch and archive digest. Missing branch
metadata or any other branch is rejected. REST `head_branch` corroborates the
name `main`, not whether it was a branch or a tag. The exact `refs/heads/main`
binding also relies on the reviewed native aggregate's runtime full-ref guard and
the publisher's exact source/workflow pins. The separate publisher branch is
allowed only at its reviewed SHA and unchanged live lease.

The verifier downloads only those IDs, checks the API archive SHA-256 and size,
and reads only a bounded exact ZIP allowlist into memory. It rejects duplicates,
paths, directory/link/special files, extra members and missing/expired artifacts.
No executable is loaded or run. The original six files are validated using the
same strict package contract: canonical manifests/checksums, actual x64 PE
resources, unsigned status, source/run binding, and exact embedded service and
package-manifest bytes. The accepted public package must equal the TLS-tested
input package byte for byte. Four strict canonical
`tracebolt.windows-setup-acceptance.v2` reports must agree on source/run and
Setup/service/driver/source-input hashes. Their bounded `frameProgress` fields
record inventory/extension readiness and finite telemetry outcomes, without raw
observations. Both install/removal cases must have complete progress and at least
two accepted v5 frames; the two cancellation cases retain zero/not-started progress.
The original raw report bytes must equal their canonical encoding and the members
of their independently downloaded report ZIPs; their SHA-256 hashes must match
the recorded report hashes. The parsed reports must exactly match the separately
retained canonical
`tracebolt.windows-setup-native-subset.v2` aggregate, with all unproven coverage
flags still false.

The aggregate's `executionProvenance` binds the four case jobs and runner
registrations, exact report artifact IDs/archive hashes/report hashes, and the TLS
input package. The publisher checks that structure and independently authenticates
it against live GitHub records and exact downloaded ZIP members. Pure JSON/schema
validation is not authentication. GitHub's artifact REST records have no uploader-
job field: case-to-artifact attribution relies on the reviewed one-case-one-upload
workflow. Fresh isolation relies on GitHub's standard hosted Windows fresh-VM-per-
job contract together with the native hosted-environment and fresh-state checks.
Hostnames may be shared across those jobs. Neither a hostname nor a runner
registration ID is VM/hardware attestation; `vmIdentityAttested` remains false.

Only a small canonical `tracebolt.windows-prerelease-plan.v2` verification plan
crosses job boundaries as bounded job outputs. It freezes seven immutable
IDs/archive digests, all five native workflow job IDs, the four case runner
registration IDs, workflow ID, source/publisher leases and all ten eventual
release-asset hashes. Runner group IDs are bound through `executionProvenance`
in the hashed aggregate and release-manifest assets.
Users do not need to copy seven artifact IDs manually. The write job re-downloads
and independently re-verifies those exact IDs/bytes, regenerates only the new
binding manifest, and requires the complete plan to match. No downloaded code is
executed and no artifact-supplied script or instruction is trusted.

Live `setup_job_provenance.verify_run` verification supplies the stored
`expected_provenance`, `require_aggregate_success=True` and
`expected_ref="refs/heads/main"`. It runs during read-only verification, write-job
preparation, immediately before the first write, before the publish PATCH, and
during final readback. After the expensive proof downloads, compact checks of the
source/publisher leases, native run/jobs and all seven artifact records close that
check window before proceeding. Compact checks re-read the current and attempt-one
records and workflow identity, and repeat the required job step names/order/conclusions and compare runner registration/group IDs to the stored
proof. A stored plan never substitutes for live checks.

The second job exists only for `publish=true` after verification succeeds. It uses
the existing `GITHUB_TOKEN` with `contents: write` and `actions: read`. Neither job
has OIDC or a signing key. It checks freshness against the tag API, release-by-tag
and a bounded authenticated release inventory, including drafts. Then it:

1. Creates one fresh lightweight tag pointing to the **accepted Setup source**.
2. Creates a fresh empty draft prerelease with `make_latest: false`.
3. Uploads exactly ten allowlisted files once and checks each returned asset ID,
   name, size, SHA-256 and URL. It reads the entire asset inventory back.
4. Reauthenticates execution provenance and rechecks the source/publisher lease,
   native run/all seven artifact identities, tag and draft state, then publishes
   once with `make_latest: false`.
5. Reads the release by ID and tag, checks all asset IDs again, and independently
   downloads every public asset without credentials to verify its final bytes.
   Final readback also reauthenticates execution provenance and repeats the
   compact lease/native/artifact checks.

The six original files and finite evidence are unchanged. The two reviewed
Markdown guide/changelog files are copied from the exact publisher checkout.
`release-manifest.json` uses `tracebolt.windows-prerelease.v2`: this separately
generated manifest binds nine payload files to the chosen release version,
accepted source/tree/run and publisher SHA/run, including immutable artifact IDs,
API archive hashes and the independently verified `executionProvenance`. It does
not hash itself. The original `SHA256SUMS` still covers only the original other
five package files.

The public release may therefore have a newer version tag while the executable
names/resources still say `v0.0.0-setup-candidate`. This is deliberate evidence
preservation. Rebuilding, signing, renaming or rewriting any tested file would
need a different native artifact acceptance, not a metadata shortcut. The
original build manifest's `nativeExecution: false` describes the builder; the
separate native evidence describes the later packaged-GUI subset.

## Failure and trust boundaries

Each mutation is attempted once. There is no delete, overwrite, force-tag,
automatic write retry or adoption of an existing/partial release. A lost response,
changed lease, mismatched asset or unavailable public download stops the run.
It may leave a tag, draft, or already-published release. Inspect it without
mutating it; do not rerun publication to “repair” or adopt the same version.
Further cleanup or a fresh version is a separate deliberate decision. A failed
final public read does not prove that the release was unpublished. If GitHub
rejects tag creation for the older accepted source under the existing token,
stop; do not substitute the publisher SHA, add workflow/admin permissions or
create a different credential. Fixture checks cannot establish that live API
permission behavior in advance.

A successful job verifies a point-in-time state, not permanent future immutability.
The publisher's no-overwrite policy is **not GitHub platform immutability** and
it does not alter that setting. These hashes/API bindings are not a signed
attestation, Authenticode identity or guarantee that Windows trusts the file.
Only GitHub's official authenticated API and HTTPS/CDN routes are used; bearer
tokens never accompany archive/public-download redirects. Unexpected CDN or API
behavior fails closed instead of accepting an arbitrary host or ignoring a hash.

The accepted proof is limited to fresh hosted Windows 2025 x64 packaged-GUI cases.
It does not prove human UAC/invitation handling, a real Linux manager/shared
dashboard, genuine reboot, upgrade, ARM64 runtime or completion of platform VM
disposal. Do not publish raw logs, console buffers, private files, invitations,
keys or telemetry. Review the attached
[installation guide](windows-prerelease-install.md) and
[changelog](windows-prerelease-changelog.md) for user-facing boundaries.

## Inert validation

Run the fixture suite without network access or Windows execution:

```sh
python3 -I -B -m unittest discover -s tests/windows_release -v
python3 -I -B -m unittest discover -s tests/windows_native_acceptance -p test_setup_gui.py -v
python3 -I -B -m unittest discover -s tests/windows_native_acceptance -p test_setup_job_provenance.py -v
```

Fixtures inject synthetic public bytes and fake API responses. They do not
establish native acceptance, real GitHub API compatibility or public release
success. `--verify` and `--publish` reject a non-Actions or mismatched environment
before network use. Ordinary module import and tests have no API side effects.

API contracts: [workflow runs](https://docs.github.com/en/rest/actions/workflow-runs),
[attempt jobs](https://docs.github.com/en/rest/actions/workflow-jobs#list-jobs-for-a-workflow-run-attempt),
[standard hosted-runner isolation](https://docs.github.com/en/actions/concepts/runners/github-hosted-runners),
[artifact IDs/digests/downloads](https://docs.github.com/en/rest/actions/artifacts),
[releases](https://docs.github.com/en/rest/releases/releases), and
[release assets](https://docs.github.com/en/rest/releases/assets).
