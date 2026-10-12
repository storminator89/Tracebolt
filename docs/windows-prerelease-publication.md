# Exact accepted Windows prerelease promotion

## Current21 adapter: source-only and disabled

The intended label is **unsigned Windows Server 2025 x64 current21 Read admin
preview; three-case packaged GUI subset**. This source preparation is not native
execution, release approval or a current native pass. The explicit
`publish-windows-current-prerelease.py` adapter has `ACCEPTED_SOURCE_TREE = None`.
It fails closed until a later independently reviewed source change pins the
actual tree from a separately approved successful current native run. Never pin
an untested checkout, substitute the publisher revision or take the pin from an
input/environment variable.

The historical `publish-windows-prerelease.py`, `run_setup_gui.py` and
`windows-prerelease.yml` retain their historical four-case contract and accepted
tree. The old publisher attaches the byte-preserved guides under
`docs/windows-prerelease-historical/`. Historical evidence cannot satisfy the
current adapter. Current guides are `windows-prerelease-install.md` and
`windows-prerelease-changelog.md`; their source-candidate wording is deliberate.

## Required native result and practical timing

Obtain separate exact-source native approval for
`windows-current-setup-acceptance.yml` and its nine unchecked inputs before any
host work. The accepted run must be owner-dispatched, attempt one, on main, with
the exact reviewed source SHA. Three fresh hosted Windows Server 2025 x64 cases
(install/remove, hidden-input cancellation, pending-transport interruption) and
the exact aggregation job must all succeed. Unavailable desktop access remains
a blocker. This publisher never dispatches a native workflow or builds/runs code.

The current gate retains six artifacts bound to that source/run:

- Three `windows-current-setup-gui-<case>-<sha>` original report archives
- `windows-current-setup-public-input-<sha>`, the exact six tested package files
- `windows-current-setup-native-subset-public-<sha>`, their unchanged accepted copy
- `windows-current-setup-native-subset-evidence-<sha>`, the canonical aggregate

**Original reports and the tested input package expire after 3 days; aggregate
outputs last 7 days.** Review actual results, prepare the later accepted-tree pin
and finish publication while every original is still available. Live artifact
metadata/availability is authoritative. The aggregate alone cannot replace
originals, even after a successful read-only verification. An expired/missing
original, same-named replacement or source rebuild must fail. A new native run
needs separate approval; a rerun cannot be relabeled attempt one.

## Manual current publication inputs

`windows-current-prerelease.yml` has five inputs:

- `expected_source_sha`: exact accepted current native source commit; its live
  tree and every current native report's sourceTree must equal the reviewed pin
- `acceptance_run_id`: the explicitly selected successful first-attempt current
  native workflow run from main, never “latest”
- `version`: fresh `vMAJOR.MINOR.PATCH-windows-preview.N`; no tag/draft/release reuse
- `expected_publisher_sha`: exact reviewed later publisher checkout/workflow SHA,
  with an unchanged current publisher-branch lease
- `publish`: false by default; true requires explicit publication approval

The historical and current workflows share tag concurrency. Both use existing
Actions token authority only, with `contents: read`/`actions: read` for verification
and `contents: write`/`actions: read` only in the explicit second publication job.
There are no new credentials, signing/OIDC, host, repository-settings or native
execution operations.

## Verification and immutable-byte contract

The current adapter selects the existing current report parser and
`current_setup_job_provenance.verify_run`; no alternative schema/route/profile can
be selected by a caller. It requires the exact native workflow/aggregate name,
three cases, four successful jobs, three distinct runner registrations, approved
owner/repository, main branch and first attempt. Required native/upload steps,
labels, job/runner/group identities and original ZIP/member hashes are checked
against live records. Original reports have the current 32 KiB bound.

The aggregate must exactly equal canonical
`tracebolt.windows-current-setup-native-subset.v1` with
`three_case_current_packaged_gui_subset`,
`unsigned-current-source-candidate-native-subset`, exact current reports and all
unproved coverage fields false. PE/source/package validation, same-source/tree/run,
public six-file equality, hashes and authenticated execution provenance are all
required. No downloaded code or arbitrary artifact-supplied instruction runs.

Artifact resolution is inside the selected run only, requiring exactly six names
and distinct immutable IDs. Each ID is reread, then its size, API archive digest,
exact bounded ZIP allowlist and member bytes are verified. Paths, links, extra
members, ambiguity and expired originals are rejected. Authenticating JSON shape
alone is insufficient. GitHub artifact records do not identify uploading jobs;
case attribution also relies on reviewed one-case-one-upload wiring. Hosted job
allocation and source checks are not VM/hardware attestation.

A canonical `tracebolt.windows-current-prerelease-plan.v1` freezes all four jobs,
three runners, six original artifacts and ten release assets. The later write
job downloads/reverifies the same bytes and requires complete frozen-plan equality.
Live original provenance is reauthenticated during prepare, write preparation,
before first write, before publish and at final readback. After each long proof
download, compact source/publisher leases, native metadata and all six artifact
identities close the verification window. Stored evidence never replaces live
availability or unchanged leases.

The write path creates one fresh lightweight tag at the accepted source, one
empty draft prerelease, uploads ten allowlisted files once, verifies all asset
IDs/digests and draft/tag state, and publishes once with `make_latest: false`.
It then independently downloads every public asset without credentials and
rechecks provenance, leases and all metadata. The six native-tested files and
aggregate are unchanged; two reviewed guides are attached verbatim. Only
`release-manifest.json` is generated, using
`tracebolt.windows-current-prerelease.v1` to bind nine other assets, exact source,
run/tree, artifact provenance, later publisher revision and separate version tag.
Original executable filenames/version and `nativeExecution: false` build metadata
remain unchanged. No rebuild/rename/reversion/signing is allowed.

## Failure, scope and trust

Every mutation is attempted once. No overwrite, adoption, force-tag, delete,
cleanup or automatic retry is provided. An uncertain response may leave a tag,
draft or public release; stop for inspection. A failed final readback does not
prove the release is unpublished. Changed leases or expired evidence also stop
later phases; never repair by substituting another source/artifact or credential.

No Windows 11, real Linux-manager/browser interoperability, complete providers,
renewal cutover, reboot, human invitation/UAC, ARM64, verified VM disposal or
optional MSI/WUA/service-control/user-helper acceptance follows. The native
guard checks implemented optional roots/images/public SCM registrations are
absent, not that optional actions work. No all-feature native claim is permitted.
Only finite evidence is public; no raw telemetry, logs, secrets or private state.

No-overwrite is publisher policy, not permanent GitHub platform immutability.
SHA-256/API bindings are neither Authenticode trust nor a signed attestation.
Unexpected HTTPS/API/CDN behavior fails closed; tokens never follow downloads.

## Inert source validation

```sh
python3 -I -B -m unittest discover -s tests/windows_release -v
python3 -I -B -m unittest discover -s tests/windows_native_acceptance -p 'test_current_setup*.py' -v
```

Synthetic API/ZIP/report fixtures and test-only pin/PE injection cannot establish
native acceptance, real API permission behavior or publication. The optional-off
Python regression inspects exact source tables and read-only guards. Its separate
injected Go presence test is source only until actually compiled/run; no native
operations are authorized by either test.
