# Manual Windows native acceptance subset

This is **source-only test infrastructure**, not a native pass or permission to
run it. It has not dispatched a workflow, installed/controlled a service, changed
an ACL, created an endpoint key, or performed cleanup during implementation.

The workflow `.github/workflows/windows-native-acceptance.yml` has only a manual
`workflow_dispatch` trigger. The reviewed `expected_source_sha` and five shared
`services`, `identity`, `app_acls`, `loopback_transport`, and `cleanup` approvals
are required. The exact collection/transport selection also requires
`inventory_metadata` for Windows inventory and `http_plaintext` for its HTTP-test
transport. All seven approvals default to false; unused extra scope is rejected.
Valid pairs are basic+TLS, Windows inventory+TLS (default selection), and Windows
inventory+explicit HTTP-test. No automatic matrix or fallback exists. A failed prerequisite
is a failing **blocked** result; it is never permission to repair existing OS
ancestor ACLs or silently choose another host. A hosted Windows image can fail
the driver's strict prerequisite checks and requires separate review, not an
exception here.

## Boundaries

- Only `storminator89/Tracebolt`, a GitHub-hosted `windows-2025` X64 runner, and
  exact lowercase 40-hex expected SHA = GitHub SHA = clean checked-out HEAD.
- The Python authorization boundary runs before any subprocess for invalid or
  missing approvals. Source/fixture steps and the native step recheck it.
- Native Windows amd64 Go host/target are verified. Both ordinary service and
  acceptance controller are built from that exact source; the controller embeds
  it with `-X main.compiledSource`. Both executable hashes are passed in fixed
  subprocess argument lists, without a shell or input interpolation.
- The controller has a ten-minute work deadline and separate two-minute owned
  cleanup budget within a twenty-minute grant. Its Python caller permits thirteen
  minutes. Timeouts/failures never count as successful cleanup. The job allows
  forty minutes including dependency setup, source fixtures and both builds.
- Keys, telemetry, raw child stdout/stderr, native paths, and binary build
  products are not uploaded. Child stderr is discarded; stdout is held only in
  bounded memory, drained on overflow so owned cleanup can finish, and strictly
  validated. Build products use a temporary folder and are removed before export.
- The sole artifact is `tracebolt-windows-native-acceptance.json`, a newly
  serialized finite report, capped at 32 KiB, retained for three days. Unknown,
  missing or duplicate fields, non-boolean truthy values, unexpected JSON,
  additional output, and invalid enums fail closed. Invalid output is not saved.
- Native pass means exactly `passed_native_subset`, all fourteen checks passing,
  successful controller exit and every required terminal proof. Failed and
  blocked finite reports may be retained but fail the job. Production-manager/production-ingress/shared-dashboard,
  hidden-console, OS shutdown/reboot and broad ancestor ACL coverage stay false.

## Source-only tests

From the repository root, with Python 3.12 or newer:

```
python -I -B -m unittest discover -s tests/windows_native_acceptance -p "test_*.py"
```

These pure tests mock subprocesses, use inert text files as binary-hash fixtures,
and check authorization, schema parity with Go, exact argv, failure redaction,
bounded output, workflow triggers and default-off approvals. They require no
Windows host or native permissions. Do not present them as native acceptance.

The separately labeled `run_source_fixtures.py` workflow step executes source,
synthetic-clock expiry and injected shutdown-handler tests on Windows. Required
named checks must actually pass without being skipped. Those fixtures never
substitute for the native report and do not prove an OS shutdown or reboot.

Calling `run_acceptance.py` without its fixed mode rejects immediately. Do not
reproduce the workflow environment to bypass review; approval comes from the
human-reviewed manual workflow for its exact dispatched source.

## Selected native inventory evidence

The manual controller uses the ordinary installed LocalService collector/sender,
then validates the exact profile frame with production decoders. The loopback
HTTP mode additionally uses production signed-request verification. Report v2
retains only the selected pair, bounded frame count and finite metric/section
quality labels. Denied or unavailable sections prevent usable-inventory success.
The Linux protected SQLite manager and shared browser are not run by this native
peer; production ingress/store fixtures and invented shared UI evidence remain
separate gates. See [manual scope and proof](../../docs/windows-native-service-acceptance.md).

The optional all-four expanded source candidate adds independent event-header,
volume, process-metric and network-endpoint acknowledgements. All false keeps the
original base v2 evidence; all true plus inventory selects v3 finite evidence.
See `docs/windows-expanded-acceptance-approval.md`. Source checks and Windows
cross-builds do not authorize or establish native execution. Production Linux
manager/store/dashboard and fresh installer acceptance remain unproven.

## Packaged GUI controller fresh prerequisites

The packaged GUI controller receives a restricted environment. Before its first
KnownFolder lookup, it derives only `SystemDrive` from the Windows API's system
Windows directory using the existing strict path validator, then sets that single
process-local variable. Ambient `SystemDrive`, `ProgramFiles` and `ProgramData`
overrides are not forwarded. KnownFolder resolution and the existing deny-existing
service/directory checks remain authoritative; no host repair or path fallback is
performed.

Finite `fresh-environment`, `fresh-layout`, `fresh-service`,
`fresh-program-files` and `fresh-program-data` stages distinguish prerequisite
failures without exporting paths, native errors or environment values. A failure
still stops before the fixture, GUI, service changes or persistent identity work.
The older `fresh` label remains readable for prior reports. Portable injected
fixtures and Windows cross-compilation do not establish that this environment
correction fixes a particular hosted native run; a separately approved exact-source
native gate remains required.

Before freezing a candidate that changes any Go source (including test files),
regenerate `tests/security/go_failure_allowlist.json` with the canonical
`derive_allowlist(ROOT)` function in `tests/security/report_go_failure.py`.
Run the complete existing **Validate bounded Go failure projection with inert
fixtures** step in `.github/workflows/validate.yml`, starting with
`python3 -B tests/security/test_go_failure_reporter.py`. The narrower Windows
source and package tests above do not verify this exact-source inventory. Keep
its fail-closed source binding intact; do not hand-edit test names or hashes.

## Pending observation and finite progress (report v2)

The packaged controller captures a protected, canonical staged receipt while the
worker is waiting for hidden input. While that worker is active, pending checks
inspect the exact captured service identity, SCM configuration and executable,
including stopped/disabled state. They do not reopen the installer store: doing
so competes with its fail-immediately exclusive lock and can make either the
observer or the worker's phase write fail. Partial cases still require a fresh
protected receipt read after the worker exits, unchanged Service/Consent, and
renewed live ownership verification. Phase may legitimately advance from
claim-started to activation-started. Production locking is unchanged.

Finite pending substages identify capture, claim wait, owned-service inspection,
console inspection, fixture-state checks and post-worker retention. The original
15-second claim wait, two-second withholding check and four-minute frame wait
are unchanged. Native report v2 adds `frameProgress`: the latest accepted-frame
counts, inventory/extension quality labels and bounded receiver checkpoint
counts. `not_started` is distinct from an observed `no_accepted_frames`; a failed
frame wait retains its latest validated V5 count instead of a success-only zero.
Accepted-but-denied collection is distinct from receiver rejection. Counters cover
only admitted exact-shape HTTP requests, not TCP/TLS handshakes or malformed
pre-admission traffic. They contain no telemetry rows, names, addresses, metrics,
secret material, errors or paths. Positive acceptance still requires the original
usable inventory/extensions predicate and at least two distinct V5 frames.

## Hosted execution provenance (aggregate v2)

Hostnames can be cloned and are not cross-job VM identifiers. The controller keeps
its within-job hostname binding and every fresh-host guard. Aggregation now also
requires authenticated GitHub attempt-1 run/workflow/job records, four distinct
successful native job IDs and four distinct positive runner registration IDs,
exact case/source/repository/actor bindings and the
reviewed Windows-2025 job wiring. Artifact archives are refetched with bounded
HTTPS reads and checked against authenticated ZIP sizes/digests and the exact
report/public-package bytes being consumed. API failure or ambiguous/missing
provenance blocks accepted-package output; there is no nonce/hostname fallback.
Only the Linux aggregation step receives the ephemeral read-only API token, and
it is removed before checkout/build subprocess environments.

The proof basis is GitHub-hosted job isolation. GitHub documents a fresh hosted
instance for each standard job; Windows runners are VMs. This is not independent
VM/hardware attestation or proof of platform disposal. Artifacts REST does not
name the uploader job, so case-to-job attribution additionally trusts this exact
reviewed workflow's one-case/one-upload wiring. Runner registration metadata is
required corroboration, not a VM identifier. Official documentation reviewed 2026-10-09:
<https://docs.github.com/en/actions/concepts/runners/github-hosted-runners> and
<https://docs.github.com/en/rest/actions/workflow-jobs>.

Aggregate v2 records this finite `executionProvenance` and accepts only exact
canonical report bytes, preserving an unambiguous report digest binding. Any release publisher
must independently call `setup_job_provenance.verify_run` with the stored proof
and `require_aggregate_success=True`; its pure schema validator alone does not
authenticate evidence. Report-v1 or aggregate-v1 artifacts must not be relabeled
as v2. The already-failed primary run remains failed; these source corrections
do not authorize another native run or establish a production collector fix.
The accepted-package aggregation runtime also requires the exact
`refs/heads/main` ref and reviewed workflow/source SHA. REST `head_branch` is
checked for matching `main` across run, attempt and artifact records, but is not
represented as independently proving the heads-versus-tags namespace. That part
of the contract relies on the exact-source aggregate runtime guard.
