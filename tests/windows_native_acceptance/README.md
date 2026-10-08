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
