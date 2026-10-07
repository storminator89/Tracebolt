# Service-action verification gates

These gates test the default-off [service-action workflow](service-action-workflow.md).
They do not install or enable a helper, provision host trust, or execute systemctl.
Existing browser suites are not counted as service-action coverage.

## Required ordinary-user Linux IPC gate

The `Required Linux service-action IPC (no skips)` CI job runs as the ordinary
Ubuntu hosted user. It prepares the locked dependencies, then disables module
network access for the selected Go invocation. Its test-only
`TRACEBOLT_REQUIRE_NATIVE_ACTION_IPC=1` switch changes unavailable native socket
fixtures from skips into failures. There is no corresponding production setting.

The bounded JSON checker requires successful command and package completion,
and all 13 exact named pass events:

- `TestAuthorityKernelPeerCredentials`
- `TestAuthorityInheritedListenerFixture`
- `TestAuthorityInheritedListenerRejectsMismatch` and its nine `pid`, `fds`,
  `fdnames`, `name`, `group`, `mode`, `symlink`, `ancestor`, `descriptor` subtests
- `TestCredentialReaderNativePasscredRejectsNonRootWriter`

The last test performs an actual AF_UNIX/SO_PASSCRED exchange, checks the kernel
credentials and verifies that the production credential reader rejects a real
nonroot writer. The inherited-listener fixtures exercise real descriptors and
kernel peer credentials with temporary ordinary-user-owned paths.

Every skip, missing/duplicate case, malformed or partial stream, unsuccessful
package/command, and mismatched source identity fails the gate. Merely compiling
or listing the tests cannot produce a pass. Raw test output stays in private
runner-temporary files and is not uploaded; the checker emits only a fixed scope
summary and the validated source SHA.

This proves the tested ordinary-user Unix mechanics and rejection behavior.
It does not prove successful production root-writer authentication, an installed
root helper, its real protected paths, a systemd socket unit or actual execution.
Those remain separately authorized native acceptance gates.

## Dedicated real-browser action flow

`tests/e2e-review/service-action-browser.mjs` runs the built React UI in real
Playwright Chromium. It starts the separate loopback-only `actionfixture` test
binary with a new private temporary state directory. Every identity, key,
observation and service name is invented and discarded after the test.

Browser preview and approval assertions observe only the bytes consumed by the
application's original bounded reader, bound to the exact armed device/POST and
original request body. The test-only observer neither clones nor fetches another
response and retains the 32 KiB action-response cap. This is not rendered-UI
acceptance by itself: all preview, consent, saved-job and helper-counter checks
still have to pass. Context-request status/replay reads keep their existing byte
and JSON checks. No response bodies, credentials or screenshots are exported.

The browser uses actual named-operator authentication and actual preview,
approval and status APIs. There is no service-action API interception or response
substitution. A synthetic test-only protocol driver uses the real purpose-signed
agent ingress and durable claim/result paths. The helper's real bounded framing,
`ServeConn` and durable state run over `net.Pipe`; helper identity/peer authority
and the executor are explicitly injected fixtures. The fake executor is held
until a bounded stdin control releases it. No HTTP control exists.

Four exact cases must pass:

1. Named operator preview binds the selected service and cancellation leaves zero
   jobs and helper calls.
2. Explicit interruption approval commits one job and held helper execution remains
   unconfirmed.
3. Agent-reported completion survives reload without automatic approval or execution
   replay.
4. Repeating the exact approved preview is idempotent and cannot execute again.

Conditions and counters establish zero calls before approval and exactly one
persisted job, claimed delivery and fake invocation afterward. The held result
must display delivery/execution uncertainty. Completion must remain explicitly
agent-reported and distinct from restart or service-health proof. A subsequent
real ingress peek must find no new deliverable work after repeated approval.

The checker requires the exact source SHA, case names, counts, zero runtime
errors and fixed scope disclosures. Missing, partial, stale, failed or unsafe
artifacts fail. It rejects setup-only output with zero cases. No raw command
permits, sessions, tokens, private keys, response bodies, traces or screenshots
are exported in the result artifact.

This browser fixture uses only the explicitly acknowledged disposable HTTP
profile. It does not establish mTLS browser trust, production actionSender
execution, native Unix isolation or installed root/systemd acceptance. The
production sender and mTLS/profile boundaries retain their separate Go tests.

## Source and environment limits

Local source compilation, fixture/API/framing smoke and evidence-checker tests
are distinct from actual browser/native execution. In this cloud container,
Unix listener creation is denied; Chromium also aborts because its process
singleton requires a Unix socket. Those failures must not be relabeled as passed
browser or native checks, and do not justify a production bypass. The new hosted
jobs must supply passing exact-source evidence before their respective gates are
reported complete.

No provisioning or repair command is added by this verification slice. The
create-only local setup and first real UI-approved disposable service action
remain the next operational implementation and acceptance steps.
