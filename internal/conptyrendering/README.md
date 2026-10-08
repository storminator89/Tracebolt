# Public ConPTY rendering probe (source candidate)

This ordinary test starts only its own inert test-binary child, which writes two
fixed public ASCII lines and exits. There is no elevation request, input,
invitation, service/coordinator import, enrollment, fixture authority, network,
ACL change, native-acceptance admission, or manual-gate environment. It requires
no special host approval. Do not interpret this statement as authorization to run
any other test. The existing ordinary Windows service-source workflow runs this probe as a
separately named step; its pure-fixture runner and the manual native acceptance
workflows remain unchanged.

The independent observer classifies sequence *families*, not grammar acceptance.
It is neither a copy of the freshgate parser nor a terminal emulator. Its finite
booleans cannot prove that the real output guard accepts the output or that a
coordinator succeeds. Unknown sequences are reported only as a boolean; parameters
and raw output are never returned, logged, or written to an artifact. A family
observation can guide a later documented public unit-test case for the real guard.

Memory is bounded: 1 KiB read buffer, 256-byte sequence buffer, 64 KiB observation
budget. Output continues draining after the observation limit so cleanup does not
block on a full pipe. Overflow and incomplete output fail the test. Unknown is a
reported observation rather than acceptance or a reason to relax another parser.
ConPTY uses default flags and a fixed 120 by 30 character viewport. It inherits
no handles. The helper accepts no arbitrary arguments or commands.

The main loop alone reads/peeks the output handle, limiting each read to the
available bytes. A separate goroutine closes ConPTY while output continues to be
drained through EOF. The run deadline is 20 seconds; cleanup terminates only the
owned process if necessary, waits up to 5 seconds for that process, closes its
output pipe to release older ConPTY close waits, and waits up to 5 seconds for
ConPTY closure. Cleanup failures produce only fixed reason labels. No cleanup
claim is made when a deadline or reaping failure occurs. A test-runner timeout is
still needed against a Windows API that itself becomes unresponsive.

The ordinary Windows workflow invokes the standalone bounded launcher:

    python -I -B tests/security/run_public_conpty_probe.py

It selects only `TestNativePublicRendering`, requires that exact test and its
package to pass without skips, and projects the exact finite family summary. Go
tests have a 45-second timeout; the launcher bounds capture to 1 MiB and allows
120 seconds including compilation, with an outer three-minute workflow-step
limit. Raw stdout/stderr and sequence bytes are never printed or uploaded. A
launcher timeout is a failure, not proof of child cleanup.

Portable observer tests run on Linux. Windows amd64/arm64 compile checks do not
execute the test and establish no Windows behavior. The candidate has not been
run natively; workflow integration is a source candidate until published and
observed. This step never invokes the separate native service/enrollment gate.

Official lifecycle references:
- https://learn.microsoft.com/en-us/windows/console/creating-a-pseudoconsole-session
- https://learn.microsoft.com/en-us/windows/console/closepseudoconsole
- https://learn.microsoft.com/en-us/windows/win32/api/namedpipeapi/nf-namedpipeapi-peeknamedpipe

Microsoft documents continued output draining during close, including older
Windows where ClosePseudoConsole blocks; newer Windows returning immediately
still requires waiting for pipe EOF. Peek/read share no concurrent handle user.
