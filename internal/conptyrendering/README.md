# Public ConPTY rendering probe (source candidate)

This ordinary test starts only its own inert test-binary child, which writes two
fixed public trust ASCII lines and the exact production-shaped non-newline prompt,
then stays alive for two seconds without reading any input and exits. There is no elevation request, input,
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

The four mode flags recognize only exact CSI `?9001h`, `?9001l`, `?1004h`, and
`?1004l` sequences outside OSC payloads. They respectively observe Win32 input
mode and focus reporting being enabled/disabled; the probe sends no reply or
input. `unknown` retains its original meaning: something outside the original
five recognized families occurred, including these newly named modes.
`residual_unknown` means an unknown remains after those four exact matches.
`first_residual_kind` is only `none`, `text_control`, `non_ascii`, `escape`,
`csi`, or `osc`, never an output byte or sequence parameter. It stays at the first
category even if later unknowns differ. Title content is never returned or used
to recognize mode patterns. Malformed OSC bodies are discarded through their
terminator, so nested lookalikes cannot become observations of external modes.

If modes are observed with no residual, those additional public-probe controls
are classified. If a residual remains, its category guides another narrowly
scoped observation. Neither outcome proves freshgate accepts the stream: the
older family flags deliberately do not validate cursor/clear/SGR parameters or
placement. It cannot retroactively diagnose a different native enrollment run.

Pattern references:
- [Microsoft Win32 input mode specification](https://github.com/microsoft/terminal/blob/main/doc/specs/%234999%20-%20Improved%20keyboard%20handling%20in%20Conpty.md)
- [Microsoft parser mode injection definitions](https://github.com/microsoft/terminal/blob/main/src/terminal/parser/stateMachine.hpp)

Memory is bounded: 1 KiB read buffer, 256-byte sequence buffer, 4096-byte public line, 64 KiB observation
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

## Live fixed-public prompt observation

The four additional booleans describe the last output-read snapshot taken while
the owned child was still running: `live_output`, `public_trust`, `exact_prompt`,
and `prompt_without_final_space`. The latter two compare the current visible-text
line to the fixed public prompt with exactly one final ASCII space, or with only
that one space omitted. They cannot both be true. Shutdown-only output cannot
set these flags. No input is sent and no console input routine is called.

This is a bounded text observation, not a terminal emulator: CSI and OSC are
classified separately by the existing observer. Cursor editing is not applied
to the text line, so interpret text flags alongside those classifications.
Partial control sequences and pending CR cannot count as an exact prompt.
Trust means only the exact fixed public fingerprint and comparison lines were
seen in order, not real identity or manager trust. No transcript is retained or exported; one 4096-byte current public-text line
is held in memory and cleared on newline and cleanup.

Portable inert tests compare the actual freshgate guard's readiness for these
two fixed public spellings using a known all-zero base64 fixture value. That
value is never entered or transmitted. The production prompt, output guard,
input barrier, echo detection, approvals and manual native gate are unchanged.
An ordinary Windows observation is required before choosing a compatibility fix.

A last-live omitted-space snapshot does not prove that no space can arrive
later. In particular, final shutdown rendering is excluded. Interpret this as
a measured live observation for this fixed two-second child, not the byte history
or root cause of another process.

On failure, the launcher now reports one closed `reason` label. A complete
nonzero Go test stream may supply exactly one already-fixed native-test failure
label, only with the exact package/test and both failed outcomes. Missing,
ambiguous or malformed failure evidence becomes `go_test_failed`. Capture and
success-projection checks have fixed labels naming their failing boundary.
Failure still exits nonzero; bounds, success requirements and raw-output
suppression are unchanged. No label proves cleanup or native acceptance.

The launcher reconstructs newline-complete lines only across consecutive output
events belonging to this exact test. A pending line is limited to 1024 characters
and cannot cross a package-output, framing/action or terminal-outcome boundary.
The original exact summary grammar and all success conditions still apply.
Missing summaries report only closed shape categories (CRLF, prefix, fields,
attribution, or absent); those categories never include unmatched output text.
This is compatibility hardening: the pinned Go 1.27.1 converter normally keeps
this approximately 413-byte summary in one event, below its 1024-byte buffer.
No claim is made that fragmentation caused the observed Windows mismatch.
