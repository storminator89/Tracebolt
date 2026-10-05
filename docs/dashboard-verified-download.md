# Verified dashboard Linux download

The invitation dialog selects the verified download command for `v0.1.0-pilot.2`.
Its source-owned pin names bootstrap publication commit
`1011c6b8d38cf85d77a342addf0493cbe1f828ca` and SHA-256
`ba0cf2b8bb25868782bbf9f7a2ae228a982895dd45f865314c6620af30731457`.
The binary/source build commit is separately pinned to
`dbbcfe203c6c39169d9b426991848cd8e736dfd6`.
Older responses without a public bootstrap checksum still offer the existing
public configuration file only. This command is for a fresh approved installation;
existing installed agents use the separately reviewed upgrade action and retain
identity/state. The selected pilot.2 predates Logs and complete process/mount
overview; it must not be used to downgrade a newer manually built pilot. Those
features require a newly verified release and pin before the download supplies them.
Existing journal-helper grants remain in place on compatible updates; the downloader
does not provision that helper or repeat its create-only setup.

The optional serializer is inert: it returns text and does not download or run
anything. Its copied output is one physical line, with semicolon-separated shell
statements and base64 public CA bytes; no backslash continuation is required.
Only the source-owned selector is called by the dialog. There is no
API field, manager configuration, environment variable, browser storage value or
user-selectable URL that can activate executable trust. The explicit pin argument
on the low-level serializer exists for source review and inert fixtures; it must
never be connected to operator-response data.

## Command boundary

The first stage:

1. Start a foreground POSIX shell with a fixed tool path and clean environment,
   preserving terminal stdin. Require deliberate root execution and terminal
   input before staging. Missing initial tools are listed together with a
   supported Debian/Ubuntu package command to review and run manually after
   administrator approval. It never invokes sudo or installs dependencies.
2. Create a new private directory below `/tmp` with umask 077. Fetch one exact
   `https://raw.githubusercontent.com/storminator89/Tracebolt/FULL_COMMIT/deploy/release/published/VERSION.py`
   into its private file. Curl ignores its startup configuration, bypasses proxies,
   permits HTTPS only, follows no redirects, requires HTTP 200, and has bounded
   connection, total time and size limits.
3. Require the exact embedded bootstrap SHA-256 before `python3 -I -B` runs.
   Downloaded bytes are never piped to a shell. The invitation's public manager
   origin, invitation ID, public bootstrap checksum and TLS CA/HTTP-test flag
   are validated and serialized through the same helper as the manual command.
   These public enrollment inputs cannot select executable trust.
4. Open the verified bytes on read-only fd 3, remove the known staging file and
   directory, clear wrapper traps, then replace the shell with
   `exec python3 -I -B /proc/self/fd/3`. Terminal stdin stays unchanged for the
   native hidden invitation prompt. There is no wrapper left to intercept TERM
   or INT, no timeout and no background installer. The reviewed bootstrap owns
   its existing TERM/INT forwarding and child wait. Before this handoff, exit
   traps attempt cleanup of only the known staging file and directory. Persistent
   installer identity/state is untouched.

A Linux-local inert fixture checks that the execution-tail process is the Python
process, retains terminal stdin and starts only after staging is removed. Direct
TERM/INT reach its handlers; direct HUP retains Python's default termination.
This does **not** add HUP handling to the reviewed bootstrap or prove installer
rollback after terminal closure. Keep the terminal open until completion and use
ordinary Ctrl+C cancellation. No SIGKILL or cancellation timeout is introduced.

The separately reviewed bootstrap owns platform rejection, release provenance,
artifact verification and installer invocation. Its Linux arm64 runtime remains
disabled. Invitation lifecycle, collection consent, comparison approval,
activation, retention and host installation permissions are unchanged.

The visible download copy warns that running the command changes accounts,
service and persistent identity, and that an HTTP-test dashboard can replace the
entire command and checksum. The command must be obtained from an independently
trusted reviewed reference. A checksum displayed by a tampered page does not
authenticate that page. Existing disposable HTTP and collection notices remain.

## Recorded release and activation evidence

- The [binary-source CI](https://github.com/storminator89/Tracebolt/actions/runs/37219826603)
  completed all 13 jobs, including 98 required browser cases, three retained
  enrollment skips and native endpoint consent/report/restart/disable checks.
- The [pilot.2 build and publication](https://github.com/storminator89/Tracebolt/actions/runs/37220222635)
  succeeded from that exact source. Its [official release](https://github.com/storminator89/Tracebolt/releases/tag/v0.1.0-pilot.2)
  has ten selected assets; the earlier partial pilot.1 draft is retained.
- The [independent public-byte check](https://github.com/storminator89/Tracebolt/actions/runs/37222069014)
  downloaded and verified all ten official assets through the strict downloader,
  checked keyless provenance and reproduced the exact bootstrap from its source
  template. It executed no Tracebolt binary or installer.
- The immutable official bootstrap source URL was read back and matched the exact
  verified 32,677 bytes and digest before selecting the UI pin.

The activation source passes 832 frontend tests, type checking/build and seven
inert command-contract tests. Its exact hosted browser check remains required;
none of these results establishes a download-based host installation, upgrade or
OS reboot. Those remain separately observed pilot operations.

Future versions must repeat the release/provenance/public-byte checks in
[the distribution guide](linux-release-distribution.md), publish a separate
immutable bootstrap source commit, then update the source-owned literal. Never
use fixture pins, manager responses or deployment configuration to choose trust.
Keep disabled/manual fallback and fail-closed tests when updating an active pin.

## Inert checks

Run `npm run typecheck`, `npm run build` and `npm test` in `web/`. The focused
`enrollment-package.test.tsx` tests compare exact fallback bytes, reject invalid
pins and public inputs, inspect first-stage trust/cleanup/terminal ordering, and
exercise English/German selection, copying, hidden secrets and consent. They
never invoke the returned command, execute downloaded code or access a release.
The separate `python3 -m unittest discover -s tests/release -p
"test_dashboard_bootstrap_wrapper.py"` fixture executes only a locally generated
inert Python program through the extracted execution tail. It has no downloader,
real bootstrap, native installer, root requirement or host-service operation.
