# Verified dashboard Linux download

The invitation dialog selects `v0.1.0-rc.2` through the source-owned bootstrap
publication commit `08c7f0ef3bb8c3f8941a071d885bdf550c7f72c5` and SHA-256
`10b372ed31d0b2e04d901286ed477a9e7b4fc4d1efe7faea78a5ae8a284db4ea`.
The binary/source build is separately bound to
`a6368b0202b1efecdb6214dc34c4302d239854f7`.

For the complete `managed-operations-v3` profile, the command selects
`--read-admin --read-admin-agent-origin` with the strictly validated public
bootstrap ingress. It configures the supported read scopes and separate helpers
after one explicit combined terminal approval, hidden invitation entry and the
usual dashboard fingerprint approval. Keep the terminal open until completion.
The main agent remains nonroot; CAP_SYS_PTRACE and log-content risks are disclosed.
Basic/non-complete profiles keep `--pending-service`. An absent, old or unknown
read-admin-capable pin offers no incomplete prepared-local downgrade for the
complete profile. Invalid bootstrap identity/origin/checksum also yields no command.

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
disabled. Invitation identity, comparison approval, activation and retention remain
unchanged. Complete-profile scope is granted only by the existing combined
read-admin terminal confirmation; merely rendering or copying the command grants nothing.

The visible download copy warns that running the command changes accounts,
service and persistent identity, and that an HTTP-test dashboard can replace the
entire command and checksum. The command must be obtained from an independently
trusted reviewed reference. A checksum displayed by a tampered page does not
authenticate that page. Existing disposable HTTP and collection notices remain.

## Recorded release and activation evidence

- [rc.2 build/publication](https://github.com/storminator89/Tracebolt/actions/runs/37511484957)
  produced [12 public assets](https://github.com/storminator89/Tracebolt/releases/tag/v0.1.0-rc.2)
  from the exact source above, including four programs for each architecture.
- [Strict public readback](https://github.com/storminator89/Tracebolt/actions/runs/37513100878)
  verified all 12 assets, exact source/workflow keyless provenance and the
  reconstructed bootstrap. No Tracebolt program or installer was executed.
- The [commit-pinned bootstrap](https://raw.githubusercontent.com/storminator89/Tracebolt/08c7f0ef3bb8c3f8941a071d885bdf550c7f72c5/deploy/release/published/v0.1.0-rc.2.py)
  was separately read back and matched its 46,739 bytes and SHA-256.
- [Native Ubuntu TLS acceptance](https://github.com/storminator89/Tracebolt/actions/runs/37508637893)
  passed all scenarios, all six functional checks and cleanup on production-equivalent
  c1cd23a source. This is not a Debian/HTTP download-installation or OS-reboot result.
- GitHub reports `immutable: false`; fixed source, manifest, bundle and asset
  hashes remain the boundary. Historical rc.1 and pilot.2 bytes are unchanged.

Focused command, UI and actual inert shell-tail checks cover both profile modes.
The activation revision's hosted browser acceptance remains separately recorded.
Future versions require fresh public provenance/byte verification and an explicit
source-owned capability/pin update; API or configuration data cannot choose trust.

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
