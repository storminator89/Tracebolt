# Verified dashboard Linux download

The invitation dialog selects the verified download command for `v0.1.0-rc.1`.
Its source-owned pin names bootstrap publication commit
`458fc072a73946032446c0d9e63220ea29cca355` and SHA-256
`85bd2c01beb3012d5d042d88448d892a270cf527786a73e7a0a67867cac47f61`.
The binary/source build commit is separately pinned to
`ccac65e7a61f0b5f0e325c3616a93273ab1e8eb1`.
Older responses without a public bootstrap checksum still offer the existing
public configuration file only. This command is for a fresh approved installation;
existing installed agents use the separately reviewed upgrade action and retain
identity/state. The selected source includes Logs and the complete process/mount
extension. Their separate local helper/collection grants remain required; selecting
this release does not enable new collection scopes or authorize a host upgrade.
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

- The [rc.1 build and publication](https://github.com/storminator89/Tracebolt/actions/runs/37310793781)
  succeeded from the exact binary/source commit above. Its
  [official release](https://github.com/storminator89/Tracebolt/releases/tag/v0.1.0-rc.1)
  has ten selected assets. Previously published pilot.2 bytes remain unchanged.
- The [independent public-byte check](https://github.com/storminator89/Tracebolt/actions/runs/37312386248)
  downloaded and verified all ten official assets through the strict downloader,
  checked exact source/workflow keyless provenance and reproduced the exact
  bootstrap from its source template. It executed no Tracebolt binary or installer.
- The [commit-pinned official bootstrap source](https://raw.githubusercontent.com/storminator89/Tracebolt/458fc072a73946032446c0d9e63220ea29cca355/deploy/release/published/v0.1.0-rc.1.py)
  was read back and matched the exact verified 37,461 bytes and digest before
  selecting the UI pin.
- GitHub reports `immutable: false` for this release. The fixed source, manifest,
  bundle and asset hashes are the verification boundary; platform-level release
  locking is not claimed.

The activation change is checked with type checking/build, the command/enrollment
UI fixtures and nine inert public-command contract tests. Its exact hosted browser
check remains required; none of these results establishes a download-based host
installation, upgrade or OS reboot. Those remain separately observed pilot operations.

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
