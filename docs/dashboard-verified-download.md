# Disabled dashboard download seam

The invitation dialog still emits exactly the existing prepared-local-checkout
command. `OFFICIAL_LINUX_BOOTSTRAP_PIN` in
`web/src/verified-download-command.ts` is **null**. No release, download or host
acceptance is implied by this source change. Older responses without a public
bootstrap checksum still offer the existing public configuration file only.

The optional serializer is inert: it returns text and does not download or run
anything. Only the source-owned selector is called by the dialog. There is no
API field, manager configuration, environment variable, browser storage value or
user-selectable URL that can activate executable trust. The explicit pin argument
on the low-level serializer exists for source review and inert fixtures; it must
never be connected to operator-response data.

## Command boundary

Once separately activated, the first stage will:

1. Start a foreground POSIX shell with a fixed tool path and clean environment,
   preserving terminal stdin. Require deliberate root execution and terminal
   input before staging. It never invokes sudo or installs dependencies.
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

## Later activation requires real evidence

Follow `docs/linux-release-distribution.md` from the reviewed release tooling.
Verify the exact successful official workflow, release assets and provenance.
Publish that run's generated bootstrap as `deploy/release/published/VERSION.py`
in a separately reviewed immutable commit, then read back its exact official
HTTPS bytes and SHA-256 using the real downloader. The bootstrap publication
commit is distinct from the binary/source build commit. Record both.

Only after those gates, replace the one null source constant with a frozen
literal containing `version`, `publicationCommit` (full lowercase 40-hex SHA)
and `bootstrapSHA256` (full lowercase 64-hex digest). Use real verified values,
never the inert fixtures. Update the deliberate null/fallback assertion in the
source test as part of that same reviewed activation delta, retaining separate
disabled/fail-closed fixture coverage. No API or deployment-config change is
needed. A generated command still does not establish real install/restart/reboot
acceptance; those require the separately authorized disposable-host gates.

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
