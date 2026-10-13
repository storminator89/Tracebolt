# Hosted macOS built-in documentation capture

This separate workflow is a documentation research gate. It runs only fixed
built-in help and nonidentifying OS-version commands on disposable standard
GitHub-hosted macOS 15 machines. It executes no Tracebolt product code or provider.
Existing source and native-fixture workflows are unchanged. Preparing this source
does not establish that either hosted documentation job has run.

## Exact command boundary

`tests/macostooldocs/run.py` contains an immutable, ten-entry allowlist:

- `/usr/bin/sw_vers -productVersion`
- `/usr/bin/sw_vers -buildVersion`
- `/usr/bin/uname -r`
- `/usr/bin/uname -m`
- `/bin/launchctl help`
- `/bin/launchctl help print`
- `/bin/launchctl help list`
- `/bin/launchctl help print-disabled`
- `/usr/bin/log help`
- `/usr/bin/log help show`

`help` is the dispatched verb for every launchctl/log invocation. The following
word names the documentation topic; it does not execute that topic. There is no
`log show`, `log stream`, `log collect`, `log emit`, predicate, archive, service
target, process target, `launchctl print`, `launchctl list`, domain inspection,
service control, provider fallback or argument supplied by a caller. Failure to
obtain a help page stops at an inconclusive documentation result; it never tries
the corresponding operational command.

The driver accepts only `--check` or no arguments. It uses exact absolute paths,
no shell, closed stdin, a fixed minimal C-locale environment, and `/` as the child
working directory. Each command has a five-second deadline. Stdout and stderr
are drained separately with a shared 64 KiB total budget for help and 128 bytes
for version output. Stderr also has a separate 16 KiB ceiling (128 bytes for
version commands); its bytes are discarded immediately, never buffered as text,
decoded, hashed, logged or published. It kills
only the fresh child session on timeout or output overflow, waits at most one
additional second, and discards the incomplete output. Ten commands therefore
have a maximum of about sixty seconds of child execution/cleanup. The entire job
has a separate five-minute timeout.

Success requires zero exit, empty stderr, complete bounded UTF-8 stdout text,
no terminal control characters, and a recognizable usage statement for help. Version output must
match a narrow nonidentifying shape and the selected architecture/macOS major.
A nonzero help exit, any stderr, empty result, unfamiliar layout, overflow or
timeout remains `inconclusive`. Both streams' content is withheld for that
invocation, even with recognizable stdout help. Some built-in help may print
solely to stderr and consequently remain unavailable; no operational fallback
is permitted. Metadata may record stderr's presence and bounded byte count,
never its text. That
conservative choice may need a reviewed adjustment after a real hosted run. It
must never be reclassified as an absent service/tool/flag, a permission denial,
an empty log store or proof that the caller can read any data.

## Version, runner and source provenance

The workflow pins the checkout/upload actions by full commit and selects only
`macos-15` (Apple Silicon) and `macos-15-intel` (Intel). These standard labels pin
the major/image family and architecture, not an immutable runner image. Actual
product/build, Darwin release, architecture and bounded GitHub image metadata
are recorded. The job and driver both reject private-repository execution; the
driver also rejects local/non-macOS, self-hosted, wrong-architecture and
unexpected runner contexts. There is no larger/paid runner fallback, install,
Go setup, package download or persistent dependency cache.

For exact tool identity, the driver reads only the four allowlisted OS binaries
(`/bin/launchctl`, `/usr/bin/log`, `/usr/bin/sw_vers`, `/usr/bin/uname`) to hash their
bytes. It accepts only a regular, non-symlink file of at most 32 MiB, checks its
size/inode/modification time before and after reading, and retains only its fixed
path and SHA-256. No executable bytes, owner identifiers or filesystem metadata
are exported. A failed fingerprint stays inconclusive. A hash plus the recorded
macOS build identifies the bundled tool bytes; it is not a standalone semantic
version. `standaloneVersion` is explicitly null: no unverified `--version`,
launchctl version operation, signature query or provider command is attempted.

Checkout is explicitly bound to `github.sha`. Evidence labels that value
`workflowSHA` (a supplied workflow identity, not an independent Git read) and
also hashes the four source files for comparison with that revision. The driver
performs no Git subprocesses. The checks are review guards, not a sandbox or
cryptographic attestation of the hosted machine. Changes to the workflow,
commands, capture driver or tests require a fresh scope review.

## Artifact and privacy boundary

Only `artifacts/review/macos-tool-docs.json` is uploaded, with fourteen-day
retention. It contains source/runner provenance, exact command arrays, exit and
bound metadata, accepted stdout documentation text with SHA-256, four validated
stdout version strings, and tool fingerprints. Arbitrary exception text and failed command
output are not emitted to the console or artifact. Existing evidence files or
symlinks are not overwritten. No logs, environment dump, hostname, account name,
UID/GID, launchd service/domain state, process inventory, credentials, grants,
private state, cache, binary or broad directory is uploaded.

No root/sudo, TCC/Full Disk Access change, account creation, enrollment, trust
change, service installation/control, persistent permission, security setting,
real log query, log emission, provider or external AI call is involved. Normal
GitHub checkout and artifact upload still use GitHub services; this is not an
OS network sandbox. The permitted host reads are limited to help, the four version
values and bounded fixed OS-binary fingerprints.

## Evidence interpretation and remaining gates

`documentation_captured` means only that all ten commands returned accepted
complete documentation/version output and all four tool fingerprints succeeded
on the recorded runner. It is not a product test pass. The evidence explicitly
sets native acceptance, log visibility, log schema and launchd-binding proof to
false. Review the actual help text for documented flags; absence of a string in
a page is not proof that a flag is unsupported across releases.

Help can establish which syntax/flags the installed tool documents. It cannot
establish actual log visibility, completeness, privacy redaction, retention,
permission requirements for a later query, JSON/NDJSON field schemas, stable
record identifiers, process attribution, launchd domain/service binding, reboot
persistence or installed-agent behavior. Synthetic transport strings below do
not represent an Apple raw-log schema.

Remaining gates are: publish/review this narrow delta; run both hosted jobs;
inspect the exact commit/source hashes, image/build, bounds and command results;
review any inconclusive result without a host-data fallback; and separately
design/authorize any actual provider, log-content or launchd acceptance work.
No log schema or native service binding should be implemented from these help
captures alone. Existing [macOS native gates](macos-status.md) remain open.

## Source-only checks and research basis

Run these commands on any development OS; neither invokes a native macOS tool:

```
python3 -B tests/macostooldocs/run.py --check
python3 -B -m unittest discover -s tests/macostooldocs -p 'test_*.py' -v
```

The tests replace every candidate subprocess before exec with this Python
interpreter running literal inert text/sleep programs. They cover exact dispatch,
missing authority/context, rejected input, finite output/time, successful and
failed text handling, valid stdout alongside sensitive-looking stderr, separate
stderr/shared output caps, stderr-only help refusal, version shapes, artifact collision, identity-read failure
and claim boundaries. Tool fingerprint calls are mocked. Test output is
synthetic validation only; it is neither Apple help nor native log evidence.

Research checked on 2026-10-13:

- [Apple's published launchctl manual source](https://github.com/apple-oss-distributions/launchd/blob/main/man/launchctl.1)
  identifies `help` as usage output. It is historical source, not current macOS
  15 behavior or an output-format contract.
- [Apple's published launchctl implementation](https://github.com/apple-oss-distributions/launchd/blob/main/support/launchctl.c)
  corroborates a help dispatcher in that historical implementation. It is not
  evidence of current launchd binding or log visibility.
- [GitHub's hosted runner reference](https://docs.github.com/en/actions/reference/runners/github-hosted-runners)
  documents the two standard runner architectures and free standard runner usage
  for public repositories.

Current authoritative help for these installed tools must come from the bounded
built-in documentation capture itself. No current Apple-hosted `log help show`
text was verified during source preparation, so this source makes no claim about
its current flags or schema. The first hosted run is deliberately the evidence
gate rather than an invented fixture of Apple's output.
