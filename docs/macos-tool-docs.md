# Hosted macOS built-in documentation capture

This separate workflow is a documentation research gate. It runs only fixed
built-in help, fixed installed public manual files and nonidentifying OS-version
commands on disposable standard GitHub-hosted macOS 15 machines. It executes no Tracebolt product code or provider.
Existing source and native-fixture workflows are unchanged. Preparing this source
does not establish that the revised hosted manual acquisition has run. Earlier
help-only evidence remains unchanged, with stderr-backed help inconclusive.

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
never its text. That conservative choice is retained even when installed manuals
are captured independently. It
must never be reclassified as an absent service/tool/flag, a permission denial,
an empty log store or proof that the caller can read any data.

## Fixed installed public manuals

Schema 2 adds four independent exact file sources, never a `man` command:

- `/usr/share/man/man1/launchctl.1`
- `/usr/share/man/man1/launchctl.1.gz`
- `/usr/share/man/man1/log.1`
- `/usr/share/man/man1/log.1.gz`

Only these paths are admitted. Plain and compressed alternatives are each
recorded; a missing alternative stays inconclusive even when the other succeeds.
There is no `MANPATH`, home/user file, locale/SDK directory, glob, filesystem
search, pager, renderer, roff preprocessor or operational command fallback.

Each path is opened component-by-component from an open `/` descriptor, using
no-follow directory descriptors and `O_NONBLOCK`. Every directory must be
root-owned, directory-typed and not group/other writable. The final source must
be a root-owned regular non-symlink file without group/other write permission.
Descriptor metadata and exact read length are checked before and after the read.
No ownership identifiers or other filesystem identity metadata are exported.
Missing, inaccessible, redirected, changed or unsafe sources remain inconclusive.
This checks the recorded installed system source; it is not a signature attestation.

Each file is capped at 128 KiB of source bytes and 256 KiB after decoding. Exact
`.gz` paths allow one complete gzip member only. Expansion is capped before it
can produce a large buffer; corrupt, truncated, concatenated and trailing-data
streams fail closed. No gzip header fields or original filename are retained.
A five-second cooperative deadline is checked between open/read/decode steps;
the existing five-minute workflow limit also bounds the whole job. A blocking
kernel filesystem operation is not promised an independently enforced timeout.

Accepted text is strict UTF-8 without control/format characters other than tab,
CR and LF, and must contain the exact tool's section-1 `.Dt` title plus `NAME`
and `SYNOPSIS` section headers. An unfamiliar source format stays inconclusive.
The artifact retains literal roff source text, never rendered HTML or executed
macros. Includes and commands in a manual are inert text; no referenced path is
opened. Text, raw-byte/text SHA-256 hashes, fixed path, format/compression, size
bounds and check outcomes are recorded with the same OS/build/tool provenance.
No raw compressed file, invalid prefix or exception message is uploaded.

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
OS network sandbox. The permitted host reads are limited to help, the four version values,
bounded fixed OS-binary fingerprints and the four fixed public manual paths.

## Evidence interpretation and remaining gates

Schema 2 distinguishes useful acquisition from full requested help coverage.
`documentation_acquired` requires all four validated version records, all four
tool fingerprints, and at least one validated current installed manual source
for **each** of `launchctl` and `log`. Only this result exits zero. Successful
help alone cannot substitute for a missing manual or required provenance.

Every command and every manual path retains its own captured/inconclusive result.
Any unavailable help leaves `requestedHelpCoverage` and
`requestedDocumentationCoverage` explicitly `partial`, even when acquisition
completed. The artifact names captured/inconclusive help IDs and the per-tool
manual availability. A missing `.gz` alternative is not promoted when the plain
source succeeds. These coverage fields concern this requested source selection,
not exhaustive tool documentation or product capabilities.

The original help-only run and its schema-1 results are not rewritten or
reclassified. In that run, general launchctl help and the four versions were
captured on both architectures; individual launchctl help and log help were
withheld. New manual evidence must actually be acquired on the current recorded
image; it cannot be substituted from source fixtures, older artifacts or the web.

This is not a product test pass. Native acceptance, log visibility, log schema
and launchd-binding proof stay false. Review actual documentation for stated
flags; a missing string never proves universal lack of support.

Help can establish which syntax/flags the installed tool documents. It cannot
establish actual log visibility, completeness, privacy redaction, retention,
permission requirements for a later query, JSON/NDJSON field schemas, stable
record identifiers, process attribution, launchd domain/service binding, reboot
persistence or installed-agent behavior. Synthetic transport strings below do
not represent an Apple raw-log schema.

Remaining gates are: review/publish this narrow correction; run both revised
hosted jobs; inspect exact commit/source hashes, image/build, bounds, manual
source checks and independently reported command results;
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

Manual tests use fully fabricated descriptor/open/read/stat results, never local
installed manual files. They cover exact paths, root/owner/mode/type/no-follow
checks, changed inputs, read/decode limits, gzip corruption and expansion,
control-safe source shape, per-source failures and partial-coverage semantics.
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
- [Apple's Command Line Primer](https://developer.apple.com/library/archive/documentation/OpenSource/Conceptual/ShellScripting/CommandLInePrimer/CommandLine.html)
  identifies `/usr/share/man` as the installed manual hierarchy; Apple's published
  launchctl manual above supplies its section-1 filename and mdoc source format.
  Current existence/content of the four exact candidates is a hosted evidence
  gate, not inferred from the archived guide.
- [Apple's manual-page format overview](https://developer.apple.com/library/archive/documentation/System/Conceptual/ManPages_iPhoneOS/man5/manpages.5.html)
  explains manual sections and synopsis conventions. This workflow reads source
  files as data instead of invoking the usual manual viewer.
- [GitHub's hosted runner reference](https://docs.github.com/en/actions/reference/runners/github-hosted-runners)
  documents the two standard runner architectures and free standard runner usage
  for public repositories.

Current authoritative documentation for these installed tools must come from
the bounded built-in help and validated installed manual captures themselves. No current Apple-hosted `log help show`
text was verified during source preparation, so this source makes no claim about
its current flags or schema. The revised hosted manual run is deliberately the evidence gate rather than an
invented fixture of Apple's output.
