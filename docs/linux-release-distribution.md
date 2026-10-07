# Linux release distribution candidate

Status: official `v0.1.0-rc.3` is published and independently verified. The
[dashboard pin](dashboard-verified-download.md) selects its immutable bootstrap
source. Actual download-based host installation, upgrade and OS reboot acceptance
remain separate pilot operations; arm64 is cross-built only.

The endpoint does not build Go programs or transfer a source archive manually.
A pinned bootstrap downloads the matching reviewed binaries and source archive,
verifies the complete release, then invokes the existing `agent-service` with
its existing exact artifact hashes and flags. That installer remains the owner
of fixed paths, account/service changes, fresh identity checks, explicit resume,
upgrade, rollback and hidden-terminal invitation input.

## Target boundary

The first runtime target is Linux amd64 on Debian 13 or Ubuntu 24.04, with systemd
as PID 1 and cgroup v2. The combined read-admin profile additionally requires
kernel 6.5 or newer. Linux arm64 is cross-built for inspection only and the
bootstrap rejects runtime installation until its own acceptance gate is recorded.
Other distributions, architectures, Windows, macOS and non-systemd environments
fail clearly. No fallback changes the supported platform or collection profile.

The target must already provide Python 3, curl, the distribution's system CA
bundle, sha256sum and ordinary system tools. There is no automatic dependency
installation, privilege escalation, global trust installation, firewall change,
remote scan, manager deployment or host execution during source validation.
An administrator runs the approved apply operation deliberately as root in a
real local terminal. Without `--apply`, no download or temporary staging occurs.

## Prerequisite and result guidance in current source

The reusable bootstrap now checks the fixed native system tools (`systemctl`,
`useradd`, `nologin`) as well as curl, Python 3.11+, sha256sum and the system CA
bundle before release-asset downloads. Missing tools are listed together with one
explicitly manual `apt-get update && apt-get install -- ...` suggestion for the
supported Debian/Ubuntu hosts. The `nologin` tool maps to `login` in both
[Debian 13](https://packages.debian.org/trixie/amd64/login/filelist) and
[Ubuntu 24.04](https://packages.ubuntu.com/noble/amd64/login/filelist).
It does not execute that command, invoke sudo,
change trust, install packages or alter permissions. A damaged CA bundle is a
separate inspection error, not an invitation to bypass certificate checks.

Applied operations also reject a missing/background controlling terminal and a
non-writable or `noexec` `/tmp` before private release staging. These checks do not
replace the native installer's later artifact, ownership, collision and retained
identity checks. Disk/network availability and service startup can still fail;
passing prerequisites is not a guarantee of installation success.

Four progress phases distinguish host checks, provenance download, verified agent
file download and entry into the native installer. Its JSON result remains on
stdout; human-readable outcome/recovery guidance is on stderr. A committed fresh
installation confirms startup enablement and an observed active process. For
`--pending-service`, approval, activation and the first successful report remain
separate dashboard observations. An actual OS reboot still needs the manual VM
gate. A failed transaction preserves identity and explains whether rollback was
confirmed; do not blindly repeat a fresh install or append `--resume` to the
copied outer shell command. Use the reviewed bootstrap's explicit resume flow
only after inspecting a compatible retained preparation and retaining the exact
release, public bootstrap and identity.

**Release boundary:** these bootstrap and native-installer improvements are included
in the independently verified `v0.1.0-rc.3` from source
`405f57f184e75736477cbd3af7a2536ddfe0e6f6`, now selected by the dashboard pin.
The published rc.2, rc.1 and pilot.2 bootstrap and binaries are unchanged. GitHub reports
`immutable: false` for rc.3; the exact source, manifest, bundle and asset hashes
remain fixed, without claiming platform-level release locking. This selection
does not establish download-based installation, upgrade or reboot acceptance.

## Exact trust chain

1. The command pins a full immutable commit and SHA-256 for a standalone Python
   bootstrap from `raw.githubusercontent.com/storminator89/Tracebolt`. It downloads
   privately over system-trusted HTTPS, without proxies or redirects, and hashes
   the file **before** running `python3 -I -B`. It is never `curl | sh`.
2. Those reviewed bootstrap bytes embed the exact release version, full source
   SHA, manifest SHA-256 and attestation-bundle SHA-256. No CLI argument, manager
   API response or environment variable can supply release URLs or trust pins.
3. The bootstrap fetches `manifest.json` and `manifest.sigstore.json` from the
   fixed version of `storminator89/Tracebolt` on GitHub Releases. Only the exact
   HTTPS GitHub asset redirect host `release-assets.githubusercontent.com` is
   accepted, once. Every DNS answer must be public; mixed/private answers,
   credentials, alternative ports, proxy settings, redirects to other hosts,
   content encodings, oversized/truncated bodies and wrong hashes fail closed.
   A supervising process enforces a whole-download 600-second deadline, including
   DNS, headers and slow-progress bodies; only the read-only download child can
   be terminated at that deadline, never an installer transaction.
4. Verification uses the official GitHub CLI **2.102.0**, downloaded transiently
   from fixed `cli/cli` release asset URLs. Its archive digest and byte count are
   independently pinned in the reviewed bootstrap. Only the one exact regular
   `bin/gh` archive member is copied as bytes into the private directory. No path,
   link, permission or other archive member is extracted; nothing is installed
   globally. The verifier executes only after its archive digest matches.
5. The bootstrap supplies its embedded public Sigstore trusted root and local
   bundle to `gh attestation verify`. The pinned CLI's `--bundle` disables its
   authentication requirement; `--custom-trusted-root` avoids online trust-root
   discovery. It uses a fresh private config/home, no token and no ambient proxy.
   Signature, certificate, signed transparency-log/timestamp and provenance checks
   are delegated to the upstream verifier, not reimplemented as custom crypto.
6. Verification must match all of: repository `storminator89/Tracebolt`, signer
   `.github/workflows/linux-release-candidate.yml`, exact source **and** signer
   commit, `refs/heads/main`, issuer `https://token.actions.githubusercontent.com`,
   GitHub-hosted runner and `https://slsa.dev/provenance/v1` predicate. The source
   and signer checks use certificate-backed policy, not just a claimed JSON field.
7. Only after that verification does the bootstrap accept the strict manifest and
   download only the three ordinary installer binaries plus the explicit source archive.
   The fresh read-admin v2 path alone also stages the attested socket-owner helper;
   explicit socket-owner maintenance stages only the source archive. Exact
   names, sizes and SHA-256 values must match. All files are private mode 0600;
   every selected artifact is rechecked before any Tracebolt binary becomes
   executable. The source archive is never extracted. Read-admin/maintenance load only the fixed
   reviewed Python modules and unit templates in memory after source inode/owner/
   mode/size/hash checks; there is no second mutable implementation download.
8. The existing installer receives the verified files and digest values directly
   as an argument list, never a shell interpolation. Ordinary interruption is
   forwarded to the installer and awaited so its existing cancellation/rollback
   contract is not replaced by an automatic force kill. Enrollment origin/public ID/
   bootstrap digest and public TLS CA remain separate inputs. Invitation secrets
   are accepted only by the existing hidden terminal prompt. No collection starts
   before the existing approval and activation conditions.

The first-stage command and its pins must come from an independently trusted
reviewed release/source reference. A tampered HTTP-test dashboard can replace a
whole displayed command; neither signatures inside the intended command nor a
checksum copied from that same compromised page can authenticate the page itself.
HTTP-test manager transport still carries its explicit disposable warning and
never supplies executable trust. Do not claim protection against a compromised
GitHub account/build workflow or a malicious newly approved bootstrap.

## Reproducible selection, not a reproducible-build guarantee

`deploy/release/build-linux-release.py` requires a clean exact Git checkout and
its declared Go version. The new source contract cross-builds `agent-service`, `enroll-agent`,
`lan-agent` and `socket-owner-reader` with CGO disabled, baseline amd64/arm64 settings, trimmed paths and
recorded VCS metadata. It makes an explicit `git archive` from that full source
SHA. The strict new manifest contains the chosen version/source, nine file hashes
and sizes, and only `linux-amd64` as the runtime target.

The attestation binds this manifest to the specific build workflow. It does not
prove that two independent builds are byte-identical, and it does not substitute
for reviewing the source, dependencies, workflow or actual runtime behavior.

The rc.3 manifest contains all nine program/source assets plus three public
bootstrap/provenance files. The combined read-admin path selects the separate
helper explicitly; an ordinary install or upgrade does not grant that scope.
Historical rc.1 and pilot.2 artifacts remain unchanged.

## Candidate build and publication gates

The manual `linux-release-candidate.yml` workflow runs only in the exact repository
on `main`. The release job has `contents: read`, and the specifically authorized
`id-token: write` and `attestations: write`. Other workflows keep their permissions.
That build job has no signing secret, offline project private key, repository
write, registry push, deployment environment or host-installation action.

The workflow validates the bootstrap fixtures and existing installer packages,
builds the candidate files, attests the exact manifest using a full-commit-pinned
GitHub action, retains the public bundle, and verifies the exact source/workflow
before creating `bootstrap.py`. With the default `publish: false`, the output is an Actions review artifact,
**not** a published GitHub Release or an activated dashboard command.

The separately authorized `publish` job has only `contents: write` and runs only
when the manual dispatcher explicitly sets `publish: true` for its chosen version,
after the candidate job succeeds. No normal build workflow gains repository write
access, and the publishing job gets no OIDC/attestation write grant. It downloads
only the exact artifact ID emitted by the candidate in this same workflow run.
Version-scoped concurrency queues duplicate requests instead of canceling a write
mid-publication.

Before any GitHub mutation, `publish-linux-release.py` snapshots the exact twelve
candidate files privately, independently verifies their keyless provenance again,
checks every manifest size/hash and compares `bootstrap.py` with the exact local
reviewed template plus the verified release pin. It then verifies the repository's
numeric identity, current `main` source SHA, and absence of the selected version
from tags, release-by-tag and authenticated draft/release listings. It refuses
uncertain or unbounded freshness results. It creates only that fresh tag and a
new draft, uploads only the expected nine artifacts, manifest, bundle and
bootstrap, and checks all returned and listed asset digests before publishing it
as a prerelease without changing the repository's `latest` release. Final release,
tag and complete asset metadata are read back once more.

No existing tag, draft, release or asset is adopted, overwritten, deleted or
silently resumed. Each mutation is tried once. A lost response or mismatch can
leave a tag or partial draft; that state is deliberately retained for inspection,
and a rerun refuses it. The job does not change repository settings, enable
immutable releases, update a branch, or activate the dashboard/bootstrap pin.
The Actions token is consumed only by the publication step for fixed official
GitHub API/upload hosts, with no redirects, raw token/error-body logging or
credential fallback.

Before activation, the authorized publisher must:

1. Run the candidate workflow on the exact reviewed `main` commit and confirm its
   actual result. Preserve the manifest, public bundle, binaries and source tar
   from that same successful run.
2. Select the exact new version and explicitly request `publish: true` in the
   reviewed workflow when publication is intended. The separate publishing job
   uses the independently approved `contents: write` scope above. If the source
   `main` SHA has changed during the build, it stops rather than publishing a
   stale or ambiguous selection. Existing/partial release state requires human
   inspection and a separate recovery decision; do not delete it to make a rerun
   pass. No repository security-setting changes are part of this operation.
3. Publish the generated bootstrap bytes as
   `deploy/release/published/VERSION.py` in a reviewed immutable source commit.
   Pin that **bootstrap publication commit** and the bootstrap digest in the
   command surface. This is separate from the binary/source build commit and
   avoids a circular manifest/bootstrap hash dependency.
4. Verify all official URLs and pinned bytes using the real downloader. Only then
   enable the download command. Keep the old manual path honestly labelled until
   this distribution is available; never substitute fabricated/test pins.
5. Run the separately authorized disposable Linux runtime gate for download,
   install, pending approval, reporting, retained-identity resume and upgrade.
   Record actual restart and actual OS reboot independently. Do not run these
   privileged acceptance operations on an unapproved host.

The reusable template remains at `RELEASE_PIN = None`. The separately published
`deploy/release/published/v0.1.0-rc.3.py` contains the verified fixed release pin;
the dashboard names bootstrap publication commit
`bba617e459bb072d4506fe6cacecaa97388ea93c` and the exact bootstrap digest.
The earlier pilot.2 source is retained unchanged. There is no private-key setup
step for this chosen keyless path.

## Verification evidence and limits

The [rc.3 build/publication](https://github.com/storminator89/Tracebolt/actions/runs/37573387512)
succeeded from the exact source above. The
[independent public-byte check](https://github.com/storminator89/Tracebolt/actions/runs/37574492167)
verified all twelve assets, exact source/workflow keyless provenance and the bootstrap's
source reconstruction without executing a Tracebolt program or installer. The
commit-pinned bootstrap source was independently read back before the UI pin update;
its exact size/hash and selection are recorded in the
[dashboard download guide](dashboard-verified-download.md). The [native Ubuntu TLS upgrade run](https://github.com/storminator89/Tracebolt/actions/runs/37572468648) passed the verified rc.2-to-405f
source-built replacement, unchanged identity/scopes/private state, local approval,
all six functional checks and cleanup. Released rc.3 bytes are separately verified
above. The user's Debian/HTTP upgrade and actual OS reboot remain separate
authorized acceptance observations.

Default fixtures cover disabled production pins, read-only preflight, platform
rejection, root/terminal boundaries, strict manifest/asset validation, tampering,
keyless verifier failure and policy flags, private staging, source non-extraction,
no automatic reset/re-enrollment, wrong/duplicate/foreign redirects, public-only
DNS, response bounds, proxy/credential isolation and artifact integrity before
execution. Publication fixtures cover explicit opt-in and Actions context, exact
artifact snapshots, stale source/repository rejection, existing tags/releases and
hidden drafts, uncertain mutations without retries/deletion, changed refs/digests
before publication, and full final readback. They perform no live GitHub writes. They use inert files and mocked service/verifier outcomes, never
fabricated GitHub certificates or a real service installation.

A separate local upstream smoke check used the official pinned GitHub CLI,
embedded root and the CLI repository's signed `sigstore-js-2.1.0` fixture. It
verified the exact upstream source/workflow identity offline and rejected wrong
repository, source commit, workflow and OIDC issuer. This establishes verifier
compatibility; it is **not** a Tracebolt workflow/release acceptance result.

Relevant existing race checks are `./internal/agentinstall`,
`./internal/bootstrapfetch` and `./cmd/agent-service`. Broader application tests and
real workflow/host gates are separately reported, never inferred from these.

## Upstream references

- [GitHub artifact attestations](https://docs.github.com/en/actions/how-tos/secure-your-work/use-artifact-attestations/use-artifact-attestations)
- [Exact CLI verification flags](https://cli.github.com/manual/gh_attestation_verify)
- [Pinned CLI implementation](https://github.com/cli/cli/blob/v2.102.0/pkg/cmd/attestation/verify/verify.go)
- [Offline trusted-root implementation](https://github.com/cli/cli/blob/v2.102.0/pkg/cmd/attestation/verification/sigstore.go)
- [CLI v2.102.0 release and published asset digests](https://github.com/cli/cli/releases/tag/v2.102.0)
- [Pinned public Sigstore root](https://github.com/sigstore/root-signing/blob/5888f358fc4ab58874447259edf83790261fc616/targets/trusted_root.json)
- [Pinned attestation action](https://github.com/actions/attest-build-provenance/blob/977bb373ede98d70efdf65b84cb5f73e068dcc2a/action.yml)
- [GitHub Release API and source-commit permission boundary](https://docs.github.com/en/rest/releases/releases)
- [Release asset API and digest readback](https://docs.github.com/en/rest/releases/assets)
- [Immutable release behavior](https://docs.github.com/en/code-security/concepts/supply-chain-security/immutable-releases)
