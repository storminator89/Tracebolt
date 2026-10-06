# One-command Linux read-admin onboarding

Status: **rc.2 is published, independently verified and selected by the dashboard
for the complete Linux profile**. One explicit terminal approval configures its
supported read scopes and separate helpers. The [native Ubuntu TLS run](https://github.com/storminator89/Tracebolt/actions/runs/37508637893)
passed registration, owners/provenance, journal content, restart, revocation and
cleanup on production-equivalent c1cd23a source. The [public rc.2 readback](https://github.com/storminator89/Tracebolt/actions/runs/37513100878)
verified all 12 assets and exact source/workflow provenance without executing an
installer. A user's download-based Debian/HTTP installation and actual OS reboot
remain separate observations; source and release checks are not that host result.

## Normal path

1. The administrator copies one verified installation/registration command from
   Add device and runs it deliberately in the endpoint's local root terminal.
2. The command shows **one combined read-admin scope** and its exact manager,
   source/release, expected bootstrap, account/service effects and content risks.
   HTTPS is the default. An explicitly selected disposable HTTP test has a
   distinct `OVER HTTP` approval including journal plaintext and impersonation.
3. After that approval, the existing installer creates the dedicated nonroot
   identity. The invitation is entered only at its hidden local terminal prompt.
   The administrator compares the full public fingerprint/comparison value and
   approves the device in the dashboard. Keep the terminal open while waiting.
4. The same command verifies activation and installer ownership, configures the
   existing inventory scopes, creates the separate bounded journal helper, then
   configures the isolated socket-owner helper as the final phase.
   There are no per-view permission commands or additional ordinary scope prompts.
5. The result names the installed read profile and confirmed phases. Incoming
   reports, timestamps and actual source coverage still need the normal dashboard
   acceptance checks. The result does not call root installation universal access.

The source bootstrap's `--read-admin` option selects this path. Its required
`--read-admin-agent-origin` is copied from the validated public bootstrap and
shown as the exact inventory/journal destination before approval. The native
installer checks that exact ingress alongside the bootstrap profile before any
account/service change. The public bootstrap SHA-256 is also shown; confirmation
uses the short `INSTALL READ ADMIN` phrase, with `OVER HTTP` only for HTTP tests. It deliberately
uses the existing approval-waiting installer, rather than returning as soon as a
pending background process starts. If `--pending-service` is also present in the
source wrapper, it is not forwarded for read-admin. `agent-service` receives
`--require-complete-profile`, a preflight-only guard requiring an exact
`managed-operations-v3` public bootstrap before account/service changes. This
flag does not itself authorize or configure any optional read permission.

Do not add these flags to the older published rc.1 command; that bootstrap does
not contain this implementation. No moving-branch or unverified download is a
substitute for publishing and verifying the new release.

The new profile is `tracebolt.linux-read-admin.v2`; its plan, immutable intent and
phase receipts are version 2. A v1 receipt never authorizes socket-owner access.
The fresh path requires Linux amd64 and kernel 6.5 or newer before installation
or grants, in addition to the existing supported-distribution/systemd/cgroup
preflight. Unsupported systems stop without a weaker fallback.

## Exactly what the one approval covers

- Dedicated non-login account, persistent endpoint identity and owned background
  service, still running as its recorded nonroot UID/GID with empty supplementary
  groups.
- Existing v3 installed dpkg software, system services and visible socket
  inventory; full visible process and mounted-filesystem generations.
- Full cached APT candidate rows and comparison/unknown metadata. Cached-only:
  no repository refresh, package installation or installability guarantee.
- Hostname and visible interface names and IPv4/IPv6 addresses.
- A separate non-login journal helper with unit-scoped access to the existing
  systemd-journal group. Its v3 policy authorizes all supported current and
  future **exact system-service** requests. Each request remains one supported
  `.service`, at most one hour within the preceding 24 hours, severity 0–7.
  Kernel, whole-system and system-wide authentication sources are excluded.
- A separate socket-owner helper with unit-scoped `CAP_SYS_PTRACE`. This is broad
  process-memory authority. Metadata-only collection is code policy, not an OS
  read-only confidentiality boundary. The helper is restricted by its fixed
  service/scope implementation to systemd-PID1-local TCP/UDP owner metadata.
  The main agent remains unprivileged with its original unit and groups.
- Transmission of these approved observations/content to the exact bound manager.
  Journal messages may contain credentials, tokens and personal information;
  best-effort masking is not a secret-free guarantee.

Full process/mount captures retain the existing 60-second cadence; full cached
APT retains its six-hour cadence. Original capture age, independent durable
floors and exact retry bytes remain owned by the existing implementations.

Socket owner metadata remains subject to namespace, visibility and source limits;
unavailable ownership stays explicit. Controlled service actions are not provisioned
by this read profile; their exact target manifests, manager signer/trust and explicit
bounded grant remain separate. There is no arbitrary shell, root-running main agent,
sudoers, polkit or broad main-agent group. There are no extra ordinary scope prompts.

## Reuse, trust and bounded phases

The verified bootstrap loads only a fixed set of regular source members from the
already checksum- and provenance-verified release archive. It rechecks source
inode, owner, mode, size and SHA-256, refuses duplicate/missing/link members, and
loads modules in memory. It never extracts an archive path or downloads a second
mutable implementation. No installed source dependency or new general workflow
framework is introduced.

The native installer and its existing ownership/transaction receipts remain
responsible for installation, enrollment and activation. After installation,
read-admin binds a small immutable intent to the exact release/manifest,
bootstrap, installer owner, device/config identity and manager origin. It checks
all inventory flags, the endpoint/manager journal contracts and the exact public
`/v4/system/capabilities` contract before optional grants. The five-field capability
must name `tracebolt.system-manager-capabilities.v1`, the bound `agentOrigin`,
`tracebolt.agent-system-inventory.v4`, `tracebolt.socket-owner-source.v1` and
`systemd-pid1-local-tcp-udp-socket-owners`. It is fetched from the stored bootstrap's
enrollment origin using its exact public CA. HTTP-test capability data is explicitly
unauthenticated. Missing, old, extra-field or mismatched responses stop; journal
capability or `managed-operations-v3` alone does not imply socket-owner support.
The existing inventory guide validates every selected preview
before enabling any missing selection; its existing nonroot CLIs own private
consent and spool initialization. Fresh journal setup owns its distinct account,
policy, socket and durable activation/floor ordering.

Three additional fixed phase pairs under the existing protected installer directory
record `inventory`, `journal` and final `socket` as started and complete. Started
is durable
before an effect; complete is durable only after its validator/readback succeeds.
These are completion evidence, not permission to invent missing state or roll
back unrelated data. There is no atomic transaction spanning all filesystem,
systemd and private-state effects. Earlier successful scopes remain recorded if a
later phase fails. No claim of whole-backup rollback resistance is added.

The journal readback uses the existing amendment inspector and nonroot
preview to verify paired policy/deployment copies, committed activation and the
original identity/generation/consume-once floors. It briefly stops only the owned
agent under the existing installer lock and restores prior activity after
unchanged-identity/baseline validation. No actual log query or action is used as
an onboarding probe.

Socket completion additionally has an immutable helper receipt binding the original
helper IDs, grant epoch, signed helper artifact hashes and sender identity. Generic
phase receipts are lifecycle evidence only. Completed socket phases are verify-only;
a disabled/revoked scope is never re-enabled. Partial effects or corruption retain
evidence and leave the agent stopped, including a failure to record parent completion. On resume, uncertain socket
evidence is rejected before manager capability fetches or earlier-phase verification.
Configuration readback does not call the native helper's Verify operation: the offline
setup CLI cannot satisfy live service-cgroup authentication. The resumed ordinary
agent performs its existing optional Verify/capture path. Setup success is not native
helper readiness, source acceptance, attribution completeness or reboot evidence.

## Explicit maintenance revocation

The same exact verified release bootstrap exposes
`--action revoke-socket-owners --apply` as a separate deliberate maintenance operation. It accepts no enrollment,
upgrade, resume, manager, invitation, CA or grant flags and asks for
`REVOKE SOCKET OWNERS`. This is not another normal setup step.

Revocation loads only the fixed source modules/templates from the verified source
archive and stages no Tracebolt binary. It requires the exact installed v2 parent
intent, completed socket phase, original immutable helper completion receipt and
root grant. The selected source hash must equal the installed source hash. It never
invokes the installer, installs artifacts, creates credentials or initializes scope.
The owned agent and helper participants are stopped/drained, root policy is disabled,
a private disabled tombstone is retained, and only socket-tagged pending bytes are
discarded while the monotonic floor remains. Prior agent activity is restored only
after confirmed completion. A partial revoke retains evidence and leaves the agent
stopped. After approval, failed revocation also contains the helper only when its
original immutable receipt, artifacts, account and loaded units prove ownership,
independently of the possibly corrupt policy/deployment. Foreign or unprovable
helper ownership is never adopted; the result reports helper shutdown unconfirmed.
There is no re-enable, renewal or rebind path.

## Existing hosts, interruption and recovery

Fresh mode refuses any existing installed or retained installer domain and any
existing journal configuration/evidence. It never treats an older/basic/v2 grant
as approval for this profile. Upgrading a binary alone cannot activate it.
Completed v2 installations use the explicit [same-scope update](read-admin-upgrade.md)
when it is present in the selected verified release. Existing installations retain their recovery workflows; this
candidate intentionally does not turn an unresolved pending journal transaction
into a fresh helper installation.

An explicitly selected `--resume-read-admin` together with the same `--read-admin`
public inputs only operates on an exact retained read-admin intent. It does not
invoke native installation/enrollment again. Fully completed phases are
revalidated; a revoked/disabled completed inventory scope is not silently
re-enabled. A phase not yet started can proceed under the renewed combined plan
approval. A started phase without a complete receipt is **uncertain** and stops
before replay. Missing/malformed receipts, changed device, origin, release,
bootstrap, ownership, policy copies, activation or floors are retained blockers.

If interruption happened during native installation, use that installer's own
reviewed same-identity recovery procedure. If installation committed but the
read-admin intent was never durably created, this read-admin resume mode cannot
adopt it. Report that narrow receipt gap and inspect the retained installation;
do not re-enroll or delete the account/state to make the fresh command work.
SIGKILL/power loss can interrupt a write or leave the service stopped. Status and
failure phase must be checked; neither elapsed time nor an old receipt is proof
that a current service or source is working.

## Inert gates and remaining acceptance

Tests replace all account, service, installation, source, permission and
collection adapters. Relevant checks are:

```sh
python3 -B -m unittest discover -s deploy/onboarding -p 'test_*.py' -v
python3 -O -B -m unittest discover -s deploy/onboarding -p 'test_*.py' -v
python3 -B -m unittest discover -s tests/release -p 'test_*.py' -v
python3 -B -m unittest discover -s deploy/inventory -p 'test_*.py' -v
python3 -B -m unittest discover -s deploy/socket-owner -p 'test_*.py' -v
python3 -B -m unittest discover -s deploy/journal -p 'test_*.py' -v
go test -race ./internal/agentinstall ./cmd/agent-service
go test -race ./internal/journalgenerationstate ./internal/journalactivation
```

The manual-only [fresh V2 disposable-systemd harness](../tests/systemd/read-admin.md)
requires an exact reviewed source revision and explicit approval of the fresh
profile, including the socket helper's broad CAP_SYS_PTRACE authority. Ordinary
checks skip privileged execution. The recorded TLS native pass is linked above;
other transport/platform runs and an actual OS reboot remain separate.

The first complete scenario checks one combined approval and registration, actual
nonroot identity, a real exact-service journal marker, controlled TCP/UDP socket
owners with original provenance, agent service restart with a newer report, and
production revocation/drain followed by ordinary reporting. Each selected transport
needs its own disposable run. Adversarial kernel/LSM cases, resource measurements
and an actual OS reboot remain separate; no existing-installation migration is
required for this fresh-install path. Real secrets, source log content and private
runtime state must not appear in repository fixtures or artifacts.
