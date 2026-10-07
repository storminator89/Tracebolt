# Selected APT updates: native source candidate

This candidate connects detected update selection to native preparation, exact
review, explicit installation approval, durable dispatch, endpoint-reported
results and reboot evidence. It is **not released or natively accepted**. The
existing installer does not provision or enable it. Source compilation, mocked
subprocesses and synthetic transport tests do not establish an installation on a
host. No real APT/dpkg/systemd operation was run for this candidate.

The first pilot supports Debian 13 amd64 with APT 3.0.3. ARM is compile-compatible
only and fails native runtime admission. At most 32 existing, explicitly allowed
amd64 packages may be selected. New dependencies, removals, downgrades, held or
partially installed packages and ambiguous source provenance fail preparation.
Foundation packages (APT/dpkg, libc, systemd, kernels/bootloaders, networking,
OpenSSH and Tracebolt) are excluded from this initial local allowlist policy.

## Implemented path

1. The detected-updates UI retains selected package identities, never treating its
   cached candidate versions as authoritative installation evidence. The manager
   requires the named operator's `plan_updates` capability and a fresh enabled
   root-helper capability bound to this endpoint incarnation and local policy.
2. The manager commits a signed preparation envelope in its private SQLite store.
   The enrolled endpoint transport consumes delivery once before returning that
   envelope. A lost claim/submission is status-only and never replayed.
3. The root broker validates the dedicated Ed25519 package signature, local
   allowlist, fixed tool pins and shared service/package mutation fence. It commits
   admission before starting an independent systemd runner. Preparation uses a
   fresh protected repository snapshot, authenticated complete metadata refresh,
   exact solver selection and staged archives. A mandatory capture-and-abort
   guard records the final APT configuration/hook stream without allowing dpkg.
4. Review displays each exact installed and target version, source package and
   version, repository label/suite/component, archive hash and bounded size. The
   complete signed plan also binds Release/index/source hashes, installed state,
   holds, configuration and the mandatory guard. The fixed conffile policy keeps
   locally modified conffiles (`--force-confold`); no arbitrary options are sent.
5. The same named actor requires `execute_updates`, current readiness and explicit
   installation acknowledgment. The manager signs exactly that preview digest and
   plan, then commits approval. The separate execution claim is also consumed once.
6. The independent runner executes the same fixed APT argv/environment/config as
   capture. The one-use pre-dpkg guard checks original permit/expiry, current local
   authority, frontend-lock owner/parent identity, inner dpkg lock, installed/hold
   state, archived bytes and exact hook operations before release to dpkg.
7. Applying survives agent/helper replacement: its unit has no parent lifecycle
   coupling, no restart and no applying cancellation timeout. Known success needs
   guard completion, exact post-install versions and clean dpkg state. Any lost
   custody, missing guard or mismatch remains needs-intervention. The UI labels
   these as endpoint-reported native results; it does not claim remote attestation.

APT maintainer scripts and triggers can change the system and restart services.
This is not a sandbox or transactional rollback. No automatic reboot, repair,
lock deletion, force clearing of uncertain jobs or automatic retry is provided.

## Explicit local setup boundary

Setup is a separate reviewed administrator action on the exact disposable pilot
host. It must not be inferred from read-admin enrollment, cached-update consent,
a manager upgrade, an existing service-action grant or this source packet.
No key, account, group, unit, socket, permission or repository was provisioned by
this candidate's tests.

- Root broker/runner/guard preparation and fixed templates are in
  [deploy/package-actions/README.md](../deploy/package-actions/README.md). Its
  `nativeAcceptanceDigest` and `serviceFenceReviewDigest` identify externally
  reviewed receipts; their presence does not itself prove acceptance. Review
  [the native gate](../deploy/package-actions/native-acceptance.md) before setup.
- Native preparation compile instructions, protected sources/keyring/preferences,
  host configuration opt-in and configuration restrictions are in
  [internal/nativeapt/README.md](../internal/nativeapt/README.md). The native
  executable is built separately against matching libapt headers; it is not run
  during the build.
- Provision a dedicated package-command Ed25519 key separately from enrollment,
  server TLS and service-command keys. `packagecontroller.Config` is the exact
  protected manager JSON at an explicitly selected path. It binds one manager,
  endpoint, incarnation, root-policy digest, transport profile, existing key path
  and private SQLite path. Set `localScopeAcknowledged` only after approval.
  The create-only source command is `package-manager-init --config <path>
  --ack-local-package-scope`. It reads preexisting protected config/key, creates
  only the durable record under an existing private directory and never resets
  state. Manager startup opens existing state only.
- Set the existing manager config's optional `packageActionsConfigFile` to that
  protected scope. The manager requires named operators and activated complete
  enrollment. Grant `plan_updates` and `execute_updates` independently and
  explicitly; no account gains them through this change.
- The agent's separate root-provisioned `/etc/tracebolt/package-client.json` uses
  `tracebolt.package-client-policy.v1`. It binds the existing sender identity,
  manager origin/ID, endpoint incarnation, dedicated public key digest, exact
  root-policy digest, transport and nonroot agent UID/GID. Absent or disabled
  policy performs no package-helper or package-network I/O. Its canonical field
  contract is `internal/lanclient/packages_local.go`.
- Production TLS is the normal transport. The explicitly disposable HTTP profile
  requires matching plaintext-risk acknowledgments at every scope. Its package
  request signatures have a distinct domain and headers; they neither encrypt
  data nor authenticate the manager. An authenticated browser session can approve
  actions and must therefore be protected.

Package and service mutations share one protected durable fence. The updated
service helper must open that exact fence. Package admission verifies both its
running executable and held fence inode; an unfenced helper started before scope
provisioning refuses new authority when the directory appears. Setup still
requires the old service helper and socket quiescent. An unknown operation blocks
both mutation families until independently reviewed intervention.

## Persistence and limits

The package plan remains limited to 128 KiB and the service permit remains 4 KiB.
The separate signed package envelope allows 192 KiB, local submit framing 264 KiB,
native status/transport 1 MiB and the browser's projected package view 512 KiB.
Existing unrelated API/service limits are unchanged. Native admission reserves
bounded outcome reporting capacity before mutation.

The manager stores at most eight immutable jobs per explicitly initialized scope;
the shared fence stores 256 consumed entries. Neither silently prunes, resets or
migrates a used scope. Capacity exhaustion requires a separately designed and
approved archival/recovery step. An unclean manager-store session intentionally
fails reopening rather than guessing whether a claim committed; this first pilot
has no automatic manager recovery procedure. Root runner custody/results persist
independently, but manager service recovery must be reviewed before production
use. A definite root busy refusal after manager delivery can leave a consumed
manager delivery without a root job; it remains unknown, with no automatic retry.

Revocation, expiry or stale readiness prevents a new claim/start. They do not
cancel or fabricate an applying job. Historical root status remains readable
under the original endpoint/key binding after executable replacement. Original
capture/result timestamps remain visible and browser retries stay bound to the
same mode, actor, selection, request ID and preview digest.

## Remaining acceptance and release work

1. Run the separate approved Debian 13 amd64 disposable-VM native gate against
   exact built binaries, including successful upgrade and failure/custody cases.
   Prove actual APT lock/hook ordering, capture abort, archive/config stability,
   post-version and dpkg verification, service concurrency, agent upgrade during
   apply, restart/reboot reconciliation and durable no-replay behavior.
2. Resolve and demonstrate manager unclean-session recovery, capacity handling,
   and the consumed-delivery/root-busy operational procedure. Never clear state
   merely to make a test or installation proceed.
3. Review provisioning permissions/templates and separately authorize setup on
   the pilot host. Build/pin artifacts and integrate only after that acceptance.
   Preserve current release/installer proof; this candidate changes neither.
4. Validate native browser flows on that accepted scope, then publish/release
   only through the existing reviewed integration path. ARM and additional
   Debian/Ubuntu/APT versions require their own compatibility and native gates.
