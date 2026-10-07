# Tracebolt repository agents

For installation/deployment requests, read **[docs/installation.md](docs/installation.md)**
first, then the relevant `deploy/` templates and current CLI source. Treat this
file as navigation and project constraints, never as permission to act on a host.

- Inspect the selected computer, OS/architecture, checkout/revision, existing work,
  toolchain, private paths and requested scope before changing anything. Preserve
  user edits. Do not assume the editing environment is the deployment server.
- Current LAN paths: default manual-v1 with preprovided approved material, or
  explicitly configured guided-v2 with a dedicated protected client-auth issuer.
  Linux `enroll-agent` uses a hidden local terminal prompt and deliberate public
  fingerprint/comparison approval; Linux `lan-agent` supports one-shot or bounded
  foreground reporting. A Linux/systemd `agent-service` candidate adds read-only preflight and separately
  authorized install/restart/upgrade/uninstall; actual service acceptance is a
  manual disposable-VM gate. Windows/macOS LAN clients, verified boot persistence
  and automatic renewal are not shipped. `make run` is the synthetic developer
  manager, not the LAN startup command.
- Obtain the required approval for deployment exposure, persistent credential or
  trust changes, firewall/global settings, service installation and destructive
  actions. Stop at missing credentials/authorization; explain the exact blocker.
  Never weaken TLS, file protection or firewall policy to make a test pass.
  Native enrollment creates persistent endpoint keys; obtain its required approval
  and hand secret invitation entry to the human/approved secure handoff. Do not
  pass invitation secrets through args, environment, URLs, files, chat or logs.
- Keep passwords, verifiers, private keys, cookies, raw telemetry and runtime state
  out of Git, logs, chat and artifacts. Use approved secure provisioning. Root CA
  private keys stay offline outside the explicitly authorized disposable HTTP setup
  helper, which creates a temporary root key in memory and never writes it. Only
  opt-in guided-v2 permits a dedicated client-auth intermediate signing key in
  protected manager custody. Public approval still
  requires independently verified identity/fingerprint and explicit authority.
- Expanded operational/package collection requires a fresh explicitly acknowledged
  profile and identity. Never relabel or reuse a basic/v2 ledger to grant it. For the
  fresh v3 HTTP background-service MVP read `docs/http-complete-first-start.md`.
  The current rc.3 complete-profile public command selects `--read-admin` and the
  validated ingress. One combined local scope approval configures inventory and
  the separate helpers; invitation input remains hidden and dashboard identity
  approval is still required. Basic/non-complete profiles retain pending-service.
  The recorded native Ubuntu TLS pass does not establish a user host or OS reboot.
- The separate hostname/interface-address extension stays off until explicit local
  consent under the existing stopped service identity. Use the documented preview,
  enable and disable commands; do not edit its sidecar or collect through the manager.
  Existing enrollment/counter state stays bound, and disabling does not refresh or
  erase retained metadata. See `docs/endpoint-identity-extension.md`.
- Optional on-demand journal content needs a compatible upgraded endpoint and a
  separate explicit local helper/content grant. Read `docs/linux-journal-helper.md`
  and `docs/journal-content-mvp.md` before proposing setup. The main agent must not
  become root or gain journal-group membership. Keep selected service allowlists,
  separate HTTP plaintext-content acknowledgement, durable consume-once floors,
  original expiry and operator-only content boundaries. Source/fixture checks do
  not authorize account, group, unit or socket changes or an actual journal read.
- Retained service-log browsing is a new create-only v4 local scope. Read
  `docs/retained-journal-browsing.md` before changing its policy, cursor protocol
  or installer integration. Never promote v1-v3 grants; the combined fresh admin
  approval must explicitly cover retained history. Keep consume-once and source
  cursor-loss truth, bounded pages, and external-AI separation.
- Complete visible process/mount generations are a separate default-off local
  extension under an existing activated v3 identity. Read
  `docs/complete-overview-extension.md` before opt-in. Keep the stopped-service
  identity guard, explicit full-scope disclosure, independent durable floors and
  original capture age. No automatic collection, re-enrollment, manager reset or
  host permission grant follows from a manager upgrade or schema initialization.
- Complete cached APT update rows are a separate default-off local scope;
  preview consent never authorizes the full generation. Before enabling or
  changing it, read `docs/complete-cached-updates-extension.md`. Preserve the
  independent durable floor, exact retry bytes, cached-only command policy,
  original metadata age and operator-only bounded paging. Fixture tests do not
  establish native Debian/Ubuntu or installed-service acceptance.
- For the fresh one-command read-admin profile, read
  `docs/read-admin-onboarding.md`. One explicit combined approval covers the
  supported read scopes/helper only; production HTTPS remains default and HTTP
  requires its full content-risk warning. Keep the main agent nonroot, retain
  started/completed phase evidence, and never adopt existing or pending journal
  state. Use only the verified rc.3 pin and matching manager source described there;
  older release commands are not compatible with the combined profile. Do not
  call fixture results native acceptance or execute any host grant without approval.
- For a completed read-admin v2 update, read `docs/read-admin-upgrade.md`. Use only
  the explicit verified coordinator; never substitute ordinary binary upgrade.
  Preserve original receipts, private state and same-scope grant bindings; require
  the separately approved native old-release-to-new-artifacts gate before release.
- For one-time existing-agent inventory consent, read
  `docs/guided-inventory-setup.md`. Its preview is nonmutating until explicit
  confirmation; existing identity-bound scope CLIs remain authoritative. Do not
  turn setup into a manager grant, journal recovery or host acceptance claim.
- Service-action setup is a create-only source candidate for one existing activated
  endpoint and one reviewed service. Read `docs/guided-service-action-setup.md`.
  Plan is read-only; manager/endpoint apply needs separate local approval. Never
  remove intent/fences or reinitialize missing used state. The old pinned release
  is incompatible; source fixtures do not authorize native setup or a target action.
- Selected native APT updates are a default-off source candidate, not released. Read
  `docs/selected-package-updates-native.md` and its native gate before setup. Source
  compilation and fake subprocess tests never authorize package installs, root
  helper grants or state reset. Keep exact signed plans, consume-once claims and
  the shared service/package mutation fence.
- Proactive AI diagnostics are a default-off manager-side scope. Read
  `docs/proactive-ai-diagnostics.md` before changing its admission or data flow. For
  optional restart-safe storage also read `docs/ai-settings-persistence.md`; never
  silently persist a provider/key/scope or bypass an unresolved storage fence.
  Preserve exact provider/device approval, claim-before-call deduplication and
  existing managed-evidence export blocks. Health-summary approval never permits
  raw logs, dump data, autonomous tools, shell commands or remediation. Fixtures
  do not authorize a real provider call, API-key entry or runtime scope grant.
- Follow Go/Node versions and dependency locks in this revision. Validate commands
  against actual flags/config. Distinguish runtime tests from cross-builds, skipped
  container tests, and proposed functionality. Never invent install/enroll flags.
- Change only requested files; keep security boundaries and provenance intact.
  Run relevant checks and report exact revision, platform, pass/fail/skip and
  remaining gates. Do not claim a real deployment from local fixtures or CI.

Build/test entry points and safe operational boundaries are in the runbook;
component detail is in `docs/lan-runtime.md`, `docs/lan-agent.md`, `docs/docker.md`
and `tests/lanclient/README.md`. For service requests also read
`docs/linux-agent-service.md`; its candidate status does not authorize host changes.

## Separately approved service-log AI

`service-journal-ai-v1` is an explicit, default-off exception implemented only by
`internal/proactivejournal`, `analysis.AnalyzeJournal` and the journal-AI API.
Never infer its approval from local journal access or `health-summary-v1`.
Preserve exact provider/credential, manager, device/service, policy-generation,
window, acknowledgement and original-expiry bindings. Log-backed source/model
text stays memory-only; durable receipt/attempt metadata must contain no log or
model prose. The existing managed-profile `BuildPacket` exclusion remains intact.
See `docs/proactive-service-log-ai.md` for bounds and the native fixture boundary.
