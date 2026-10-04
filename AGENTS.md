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
  The public command fetches bootstrap metadata and selects `--pending-service`;
  invitation input remains hidden and no collection begins before approval and
  activation. Helper/source checks do not establish actual service or reboot acceptance.
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
- Complete visible process/mount generations are a separate default-off local
  extension under an existing activated v3 identity. Read
  `docs/complete-overview-extension.md` before opt-in. Keep the stopped-service
  identity guard, explicit full-scope disclosure, independent durable floors and
  original capture age. No automatic collection, re-enrollment, manager reset or
  host permission grant follows from a manager upgrade or schema initialization.
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
