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
  foreground reporting. Windows/macOS LAN clients, OS installers/services, boot
  persistence and renewal are not shipped. `make run` is the synthetic developer
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
  private keys stay offline. Only opt-in guided-v2 permits a dedicated preprovided
  client-auth intermediate signing key in protected manager custody. Public approval still
  requires independently verified identity/fingerprint and explicit authority.
- Follow Go/Node versions and dependency locks in this revision. Validate commands
  against actual flags/config. Distinguish runtime tests from cross-builds, skipped
  container tests, and proposed functionality. Never invent install/enroll flags.
- Change only requested files; keep security boundaries and provenance intact.
  Run relevant checks and report exact revision, platform, pass/fail/skip and
  remaining gates. Do not claim a real deployment from local fixtures or CI.

Build/test entry points and safe operational boundaries are in the runbook;
component detail is in `docs/lan-runtime.md`, `docs/lan-agent.md`, `docs/docker.md`
and `tests/lanclient/README.md`.
